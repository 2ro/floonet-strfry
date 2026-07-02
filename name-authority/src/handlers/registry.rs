// The name registry: availability, register, release. In paid mode (`name`),
// registration is gated on a confirmed GoblinPay payment.

use crate::auth::verify_nip98;
use crate::config::PayMode;
use crate::db::App;
use crate::names::{is_reserved, valid_name, valid_pubkey_hex};
use crate::paid::{ensure_paid, payment_required_json, PaidOutcome};
use crate::util::{client_ip, unix_now};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

pub async fn availability(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !app.allow_read(&client_ip(&headers)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    if !valid_name(&name, app.cfg.name_min, app.cfg.name_max) {
        return (
            StatusCode::OK,
            Json(json!({"name": name, "available": false, "reason": "invalid"})),
        )
            .into_response();
    }
    if is_reserved(&name, &app.cfg.extra_reserved) {
        return (
            StatusCode::OK,
            Json(json!({"name": name, "available": false, "reason": "reserved"})),
        )
            .into_response();
    }
    if app.lookup(&name).is_some() {
        return (
            StatusCode::OK,
            Json(json!({"name": name, "available": false, "reason": "taken"})),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(json!({"name": name, "available": true})),
    )
        .into_response()
}

#[derive(Deserialize)]
struct RegisterBody {
    name: String,
    pubkey: String,
}

pub async fn register(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow_write("reg", &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }

    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::POST,
        "/api/v1/register",
        &body,
        &app.cfg.base_url,
        app.cfg.auth_max_age_secs,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
    };
    if !app.auth_event_fresh(&auth_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth event replayed"})),
        )
            .into_response();
    }

    // The cooldown is set by a *release*, not a claim: it blocks re-registering
    // a new name for the cooldown window after you let one go (anti-churn),
    // while claiming itself never locks you out of an immediate release.
    // Checked after auth so strangers can't probe someone's budget.
    if app.cooldown_active("namechange", &auth_pubkey, app.cfg.name_change_cooldown) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "name_change_cooldown"})),
        )
            .into_response();
    }

    let req: RegisterBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid body"})),
            )
                .into_response()
        }
    };
    let name = req.name.to_lowercase();
    let pubkey = req.pubkey.to_lowercase();

    if !valid_pubkey_hex(&pubkey) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid pubkey"})),
        )
            .into_response();
    }
    if pubkey != auth_pubkey {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth pubkey does not match body pubkey"})),
        )
            .into_response();
    }
    if !valid_name(&name, app.cfg.name_min, app.cfg.name_max) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid name"})),
        )
            .into_response();
    }
    if is_reserved(&name, &app.cfg.extra_reserved) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "name reserved"})),
        )
            .into_response();
    }

    // Existing active registration of this exact name.
    if let Some(owner) = app.lookup(&name) {
        if owner == pubkey {
            return (
                StatusCode::OK,
                Json(json!({"name": name, "nip05": format!("{name}@{}", app.cfg.domain)})),
            )
                .into_response();
        }
        return (StatusCode::CONFLICT, Json(json!({"error": "name taken"}))).into_response();
    }
    // One active name per pubkey.
    if let Some(existing) = app.name_of(&pubkey) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "pubkey already has a name", "name": existing})),
        )
            .into_response();
    }

    // Paid names: with FLOONET_PAY_MODE=name, a confirmed GoblinPay payment
    // must exist before the claim goes through. The 402 body carries the
    // hosted pay URL so a client can send the payer straight there and retry
    // this same call once the invoice settles. Checked AFTER validation and
    // availability so nobody is asked to pay for an impossible claim.
    if app.cfg.pay_mode == PayMode::Name {
        let (app2, pk) = (app.clone(), auth_pubkey.clone());
        let outcome = tokio::task::spawn_blocking(move || ensure_paid(&app2, &pk, "name"))
            .await
            .unwrap_or_else(|e| PaidOutcome::Unavailable(format!("join error: {e}")));
        match outcome {
            PaidOutcome::Paid => {}
            PaidOutcome::Due {
                invoice_id,
                pay_url,
                price_nanogrin,
            } => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(payment_required_json(
                        "name",
                        &invoice_id,
                        &pay_url,
                        price_nanogrin,
                    )),
                )
                    .into_response();
            }
            PaidOutcome::Unavailable(e) => {
                tracing::error!("paid check unavailable: {e}");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "payment backend unavailable, try again"})),
                )
                    .into_response();
            }
        }
    }

    // INSERT guarded by the name PRIMARY KEY and the partial-unique pubkey
    // index. The ON CONFLICT(name) only revives a released name; a concurrent
    // double-register (same pubkey, different names) is caught by the unique
    // pubkey index and surfaces as a constraint error -> 409.
    let res = app.db.lock().execute(
        "INSERT INTO names (name, pubkey, created_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(name) DO UPDATE SET pubkey = excluded.pubkey,
            created_at = excluded.created_at, released_at = NULL
         WHERE names.released_at IS NOT NULL",
        rusqlite::params![name, pubkey, unix_now()],
    );
    match res {
        // rows == 0 means the ON CONFLICT no-op fired (name already active):
        // not acquired, report a conflict rather than a false success.
        Ok(0) => (StatusCode::CONFLICT, Json(json!({"error": "name taken"}))).into_response(),
        Ok(_) => {
            // A paid claim consumes its grant: releasing this name later and
            // claiming another requires a fresh payment.
            if app.cfg.pay_mode == PayMode::Name {
                app.consume_grant(&auth_pubkey, "name");
            }
            // No record_op here: claiming a name must not start a cooldown,
            // so a user can claim and then immediately release if they change
            // their mind. Only release arms the cooldown.
            tracing::info!("registered {name} -> {pubkey}");
            (
                StatusCode::CREATED,
                Json(json!({"name": name, "nip05": format!("{name}@{}", app.cfg.domain)})),
            )
                .into_response()
        }
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            // The partial-unique pubkey index rejected a second active name.
            (
                StatusCode::CONFLICT,
                Json(json!({"error": "pubkey already has a name"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("db insert failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "db error"})),
            )
                .into_response()
        }
    }
}

pub async fn unregister(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow_write("unreg", &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let name = name.to_lowercase();
    let path = format!("/api/v1/register/{name}");
    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::DELETE,
        &path,
        &[],
        &app.cfg.base_url,
        app.cfg.auth_max_age_secs,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return (code, Json(json!({"error": msg}))).into_response(),
    };
    if !app.auth_event_fresh(&auth_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "auth event replayed"})),
        )
            .into_response();
    }
    // Release is always allowed (no cooldown check): you can let a name go the
    // instant after claiming it. Releasing is what *arms* the cooldown below,
    // which then blocks re-registering a new name for the cooldown window.
    match app.lookup(&name) {
        Some(owner) if owner == auth_pubkey => {
            let res = app.db.lock().execute(
                "UPDATE names SET released_at = ?2 WHERE name = ?1 AND released_at IS NULL",
                rusqlite::params![name, unix_now()],
            );
            match res {
                Ok(_) => {
                    app.record_op("namechange", &auth_pubkey);
                    tracing::info!("released {name}");
                    (
                        StatusCode::OK,
                        Json(json!({"name": name, "released": true})),
                    )
                        .into_response()
                }
                Err(e) => {
                    tracing::error!("db release failed: {e}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": "db error"})),
                    )
                        .into_response()
                }
            }
        }
        Some(_) => (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "not the owner"})),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "name not found"})),
        )
            .into_response(),
    }
}
