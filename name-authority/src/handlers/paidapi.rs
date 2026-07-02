// The paid-resource API surface.
//
//   GET  /api/v1/paid/{pubkey}        write-grant status. This is what the
//                                     relay write policy plugin consults in
//                                     FLOONET_PAY_MODE=write; it never sees
//                                     the GoblinPay token. Lazily refreshes a
//                                     pending grant (poll throttled).
//   POST /api/v1/quote                NIP-98 authed. Body {"resource": ...}.
//                                     Returns 402 with the price and hosted
//                                     pay URL while due, 200 once paid.
//   POST /api/v1/goblinpay/webhook    HMAC-verified nudge from GoblinPay.
//                                     Never trusted on its own: it only
//                                     triggers a REST re-poll of the invoice,
//                                     so replays cannot grant anything.

use crate::auth::verify_nip98;
use crate::config::PayMode;
use crate::db::App;
use crate::names::valid_pubkey_hex;
use crate::paid::{ensure_paid, payment_required_json, PaidOutcome};
use crate::util::{client_ip, ct_eq};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use std::sync::Arc;

/// GET /api/v1/paid/{pubkey}: does this pubkey hold a confirmed `write`
/// grant? Public and cheap by design (the plugin calls it on the write path);
/// answers from the grants table, refreshing a pending grant at most once per
/// poll interval. In free mode everything is paid.
pub async fn paid_status(
    State(app): State<Arc<App>>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !app.allow_read(&client_ip(&headers)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let pubkey = pubkey.to_lowercase();
    if !valid_pubkey_hex(&pubkey) {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }
    if app.cfg.pay_mode != PayMode::Write {
        // Not selling write access: every pubkey may write.
        return Json(json!({"pubkey": pubkey, "paid": true})).into_response();
    }
    // Fast path: answer from the table without touching GoblinPay.
    if let Some(grant) = app.grant(&pubkey, "write") {
        if grant.status == "paid" {
            return Json(json!({"pubkey": pubkey, "paid": true})).into_response();
        }
        // Pending: give ensure_paid a (throttled) chance to see settlement.
        let (app2, pk) = (app.clone(), pubkey.clone());
        let outcome = tokio::task::spawn_blocking(move || ensure_paid(&app2, &pk, "write"))
            .await
            .unwrap_or_else(|e| PaidOutcome::Unavailable(format!("join error: {e}")));
        let paid = matches!(outcome, PaidOutcome::Paid);
        return Json(json!({"pubkey": pubkey, "paid": paid})).into_response();
    }
    // No grant at all: not paid. Quoting/creating invoices is NOT done here;
    // that is the authenticated /api/v1/quote endpoint, so an unauthenticated
    // scraper can never mint invoices.
    Json(json!({"pubkey": pubkey, "paid": false})).into_response()
}

#[derive(Deserialize)]
struct QuoteBody {
    resource: String,
}

/// POST /api/v1/quote (NIP-98): quote a paid resource for the authenticated
/// pubkey. Creates (or reuses) the GoblinPay invoice and returns 402 with the
/// pay URL while payment is due, 200 {"paid": true} once confirmed. This is
/// how a client obtains the pay page for `write` access; for `name`, the
/// register endpoint returns the same 402 shape on its own.
pub async fn quote(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow_write("quote", &ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::POST,
        "/api/v1/quote",
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
    let req: QuoteBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid body"})),
            )
                .into_response()
        }
    };
    let resource = req.resource;
    let sellable = match (app.cfg.pay_mode, resource.as_str()) {
        (PayMode::Name, "name") => true,
        (PayMode::Write, "write") => true,
        _ => false,
    };
    if !sellable {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "resource not for sale on this authority"})),
        )
            .into_response();
    }
    let (app2, pk, res2) = (app.clone(), auth_pubkey.clone(), resource.clone());
    let outcome = tokio::task::spawn_blocking(move || ensure_paid(&app2, &pk, &res2))
        .await
        .unwrap_or_else(|e| PaidOutcome::Unavailable(format!("join error: {e}")));
    match outcome {
        PaidOutcome::Paid => Json(json!({
            "resource": resource,
            "pubkey": auth_pubkey,
            "paid": true,
        }))
        .into_response(),
        PaidOutcome::Due {
            invoice_id,
            pay_url,
            price_nanogrin,
        } => (
            StatusCode::PAYMENT_REQUIRED,
            Json(payment_required_json(
                &resource,
                &invoice_id,
                &pay_url,
                price_nanogrin,
            )),
        )
            .into_response(),
        PaidOutcome::Unavailable(e) => {
            tracing::error!("quote unavailable: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "payment backend unavailable, try again"})),
            )
                .into_response()
        }
    }
}

/// POST /api/v1/goblinpay/webhook: GoblinPay's payment notification
/// (HMAC-SHA256 over the raw body, `X-GoblinPay-Signature: sha256=<hex>`).
/// Verified against GOBLINPAY_WEBHOOK_SECRET, then used ONLY as a nudge: the
/// matching pending grant is re-polled over the authenticated REST API, so a
/// replayed or forged-but-signed delivery cannot grant anything on its own.
/// 404 when no secret is configured (feature off).
pub async fn goblinpay_webhook(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(secret) = app.cfg.goblinpay_webhook_secret.clone() else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    };
    let provided = headers
        .get("x-goblinpay-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key");
    mac.update(&body);
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    if !ct_eq(provided.trim().as_bytes(), expected.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "bad signature"})),
        )
            .into_response();
    }
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid body"})),
        )
            .into_response();
    };
    let Some(invoice_id) = payload.get("invoice_id").and_then(|v| v.as_str()) else {
        // Signed but not about an invoice we track; acknowledge so GoblinPay
        // stops retrying.
        return Json(json!({"ok": true})).into_response();
    };
    let Some(grant) = app.grant_by_invoice(invoice_id) else {
        return Json(json!({"ok": true})).into_response();
    };
    if grant.status != "paid" {
        // Confirm via REST before promoting (the webhook is only a nudge).
        let app2 = app.clone();
        let iid = invoice_id.to_string();
        let confirmed = tokio::task::spawn_blocking(move || {
            app2.paywall
                .as_ref()
                .map(|p| p.backend.invoice_status(&iid))
                .transpose()
                .ok()
                .flatten()
                .map(|s| s == "paid")
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if confirmed {
            app.mark_grant_paid(invoice_id);
            tracing::info!(
                "webhook confirmed payment: {} for {} ({})",
                invoice_id,
                grant.pubkey,
                grant.resource
            );
        }
    }
    Json(json!({"ok": true})).into_response()
}
