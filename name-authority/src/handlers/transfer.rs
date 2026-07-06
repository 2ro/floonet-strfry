// Name transfers: the offer/claim marketplace (spec sections 3-6). Mounted only
// when `FLOONET_TRANSFERS` is set; otherwise these routes do not exist and
// requests 404.
//
//   POST   /api/v1/transfer/offer          seller lodges a signed kind-3402 offer
//   GET    /api/v1/transfer/offer/{id}      public: read the offer + its status
//   DELETE /api/v1/transfer/offer/{id}      seller revokes a live offer
//   POST   /api/v1/transfer/claim           buyer claims the name with a Grin proof
//
// A transfer reassigns one name row from the seller's pubkey to the buyer's
// after verifying a seller-signed offer and an on-chain Grin payment proof. Keys
// never move; only the name's `pubkey` changes. This path is strictly
// non-custodial and has ZERO GoblinPay involvement: it is pure in-process crypto
// plus a read-only Grin node foreign API. See docs-notes/name-transfer-spec.md.

use crate::auth::verify_nip98;
use crate::db::{App, OfferRow};
use crate::names::{valid_name, valid_pubkey_hex};
use crate::proof::{
    decode_grin_address, normalize_grin_address, parse_payment_proof, verify_signatures,
};
use crate::util::{client_ip, unix_now};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use nostr::{Event, JsonUtil, Kind};
use serde_json::{json, Value};
use std::sync::Arc;

/// The Goblin-defined offer event kind (spec section 3).
const OFFER_KIND: u16 = 3402;

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// The six required tags of a kind-3402 offer.
struct OfferTags {
    name: String,
    domain: String,
    buyer: String,
    price: String,
    proof_address: String,
    expiration: String,
}

/// Pull the six required tags out of a kind-3402 event. `None` if any is
/// missing (a malformed offer).
fn extract_offer_tags(event: &Event) -> Option<OfferTags> {
    let mut name = None;
    let mut domain = None;
    let mut buyer = None;
    let mut price = None;
    let mut proof_address = None;
    let mut expiration = None;
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        let Some(key) = parts.first().map(|s| s.as_str()) else {
            continue;
        };
        let val = parts.get(1).cloned();
        match key {
            "name" => name = val,
            "domain" => domain = val,
            "p" => buyer = val,
            "price" => price = val,
            "proof_address" => proof_address = val,
            "expiration" => expiration = val,
            _ => {}
        }
    }
    Some(OfferTags {
        name: name?,
        domain: domain?,
        buyer: buyer?,
        price: price?,
        proof_address: proof_address?,
        expiration: expiration?,
    })
}

/// Success body shared by a fresh claim and its idempotent retry (spec section
/// 6: register's shape plus the buyer pubkey).
fn claim_success(name: &str, domain: &str, buyer: &str) -> Value {
    json!({
        "name": name,
        "nip05": format!("{name}@{domain}"),
        "pubkey": buyer,
    })
}

/// Lazily settle an offer that is `live` in the database but past its
/// expiration: transition it to `expired` and record the chain tip as
/// `end_height` at the moment the authority first observes the expiry (spec
/// section 5). If the node is unreachable we still expire it but leave
/// `end_height` NULL, which fails a late claim closed. Returns the offer as it
/// now stands.
async fn settle_expiry(app: &Arc<App>, offer: OfferRow, now: i64) -> OfferRow {
    if offer.status != "live" || offer.expiration >= now {
        return offer;
    }
    let end_height = match &app.node {
        Some(node) => node.tip_height().await.ok().map(|h| h as i64),
        None => None,
    };
    let _ = app.mark_offer_dead(&offer.offer_id, "expired", end_height, now);
    app.get_offer(&offer.offer_id).unwrap_or(offer)
}

/// POST /api/v1/transfer/offer - lodge a seller-signed offer.
pub async fn lodge_offer(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow_write("transfer", &ip) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::POST,
        "/api/v1/transfer/offer",
        &body,
        &app.cfg.base_url,
        app.cfg.auth_max_age_secs,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return err(code, &msg),
    };
    if !app.auth_event_fresh(&auth_id) {
        return err(StatusCode::UNAUTHORIZED, "auth event replayed");
    }

    // Body: {"offer": <kind-3402 event>}.
    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid offer"),
    };
    let Some(offer_val) = req.get("offer") else {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    };
    let event = match Event::from_json(offer_val.to_string()) {
        Ok(e) => e,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid offer"),
    };
    // Schnorr signature AND event-id integrity (the id hashes every field, so a
    // valid event is an unforgeable binding of name/buyer/price/address/expiry).
    if event.verify().is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    }
    if event.kind != Kind::Custom(OFFER_KIND) {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    }
    let seller = event.pubkey.to_hex();
    if seller != auth_pubkey {
        return err(
            StatusCode::UNAUTHORIZED,
            "auth pubkey does not match offer pubkey",
        );
    }
    let Some(tags) = extract_offer_tags(&event) else {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    };

    let name = tags.name;
    if !valid_name(&name, app.cfg.name_min, app.cfg.name_max) {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    }
    if tags.domain != app.cfg.domain {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    }
    let buyer = tags.buyer.to_lowercase();
    if !valid_pubkey_hex(&buyer) {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    }
    let Ok(price) = tags.price.trim().parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    };
    let proof_address = normalize_grin_address(&tags.proof_address);
    if decode_grin_address(&proof_address).is_none() {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    }
    let Ok(expiration) = tags.expiration.trim().parse::<i64>() else {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    };

    let now = unix_now();
    // Expiry must be in the future and at most transfer_max_offer_ttl out.
    if expiration <= now || expiration > now + app.cfg.transfer_max_offer_ttl {
        return err(StatusCode::BAD_REQUEST, "invalid offer");
    }

    // Seller must be the current active owner of the name.
    if app.lookup(&name).as_deref() != Some(seller.as_str()) {
        return err(StatusCode::FORBIDDEN, "not the owner");
    }
    // At most one live offer per name.
    if app.live_offer_for_name(&name, now) {
        return err(StatusCode::CONFLICT, "offer_exists");
    }
    // No other live offer uses the same proof_address. Sellers mint a fresh
    // per-sale address (the normative client contract), so for conformant
    // wallets this never fires; a fixed-address seller is serialized to one
    // live offer at a time across all names they own.
    let price_i64 = price as i64;
    if app.live_offer_binding(&proof_address, now) {
        return err(StatusCode::CONFLICT, "offer_ambiguous");
    }

    let offer_id = event.id.to_hex();
    match app.insert_offer(
        &offer_id,
        &event.as_json(),
        &name,
        &seller,
        &buyer,
        price_i64,
        &proof_address,
        expiration,
        now,
    ) {
        Ok(_) => {
            tracing::info!("offer {offer_id} lodged: {name} -> {buyer} for {price}");
            (
                StatusCode::CREATED,
                Json(json!({
                    "offer_id": offer_id,
                    "name": name,
                    "expires_at": expiration,
                })),
            )
                .into_response()
        }
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            // Same offer id already lodged.
            err(StatusCode::CONFLICT, "offer_exists")
        }
        Err(e) => {
            tracing::error!("offer insert failed: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "db error")
        }
    }
}

/// GET /api/v1/transfer/offer/{offer_id} - public read of the offer + status.
pub async fn read_offer(
    State(app): State<Arc<App>>,
    Path(offer_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !app.allow_read(&client_ip(&headers)) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let Some(offer) = app.get_offer(&offer_id) else {
        return err(StatusCode::NOT_FOUND, "not found");
    };
    let offer = settle_expiry(&app, offer, unix_now()).await;
    let event_val: Value = serde_json::from_str(&offer.event_json).unwrap_or(Value::Null);
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        json!({ "offer": event_val, "status": offer.status }).to_string(),
    )
        .into_response()
}

/// DELETE /api/v1/transfer/offer/{offer_id} - seller revokes a live offer.
pub async fn revoke_offer(
    State(app): State<Arc<App>>,
    Path(offer_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !app.allow_write("transfer", &client_ip(&headers)) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    let path = format!("/api/v1/transfer/offer/{offer_id}");
    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::DELETE,
        &path,
        &[],
        &app.cfg.base_url,
        app.cfg.auth_max_age_secs,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return err(code, &msg),
    };
    if !app.auth_event_fresh(&auth_id) {
        return err(StatusCode::UNAUTHORIZED, "auth event replayed");
    }
    let Some(offer) = app.get_offer(&offer_id) else {
        return err(StatusCode::NOT_FOUND, "not found");
    };
    if auth_pubkey != offer.seller_pubkey {
        return err(StatusCode::FORBIDDEN, "not the owner");
    }
    if offer.status == "consumed" {
        return err(StatusCode::CONFLICT, "offer_consumed");
    }
    if offer.status == "revoked" {
        // Idempotent: already revoked.
        return (
            StatusCode::OK,
            Json(json!({ "offer_id": offer_id, "status": "revoked" })),
        )
            .into_response();
    }

    let now = unix_now();
    if offer.status == "live" {
        // Record the chain tip at revocation so a payment already settled below
        // it can still be claimed within the grace window (spec section 5).
        let end_height = match &app.node {
            Some(node) => node.tip_height().await.ok().map(|h| h as i64),
            None => None,
        };
        let _ = app.mark_offer_dead(&offer.offer_id, "revoked", end_height, now);
    } else {
        // Already expired: flip to revoked but keep the death record it earned
        // at expiry (do not reset end_height/state_changed_at).
        let _ = app.db.lock().execute(
            "UPDATE offers SET status = 'revoked' WHERE offer_id = ?1",
            [&offer.offer_id],
        );
    }
    tracing::info!("offer {offer_id} revoked");
    (
        StatusCode::OK,
        Json(json!({ "offer_id": offer_id, "status": "revoked" })),
    )
        .into_response()
}

/// Terminal error of the atomic claim transaction, mapped to an HTTP status.
enum TxErr {
    OwnerChanged,
    BuyerHasName,
    Reused,
    Db,
}

/// The single atomic SQLite transaction (spec section 5): reassign the name,
/// record the transfer (UNIQUE excess = durable single-use), consume the offer.
/// Any error drops the transaction, rolling everything back.
fn run_claim_txn(
    conn: &mut rusqlite::Connection,
    offer: &OfferRow,
    excess_hex: &str,
    kernel_height: Option<i64>,
    now: i64,
) -> Result<(), TxErr> {
    let tx = conn.transaction().map_err(|_| TxErr::Db)?;

    // Owner-guarded reassignment; must move exactly one row. The partial-unique
    // idx_active_pubkey rejects a buyer who raced into another active name.
    let updated = match tx.execute(
        "UPDATE names SET pubkey = ?2, created_at = ?3 \
         WHERE name = ?1 AND pubkey = ?4 AND released_at IS NULL",
        rusqlite::params![offer.name, offer.buyer_pubkey, now, offer.seller_pubkey],
    ) {
        Ok(n) => n,
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            return Err(TxErr::BuyerHasName)
        }
        Err(_) => return Err(TxErr::Db),
    };
    if updated != 1 {
        return Err(TxErr::OwnerChanged);
    }

    // Durable single-use record. UNIQUE(kernel_excess) is the real replay guard.
    match tx.execute(
        "INSERT INTO transfers (offer_id, name, seller_pubkey, buyer_pubkey, \
         price_nanogrin, kernel_excess, kernel_height, claimed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            offer.offer_id,
            offer.name,
            offer.seller_pubkey,
            offer.buyer_pubkey,
            offer.price_nanogrin,
            excess_hex,
            kernel_height,
            now
        ],
    ) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            return Err(TxErr::Reused)
        }
        Err(_) => return Err(TxErr::Db),
    }

    // Consume the offer.
    tx.execute(
        "UPDATE offers SET status = 'consumed' WHERE offer_id = ?1",
        [&offer.offer_id],
    )
    .map_err(|_| TxErr::Db)?;

    tx.commit().map_err(|_| TxErr::Db)
}

/// POST /api/v1/transfer/claim - buyer claims the name with a Grin proof.
pub async fn claim(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let ip = client_ip(&headers);
    if !app.allow_write("transfer", &ip) {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    }
    // 1. NIP-98 auth (payload sha256 over the body is enforced by verify_nip98
    //    since the body is non-empty) + one-time event-id replay set.
    let (auth_pubkey, auth_id) = match verify_nip98(
        &headers,
        &Method::POST,
        "/api/v1/transfer/claim",
        &body,
        &app.cfg.base_url,
        app.cfg.auth_max_age_secs,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return err(code, &msg),
    };
    if !app.auth_event_fresh(&auth_id) {
        return err(StatusCode::UNAUTHORIZED, "auth event replayed");
    }

    let req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid body"),
    };
    let offer_id = match req.get("offer_id").and_then(|v| v.as_str()) {
        Some(s) if s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()) => s.to_lowercase(),
        _ => return err(StatusCode::BAD_REQUEST, "invalid body"),
    };
    let Some(proof_val) = req.get("proof") else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    let Some(proof) = parse_payment_proof(proof_val) else {
        return err(StatusCode::BAD_REQUEST, "invalid proof");
    };

    // 2. Offer exists (and lazily settle an expired-but-still-live row first).
    let Some(offer) = app.get_offer(&offer_id) else {
        return err(StatusCode::NOT_FOUND, "not found");
    };
    let now = unix_now();
    let offer = settle_expiry(&app, offer, now).await;

    if offer.status == "consumed" {
        // Idempotent retry: same (offer_id, excess) that already succeeded.
        if let Some((excess, name, buyer)) = app.transfer_for_offer(&offer_id) {
            if excess == proof.excess_hex {
                return (
                    StatusCode::OK,
                    Json(claim_success(&name, &app.cfg.domain, &buyer)),
                )
                    .into_response();
            }
        }
        return err(StatusCode::CONFLICT, "offer_consumed");
    }

    // 3. Revoked/expired: honored only within grace AND if the payment settled
    //    at/below the recorded end_height. The height comes from the node
    //    (step 9); here we gate on grace + end_height presence, and apply the
    //    kernel_height <= end_height test once we have the height.
    let dead_err = if offer.status == "revoked" {
        "offer_revoked"
    } else {
        "offer_expired"
    };
    let mut dead_end_height: Option<i64> = None;
    if offer.status == "revoked" || offer.status == "expired" {
        let changed = offer.state_changed_at.unwrap_or(now);
        if now - changed > app.cfg.transfer_claim_grace {
            return err(StatusCode::GONE, dead_err);
        }
        match offer.end_height {
            Some(h) => dead_end_height = Some(h),
            // Fail closed: without a recorded death height we cannot prove the
            // payment settled before the offer died.
            None => return err(StatusCode::GONE, dead_err),
        }
    }

    // 4. NIP-98 pubkey is the offer's buyer.
    if auth_pubkey != offer.buyer_pubkey {
        return err(StatusCode::UNAUTHORIZED, "not the buyer");
    }
    // 5. Seller is still the current owner (defensive; lodge rule 5 holds it).
    if app.lookup(&offer.name).as_deref() != Some(offer.seller_pubkey.as_str()) {
        return err(StatusCode::CONFLICT, "owner_changed");
    }
    // 6. Both proof signatures verify over the canonical 73-byte message.
    if !verify_signatures(&proof) {
        return err(StatusCode::BAD_REQUEST, "invalid proof");
    }
    // 7. Recipient address equals the offer's proof_address.
    if normalize_grin_address(&proof.recipient_address) != offer.proof_address {
        return err(StatusCode::CONFLICT, "proof_address_mismatch");
    }
    // 8. Amount equals price, exact (the amount is half of the (R, A) binding).
    if offer.price_nanogrin < 0 || proof.amount != offer.price_nanogrin as u64 {
        return err(StatusCode::CONFLICT, "proof_amount_mismatch");
    }
    // 9. Kernel is on chain with >= min_conf confirmations. A node error or a
    //    not-yet-mined kernel is a retryable payment_unconfirmed, not a 500.
    let kernel = match &app.node {
        Some(node) => node.kernel(&proof.excess_hex).await,
        None => Err("transfers enabled but no node configured".to_string()),
    };
    let kernel = match kernel {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("kernel lookup failed for claim: {e}");
            return err(StatusCode::CONFLICT, "payment_unconfirmed");
        }
    };
    if !kernel.found || kernel.confirmations < app.cfg.transfer_min_conf {
        return err(StatusCode::CONFLICT, "payment_unconfirmed");
    }
    let kernel_height = kernel.height.map(|h| h as i64);
    // Final death-window gate: the payment must have settled at/before the
    // height at which the offer died.
    if let Some(end_h) = dead_end_height {
        match kernel_height {
            Some(kh) if kh <= end_h => {}
            _ => return err(StatusCode::GONE, dead_err),
        }
    }
    // 10. Excess never consumed before (durable UNIQUE column, not the in-memory
    //     replay set). The transaction's UNIQUE(kernel_excess) is the last word.
    if app.excess_used(&proof.excess_hex) {
        return err(StatusCode::CONFLICT, "proof_reused");
    }
    // 11. Buyer holds no active name. REJECT (never replace); retryable after
    //     the buyer releases their old name. EXEMPT from the name-change
    //     cooldown - a paid transfer is not churn.
    if let Some(existing) = app.name_of(&offer.buyer_pubkey) {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "pubkey already has a name", "name": existing })),
        )
            .into_response();
    }

    // Atomic execution.
    let result = {
        let mut conn = app.db.lock();
        run_claim_txn(&mut conn, &offer, &proof.excess_hex, kernel_height, now)
    };
    match result {
        Ok(()) => {
            // Arm the seller's name-change cooldown, consistent with release.
            app.record_op("namechange", &offer.seller_pubkey);
            tracing::info!(
                "transfer {} claimed: {} -> {}",
                offer.offer_id,
                offer.name,
                offer.buyer_pubkey
            );
            (
                StatusCode::CREATED,
                Json(claim_success(
                    &offer.name,
                    &app.cfg.domain,
                    &offer.buyer_pubkey,
                )),
            )
                .into_response()
        }
        Err(TxErr::OwnerChanged) => err(StatusCode::CONFLICT, "owner_changed"),
        Err(TxErr::BuyerHasName) => err(StatusCode::CONFLICT, "pubkey already has a name"),
        Err(TxErr::Reused) => err(StatusCode::CONFLICT, "proof_reused"),
        Err(TxErr::Db) => {
            tracing::error!("claim transaction failed for offer {}", offer.offer_id);
            err(StatusCode::INTERNAL_SERVER_ERROR, "db error")
        }
    }
}
