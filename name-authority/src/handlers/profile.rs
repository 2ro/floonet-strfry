// Public profile lookup: `/api/v1/profile/{name}`.

use crate::db::App;
use crate::names::{valid_name, valid_pubkey_hex};
use crate::util::client_ip;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::sync::Arc;

/// GET /api/v1/profile/{name} — public profile: the active pubkey for a name.
/// Avatars are not served here; clients render them from the pubkey.
pub async fn profile(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
    headers: HeaderMap,
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
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
    }
    match app.lookup(&name) {
        Some(pubkey) => (
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            json!({"name": name, "pubkey": pubkey}).to_string(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

/// GET /api/v1/by-pubkey/{pubkey} — reverse lookup: the active name a pubkey
/// holds, if any. This is the authoritative answer to "what's this key's
/// @username", and unlike the kind-0 + well-known dance it needs a single
/// request — so a client can show a contact's name even when it can't fetch
/// their published profile. Returns `{name, pubkey}` or 404.
pub async fn by_pubkey(
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
    match app.name_of(&pubkey) {
        Some(name) => (
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            json!({"name": name, "pubkey": pubkey}).to_string(),
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}
