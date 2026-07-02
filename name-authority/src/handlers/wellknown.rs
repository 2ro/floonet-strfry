// NIP-05 resolution: `/.well-known/nostr.json?name=<name>`.

use crate::db::App;
use crate::names::valid_name;
use crate::util::client_ip;
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct WellKnownParams {
    name: Option<String>,
}

pub async fn well_known(
    State(app): State<Arc<App>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<WellKnownParams>,
) -> Response {
    if !app.allow_read(&client_ip(&headers)) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            Json(json!({"error": "rate_limited"})),
        )
            .into_response();
    }
    let mut names = serde_json::Map::new();
    let mut relays = serde_json::Map::new();
    if let Some(name) = params.name.map(|n| n.to_lowercase()) {
        if valid_name(&name, app.cfg.name_min, app.cfg.name_max) {
            if let Some(pk) = app.lookup(&name) {
                names.insert(name, json!(pk.clone()));
                relays.insert(pk, json!(app.cfg.relays));
            }
        }
    }
    let body = json!({ "names": names, "relays": relays });
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}
