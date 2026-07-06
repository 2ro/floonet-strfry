// HTTP handlers, grouped by surface. The `routes()` builder wires them onto
// an axum `Router` over the shared `App` state so both `main` and the
// integration tests construct the identical app.

pub mod misc;
pub mod paidapi;
pub mod profile;
pub mod registry;
pub mod transfer;
pub mod wellknown;

use crate::db::App;
use axum::{
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;

/// Build the full router over a shared [`App`]. The name-transfer routes are
/// mounted only when `FLOONET_TRANSFERS` is set; otherwise they do not exist
/// and requests to them 404.
pub fn routes(app: Arc<App>) -> Router {
    let mut router = Router::new()
        .route("/.well-known/nostr.json", get(wellknown::well_known))
        .route("/api/v1/name/{name}", get(registry::availability))
        .route("/api/v1/register", post(registry::register))
        .route("/api/v1/register/{name}", delete(registry::unregister))
        .route("/api/v1/profile/{name}", get(profile::profile))
        .route("/api/v1/by-pubkey/{pubkey}", get(profile::by_pubkey))
        .route("/api/v1/paid/{pubkey}", get(paidapi::paid_status))
        .route("/api/v1/quote", post(paidapi::quote))
        .route(
            "/api/v1/goblinpay/webhook",
            post(paidapi::goblinpay_webhook),
        )
        .route("/api/v1/health", get(misc::health))
        .route("/", get(misc::landing));

    if app.cfg.allow_transfers {
        router = router
            .route("/api/v1/transfer/offer", post(transfer::lodge_offer))
            .route(
                "/api/v1/transfer/offer/{offer_id}",
                get(transfer::read_offer).delete(transfer::revoke_offer),
            )
            .route("/api/v1/transfer/claim", post(transfer::claim));
    }

    router.with_state(app)
}
