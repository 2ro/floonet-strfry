// floonet-name-authority — the name authority bundled with a Floonet relay.
//
// Endpoints (see the repo README for the full table):
//   GET    /.well-known/nostr.json?name=<name>   NIP-05 resolution (CORS *)
//   GET    /api/v1/name/{name}                   availability check
//   POST   /api/v1/register                      {name, pubkey} + NIP-98 auth
//   DELETE /api/v1/register/{name}               NIP-98 auth by owner
//   GET    /api/v1/profile/{name}                public profile (pubkey)
//   GET    /api/v1/by-pubkey/{pubkey}            reverse lookup
//   GET    /api/v1/paid/{pubkey}                 write-grant status (plugin)
//   POST   /api/v1/quote                         NIP-98; price/pay URL
//   POST   /api/v1/goblinpay/webhook             HMAC-verified payment nudge
//   GET    /api/v1/health                        liveness
//   GET    /                                     landing page
//
// When FLOONET_TRANSFERS is set, the name-transfer routes are also mounted
// (else they 404): POST/GET/DELETE /api/v1/transfer/offer[/{id}] and
// POST /api/v1/transfer/claim. Strictly non-custodial, no GoblinPay
// involvement. See the README and docs-notes/name-transfer-spec.md.

use floonet_name_authority::{handlers, setup, App, Config};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Pick up a conventional env file if one exists (non-overriding), so a
    // direct run reuses prior configuration. Under systemd/docker the real
    // environment is already set, so this changes nothing there.
    if let Some(path) = setup::load_first_existing() {
        tracing::info!("loaded configuration from {}", path.display());
    }

    // First-run wizard: only when nothing is configured AND we are on a TTY.
    // Existing deploys always set FLOONET_DOMAIN (compose/systemd) and are not
    // interactive, so they never reach this branch.
    if setup::decide_wizard(setup::config_present(), setup::is_interactive()) {
        match setup::run_first_run_wizard() {
            Ok(path) => {
                if let Err(e) = setup::load_env_file(&path) {
                    eprintln!("could not load the file just written ({}): {e}", path.display());
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("setup wizard failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("configuration error: {e}");
            eprintln!("configuration error: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("resolved config: {}", cfg.summary());

    let bind = cfg.bind_addr.clone();
    let app = Arc::new(App::open(cfg));
    let router = handlers::routes(app);

    let listener = tokio::net::TcpListener::bind(&bind).await.expect("bind");
    tracing::info!("floonet-name-authority listening on {bind}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}
