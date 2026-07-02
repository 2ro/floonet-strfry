// Liveness and the landing page.

use crate::db::App;
use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use std::sync::Arc;

pub async fn health() -> &'static str {
    "ok"
}

/// A minimal, neutral landing page. Domain and relay are filled from config
/// so an operator's page reflects their own authority. Deliberately says
/// nothing about what clients exchange over the relay.
pub async fn landing(State(app): State<Arc<App>>) -> Response {
    let domain = html_escape(&app.cfg.domain);
    let relay = html_escape(app.cfg.relays.first().map(String::as_str).unwrap_or("-"));
    Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Floonet</title>
<style>
body{{margin:0;background:#0E0E0C;color:#FAFAF7;font:16px/1.5 system-ui,sans-serif;
display:flex;min-height:100vh;align-items:center;justify-content:center}}
main{{max-width:520px;padding:32px}}
h1{{font-size:44px;letter-spacing:-1.5px;margin:0 0 12px;color:#FFD60A}}
p{{color:#9A988F;margin:8px 0}}
code{{background:#1A1A17;border-radius:6px;padding:2px 6px;color:#FAFAF7}}
</style></head><body><main>
<h1>Floonet</h1>
<p>A Floonet relay for the Grin community Nostr network.</p>
<p>Names here look like <code>you@{domain}</code>.</p>
<p>Relay: <code>{relay}</code></p>
<p>Please use a Nostr client to connect.</p>
</main></body></html>"#
    ))
    .into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
