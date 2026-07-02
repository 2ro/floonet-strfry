// NIP-98 HTTP authorization: verify a `Authorization: Nostr <base64-event>`
// header, including signature, kind, freshness, and the url/method/payload
// tags. The `u`-tag is checked against the configured public base URL, so a
// wrong BASE_URL silently fails every authenticated call.

use axum::http::{header, HeaderMap, Method, StatusCode};
use base64::Engine;
use nostr::{Event, JsonUtil, Kind, Timestamp};
use sha2::{Digest, Sha256};

/// Verify a NIP-98 auth header for `method`+`url_path` over `body`.
/// `base_url` is the operator's public base (`https://host`) and
/// `auth_max_age_secs` bounds event freshness.
/// On success returns (authenticated pubkey hex, auth event id hex).
pub fn verify_nip98(
    headers: &HeaderMap,
    method: &Method,
    url_path: &str,
    body: &[u8],
    base_url: &str,
    auth_max_age_secs: i64,
) -> Result<(String, String), (StatusCode, String)> {
    let unauthorized = |msg: &str| (StatusCode::UNAUTHORIZED, msg.to_string());

    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| unauthorized("missing Authorization header"))?;
    let b64 = auth
        .strip_prefix("Nostr ")
        .ok_or_else(|| unauthorized("Authorization scheme must be Nostr"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| unauthorized("invalid base64 auth event"))?;
    let event = Event::from_json(&raw).map_err(|_| unauthorized("invalid auth event json"))?;
    event
        .verify()
        .map_err(|_| unauthorized("bad event signature"))?;

    if event.kind != Kind::HttpAuth {
        return Err(unauthorized("auth event kind must be 27235"));
    }
    let now = Timestamp::now();
    let age = (now.as_secs() as i64) - (event.created_at.as_secs() as i64);
    // Allow modest backward skew but only a few seconds forward, to bound the
    // replay window (paired with one-time event-id enforcement at the caller).
    if age > auth_max_age_secs || age < -5 {
        return Err(unauthorized("auth event expired or post-dated"));
    }

    let mut u_ok = false;
    let mut method_ok = false;
    let mut payload_hash: Option<String> = None;
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(|s| s.as_str()) {
            Some("u") => {
                if let Some(u) = parts.get(1) {
                    let expected = format!("{base_url}{url_path}");
                    let normalized = u.trim_end_matches('/');
                    u_ok = normalized == expected.trim_end_matches('/');
                }
            }
            Some("method") => {
                if let Some(m) = parts.get(1) {
                    method_ok = m.eq_ignore_ascii_case(method.as_str());
                }
            }
            Some("payload") => {
                payload_hash = parts.get(1).cloned();
            }
            _ => {}
        }
    }
    if !u_ok {
        return Err(unauthorized("auth event url mismatch"));
    }
    if !method_ok {
        return Err(unauthorized("auth event method mismatch"));
    }
    if let Some(expect) = payload_hash {
        let got = hex::encode(Sha256::digest(body));
        if !expect.eq_ignore_ascii_case(&got) {
            return Err(unauthorized("auth event payload hash mismatch"));
        }
    } else if !body.is_empty() {
        return Err(unauthorized("auth event missing payload hash"));
    }

    Ok((event.pubkey.to_hex(), event.id.to_hex()))
}
