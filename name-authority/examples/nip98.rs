//! Mint a NIP-98 `Authorization: Nostr <base64-event>` header for calling this
//! authority's authenticated endpoints (register / unregister / quote) with a
//! plain HTTP client like `curl`. Handy for operators and CI: no external
//! nostr tooling required, since the crate already depends on `nostr`.
//!
//! Usage:
//!   # generate a throwaway identity (prints its secret+pubkey to stderr)
//!   cargo run --example nip98 -- GET /api/v1/name/alice
//!
//!   # reuse an identity and sign over a request body
//!   FLOONET_BASE_URL=https://nm.floonet.dev NIP98_SK=<64-hex-secret> \
//!     cargo run --example nip98 -- POST /api/v1/register '{"name":"alice","pubkey":"<hex>"}'
//!
//! The header value is printed to stdout (nothing else), so it can be captured
//! straight into a curl invocation:
//!
//!   AUTH=$(NIP98_SK=$SK cargo run -q --example nip98 -- POST /api/v1/register "$BODY")
//!   curl -H "Authorization: $AUTH" -d "$BODY" https://nm.floonet.dev/api/v1/register
//!
//! The `u` tag is built from FLOONET_BASE_URL (default https://nm.floonet.dev),
//! which MUST equal the authority's configured base URL — that is what the
//! server verifies the signature's `u` tag against.

use base64::Engine;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use sha2::{Digest, Sha256};

fn main() {
    let mut args = std::env::args().skip(1);
    let method = args
        .next()
        .expect("usage: nip98 <METHOD> <PATH> [BODY]  (e.g. POST /api/v1/register '{...}')");
    let path = args
        .next()
        .expect("usage: nip98 <METHOD> <PATH> [BODY]  (e.g. POST /api/v1/register '{...}')");
    let body = args.next().unwrap_or_default();

    let base_url =
        std::env::var("FLOONET_BASE_URL").unwrap_or_else(|_| "https://nm.floonet.dev".to_string());

    let keys = match std::env::var("NIP98_SK") {
        Ok(sk) if !sk.trim().is_empty() => Keys::parse(sk.trim()).expect("invalid NIP98_SK"),
        _ => {
            let k = Keys::generate();
            eprintln!("generated secret (hex): {}", k.secret_key().to_secret_hex());
            k
        }
    };
    eprintln!("pubkey (hex): {}", keys.public_key().to_hex());

    let url = format!("{base_url}{path}");
    let mut tags = vec![
        Tag::parse(["u", &url]).unwrap(),
        Tag::parse(["method", &method]).unwrap(),
    ];
    if !body.is_empty() {
        let payload = hex::encode(Sha256::digest(body.as_bytes()));
        tags.push(Tag::parse(["payload", &payload]).unwrap());
    }
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(Timestamp::now())
        .sign_with_keys(&keys)
        .expect("sign NIP-98 event");
    let b64 = base64::engine::general_purpose::STANDARD.encode(event.as_json());
    println!("Nostr {b64}");
}
