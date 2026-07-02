// HTTP integration tests: drive the real router via `tower::ServiceExt::oneshot`
// with signed NIP-98 auth events, covering the registration and release flows
// (auth/replay/cooldown edge cases) plus the paid-name, paid-write and
// GoblinPay-webhook flows against a mock payment backend.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use floonet_name_authority::config::PayMode;
use floonet_name_authority::paid::{testing::MockPay, Paywall};
use floonet_name_authority::{handlers, App, Config};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const BASE_URL: &str = "https://floonet.example";

/// Build a NIP-98 `Authorization: Nostr <b64>` header value, signed by `keys`,
/// for the given method/path/body. `age_secs` ages the event's created_at into
/// the past (negative = post-dated); the default flow uses 0.
fn nip98_header(keys: &Keys, method: &str, path: &str, body: &[u8], age_secs: i64) -> String {
    let url = format!("{BASE_URL}{path}");
    let mut tags = vec![
        Tag::parse(["u", &url]).unwrap(),
        Tag::parse(["method", method]).unwrap(),
    ];
    if !body.is_empty() {
        let payload = hex::encode(Sha256::digest(body));
        tags.push(Tag::parse(["payload", &payload]).unwrap());
    }
    let created = Timestamp::now().as_secs() as i64 - age_secs;
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created as u64))
        .sign_with_keys(keys)
        .unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(event.as_json());
    format!("Nostr {b64}")
}

fn test_app() -> Arc<App> {
    Arc::new(App::open(Config::for_test()))
}

/// An app in the given paid mode wired to a shared mock GoblinPay backend.
fn paid_test_app(mode: PayMode) -> (Arc<App>, std::sync::Arc<MockPay>) {
    let mock = std::sync::Arc::new(MockPay::default());
    let mut cfg = Config::for_test();
    cfg.pay_mode = mode;
    cfg.goblinpay_webhook_secret = Some("whsec".into());
    let mut app = App::open(cfg);
    app.paywall = Some(Paywall {
        backend: Box::new(mock.clone()),
        name_price_nanogrin: 1_500_000_000,
        write_price_nanogrin: 500_000_000,
    });
    (Arc::new(app), mock)
}

async fn send(app: Arc<App>, req: Request<Body>) -> (StatusCode, Value) {
    let resp = handlers::routes(app).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn register_req(keys: &Keys, name: &str) -> Request<Body> {
    register_req_aged(keys, name, 0)
}

/// Like [`register_req`] but ages the NIP-98 event `age_secs` into the past.
/// Retry-style tests need distinct ages: two otherwise-identical auth events
/// signed within the same second share an event id and trip the (correct)
/// replay rejection.
fn register_req_aged(keys: &Keys, name: &str, age_secs: i64) -> Request<Body> {
    let body = serde_json::json!({ "name": name, "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    let auth = nip98_header(keys, "POST", "/api/v1/register", &body, age_secs);
    Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.1")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn register_happy_path() {
    let app = test_app();
    let keys = Keys::generate();
    let (status, json) = send(app, register_req(&keys, "alice")).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["nip05"], "alice@floonet.example");
}

#[tokio::test]
async fn register_replay_rejected() {
    let app = test_app();
    let keys = Keys::generate();
    let body = serde_json::json!({ "name": "alice", "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    let auth = nip98_header(&keys, "POST", "/api/v1/register", &body, 0);
    let build = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/register")
            .header("authorization", auth.clone())
            .header("x-real-ip", "10.0.0.2")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap()
    };
    let (s1, _) = send(app.clone(), build()).await;
    assert_eq!(s1, StatusCode::CREATED);
    // Same signed auth event a second time -> replay rejection.
    let (s2, json) = send(app, build()).await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth event replayed");
}

#[tokio::test]
async fn register_expired_auth_rejected() {
    let app = test_app();
    let keys = Keys::generate();
    let body = serde_json::json!({ "name": "alice", "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    // 120s in the past, older than the 60s max age.
    let auth = nip98_header(&keys, "POST", "/api/v1/register", &body, 120);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.3")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth event expired or post-dated");
}

#[tokio::test]
async fn register_u_tag_mismatch_rejected() {
    let app = test_app();
    let keys = Keys::generate();
    let body = serde_json::json!({ "name": "alice", "pubkey": keys.public_key().to_hex() })
        .to_string()
        .into_bytes();
    // Sign for the wrong path so the u-tag won't match.
    let auth = nip98_header(&keys, "POST", "/api/v1/profile/alice", &body, 0);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.4")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth event url mismatch");
}

#[tokio::test]
async fn register_wrong_pubkey_rejected() {
    let app = test_app();
    let signer = Keys::generate();
    let other = Keys::generate();
    // Body claims `other`'s pubkey but is signed by `signer`.
    let body = serde_json::json!({ "name": "alice", "pubkey": other.public_key().to_hex() })
        .to_string()
        .into_bytes();
    let auth = nip98_header(&signer, "POST", "/api/v1/register", &body, 0);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/register")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.0.5")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "auth pubkey does not match body pubkey");
}

#[tokio::test]
async fn taken_name_conflicts() {
    let app = test_app();
    let alice = Keys::generate();
    let bob = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&alice, "shared")).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, json) = send(app, register_req(&bob, "shared")).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(json["error"], "name taken");
}

#[tokio::test]
async fn second_name_per_key_conflicts() {
    let app = test_app();
    let keys = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&keys, "first")).await;
    assert_eq!(s1, StatusCode::CREATED);
    let (s2, json) = send(app, register_req(&keys, "second")).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(json["error"], "pubkey already has a name");
}

#[tokio::test]
async fn release_arms_cooldown_blocking_reregister() {
    let app = test_app();
    let keys = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&keys, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    // Release the name.
    let del_auth = nip98_header(&keys, "DELETE", "/api/v1/register/alice", &[], 0);
    let del = Request::builder()
        .method("DELETE")
        .uri("/api/v1/register/alice")
        .header("authorization", del_auth)
        .header("x-real-ip", "10.0.0.6")
        .body(Body::empty())
        .unwrap();
    let (sdel, _) = send(app.clone(), del).await;
    assert_eq!(sdel, StatusCode::OK);

    // A fresh registration is now blocked by the cooldown the release armed.
    let (sreg, json) = send(app, register_req(&keys, "bob")).await;
    assert_eq!(sreg, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json["error"], "name_change_cooldown");
}

#[tokio::test]
async fn wellknown_resolves_registered_name() {
    let app = test_app();
    let keys = Keys::generate();
    let (s1, _) = send(app.clone(), register_req(&keys, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/nostr.json?name=alice")
        .header("x-real-ip", "10.0.2.1")
        .body(Body::empty())
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["names"]["alice"], keys.public_key().to_hex());
}

#[tokio::test]
async fn by_pubkey_reverse_lookup() {
    let app = test_app();
    let keys = Keys::generate();
    let pk = keys.public_key().to_hex();
    let (s1, _) = send(app.clone(), register_req(&keys, "alice")).await;
    assert_eq!(s1, StatusCode::CREATED);

    // Known key -> its active name.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/by-pubkey/{pk}"))
        .header("x-real-ip", "10.0.3.1")
        .body(Body::empty())
        .unwrap();
    let (status, json) = send(app.clone(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["name"], "alice");
    assert_eq!(json["pubkey"], pk);

    // Unknown (but well-formed) key -> 404.
    let other = Keys::generate().public_key().to_hex();
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/by-pubkey/{other}"))
        .header("x-real-ip", "10.0.3.2")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(app.clone(), req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Malformed key -> 404, not a 500.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/by-pubkey/not-a-key")
        .header("x-real-ip", "10.0.3.3")
        .body(Body::empty())
        .unwrap();
    let (status, _) = send(app, req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// --- paid mode ---

#[tokio::test]
async fn paid_name_402_then_registers_after_payment() {
    let (app, mock) = paid_test_app(PayMode::Name);
    let keys = Keys::generate();

    // First attempt: 402 with the invoice + hosted pay URL.
    let (s1, j1) = send(app.clone(), register_req(&keys, "alice")).await;
    assert_eq!(s1, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(j1["error"], "payment_required");
    assert_eq!(j1["resource"], "name");
    assert_eq!(j1["price_grin"], "1.5");
    let invoice_id = j1["invoice_id"].as_str().unwrap().to_string();
    assert!(j1["pay_url"].as_str().unwrap().contains(&invoice_id));

    // Retrying before payment: same invoice, still 402.
    let (s2, j2) = send(app.clone(), register_req_aged(&keys, "alice", 1)).await;
    assert_eq!(s2, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(j2["invoice_id"], invoice_id.as_str());

    // Settle the invoice at the (mock) backend; the retry now succeeds.
    mock.statuses.lock().insert(invoice_id, "paid".into());
    let (s3, j3) = send(app.clone(), register_req_aged(&keys, "alice", 2)).await;
    assert_eq!(s3, StatusCode::CREATED);
    assert_eq!(j3["nip05"], "alice@floonet.example");

    // The grant was consumed: releasing and claiming again needs a new payment
    // (checked via the grants table through a fresh register by another name;
    // the cooldown from release also applies, so check the grant directly).
    assert!(app.grant(&keys.public_key().to_hex(), "name").is_none());
}

#[tokio::test]
async fn paid_name_does_not_quote_for_invalid_or_taken_names() {
    let (app, mock) = paid_test_app(PayMode::Name);
    let alice = Keys::generate();

    // Pay and claim as alice.
    let (_, j) = send(app.clone(), register_req(&alice, "alice")).await;
    let invoice_id = j["invoice_id"].as_str().unwrap().to_string();
    mock.statuses.lock().insert(invoice_id, "paid".into());
    let (s, _) = send(app.clone(), register_req_aged(&alice, "alice", 1)).await;
    assert_eq!(s, StatusCode::CREATED);

    // Bob tries the taken name: conflict BEFORE any invoice is created.
    let bob = Keys::generate();
    let created_before = mock.created.lock().len();
    let (s2, j2) = send(app.clone(), register_req(&bob, "alice")).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(j2["error"], "name taken");
    assert_eq!(mock.created.lock().len(), created_before, "no invoice minted");

    // A reserved name also never mints an invoice.
    let (s3, _) = send(app.clone(), register_req(&bob, "admin")).await;
    assert_eq!(s3, StatusCode::FORBIDDEN);
    assert_eq!(mock.created.lock().len(), created_before);
}

#[tokio::test]
async fn paid_status_reflects_write_grants() {
    let (app, mock) = paid_test_app(PayMode::Write);
    let keys = Keys::generate();
    let pk = keys.public_key().to_hex();

    let paid_req = |pk: &str| {
        Request::builder()
            .method("GET")
            .uri(format!("/api/v1/paid/{pk}"))
            .header("x-real-ip", "10.0.4.1")
            .body(Body::empty())
            .unwrap()
    };

    // No grant: not paid (and no invoice is minted by the public endpoint).
    let (s1, j1) = send(app.clone(), paid_req(&pk)).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(j1["paid"], false);
    assert_eq!(mock.created.lock().len(), 0);

    // Quote write access (NIP-98) -> 402 with the pay URL.
    let body = serde_json::json!({"resource": "write"}).to_string().into_bytes();
    let auth = nip98_header(&keys, "POST", "/api/v1/quote", &body, 0);
    let quote = Request::builder()
        .method("POST")
        .uri("/api/v1/quote")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.4.2")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (s2, j2) = send(app.clone(), quote).await;
    assert_eq!(s2, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(j2["resource"], "write");
    assert_eq!(j2["price_grin"], "0.5");
    let invoice_id = j2["invoice_id"].as_str().unwrap().to_string();

    // Still unpaid until the invoice settles.
    let (_, j3) = send(app.clone(), paid_req(&pk)).await;
    assert_eq!(j3["paid"], false);

    // Settle; the status endpoint (which the relay plugin polls) flips.
    mock.statuses.lock().insert(invoice_id, "paid".into());
    let (_, j4) = send(app.clone(), paid_req(&pk)).await;
    assert_eq!(j4["paid"], true);
}

#[tokio::test]
async fn quote_rejects_resources_not_for_sale() {
    let (app, _mock) = paid_test_app(PayMode::Name);
    let keys = Keys::generate();
    let body = serde_json::json!({"resource": "write"}).to_string().into_bytes();
    let auth = nip98_header(&keys, "POST", "/api/v1/quote", &body, 0);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/quote")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.5.1")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "resource not for sale on this authority");
}

#[tokio::test]
async fn paid_status_is_true_when_not_selling_writes() {
    // In `name` mode (and off mode) the relay plugin must see paid=true.
    let (app, _mock) = paid_test_app(PayMode::Name);
    let pk = Keys::generate().public_key().to_hex();
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/paid/{pk}"))
        .header("x-real-ip", "10.0.6.1")
        .body(Body::empty())
        .unwrap();
    let (status, json) = send(app, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["paid"], true);
}

#[tokio::test]
async fn goblinpay_webhook_nudges_grant_to_paid() {
    let (app, mock) = paid_test_app(PayMode::Write);
    let keys = Keys::generate();
    let pk = keys.public_key().to_hex();

    // Create a pending write grant via quote.
    let body = serde_json::json!({"resource": "write"}).to_string().into_bytes();
    let auth = nip98_header(&keys, "POST", "/api/v1/quote", &body, 0);
    let quote = Request::builder()
        .method("POST")
        .uri("/api/v1/quote")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.7.1")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (_, j) = send(app.clone(), quote).await;
    let invoice_id = j["invoice_id"].as_str().unwrap().to_string();

    // Settle at the backend, then deliver the signed webhook nudge.
    mock.statuses.lock().insert(invoice_id.clone(), "paid".into());
    let payload = serde_json::json!({
        "event_id": "evt-1",
        "event_type": "payment.confirmed",
        "invoice_id": invoice_id,
    })
    .to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec").unwrap();
    mac.update(payload.as_bytes());
    let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let hook = Request::builder()
        .method("POST")
        .uri("/api/v1/goblinpay/webhook")
        .header("x-goblinpay-signature", sig)
        .header("content-type", "application/json")
        .body(Body::from(payload.clone()))
        .unwrap();
    let (s, _) = send(app.clone(), hook).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(app.grant(&pk, "write").unwrap().status, "paid");

    // A bad signature is rejected outright.
    let hook = Request::builder()
        .method("POST")
        .uri("/api/v1/goblinpay/webhook")
        .header("x-goblinpay-signature", "sha256=deadbeef")
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();
    let (s, _) = send(app, hook).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_alone_cannot_grant_unpaid_invoice() {
    // The webhook is only a nudge: if GoblinPay's REST API still says the
    // invoice is open, a signed webhook claiming payment changes nothing.
    let (app, _mock) = paid_test_app(PayMode::Write);
    let keys = Keys::generate();
    let pk = keys.public_key().to_hex();

    let body = serde_json::json!({"resource": "write"}).to_string().into_bytes();
    let auth = nip98_header(&keys, "POST", "/api/v1/quote", &body, 0);
    let quote = Request::builder()
        .method("POST")
        .uri("/api/v1/quote")
        .header("authorization", auth)
        .header("x-real-ip", "10.0.8.1")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (_, j) = send(app.clone(), quote).await;
    let invoice_id = j["invoice_id"].as_str().unwrap().to_string();

    // Signed webhook, but the backend still reports the invoice open.
    let payload = serde_json::json!({
        "event_id": "evt-2",
        "event_type": "payment.confirmed",
        "invoice_id": invoice_id,
    })
    .to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(b"whsec").unwrap();
    mac.update(payload.as_bytes());
    let sig = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    let hook = Request::builder()
        .method("POST")
        .uri("/api/v1/goblinpay/webhook")
        .header("x-goblinpay-signature", sig)
        .header("content-type", "application/json")
        .body(Body::from(payload))
        .unwrap();
    let (s, _) = send(app.clone(), hook).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(app.grant(&pk, "write").unwrap().status, "pending");
}
