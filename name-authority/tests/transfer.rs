// HTTP integration tests for the name-transfer marketplace (spec sections 3-6).
// Drives the real router via `tower::ServiceExt::oneshot` with a scriptable
// in-process chain source (no live Grin node), real schnorr-signed kind-3402
// offers, and real ed25519-signed Grin payment proofs. Nothing here fakes the
// proof verification: the 73-byte message is signed with genuine ed25519 keys.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use floonet_name_authority::node::TestChainSource;
use floonet_name_authority::proof::{grin_address_from_pubkey, payment_proof_message};
use floonet_name_authority::{handlers, App, Config};
use http_body_util::BodyExt;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use tower::ServiceExt;

const BASE_URL: &str = "https://floonet.example";
const DOMAIN: &str = "floonet.example";
const PRICE: u64 = 500_000_000_381_624;
const PRICE_STR: &str = "500000000381624";

// --- app / node harness -----------------------------------------------------

/// A transfers-enabled app with an injected scriptable chain source at tip 1000.
fn transfer_app() -> (Arc<App>, Arc<TestChainSource>) {
    let mut cfg = Config::for_test();
    cfg.allow_transfers = true;
    cfg.grin_node_url = Some("http://test-node/v2/foreign".into());
    let node = Arc::new(TestChainSource::new(1000));
    let app = Arc::new(App::open_with_node(cfg, Some(node.clone())));
    (app, node)
}

/// A transfers-disabled app (default config): the transfer routes are absent.
fn disabled_app() -> Arc<App> {
    Arc::new(App::open(Config::for_test()))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Seed a name directly as owned by `pubkey` (bypasses the register flow).
fn seed_name(app: &Arc<App>, name: &str, pubkey: &str) {
    app.db
        .lock()
        .execute(
            "INSERT INTO names (name, pubkey, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![name, pubkey, 1i64],
        )
        .unwrap();
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

// --- NIP-98 auth (mirrors tests/http.rs) ------------------------------------

fn nip98_header(keys: &Keys, method: &str, path: &str, body: &[u8]) -> String {
    nip98_header_aged(keys, method, path, body, 0)
}

/// Like [`nip98_header`] but ages `created_at` into the past by `age_secs`. A
/// retry needs a distinct auth event (the authority enforces one-time event
/// ids); real clients get that from the passage of time, tests get it here.
fn nip98_header_aged(keys: &Keys, method: &str, path: &str, body: &[u8], age_secs: i64) -> String {
    use sha2::{Digest, Sha256};
    let url = format!("{BASE_URL}{path}");
    let mut tags = vec![
        Tag::parse(["u", &url]).unwrap(),
        Tag::parse(["method", method]).unwrap(),
    ];
    if !body.is_empty() {
        tags.push(Tag::parse(["payload", &hex::encode(Sha256::digest(body))]).unwrap());
    }
    let created = Timestamp::now().as_secs() as i64 - age_secs;
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created as u64))
        .sign_with_keys(keys)
        .unwrap();
    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event.as_json())
    )
}

// --- offer / proof builders -------------------------------------------------

/// Build a signed kind-3402 offer event.
#[allow(clippy::too_many_arguments)]
fn offer_event(
    seller: &Keys,
    name: &str,
    domain: &str,
    buyer_hex: &str,
    price: &str,
    proof_addr: &str,
    expiration: i64,
) -> nostr::Event {
    let tags = vec![
        Tag::parse(["name", name]).unwrap(),
        Tag::parse(["domain", domain]).unwrap(),
        Tag::parse(["p", buyer_hex]).unwrap(),
        Tag::parse(["price", price]).unwrap(),
        Tag::parse(["proof_address", proof_addr]).unwrap(),
        Tag::parse(["expiration", &expiration.to_string()]).unwrap(),
    ];
    EventBuilder::new(Kind::Custom(3402), "")
        .tags(tags)
        .sign_with_keys(seller)
        .unwrap()
}

fn lodge_req(seller: &Keys, event: &nostr::Event, ip: &str) -> Request<Body> {
    let ev: Value = serde_json::from_str(&event.as_json()).unwrap();
    let body = json!({ "offer": ev }).to_string().into_bytes();
    let auth = nip98_header(seller, "POST", "/api/v1/transfer/offer", &body);
    Request::builder()
        .method("POST")
        .uri("/api/v1/transfer/offer")
        .header("authorization", auth)
        .header("x-real-ip", ip)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// A fresh Grin wallet: ed25519 signing key + its grin1 slatepack address.
fn grin_wallet() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let addr = grin_address_from_pubkey(&sk.verifying_key().to_bytes(), "grin");
    (sk, addr)
}

fn rand_excess() -> [u8; 33] {
    let mut e = [0u8; 33];
    OsRng.fill_bytes(&mut e);
    e
}

/// Build a real six-field Grin payment proof, both signatures over the genuine
/// 73-byte message.
fn build_proof(
    recipient: &SigningKey,
    sender: &SigningKey,
    amount: u64,
    excess: &[u8; 33],
) -> Value {
    let excess_hex = hex::encode(excess);
    let sender_pub = sender.verifying_key().to_bytes();
    let msg = payment_proof_message(amount, &excess_hex, &sender_pub).unwrap();
    json!({
        "amount": amount.to_string(),
        "excess": excess_hex,
        "recipient_address": grin_address_from_pubkey(&recipient.verifying_key().to_bytes(), "grin"),
        "recipient_sig": hex::encode(recipient.sign(&msg).to_bytes()),
        "sender_address": grin_address_from_pubkey(&sender.verifying_key().to_bytes(), "grin"),
        "sender_sig": hex::encode(sender.sign(&msg).to_bytes()),
    })
}

fn claim_req(buyer: &Keys, offer_id: &str, proof: &Value, ip: &str) -> Request<Body> {
    claim_req_aged(buyer, offer_id, proof, ip, 0)
}

fn claim_req_aged(
    buyer: &Keys,
    offer_id: &str,
    proof: &Value,
    ip: &str,
    age_secs: i64,
) -> Request<Body> {
    let body = json!({ "offer_id": offer_id, "proof": proof })
        .to_string()
        .into_bytes();
    let auth = nip98_header_aged(buyer, "POST", "/api/v1/transfer/claim", &body, age_secs);
    Request::builder()
        .method("POST")
        .uri("/api/v1/transfer/claim")
        .header("authorization", auth)
        .header("x-real-ip", ip)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Lodge a standard offer for `name` owned by `seller`, to `buyer`, paid to
/// `recipient_addr`. Returns the offer_id.
async fn lodge_ok(
    app: &Arc<App>,
    seller: &Keys,
    name: &str,
    buyer: &Keys,
    recipient_addr: &str,
) -> String {
    let ev = offer_event(
        seller,
        name,
        DOMAIN,
        &buyer.public_key().to_hex(),
        PRICE_STR,
        recipient_addr,
        now() + 3600,
    );
    let (status, json) = send(app.clone(), lodge_req(seller, &ev, "10.1.0.1")).await;
    assert_eq!(status, StatusCode::CREATED, "lodge failed: {json}");
    json["offer_id"].as_str().unwrap().to_string()
}

// --- toggle / config --------------------------------------------------------

#[tokio::test]
async fn transfer_routes_absent_when_disabled() {
    let app = disabled_app();
    for req in [
        Request::builder()
            .method("POST")
            .uri("/api/v1/transfer/offer")
            .header("x-real-ip", "10.0.9.1")
            .body(Body::from("{}"))
            .unwrap(),
        Request::builder()
            .method("GET")
            .uri("/api/v1/transfer/offer/abc")
            .header("x-real-ip", "10.0.9.2")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .method("POST")
            .uri("/api/v1/transfer/claim")
            .header("x-real-ip", "10.0.9.3")
            .body(Body::from("{}"))
            .unwrap(),
    ] {
        let (status, _) = send(app.clone(), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

// --- lodge state machine ----------------------------------------------------

#[tokio::test]
async fn lodge_happy_path() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;
    assert_eq!(id.len(), 64);
}

#[tokio::test]
async fn lodge_duplicate_live_offer_for_name_conflicts() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    // A second live offer for the same name, with a DIFFERENT binding so this
    // is offer_exists and not offer_ambiguous.
    let (_r2, addr2) = grin_wallet();
    let ev = offer_event(
        &seller,
        "alice",
        DOMAIN,
        &buyer.public_key().to_hex(),
        "999",
        &addr2,
        now() + 3600,
    );
    let (status, json) = send(app.clone(), lodge_req(&seller, &ev, "10.1.0.2")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "offer_exists");
}

#[tokio::test]
async fn lodge_ambiguous_binding_conflicts() {
    let (app, _node) = transfer_app();
    let (seller1, seller2) = (Keys::generate(), Keys::generate());
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller1.public_key().to_hex());
    seed_name(&app, "bob", &seller2.public_key().to_hex());

    // Two different names, same proof_address: blocked at the second even
    // though the price differs (the live-uniqueness rule keys on the address
    // alone; a fresh per-sale address is the normative client contract).
    lodge_ok(&app, &seller1, "alice", &buyer, &addr).await;
    let ev = offer_event(
        &seller2,
        "bob",
        DOMAIN,
        &buyer.public_key().to_hex(),
        "123456789",
        &addr,
        now() + 3600,
    );
    let (status, json) = send(app.clone(), lodge_req(&seller2, &ev, "10.1.0.3")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "offer_ambiguous");
}

#[tokio::test]
async fn lodge_distinct_addresses_same_price_ok() {
    let (app, _node) = transfer_app();
    let (seller1, seller2) = (Keys::generate(), Keys::generate());
    let buyer1 = Keys::generate();
    let buyer2 = Keys::generate();
    let (_r1, addr1) = grin_wallet();
    let (_r2, addr2) = grin_wallet();
    seed_name(&app, "alice", &seller1.public_key().to_hex());
    seed_name(&app, "bob", &seller2.public_key().to_hex());

    // Fresh per-sale addresses: two live offers with the identical price are
    // fine, the unique address alone disambiguates the sales.
    lodge_ok(&app, &seller1, "alice", &buyer1, &addr1).await;
    lodge_ok(&app, &seller2, "bob", &buyer2, &addr2).await;
}

#[tokio::test]
async fn lodge_wrong_domain_rejected() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let ev = offer_event(
        &seller,
        "alice",
        "evil.example",
        &buyer.public_key().to_hex(),
        PRICE_STR,
        &addr,
        now() + 3600,
    );
    let (status, json) = send(app.clone(), lodge_req(&seller, &ev, "10.1.0.4")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid offer");
}

#[tokio::test]
async fn lodge_bad_expiry_rejected() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    // In the past.
    let past = offer_event(
        &seller,
        "alice",
        DOMAIN,
        &buyer.public_key().to_hex(),
        PRICE_STR,
        &addr,
        now() - 10,
    );
    let (s1, _) = send(app.clone(), lodge_req(&seller, &past, "10.1.0.5")).await;
    assert_eq!(s1, StatusCode::BAD_REQUEST);
    // Beyond max TTL.
    let far = offer_event(
        &seller,
        "alice",
        DOMAIN,
        &buyer.public_key().to_hex(),
        PRICE_STR,
        &addr,
        now() + 10_000_000,
    );
    let (s2, _) = send(app.clone(), lodge_req(&seller, &far, "10.1.0.6")).await;
    assert_eq!(s2, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn lodge_missing_tag_rejected() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    // Drop the proof_address tag entirely.
    let tags = vec![
        Tag::parse(["name", "alice"]).unwrap(),
        Tag::parse(["domain", DOMAIN]).unwrap(),
        Tag::parse(["p", &buyer.public_key().to_hex()]).unwrap(),
        Tag::parse(["price", PRICE_STR]).unwrap(),
        Tag::parse(["expiration", &(now() + 3600).to_string()]).unwrap(),
    ];
    let ev = EventBuilder::new(Kind::Custom(3402), "")
        .tags(tags)
        .sign_with_keys(&seller)
        .unwrap();
    let (status, json) = send(app.clone(), lodge_req(&seller, &ev, "10.1.0.7")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid offer");
}

#[tokio::test]
async fn lodge_bad_signature_rejected() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let ev = offer_event(
        &seller,
        "alice",
        DOMAIN,
        &buyer.public_key().to_hex(),
        PRICE_STR,
        &addr,
        now() + 3600,
    );
    // Corrupt the signature but keep valid JSON.
    let mut v: Value = serde_json::from_str(&ev.as_json()).unwrap();
    let sig = v["sig"].as_str().unwrap().to_string();
    let mut bad = sig.clone();
    bad.replace_range(0..2, if sig.starts_with("00") { "ff" } else { "00" });
    v["sig"] = json!(bad);
    let body = json!({ "offer": v }).to_string().into_bytes();
    let auth = nip98_header(&seller, "POST", "/api/v1/transfer/offer", &body);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/transfer/offer")
        .header("authorization", auth)
        .header("x-real-ip", "10.1.0.8")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, json) = send(app.clone(), req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid offer");
}

#[tokio::test]
async fn lodge_non_owner_rejected() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    // Nobody owns "alice".
    let ev = offer_event(
        &seller,
        "alice",
        DOMAIN,
        &buyer.public_key().to_hex(),
        PRICE_STR,
        &addr,
        now() + 3600,
    );
    let (status, json) = send(app.clone(), lodge_req(&seller, &ev, "10.1.0.9")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"], "not the owner");
}

// --- revoke -----------------------------------------------------------------

fn revoke_req(seller: &Keys, offer_id: &str, ip: &str) -> Request<Body> {
    let path = format!("/api/v1/transfer/offer/{offer_id}");
    let auth = nip98_header(seller, "DELETE", &path, &[]);
    Request::builder()
        .method("DELETE")
        .uri(&path)
        .header("authorization", auth)
        .header("x-real-ip", ip)
        .body(Body::empty())
        .unwrap()
}

async fn read_status(app: &Arc<App>, offer_id: &str, ip: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/transfer/offer/{offer_id}"))
        .header("x-real-ip", ip)
        .body(Body::empty())
        .unwrap();
    send(app.clone(), req).await
}

#[tokio::test]
async fn revoke_happy_then_status_revoked() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let (status, json) = send(app.clone(), revoke_req(&seller, &id, "10.2.0.1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "revoked");

    let (s, j) = read_status(&app, &id, "10.2.0.2").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(j["status"], "revoked");
}

#[tokio::test]
async fn revoke_not_owner_rejected() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let stranger = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;
    let (status, json) = send(app.clone(), revoke_req(&stranger, &id, "10.2.0.3")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"], "not the owner");
}

#[tokio::test]
async fn revoke_consumed_conflicts() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);
    let (s, _) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.2.0.4")).await;
    assert_eq!(s, StatusCode::CREATED);

    // Revoking a consumed offer conflicts.
    let (status, json) = send(app.clone(), revoke_req(&seller, &id, "10.2.0.5")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "offer_consumed");
}

#[tokio::test]
async fn offer_expiry_transitions_on_read() {
    let (app, _node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_r, addr) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    // Force the stored expiration into the past, then read: it settles expired
    // and records the chain tip (1000) as end_height.
    app.db
        .lock()
        .execute(
            "UPDATE offers SET expiration = ?2 WHERE offer_id = ?1",
            rusqlite::params![id, now() - 10],
        )
        .unwrap();
    let (status, json) = read_status(&app, &id, "10.2.0.6").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["status"], "expired");
    let end: Option<i64> = app
        .db
        .lock()
        .query_row(
            "SELECT end_height FROM offers WHERE offer_id = ?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(end, Some(1000));
}

// --- late claim rules -------------------------------------------------------

#[tokio::test]
async fn late_claim_within_grace_and_below_end_height_honored() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    // Payment settled at height 900; the offer is revoked with the tip at 1000.
    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);
    node.set_tip(1000);
    let (s, _) = send(app.clone(), revoke_req(&seller, &id, "10.3.0.1")).await;
    assert_eq!(s, StatusCode::OK);

    // 900 <= 1000 and within grace: the claim is still honored.
    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.3.0.2")).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert_eq!(json["pubkey"], buyer.public_key().to_hex());
}

#[tokio::test]
async fn late_claim_kernel_above_end_height_gone() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    // Revoke at tip 1000, but the kernel only lands later at height 2000.
    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_tip(1000);
    let (s, _) = send(app.clone(), revoke_req(&seller, &id, "10.3.0.3")).await;
    assert_eq!(s, StatusCode::OK);
    node.set_kernel(&hex::encode(excess), 2000, 10);

    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.3.0.4")).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(json["error"], "offer_revoked");
}

#[tokio::test]
async fn late_claim_outside_grace_gone() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);
    node.set_tip(1000);
    let (s, _) = send(app.clone(), revoke_req(&seller, &id, "10.3.0.5")).await;
    assert_eq!(s, StatusCode::OK);
    // Push the state change well outside the grace window.
    app.db
        .lock()
        .execute(
            "UPDATE offers SET state_changed_at = ?2 WHERE offer_id = ?1",
            rusqlite::params![id, now() - 200_000],
        )
        .unwrap();

    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.3.0.6")).await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(json["error"], "offer_revoked");
}

// --- claim verification -----------------------------------------------------

#[tokio::test]
async fn claim_bad_recipient_sig_rejected() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let mut proof = build_proof(&recipient, &sender, PRICE, &excess);
    let mut sig = proof["recipient_sig"].as_str().unwrap().to_string();
    sig.replace_range(0..2, "ff");
    proof["recipient_sig"] = json!(sig);
    node.set_kernel(&hex::encode(excess), 900, 10);
    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.4.0.1")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid proof");
}

#[tokio::test]
async fn claim_bad_sender_sig_rejected() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let mut proof = build_proof(&recipient, &sender, PRICE, &excess);
    let mut sig = proof["sender_sig"].as_str().unwrap().to_string();
    sig.replace_range(0..2, "ff");
    proof["sender_sig"] = json!(sig);
    node.set_kernel(&hex::encode(excess), 900, 10);
    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.4.0.2")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "invalid proof");
}

#[tokio::test]
async fn claim_wrong_amount_rejected() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    // Proof is correctly signed but for a different amount than the price.
    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE - 1, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);
    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.4.0.3")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "proof_amount_mismatch");
}

#[tokio::test]
async fn claim_wrong_recipient_address_rejected() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (_offer_recipient, addr) = grin_wallet();
    let (other_recipient, _) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    // Proof pays a DIFFERENT recipient than the offer's proof_address.
    let excess = rand_excess();
    let proof = build_proof(&other_recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);
    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.4.0.4")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "proof_address_mismatch");
}

#[tokio::test]
async fn claim_unconfirmed_payment_rejected() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    // Kernel found but only 3 confirmations (< min_conf 10).
    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 998, 3);
    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.4.0.5")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(json["error"], "payment_unconfirmed");

    // A kernel the node has never seen is likewise unconfirmed.
    let excess2 = rand_excess();
    let proof2 = build_proof(&recipient, &sender, PRICE, &excess2);
    let (status2, json2) = send(app.clone(), claim_req(&buyer, &id, &proof2, "10.4.0.6")).await;
    assert_eq!(status2, StatusCode::CONFLICT);
    assert_eq!(json2["error"], "payment_unconfirmed");
}

#[tokio::test]
async fn claim_wrong_buyer_key_rejected() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let impostor = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);
    // Signed by the wrong key (not the offer's p tag).
    let (status, json) = send(app.clone(), claim_req(&impostor, &id, &proof, "10.4.0.7")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "not the buyer");
}

#[tokio::test]
async fn claim_replayed_excess_rejected() {
    let (app, node) = transfer_app();
    let seller1 = Keys::generate();
    let seller2 = Keys::generate();
    let buyer1 = Keys::generate();
    let buyer2 = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller1.public_key().to_hex());
    seed_name(&app, "bob", &seller2.public_key().to_hex());

    let excess = rand_excess();
    node.set_kernel(&hex::encode(excess), 900, 10);

    // First sale consumes the excess.
    let id1 = lodge_ok(&app, &seller1, "alice", &buyer1, &addr).await;
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    let (s1, _) = send(app.clone(), claim_req(&buyer1, &id1, &proof, "10.4.0.8")).await;
    assert_eq!(s1, StatusCode::CREATED);

    // A second sale (same address+price now that the first is consumed) cannot
    // reuse the same kernel.
    let id2 = lodge_ok(&app, &seller2, "bob", &buyer2, &addr).await;
    let (s2, j2) = send(app.clone(), claim_req(&buyer2, &id2, &proof, "10.4.0.9")).await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(j2["error"], "proof_reused");
}

#[tokio::test]
async fn claim_buyer_already_has_name_then_release_and_retry() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    // Buyer already owns "oldname".
    seed_name(&app, "oldname", &buyer.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);

    // Rejected while the buyer still holds a name (retryable, non-destructive).
    let (s1, j1) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.5.0.1")).await;
    assert_eq!(s1, StatusCode::CONFLICT);
    assert_eq!(j1["error"], "pubkey already has a name");

    // Buyer releases the old name (this arms the buyer's name-change cooldown).
    let del_auth = nip98_header(&buyer, "DELETE", "/api/v1/register/oldname", &[]);
    let del = Request::builder()
        .method("DELETE")
        .uri("/api/v1/register/oldname")
        .header("authorization", del_auth)
        .header("x-real-ip", "10.5.0.2")
        .body(Body::empty())
        .unwrap();
    let (sdel, _) = send(app.clone(), del).await;
    assert_eq!(sdel, StatusCode::OK);
    assert!(app.cooldown_active(
        "namechange",
        &buyer.public_key().to_hex(),
        Duration::from_secs(600)
    ));

    // Retry: the claim is EXEMPT from the name-change cooldown, so it succeeds.
    // (Aged auth event so it is a distinct, non-replayed NIP-98 request.)
    let (s2, j2) = send(
        app.clone(),
        claim_req_aged(&buyer, &id, &proof, "10.5.0.3", 2),
    )
    .await;
    assert_eq!(s2, StatusCode::CREATED, "{j2}");
    assert_eq!(j2["pubkey"], buyer.public_key().to_hex());
}

#[tokio::test]
async fn successful_claim_reassigns_consumes_and_arms_cooldown() {
    let (app, node) = transfer_app();
    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);

    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.6.0.1")).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(json["name"], "alice");
    assert_eq!(json["nip05"], "alice@floonet.example");
    assert_eq!(json["pubkey"], buyer.public_key().to_hex());

    // Name reassigned to the buyer.
    assert_eq!(app.lookup("alice"), Some(buyer.public_key().to_hex()));
    assert_eq!(app.name_of(&seller.public_key().to_hex()), None);
    // Offer consumed.
    let (_, st) = read_status(&app, &id, "10.6.0.2").await;
    assert_eq!(st["status"], "consumed");
    // Seller's name-change cooldown armed (consistent with a release).
    assert!(app.cooldown_active(
        "namechange",
        &seller.public_key().to_hex(),
        Duration::from_secs(600)
    ));

    // Idempotent retry with the same (offer_id, excess): 200, same body.
    // (Aged auth event so it is a distinct, non-replayed NIP-98 request.)
    let (rs, rj) = send(
        app.clone(),
        claim_req_aged(&buyer, &id, &proof, "10.6.0.3", 2),
    )
    .await;
    assert_eq!(rs, StatusCode::OK);
    assert_eq!(rj["name"], "alice");
    assert_eq!(rj["nip05"], "alice@floonet.example");
    assert_eq!(rj["pubkey"], buyer.public_key().to_hex());
}

// --- transfers x paid mode --------------------------------------------------

#[tokio::test]
async fn transfers_work_with_pay_mode_active() {
    // Transfers and paid-names are independently toggleable: with
    // FLOONET_PAY_MODE=name active (registration gated on a GoblinPay payment),
    // a transfer claim still completes with ZERO GoblinPay involvement. The
    // claim path never touches the paywall, so a claim succeeds even though the
    // backend is a mock that would refuse any invoice.
    use floonet_name_authority::config::PayMode;
    use floonet_name_authority::paid::{testing::MockPay, Paywall};

    let mut cfg = Config::for_test();
    cfg.allow_transfers = true;
    cfg.grin_node_url = Some("http://test-node/v2/foreign".into());
    cfg.pay_mode = PayMode::Name;
    let node = Arc::new(TestChainSource::new(1000));
    let mut app = App::open_with_node(cfg, Some(node.clone()));
    app.paywall = Some(Paywall {
        backend: Box::new(Arc::new(MockPay::default())),
        name_price_nanogrin: 1_500_000_000,
        write_price_nanogrin: 500_000_000,
    });
    let app = Arc::new(app);

    let seller = Keys::generate();
    let buyer = Keys::generate();
    let (recipient, addr) = grin_wallet();
    let (sender, _) = grin_wallet();
    seed_name(&app, "alice", &seller.public_key().to_hex());
    let id = lodge_ok(&app, &seller, "alice", &buyer, &addr).await;

    let excess = rand_excess();
    let proof = build_proof(&recipient, &sender, PRICE, &excess);
    node.set_kernel(&hex::encode(excess), 900, 10);
    let (status, json) = send(app.clone(), claim_req(&buyer, &id, &proof, "10.7.0.1")).await;
    assert_eq!(status, StatusCode::CREATED, "{json}");
    assert_eq!(json["pubkey"], buyer.public_key().to_hex());
    assert_eq!(json["nip05"], "alice@floonet.example");
}
