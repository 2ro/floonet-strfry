// The paid-resource layer: one GoblinPay-backed mechanism applied to many
// paid uses. `name` (pay to claim a name) and `write` (pay to publish on the
// relay) are the built-in resources; a future paid use (e.g. media/blob
// storage over NIP-96 or Blossom) is the same pattern: pick a resource id,
// give it a price, gate its endpoint on `ensure_paid`.
//
// Design notes:
//   * The GoblinPay conversation is fully owned by this authority. The relay
//     write policy plugin only ever asks "is this pubkey paid?"; it never
//     holds the GoblinPay token.
//   * GoblinPay's REST status is the single source of truth. Webhooks (when
//     configured) are a nudge to re-poll, never trusted on their own, so a
//     replayed delivery can grant nothing the REST API does not confirm.
//   * Fail closed: any transport error means "not paid yet" and the caller
//     keeps returning 402 with the same pay URL.

use crate::config::{nanogrin_to_grin, Config, PayMode};
use crate::db::App;
use crate::util::unix_now;
use std::sync::Arc;

/// A created (or previously created) GoblinPay invoice for a grant.
#[derive(Debug, Clone)]
pub struct Invoice {
    pub id: String,
    pub pay_url: String,
    pub status: String,
}

/// The payment backend. Boxed as a trait so tests can substitute a mock and
/// a future backend can slot in without touching the grant logic.
pub trait PayBackend: Send + Sync {
    /// Create an invoice; returns its id, hosted pay URL and status.
    fn create_invoice(
        &self,
        order_ref: &str,
        amount_nanogrin: u64,
        memo: &str,
    ) -> Result<Invoice, String>;
    /// Current status of an invoice: `open`, `paid` or `expired`.
    fn invoice_status(&self, invoice_id: &str) -> Result<String, String>;
}

/// The real GoblinPay REST backend (`POST /invoice`, `GET /invoice/{id}`,
/// Bearer-token auth). Blocking (ureq); call via `spawn_blocking`.
pub struct GoblinPay {
    pub url: String,
    token: String,
    agent: ureq::Agent,
}

impl GoblinPay {
    pub fn new(url: String, token: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        GoblinPay { url, token, agent }
    }
}

impl PayBackend for GoblinPay {
    fn create_invoice(
        &self,
        order_ref: &str,
        amount_nanogrin: u64,
        memo: &str,
    ) -> Result<Invoice, String> {
        let resp = self
            .agent
            .post(&format!("{}/invoice", self.url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(serde_json::json!({
                "order_ref": order_ref,
                "amount_grin": amount_nanogrin,
                "memo": memo,
            }))
            .map_err(|e| format!("goblinpay create invoice: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("goblinpay create invoice body: {e}"))?;
        parse_invoice(&body)
    }

    fn invoice_status(&self, invoice_id: &str) -> Result<String, String> {
        let resp = self
            .agent
            .get(&format!("{}/invoice/{invoice_id}", self.url))
            .set("Authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(|e| format!("goblinpay invoice status: {e}"))?;
        let body: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("goblinpay invoice status body: {e}"))?;
        body.get("status")
            .and_then(|s| s.as_str())
            .map(str::to_string)
            .ok_or_else(|| "goblinpay invoice status missing".into())
    }
}

fn parse_invoice(body: &serde_json::Value) -> Result<Invoice, String> {
    let field = |k: &str| {
        body.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("goblinpay invoice missing `{k}`"))
    };
    Ok(Invoice {
        id: field("invoice_id")?,
        pay_url: field("pay_url")?,
        status: field("status")?,
    })
}

/// The paywall: a backend plus the operator's prices. Present on the `App`
/// only when `FLOONET_PAY_MODE` is not `off`.
pub struct Paywall {
    pub backend: Box<dyn PayBackend>,
    pub name_price_nanogrin: u64,
    pub write_price_nanogrin: u64,
}

impl Paywall {
    pub fn from_config(cfg: &Config) -> Option<Self> {
        if cfg.pay_mode == PayMode::Off {
            return None;
        }
        Some(Paywall {
            backend: Box::new(GoblinPay::new(
                cfg.goblinpay_url.clone(),
                cfg.goblinpay_token.clone(),
            )),
            name_price_nanogrin: cfg.name_price_nanogrin,
            write_price_nanogrin: cfg.write_price_nanogrin,
        })
    }

    pub fn price_nanogrin(&self, resource: &str) -> u64 {
        match resource {
            "name" => self.name_price_nanogrin,
            "write" => self.write_price_nanogrin,
            _ => 0,
        }
    }
}

/// Outcome of a paid-resource check.
#[derive(Debug, Clone)]
pub enum PaidOutcome {
    /// The pubkey holds a confirmed grant for the resource.
    Paid,
    /// Payment is still due; here is where to pay.
    Due {
        invoice_id: String,
        pay_url: String,
        price_nanogrin: u64,
    },
    /// The payment backend could not be reached or answered garbage. Callers
    /// fail closed (treat as not paid) and surface a retryable error.
    Unavailable(String),
}

/// A row in `paid_grants`.
#[derive(Debug, Clone)]
pub struct Grant {
    pub pubkey: String,
    pub resource: String,
    pub invoice_id: String,
    pub pay_url: String,
    pub amount_nanogrin: u64,
    pub status: String, // "pending" | "paid"
}

impl App {
    /// The grant row for (pubkey, resource), if any.
    pub fn grant(&self, pubkey: &str, resource: &str) -> Option<Grant> {
        self.db
            .lock()
            .query_row(
                "SELECT pubkey, resource, invoice_id, pay_url, amount_nanogrin, status
                 FROM paid_grants WHERE pubkey = ?1 AND resource = ?2",
                rusqlite::params![pubkey, resource],
                |r| {
                    Ok(Grant {
                        pubkey: r.get(0)?,
                        resource: r.get(1)?,
                        invoice_id: r.get(2)?,
                        pay_url: r.get(3)?,
                        amount_nanogrin: r.get::<_, i64>(4)? as u64,
                        status: r.get(5)?,
                    })
                },
            )
            .ok()
    }

    /// Insert or replace the pending grant for (pubkey, resource).
    pub fn put_pending_grant(&self, pubkey: &str, resource: &str, inv: &Invoice, amount: u64) {
        let _ = self.db.lock().execute(
            "INSERT INTO paid_grants
                 (pubkey, resource, invoice_id, pay_url, amount_nanogrin, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)
             ON CONFLICT(pubkey, resource) DO UPDATE SET
                 invoice_id = excluded.invoice_id, pay_url = excluded.pay_url,
                 amount_nanogrin = excluded.amount_nanogrin, status = 'pending',
                 created_at = excluded.created_at, paid_at = NULL",
            rusqlite::params![
                pubkey,
                resource,
                inv.id,
                inv.pay_url,
                amount as i64,
                unix_now()
            ],
        );
    }

    /// Mark the grant holding `invoice_id` as paid. Returns true if a row
    /// changed.
    pub fn mark_grant_paid(&self, invoice_id: &str) -> bool {
        self.db
            .lock()
            .execute(
                "UPDATE paid_grants SET status = 'paid', paid_at = ?2
                 WHERE invoice_id = ?1 AND status != 'paid'",
                rusqlite::params![invoice_id, unix_now()],
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Grant row (if any) holding `invoice_id`; used by the webhook receiver.
    pub fn grant_by_invoice(&self, invoice_id: &str) -> Option<Grant> {
        self.db
            .lock()
            .query_row(
                "SELECT pubkey, resource, invoice_id, pay_url, amount_nanogrin, status
                 FROM paid_grants WHERE invoice_id = ?1",
                [invoice_id],
                |r| {
                    Ok(Grant {
                        pubkey: r.get(0)?,
                        resource: r.get(1)?,
                        invoice_id: r.get(2)?,
                        pay_url: r.get(3)?,
                        amount_nanogrin: r.get::<_, i64>(4)? as u64,
                        status: r.get(5)?,
                    })
                },
            )
            .ok()
    }

    /// Delete a grant (used to consume a `name` grant once the registration
    /// it paid for succeeds, so a released name needs a fresh payment).
    pub fn consume_grant(&self, pubkey: &str, resource: &str) {
        let _ = self.db.lock().execute(
            "DELETE FROM paid_grants WHERE pubkey = ?1 AND resource = ?2",
            rusqlite::params![pubkey, resource],
        );
    }
}

/// The heart of the paid layer: make sure `pubkey` has paid for `resource`.
///
/// * confirmed grant: `Paid`.
/// * pending grant: poll GoblinPay (throttled by `paid_poll_interval` via the
///   in-memory cooldown map so external callers cannot hammer GoblinPay);
///   `paid` promotes the grant, `expired` rolls a fresh invoice, otherwise
///   the existing pay URL is returned again.
/// * no grant: create an invoice and store a pending grant.
///
/// Blocking (talks to GoblinPay); call via `spawn_blocking` from handlers.
pub fn ensure_paid(app: &Arc<App>, pubkey: &str, resource: &str) -> PaidOutcome {
    let Some(paywall) = app.paywall.as_ref() else {
        // No paywall configured: everything is free.
        return PaidOutcome::Paid;
    };
    let price = paywall.price_nanogrin(resource);

    if let Some(grant) = app.grant(pubkey, resource) {
        if grant.status == "paid" {
            return PaidOutcome::Paid;
        }
        // Pending: throttle status polls per grant.
        let poll_key = format!("{pubkey}:{resource}");
        if !app.cooldown_active("paidpoll", &poll_key, app.cfg.paid_poll_interval) {
            app.record_op("paidpoll", &poll_key);
            match paywall.backend.invoice_status(&grant.invoice_id) {
                Ok(status) if status == "paid" => {
                    app.mark_grant_paid(&grant.invoice_id);
                    tracing::info!("grant paid: {resource} for {pubkey}");
                    return PaidOutcome::Paid;
                }
                Ok(status) if status == "expired" => {
                    tracing::info!("invoice expired, rolling a new one: {}", grant.invoice_id);
                    return new_grant(app, paywall, pubkey, resource, price);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("paid poll failed: {e}");
                    // Fall through: return the existing pay URL; the client
                    // can pay/retry regardless of this poll failing.
                }
            }
        }
        return PaidOutcome::Due {
            invoice_id: grant.invoice_id,
            pay_url: grant.pay_url,
            price_nanogrin: grant.amount_nanogrin,
        };
    }

    new_grant(app, paywall, pubkey, resource, price)
}

fn new_grant(
    app: &Arc<App>,
    paywall: &Paywall,
    pubkey: &str,
    resource: &str,
    price: u64,
) -> PaidOutcome {
    let order_ref = format!("floonet-{resource}:{pubkey}");
    let memo = format!("Floonet {resource} ({})", app.cfg.domain);
    match paywall.backend.create_invoice(&order_ref, price, &memo) {
        Ok(inv) => {
            app.put_pending_grant(pubkey, resource, &inv, price);
            PaidOutcome::Due {
                invoice_id: inv.id,
                pay_url: inv.pay_url,
                price_nanogrin: price,
            }
        }
        Err(e) => {
            tracing::error!("create invoice failed: {e}");
            PaidOutcome::Unavailable(e)
        }
    }
}

/// The JSON body of a 402 response: everything a client needs to pay and
/// retry, including the hosted GoblinPay page it can send the payer to.
pub fn payment_required_json(
    resource: &str,
    invoice_id: &str,
    pay_url: &str,
    price_nanogrin: u64,
) -> serde_json::Value {
    serde_json::json!({
        "error": "payment_required",
        "resource": resource,
        "invoice_id": invoice_id,
        "pay_url": pay_url,
        "price_grin": nanogrin_to_grin(price_nanogrin),
        "price_nanogrin": price_nanogrin,
        "currency": "GRIN",
    })
}

#[doc(hidden)]
pub mod testing {
    //! A mock backend for unit/integration tests. Not part of the public
    //! API surface; exposed (like `Config::for_test`) because integration
    //! tests compile as a separate crate and cannot see `#[cfg(test)]` items.
    use super::*;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct MockPay {
        /// invoice_id -> status
        pub statuses: Mutex<HashMap<String, String>>,
        pub created: Mutex<Vec<String>>,
        pub fail: Mutex<bool>,
        counter: Mutex<u64>,
    }

    impl PayBackend for std::sync::Arc<MockPay> {
        fn create_invoice(
            &self,
            order_ref: &str,
            _amount_nanogrin: u64,
            _memo: &str,
        ) -> Result<Invoice, String> {
            if *self.fail.lock() {
                return Err("mock backend down".into());
            }
            let mut c = self.counter.lock();
            *c += 1;
            let id = format!("inv-{}", *c);
            self.statuses.lock().insert(id.clone(), "open".into());
            self.created.lock().push(order_ref.to_string());
            Ok(Invoice {
                id: id.clone(),
                pay_url: format!("https://pay.example/pay/{id}"),
                status: "open".into(),
            })
        }

        fn invoice_status(&self, invoice_id: &str) -> Result<String, String> {
            if *self.fail.lock() {
                return Err("mock backend down".into());
            }
            self.statuses
                .lock()
                .get(invoice_id)
                .cloned()
                .ok_or_else(|| "unknown invoice".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::MockPay;
    use super::*;
    use crate::config::Config;

    /// An app in paid (name) mode plus a shared handle to its mock backend.
    fn paid_app() -> (Arc<App>, std::sync::Arc<MockPay>) {
        let mock = std::sync::Arc::new(MockPay::default());
        let mut cfg = Config::for_test();
        cfg.pay_mode = PayMode::Name;
        let mut app = App::open(cfg);
        app.paywall = Some(Paywall {
            backend: Box::new(mock.clone()),
            name_price_nanogrin: 1_500_000_000,
            write_price_nanogrin: 500_000_000,
        });
        (Arc::new(app), mock)
    }

    #[test]
    fn free_mode_is_always_paid() {
        let app = Arc::new(App::open(Config::for_test()));
        assert!(matches!(
            ensure_paid(&app, &"a".repeat(64), "name"),
            PaidOutcome::Paid
        ));
    }

    #[test]
    fn unpaid_gets_invoice_then_paid_after_settlement() {
        let (app, mock) = paid_app();
        let pk = "a".repeat(64);

        // First ask: an invoice is created and payment is due.
        let due = ensure_paid(&app, &pk, "name");
        let PaidOutcome::Due {
            invoice_id,
            pay_url,
            price_nanogrin,
        } = due
        else {
            panic!("expected Due, got {due:?}");
        };
        assert_eq!(price_nanogrin, 1_500_000_000);
        assert!(pay_url.contains(&invoice_id));

        // Second ask: same invoice (idempotent), still due.
        let again = ensure_paid(&app, &pk, "name");
        let PaidOutcome::Due {
            invoice_id: id2, ..
        } = again
        else {
            panic!("expected Due");
        };
        assert_eq!(id2, invoice_id);

        // Settle at the backend; the next ask promotes the grant.
        mock.statuses
            .lock()
            .insert(invoice_id.clone(), "paid".into());
        assert!(matches!(ensure_paid(&app, &pk, "name"), PaidOutcome::Paid));
        // And it stays paid without further polling.
        assert!(matches!(ensure_paid(&app, &pk, "name"), PaidOutcome::Paid));
    }

    #[test]
    fn expired_invoice_rolls_a_fresh_one() {
        let (app, mock) = paid_app();
        let pk = "b".repeat(64);
        let PaidOutcome::Due { invoice_id, .. } = ensure_paid(&app, &pk, "name") else {
            panic!("expected Due");
        };
        mock.statuses
            .lock()
            .insert(invoice_id.clone(), "expired".into());
        let PaidOutcome::Due {
            invoice_id: id2, ..
        } = ensure_paid(&app, &pk, "name")
        else {
            panic!("expected Due");
        };
        assert_ne!(id2, invoice_id, "a fresh invoice replaces the expired one");
    }

    #[test]
    fn backend_down_fails_closed() {
        let (app, mock) = paid_app();
        *mock.fail.lock() = true;
        let out = ensure_paid(&app, &"c".repeat(64), "name");
        assert!(matches!(out, PaidOutcome::Unavailable(_)));
    }

    #[test]
    fn consume_grant_requires_repayment() {
        let (app, _mock) = paid_app();
        let pk = "d".repeat(64);
        let PaidOutcome::Due { invoice_id, .. } = ensure_paid(&app, &pk, "name") else {
            panic!("expected Due");
        };
        app.mark_grant_paid(&invoice_id);
        assert!(matches!(ensure_paid(&app, &pk, "name"), PaidOutcome::Paid));
        app.consume_grant(&pk, "name");
        assert!(matches!(
            ensure_paid(&app, &pk, "name"),
            PaidOutcome::Due { .. }
        ));
    }

    #[test]
    fn resources_are_independent() {
        let (app, _mock) = paid_app();
        let pk = "e".repeat(64);
        let PaidOutcome::Due { invoice_id, .. } = ensure_paid(&app, &pk, "name") else {
            panic!("expected Due");
        };
        app.mark_grant_paid(&invoice_id);
        assert!(matches!(ensure_paid(&app, &pk, "name"), PaidOutcome::Paid));
        // Paying for a name does not grant write access.
        assert!(matches!(
            ensure_paid(&app, &pk, "write"),
            PaidOutcome::Due { .. }
        ));
    }
}
