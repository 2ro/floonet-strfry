// Shared application state and the SQLite layer.
//
// `App` is the single piece of state handed to every handler: the database
// connection, the in-memory rate/cooldown maps, the optional paywall, and
// the resolved config. The schema is a const so tests can stand up an
// identical in-memory database.

use crate::config::Config;
use crate::node::ChainSource;
use crate::paid::Paywall;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

/// The full schema. Idempotent (`IF NOT EXISTS`), so it doubles as the
/// migration applied at every startup.
pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS names (
        name TEXT PRIMARY KEY,
        pubkey TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        released_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_names_pubkey ON names(pubkey);
    -- Enforce one active name per pubkey at the DB layer (defeats the
    -- check-then-insert race that app code alone cannot close).
    CREATE UNIQUE INDEX IF NOT EXISTS idx_active_pubkey
        ON names(pubkey) WHERE released_at IS NULL;
    -- Paid-resource grants: one open grant per (pubkey, resource). `status`
    -- is 'pending' until the GoblinPay invoice settles, then 'paid'.
    CREATE TABLE IF NOT EXISTS paid_grants (
        pubkey TEXT NOT NULL,
        resource TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        pay_url TEXT NOT NULL,
        amount_nanogrin INTEGER NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        paid_at INTEGER,
        PRIMARY KEY (pubkey, resource)
    );
    CREATE INDEX IF NOT EXISTS idx_grants_invoice ON paid_grants(invoice_id);
    -- Name-transfer offers (kind 3402 events lodged by sellers). status is one
    -- of live | consumed | revoked | expired. end_height/state_changed_at are
    -- recorded when an offer leaves `live` by revocation or expiry, and gate
    -- late claims (a payment must settle before the offer died).
    CREATE TABLE IF NOT EXISTS offers (
        offer_id TEXT PRIMARY KEY,
        event_json TEXT NOT NULL,
        name TEXT NOT NULL,
        seller_pubkey TEXT NOT NULL,
        buyer_pubkey TEXT NOT NULL,
        price_nanogrin INTEGER NOT NULL,
        proof_address TEXT NOT NULL,
        expiration INTEGER NOT NULL,
        status TEXT NOT NULL,
        end_height INTEGER,
        state_changed_at INTEGER,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_offers_name ON offers(name);
    CREATE INDEX IF NOT EXISTS idx_offers_addr ON offers(proof_address);
    -- Completed transfers. The UNIQUE on kernel_excess is the durable single-use
    -- guarantee against proof replay (the in-memory replay set is not enough).
    CREATE TABLE IF NOT EXISTS transfers (
        offer_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        seller_pubkey TEXT NOT NULL,
        buyer_pubkey TEXT NOT NULL,
        price_nanogrin INTEGER NOT NULL,
        kernel_excess TEXT NOT NULL UNIQUE,
        kernel_height INTEGER,
        claimed_at INTEGER NOT NULL
    );";

/// A lodged offer row (spec section 3 / 5).
#[derive(Debug, Clone)]
pub struct OfferRow {
    pub offer_id: String,
    pub event_json: String,
    pub name: String,
    pub seller_pubkey: String,
    pub buyer_pubkey: String,
    pub price_nanogrin: i64,
    pub proof_address: String,
    pub expiration: i64,
    pub status: String,
    pub end_height: Option<i64>,
    pub state_changed_at: Option<i64>,
    pub created_at: i64,
}

pub struct App {
    pub db: Mutex<Connection>,
    pub rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// Seen NIP-98 auth event ids (one-time use within the freshness window).
    pub seen_auth: Mutex<HashMap<String, Instant>>,
    /// Resolved runtime config.
    pub cfg: Config,
    /// GoblinPay paywall; `None` when FLOONET_PAY_MODE=off (everything free).
    /// The transfer path never touches this: transfers are strictly
    /// non-custodial and independent of the paywall.
    pub paywall: Option<Paywall>,
    /// Grin node for transfer claims. `None` when transfers are disabled; the
    /// transfer routes are then not mounted, so it is never read in that case.
    pub node: Option<Arc<dyn ChainSource>>,
}

impl App {
    /// Open the database at `cfg.db_path`, applying the schema and wiring the
    /// paywall from config. Pass a `:memory:` db path for tests. When transfers
    /// are enabled a real [`crate::node::NodeClient`] is built from the
    /// configured node URL.
    pub fn open(cfg: Config) -> Self {
        let node: Option<Arc<dyn ChainSource>> = if cfg.allow_transfers {
            Some(Arc::new(crate::node::NodeClient::new(
                cfg.grin_node_endpoints(),
            )))
        } else {
            None
        };
        Self::open_with_node(cfg, node)
    }

    /// Open with an explicit chain source. Integration tests use this to inject
    /// a scriptable [`crate::node::TestChainSource`] and drive claims without a
    /// live Grin node.
    pub fn open_with_node(cfg: Config, node: Option<Arc<dyn ChainSource>>) -> Self {
        let db = Connection::open(&cfg.db_path).expect("open sqlite db");
        // WAL lets the readers (availability/well-known) proceed concurrently
        // with the single writer instead of serializing on one lock.
        let _ = db.pragma_update(None, "journal_mode", "WAL");
        let _ = db.busy_timeout(Duration::from_secs(5));
        db.execute_batch(SCHEMA).expect("init schema");
        let paywall = Paywall::from_config(&cfg);
        App {
            db: Mutex::new(db),
            rate: Mutex::new(HashMap::new()),
            seen_auth: Mutex::new(HashMap::new()),
            cfg,
            paywall,
            node,
        }
    }

    /// Active (non-released) pubkey for a name.
    pub fn lookup(&self, name: &str) -> Option<String> {
        self.db
            .lock()
            .query_row(
                "SELECT pubkey FROM names WHERE name = ?1 AND released_at IS NULL",
                [name],
                |r| r.get::<_, String>(0),
            )
            .ok()
    }

    /// Active name owned by a pubkey.
    pub fn name_of(&self, pubkey: &str) -> Option<String> {
        self.db
            .lock()
            .query_row(
                "SELECT name FROM names WHERE pubkey = ?1 AND released_at IS NULL",
                [pubkey],
                |r| r.get::<_, String>(0),
            )
            .ok()
    }

    /// Fetch a lodged offer by its event id.
    pub fn get_offer(&self, offer_id: &str) -> Option<OfferRow> {
        self.db
            .lock()
            .query_row(
                "SELECT offer_id, event_json, name, seller_pubkey, buyer_pubkey, \
                 price_nanogrin, proof_address, expiration, status, end_height, \
                 state_changed_at, created_at FROM offers WHERE offer_id = ?1",
                [offer_id],
                map_offer,
            )
            .ok()
    }

    /// True when a live, unexpired offer already exists for `name` (spec lodge
    /// check 5, `offer_exists`). A db-`live` row past its expiration does not
    /// count: it is effectively dead and a fresh offer may be lodged.
    pub fn live_offer_for_name(&self, name: &str, now: i64) -> bool {
        self.db
            .lock()
            .query_row(
                "SELECT 1 FROM offers WHERE name = ?1 AND status = 'live' \
                 AND expiration >= ?2 LIMIT 1",
                rusqlite::params![name, now],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// True when another live, unexpired offer already uses this
    /// `proof_address` (spec lodge check 6, `offer_ambiguous`). The normative
    /// client contract is a fresh per-sale address, so this never fires for
    /// conformant sellers; for fixed-address wallets it serializes the seller
    /// to one live offer at a time across all names they own. Keys on the
    /// address ALONE (not address+price), per the spec.
    pub fn live_offer_binding(&self, proof_address: &str, now: i64) -> bool {
        self.db
            .lock()
            .query_row(
                "SELECT 1 FROM offers WHERE proof_address = ?1 \
                 AND status = 'live' AND expiration >= ?2 LIMIT 1",
                rusqlite::params![proof_address, now],
                |_| Ok(()),
            )
            .is_ok()
    }

    /// Insert a fresh `live` offer. Returns the number of rows (1) or a db
    /// error; a primary-key clash means the same offer id was already lodged.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_offer(
        &self,
        offer_id: &str,
        event_json: &str,
        name: &str,
        seller_pubkey: &str,
        buyer_pubkey: &str,
        price_nanogrin: i64,
        proof_address: &str,
        expiration: i64,
        created_at: i64,
    ) -> rusqlite::Result<usize> {
        self.db.lock().execute(
            "INSERT INTO offers (offer_id, event_json, name, seller_pubkey, buyer_pubkey, \
             price_nanogrin, proof_address, expiration, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'live', ?9)",
            rusqlite::params![
                offer_id,
                event_json,
                name,
                seller_pubkey,
                buyer_pubkey,
                price_nanogrin,
                proof_address,
                expiration,
                created_at
            ],
        )
    }

    /// Transition a live offer to a terminal state, recording the chain tip as
    /// `end_height` and the moment of the change (for the claim grace window).
    /// Only affects rows still `live`, so it is idempotent under races.
    pub fn mark_offer_dead(
        &self,
        offer_id: &str,
        status: &str,
        end_height: Option<i64>,
        state_changed_at: i64,
    ) -> rusqlite::Result<usize> {
        self.db.lock().execute(
            "UPDATE offers SET status = ?2, end_height = ?3, state_changed_at = ?4 \
             WHERE offer_id = ?1 AND status = 'live'",
            rusqlite::params![offer_id, status, end_height, state_changed_at],
        )
    }

    /// The completed transfer for an offer id, if any (idempotent-retry lookup).
    /// Returns `(kernel_excess, name, buyer_pubkey)`.
    pub fn transfer_for_offer(&self, offer_id: &str) -> Option<(String, String, String)> {
        self.db
            .lock()
            .query_row(
                "SELECT kernel_excess, name, buyer_pubkey FROM transfers WHERE offer_id = ?1",
                [offer_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .ok()
    }

    /// True when this kernel excess was already consumed by a transfer (spec
    /// claim check 10, `proof_reused`).
    pub fn excess_used(&self, excess_hex: &str) -> bool {
        self.db
            .lock()
            .query_row(
                "SELECT 1 FROM transfers WHERE kernel_excess = ?1 LIMIT 1",
                [excess_hex],
                |_| Ok(()),
            )
            .is_ok()
    }
}

/// Map a full `offers` row to [`OfferRow`].
fn map_offer(r: &rusqlite::Row) -> rusqlite::Result<OfferRow> {
    Ok(OfferRow {
        offer_id: r.get(0)?,
        event_json: r.get(1)?,
        name: r.get(2)?,
        seller_pubkey: r.get(3)?,
        buyer_pubkey: r.get(4)?,
        price_nanogrin: r.get(5)?,
        proof_address: r.get(6)?,
        expiration: r.get(7)?,
        status: r.get(8)?,
        end_height: r.get(9)?,
        state_changed_at: r.get(10)?,
        created_at: r.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A released name is immediately revivable by a new key via the register
    /// upsert.
    #[test]
    fn released_name_immediately_reclaimable() {
        let db = Connection::open_in_memory().expect("db");
        db.execute_batch(SCHEMA).unwrap();
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        db.execute(
            "INSERT INTO names (name, pubkey, created_at, released_at) VALUES ('alice', ?1, 1, 5)",
            rusqlite::params![a],
        )
        .unwrap();
        let n = db
            .execute(
                "INSERT INTO names (name, pubkey, created_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(name) DO UPDATE SET pubkey = excluded.pubkey,
                    created_at = excluded.created_at, released_at = NULL
                 WHERE names.released_at IS NOT NULL",
                rusqlite::params!["alice", b, 6],
            )
            .unwrap();
        assert_eq!(n, 1);
        let owner: String = db
            .query_row(
                "SELECT pubkey FROM names WHERE name='alice' AND released_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(owner, b);
    }
}
