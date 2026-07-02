// Shared application state and the SQLite layer.
//
// `App` is the single piece of state handed to every handler: the database
// connection, the in-memory rate/cooldown maps, the optional paywall, and
// the resolved config. The schema is a const so tests can stand up an
// identical in-memory database.

use crate::config::Config;
use crate::paid::Paywall;
use parking_lot::Mutex;
use rusqlite::Connection;
use std::{
    collections::HashMap,
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
    CREATE INDEX IF NOT EXISTS idx_grants_invoice ON paid_grants(invoice_id);";

pub struct App {
    pub db: Mutex<Connection>,
    pub rate: Mutex<HashMap<String, Vec<Instant>>>,
    /// Seen NIP-98 auth event ids (one-time use within the freshness window).
    pub seen_auth: Mutex<HashMap<String, Instant>>,
    /// Resolved runtime config.
    pub cfg: Config,
    /// GoblinPay paywall; `None` when FLOONET_PAY_MODE=off (everything free).
    pub paywall: Option<Paywall>,
}

impl App {
    /// Open the database at `cfg.db_path`, applying the schema and wiring the
    /// paywall from config. Pass a `:memory:` db path for tests.
    pub fn open(cfg: Config) -> Self {
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
