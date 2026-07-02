// In-memory rate limiting, cooldowns, and NIP-98 replay tracking. All of this
// state is intentionally non-persistent: on restart the replay window and
// cooldowns reset (documented in the security model).

use crate::db::App;
use std::time::{Duration, Instant};

impl App {
    /// Record a NIP-98 auth event id as used; returns false if already seen
    /// within the freshness window (replay).
    pub fn auth_event_fresh(&self, event_id: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.cfg.auth_max_age_secs as u64 + 5);
        let mut seen = self.seen_auth.lock();
        seen.retain(|_, t| now.duration_since(*t) < window);
        if seen.contains_key(event_id) {
            return false;
        }
        seen.insert(event_id.to_string(), now);
        true
    }

    /// True when an operation in this bucket happened within the window.
    /// Check-only — pair with [`Self::record_op`] on success, so failed
    /// attempts (taken name, bad auth) never burn the caller's cooldown.
    pub fn cooldown_active(&self, bucket: &str, key: &str, window: Duration) -> bool {
        let k = format!("{bucket}:{key}");
        let now = Instant::now();
        let mut map = self.rate.lock();
        if let Some(hits) = map.get_mut(&k) {
            hits.retain(|t| now.duration_since(*t) < window);
            return !hits.is_empty();
        }
        false
    }

    /// Record a completed operation for cooldown tracking.
    pub fn record_op(&self, bucket: &str, key: &str) {
        let k = format!("{bucket}:{key}");
        self.rate.lock().entry(k).or_default().push(Instant::now());
    }

    /// Sliding-window in-memory rate limiter. Returns true when the call is allowed.
    pub fn allow(&self, bucket: &str, ip: &str, max: usize, window: Duration) -> bool {
        let key = format!("{bucket}:{ip}");
        let now = Instant::now();
        let mut map = self.rate.lock();
        let hits = map.entry(key).or_default();
        hits.retain(|t| now.duration_since(*t) < window);
        if hits.len() >= max {
            return false;
        }
        hits.push(now);
        // Opportunistic global cleanup to bound memory.
        if map.len() > 50_000 {
            map.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < window));
        }
        true
    }

    /// Convenience wrappers using the configured ceilings.
    pub fn allow_read(&self, ip: &str) -> bool {
        self.allow(
            "read",
            ip,
            self.cfg.read_rate_max,
            self.cfg.read_rate_window,
        )
    }

    pub fn allow_write(&self, bucket: &str, ip: &str) -> bool {
        self.allow(
            bucket,
            ip,
            self.cfg.write_rate_max,
            self.cfg.write_rate_window,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn app() -> App {
        App::open(Config::for_test())
    }

    #[test]
    fn allow_caps_at_max() {
        let app = app();
        let w = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(app.allow("b", "1.2.3.4", 3, w));
        }
        assert!(!app.allow("b", "1.2.3.4", 3, w));
        // A different IP has its own bucket.
        assert!(app.allow("b", "5.6.7.8", 3, w));
    }

    #[test]
    fn auth_replay_detected() {
        let app = app();
        assert!(app.auth_event_fresh("eventid"));
        assert!(!app.auth_event_fresh("eventid"));
    }

    #[test]
    fn cooldown_records_and_clears() {
        let app = app();
        let w = Duration::from_secs(600);
        assert!(!app.cooldown_active("nc", "pk", w));
        app.record_op("nc", "pk");
        assert!(app.cooldown_active("nc", "pk", w));
        // A zero window means nothing is ever "recent".
        assert!(!app.cooldown_active("nc", "pk", Duration::ZERO));
    }
}
