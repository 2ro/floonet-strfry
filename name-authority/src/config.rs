// Runtime configuration. Everything that identifies a particular operator's
// name authority lives here and is read from the environment at startup, so
// any operator can run their own authority without touching the source.

use std::time::Duration;

/// How this authority charges for its resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayMode {
    /// Everything is free.
    Off,
    /// Claiming a name requires a confirmed GoblinPay payment.
    Name,
    /// Publishing to the relay requires a confirmed GoblinPay payment
    /// (enforced by the write policy plugin, which consults this authority).
    Write,
}

impl PayMode {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "off" => Ok(PayMode::Off),
            "name" => Ok(PayMode::Name),
            "write" => Ok(PayMode::Write),
            other => Err(format!(
                "FLOONET_PAY_MODE must be off, name or write (got `{other}`)"
            )),
        }
    }
}

/// Resolved, validated runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Bare host the names live under, e.g. `floonet.example` (the `@domain`
    /// part of `name@domain`).
    pub domain: String,
    /// Public base URL, e.g. `https://floonet.example`. Load-bearing: NIP-98
    /// `u`-tag verification builds the expected URL from this, so it MUST
    /// equal the scheme+host clients actually reach, or all authenticated
    /// calls fail.
    pub base_url: String,
    /// Relays advertised in `/.well-known/nostr.json` `relays` map.
    pub relays: Vec<String>,
    /// Address the HTTP server binds (loopback by default; sit behind a proxy).
    pub bind_addr: String,
    /// SQLite database path.
    pub db_path: String,

    /// After releasing a name, how long a pubkey must wait before claiming a
    /// new one (anti-churn brake).
    pub name_change_cooldown: Duration,
    /// Max age (seconds) of an accepted NIP-98 auth event.
    pub auth_max_age_secs: i64,
    /// Minimum/maximum name length in characters.
    pub name_min: usize,
    pub name_max: usize,

    /// Read endpoints: requests per IP per `read_window`.
    pub read_rate_max: usize,
    pub read_rate_window: Duration,
    /// Write endpoints (register/unregister/quote): per IP per `write_window`.
    pub write_rate_max: usize,
    pub write_rate_window: Duration,

    /// Additional reserved names: the operator's own domain labels (so the
    /// brand a domain represents can't be impersonated) plus any names from
    /// an optional `FLOONET_RESERVED_FILE`. Extends the built-in generic list.
    pub extra_reserved: Vec<String>,

    /// Paid mode. `Off` runs a free authority (the default).
    pub pay_mode: PayMode,
    /// Price of a name, in nanogrin (parsed from FLOONET_NAME_PRICE_GRIN).
    pub name_price_nanogrin: u64,
    /// Price of write access, in nanogrin (FLOONET_WRITE_PRICE_GRIN).
    pub write_price_nanogrin: u64,
    /// GoblinPay server base URL (e.g. `https://pay.example`).
    pub goblinpay_url: String,
    /// GoblinPay API token (Bearer). From GOBLINPAY_TOKEN or, preferably, a
    /// 0400 file named by GOBLINPAY_TOKEN_FILE.
    pub goblinpay_token: String,
    /// Optional GoblinPay webhook secret. When set, POST
    /// /api/v1/goblinpay/webhook verifies the HMAC and refreshes the matching
    /// grant immediately instead of waiting for the next poll.
    pub goblinpay_webhook_secret: Option<String>,
    /// Minimum interval between GoblinPay status polls per grant.
    pub paid_poll_interval: Duration,
}

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Ok(v) => v.parse().unwrap_or(default),
        Err(_) => default,
    }
}

/// Parse a decimal GRIN amount ("1", "0.5", "2.25") into nanogrin. Rejects
/// negatives, more than 9 fractional digits, and garbage.
pub fn grin_to_nanogrin(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let bad = || format!("invalid GRIN amount `{s}`");
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(bad());
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(bad());
    }
    if frac.len() > 9 {
        return Err(format!("`{s}` has more than 9 decimal places"));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| bad())?
    };
    let mut frac_n: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse().map_err(|_| bad())?
    };
    frac_n *= 10u64.pow(9 - frac.len() as u32);
    whole
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(frac_n))
        .ok_or_else(bad)
}

/// Format nanogrin as a trimmed decimal GRIN string.
pub fn nanogrin_to_grin(nano: u64) -> String {
    let whole = nano / 1_000_000_000;
    let frac = nano % 1_000_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        let frac = format!("{frac:09}");
        format!("{whole}.{}", frac.trim_end_matches('0'))
    }
}

impl Config {
    /// Load from the environment and validate. Returns an error string on
    /// misconfiguration (caller should fail fast).
    pub fn from_env() -> Result<Self, String> {
        let domain = env_string("FLOONET_DOMAIN", "floonet.example");
        let base_url = env_string("FLOONET_BASE_URL", "https://floonet.example");
        let relays = env_string("FLOONET_RELAYS", "wss://floonet.example")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let bind_addr = env_string("FLOONET_NAMES_BIND", "127.0.0.1:8191");
        let db_path = env_string("FLOONET_NAMES_DB", "/var/lib/floonet-authority/names.db");

        let name_change_cooldown =
            Duration::from_secs(env_parse("FLOONET_NAME_CHANGE_COOLDOWN_SECS", 600u64));
        let auth_max_age_secs = env_parse("FLOONET_AUTH_MAX_AGE_SECS", 60i64);
        let name_min = env_parse("FLOONET_NAME_MIN", 3usize);
        let name_max = env_parse("FLOONET_NAME_MAX", 20usize);

        let read_rate_max = env_parse("FLOONET_READ_RATE_MAX", 120usize);
        let read_rate_window =
            Duration::from_secs(env_parse("FLOONET_READ_RATE_WINDOW_SECS", 60u64));
        let write_rate_max = env_parse("FLOONET_WRITE_RATE_MAX", 10usize);
        let write_rate_window =
            Duration::from_secs(env_parse("FLOONET_WRITE_RATE_WINDOW_SECS", 3600u64));

        // Reserve the operator's own domain labels (e.g. `floonet` for
        // `floonet.example`) so the brand the domain stands for can't be
        // claimed or look-alike-folded into. Then layer on any names from
        // the optional reserved file.
        let mut extra_reserved = crate::names::domain_reserved(&domain);
        if let Ok(path) = std::env::var("FLOONET_RESERVED_FILE") {
            if !path.is_empty() {
                extra_reserved.extend(load_reserved_file(&path)?);
            }
        }

        let pay_mode = PayMode::parse(&env_string("FLOONET_PAY_MODE", "off"))?;
        let name_price_nanogrin = grin_to_nanogrin(&env_string("FLOONET_NAME_PRICE_GRIN", "0"))?;
        let write_price_nanogrin = grin_to_nanogrin(&env_string("FLOONET_WRITE_PRICE_GRIN", "0"))?;
        let goblinpay_url = env_string("GOBLINPAY_URL", "")
            .trim_end_matches('/')
            .to_string();
        let goblinpay_token = match std::env::var("GOBLINPAY_TOKEN_FILE") {
            Ok(path) if !path.is_empty() => std::fs::read_to_string(&path)
                .map_err(|e| format!("GOBLINPAY_TOKEN_FILE `{path}` unreadable: {e}"))?
                .trim()
                .to_string(),
            _ => env_string("GOBLINPAY_TOKEN", ""),
        };
        let goblinpay_webhook_secret =
            std::env::var("GOBLINPAY_WEBHOOK_SECRET").ok().filter(|s| !s.is_empty());
        let paid_poll_interval =
            Duration::from_secs(env_parse("FLOONET_PAID_POLL_INTERVAL_SECS", 5u64));

        let cfg = Config {
            domain,
            base_url,
            relays,
            bind_addr,
            db_path,
            name_change_cooldown,
            auth_max_age_secs,
            name_min,
            name_max,
            read_rate_max,
            read_rate_window,
            write_rate_max,
            write_rate_window,
            extra_reserved,
            pay_mode,
            name_price_nanogrin,
            write_price_nanogrin,
            goblinpay_url,
            goblinpay_token,
            goblinpay_webhook_secret,
            paid_poll_interval,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Fail-fast consistency checks. A wrong BASE_URL silently breaks every
    /// authenticated call (the `u`-tag never matches), so we refuse to start;
    /// likewise a paid mode without a working GoblinPay wiring or price.
    pub fn validate(&self) -> Result<(), String> {
        if self.domain.is_empty() {
            return Err("FLOONET_DOMAIN must not be empty".into());
        }
        let host = self.base_url.strip_prefix("https://").ok_or_else(|| {
            format!(
                "FLOONET_BASE_URL must start with https:// (got `{}`)",
                self.base_url
            )
        })?;
        if host.is_empty() {
            return Err("FLOONET_BASE_URL has no host".into());
        }
        // The host part of BASE_URL must match DOMAIN (allowing an explicit
        // port), otherwise the `@domain` names and the auth URL disagree.
        let host_no_port = host.split('/').next().unwrap_or(host);
        let host_bare = host_no_port.split(':').next().unwrap_or(host_no_port);
        if host_bare != self.domain {
            return Err(format!(
                "FLOONET_BASE_URL host `{host_bare}` does not match FLOONET_DOMAIN `{}`",
                self.domain
            ));
        }
        if self.name_min == 0 || self.name_min > self.name_max {
            return Err(format!(
                "invalid name length bounds: min={} max={}",
                self.name_min, self.name_max
            ));
        }
        if self.pay_mode != PayMode::Off {
            if self.goblinpay_url.is_empty() {
                return Err("FLOONET_PAY_MODE is on but GOBLINPAY_URL is not set".into());
            }
            if self.goblinpay_token.is_empty() {
                return Err(
                    "FLOONET_PAY_MODE is on but no GoblinPay token is set \
                     (GOBLINPAY_TOKEN or GOBLINPAY_TOKEN_FILE)"
                        .into(),
                );
            }
        }
        if self.pay_mode == PayMode::Name && self.name_price_nanogrin == 0 {
            return Err("FLOONET_PAY_MODE=name needs FLOONET_NAME_PRICE_GRIN > 0".into());
        }
        if self.pay_mode == PayMode::Write && self.write_price_nanogrin == 0 {
            return Err("FLOONET_PAY_MODE=write needs FLOONET_WRITE_PRICE_GRIN > 0".into());
        }
        Ok(())
    }

    /// One-line summary for the startup log. The GoblinPay token is a secret
    /// and never logged.
    pub fn summary(&self) -> String {
        format!(
            "domain={} base_url={} relays={:?} bind={} db={} \
             name_len={}..={} cooldown={}s auth_max_age={}s \
             read={}req/{}s write={}req/{}s reserved_extra={} \
             pay_mode={:?} name_price={}g write_price={}g goblinpay={}",
            self.domain,
            self.base_url,
            self.relays,
            self.bind_addr,
            self.db_path,
            self.name_min,
            self.name_max,
            self.name_change_cooldown.as_secs(),
            self.auth_max_age_secs,
            self.read_rate_max,
            self.read_rate_window.as_secs(),
            self.write_rate_max,
            self.write_rate_window.as_secs(),
            self.extra_reserved.len(),
            self.pay_mode,
            nanogrin_to_grin(self.name_price_nanogrin),
            nanogrin_to_grin(self.write_price_nanogrin),
            if self.goblinpay_url.is_empty() {
                "unset"
            } else {
                &self.goblinpay_url
            },
        )
    }
}

/// Read an optional reserved-names file: one lowercase name per line, blank
/// lines and `#` comments ignored. Missing file is a hard error (the operator
/// asked for it via env), but the names themselves are not validated here.
fn load_reserved_file(path: &str) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("FLOONET_RESERVED_FILE `{path}` unreadable: {e}"))?;
    Ok(text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect())
}

impl Config {
    /// A minimal config for tests/integration, pointing at in-memory state.
    /// Kept out of the public docs but available to integration tests (which
    /// compile as a separate crate and so can't see `#[cfg(test)]` items).
    #[doc(hidden)]
    pub fn for_test() -> Self {
        Config {
            domain: "floonet.example".into(),
            base_url: "https://floonet.example".into(),
            relays: vec!["wss://floonet.example".into()],
            bind_addr: "127.0.0.1:0".into(),
            db_path: ":memory:".into(),
            name_change_cooldown: Duration::from_secs(600),
            auth_max_age_secs: 60,
            name_min: 3,
            name_max: 20,
            read_rate_max: 100_000,
            read_rate_window: Duration::from_secs(60),
            write_rate_max: 100_000,
            write_rate_window: Duration::from_secs(3600),
            // Mirror from_env: the domain's own label is reserved.
            extra_reserved: crate::names::domain_reserved("floonet.example"),
            pay_mode: PayMode::Off,
            name_price_nanogrin: 0,
            write_price_nanogrin: 0,
            goblinpay_url: String::new(),
            goblinpay_token: String::new(),
            goblinpay_webhook_secret: None,
            paid_poll_interval: Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        Config::for_test()
    }

    #[test]
    fn rejects_non_https_base_url() {
        let mut c = base();
        c.base_url = "http://floonet.example".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_base_url_domain_mismatch() {
        let mut c = base();
        c.base_url = "https://example.com".into();
        assert!(c.validate().is_err());
    }

    #[test]
    fn accepts_matching_base_url_with_port() {
        let mut c = base();
        c.domain = "names.example".into();
        c.base_url = "https://names.example:8443".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_bad_name_bounds() {
        let mut c = base();
        c.name_min = 10;
        c.name_max = 5;
        assert!(c.validate().is_err());
    }

    #[test]
    fn paid_mode_requires_goblinpay_and_price() {
        let mut c = base();
        c.pay_mode = PayMode::Name;
        assert!(c.validate().is_err()); // no url
        c.goblinpay_url = "https://pay.example".into();
        assert!(c.validate().is_err()); // no token
        c.goblinpay_token = "tok".into();
        assert!(c.validate().is_err()); // no price
        c.name_price_nanogrin = grin_to_nanogrin("1.5").unwrap();
        assert!(c.validate().is_ok());

        let mut w = base();
        w.pay_mode = PayMode::Write;
        w.goblinpay_url = "https://pay.example".into();
        w.goblinpay_token = "tok".into();
        assert!(w.validate().is_err()); // no write price
        w.write_price_nanogrin = 1;
        assert!(w.validate().is_ok());
    }

    #[test]
    fn grin_amount_parsing() {
        assert_eq!(grin_to_nanogrin("1").unwrap(), 1_000_000_000);
        assert_eq!(grin_to_nanogrin("0.5").unwrap(), 500_000_000);
        assert_eq!(grin_to_nanogrin("2.25").unwrap(), 2_250_000_000);
        assert_eq!(grin_to_nanogrin("0.000000001").unwrap(), 1);
        assert_eq!(grin_to_nanogrin("0").unwrap(), 0);
        assert!(grin_to_nanogrin("").is_err());
        assert!(grin_to_nanogrin(".").is_err());
        assert!(grin_to_nanogrin("-1").is_err());
        assert!(grin_to_nanogrin("1.0000000001").is_err());
        assert!(grin_to_nanogrin("1,5").is_err());
        assert_eq!(nanogrin_to_grin(1_500_000_000), "1.5");
        assert_eq!(nanogrin_to_grin(2_000_000_000), "2");
    }
}
