// Name and pubkey rules: validity, the reserved list, and look-alike folding
// that stops digit/separator homographs of reserved terms.

/// Built-in reserved names. These are generic infrastructure, role and
/// finance terms that no operator should hand out as a payment identity —
/// they are domain-agnostic on purpose. The operator's own brand is reserved
/// separately and dynamically from their domain (see
/// [`domain_reserved`]); operators can add more via a reserved file
/// (see [`crate::config::Config::extra_reserved`]).
pub const RESERVED: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "support",
    "help",
    "info",
    "mail",
    "email",
    "www",
    "relay",
    "nostr",
    "pay",
    "payment",
    "payments",
    "wallet",
    "official",
    "security",
    "abuse",
    "postmaster",
    "hostmaster",
    "webmaster",
    "contact",
    "team",
    "staff",
    "mod",
    "moderator",
    "moderators",
    "system",
    "bot",
    "api",
    "app",
    "dev",
    "developer",
    "test",
    "testing",
    "anonymous",
    "anon",
    "null",
    "void",
    "owner",
    "ceo",
    "register",
    "registration",
    "account",
    "accounts",
    "verify",
    "verified",
    "billing",
    "donate",
    "treasury",
    "faucet",
    "exchange",
    "swap",
    "bank",
    "money",
    "cash",
    "fees",
    "fee",
    "node",
    "miner",
    "mining",
    "explorer",
    "status",
    "blog",
    "news",
    "docs",
    "wiki",
    "store",
    "shop",
];

/// True when `name` satisfies the length bounds and character rules: ASCII
/// lowercase alphanumerics plus `. _ -`, starting and ending alphanumeric.
pub fn valid_name(name: &str, name_min: usize, name_max: usize) -> bool {
    let len = name.chars().count();
    if !(name_min..=name_max).contains(&len) {
        return false;
    }
    let bytes = name.as_bytes();
    let ok_char =
        |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-');
    if !bytes.iter().all(|&c| ok_char(c)) {
        return false;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    (first.is_ascii_lowercase() || first.is_ascii_digit())
        && (last.is_ascii_lowercase() || last.is_ascii_digit())
}

/// Fold a name to catch separator/digit look-alikes of reserved terms, so
/// `g0blin`, `g-o-b-l-i-n` and `supp0rt` can't impersonate `goblin`/`support`
/// as payment identities. Conservative: a name is only blocked when its folded
/// form exactly equals a reserved term's folded form (so `goblinfan` stays free).
pub fn fold_lookalike(name: &str) -> String {
    name.chars()
        .filter_map(|c| match c {
            '.' | '_' | '-' => None,
            '0' => Some('o'),
            '1' => Some('i'),
            '3' => Some('e'),
            '4' => Some('a'),
            '5' => Some('s'),
            '7' => Some('t'),
            '8' => Some('b'),
            '9' => Some('g'),
            c => Some(c),
        })
        .collect()
}

/// True when `name` is reserved outright or folds onto a reserved term. The
/// `extra` slice holds the operator's domain labels and any names from the
/// optional reserved file (see [`crate::config::Config::extra_reserved`]).
pub fn is_reserved(name: &str, extra: &[String]) -> bool {
    if RESERVED.contains(&name) || extra.iter().any(|r| r == name) {
        return true;
    }
    let folded = fold_lookalike(name);
    RESERVED.iter().any(|r| fold_lookalike(r) == folded)
        || extra.iter().any(|r| fold_lookalike(r) == folded)
}

/// Reserved names derived from the operator's own domain, so a domain's brand
/// can't be claimed (or look-alike-folded) as a payment handle. Each dot label
/// except the final TLD is reserved: `goblin.st` → `["goblin"]`,
/// `names.acme.example` → `["names", "acme"]`. A single-label host (e.g.
/// `localhost`) reserves that label. Lowercased; empty labels dropped.
pub fn domain_reserved(domain: &str) -> Vec<String> {
    let labels: Vec<&str> = domain
        .trim()
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .collect();
    let keep = if labels.len() > 1 {
        &labels[..labels.len() - 1]
    } else {
        &labels[..]
    };
    keep.iter().map(|l| l.to_lowercase()).collect()
}

pub fn valid_pubkey_hex(pk: &str) -> bool {
    pk.len() == 64
        && pk
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: usize = 3;
    const MAX: usize = 20;

    #[test]
    fn name_validation() {
        assert!(valid_name("ada", MIN, MAX));
        assert!(valid_name("ada.wren-99_x", MIN, MAX));
        assert!(!valid_name("ab", MIN, MAX));
        assert!(!valid_name("Ada", MIN, MAX));
        assert!(!valid_name(".ada", MIN, MAX));
        assert!(!valid_name("ada.", MIN, MAX));
        assert!(!valid_name("a d a", MIN, MAX));
        assert!(!valid_name(&"a".repeat(21), MIN, MAX));
        assert!(valid_name(&"a".repeat(20), MIN, MAX));
        assert!(!valid_name("päge", MIN, MAX));
    }

    #[test]
    fn reserved_and_lookalikes() {
        // Generic infra/role terms are reserved out of the box, with folding.
        assert!(is_reserved("support", &[]));
        assert!(is_reserved("supp0rt", &[]));
        assert!(is_reserved("adm1n", &[]));
        // Brand terms are NOT built in — they come from the domain labels.
        assert!(!is_reserved("goblin", &[]));
        // Operator/domain-supplied extras work both literally and folded.
        assert!(is_reserved("acme", &["acme".to_string()]));
        assert!(is_reserved("acm3", &["acme".to_string()]));
        assert!(!is_reserved("acmecorp", &["acme".to_string()]));
    }

    #[test]
    fn domain_labels_reserved() {
        assert_eq!(domain_reserved("goblin.st"), vec!["goblin"]);
        assert_eq!(domain_reserved("acme.example"), vec!["acme"]);
        assert_eq!(domain_reserved("names.acme.example"), vec!["names", "acme"]);
        assert_eq!(domain_reserved("GOBLIN.ST"), vec!["goblin"]);
        assert_eq!(domain_reserved("localhost"), vec!["localhost"]);
        // The brand and its look-alikes fall to is_reserved via these labels.
        let extra = domain_reserved("goblin.st");
        assert!(is_reserved("goblin", &extra));
        assert!(is_reserved("g0blin", &extra));
        assert!(is_reserved("g-o-b-l-i-n", &extra));
        assert!(!is_reserved("goblinfan", &extra));
    }

    #[test]
    fn pubkey_validation() {
        assert!(valid_pubkey_hex(
            "91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05"
        ));
        assert!(!valid_pubkey_hex(
            "91CF9DBBEA5E6511FD2BBB190B112055EE4131C5D2BBB9FAEDF3EE8CBEAC0D05"
        ));
        assert!(!valid_pubkey_hex("abc"));
    }
}
