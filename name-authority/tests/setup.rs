// Tests for the first-run setup wizard (src/setup.rs). The wizard is a
// COMPLEMENT to the env-var config: it must never fire for a configured
// (headless) deploy, and when it does fire it must write an env file whose
// values satisfy Config::validate(). These tests avoid mutating the shared
// process environment except through uniquely named keys, so they are safe to
// run in parallel with the rest of the suite.

use std::io::Cursor;
use std::path::PathBuf;

use floonet_name_authority::setup::{
    self, collect_answers, db_path_in, load_env_file, parse_env_file, render_env, run_wizard,
    Answers,
};

/// The headless guarantee: whenever configuration is present, the wizard is
/// never chosen, regardless of whether we are on a TTY. This is the core
/// "config-present means the wizard never triggers" test.
#[test]
fn config_present_never_runs_wizard() {
    assert!(!setup::decide_wizard(true, true), "present + tty must skip wizard");
    assert!(!setup::decide_wizard(true, false), "present + no tty must skip wizard");
}

/// The only case that runs the wizard: nothing configured AND an interactive
/// terminal. A non-TTY with no config stays headless (today's behavior).
#[test]
fn wizard_only_when_absent_and_interactive() {
    assert!(setup::decide_wizard(false, true), "absent + tty runs wizard");
    assert!(!setup::decide_wizard(false, false), "absent + no tty stays headless");
}

#[test]
fn parse_env_file_handles_comments_quotes_and_export() {
    let text = "\
# a comment
FLOONET_DOMAIN=names.example

  export FLOONET_BASE_URL=https://names.example
QUOTED=\"a value\"
SINGLE='b value'
# trailing comment
BLANKVAL=
=nokey
";
    let pairs = parse_env_file(text);
    assert_eq!(
        pairs,
        vec![
            ("FLOONET_DOMAIN".to_string(), "names.example".to_string()),
            ("FLOONET_BASE_URL".to_string(), "https://names.example".to_string()),
            ("QUOTED".to_string(), "a value".to_string()),
            ("SINGLE".to_string(), "b value".to_string()),
            ("BLANKVAL".to_string(), "".to_string()),
        ]
    );
}

#[test]
fn render_env_derives_base_url_and_relays_from_domain() {
    let a = Answers {
        domain: "names.example".into(),
        bind_addr: "127.0.0.1:8191".into(),
        data_dir: "/var/lib/floonet-authority".into(),
        pay_mode: "off".into(),
        price_grin: String::new(),
        goblinpay_url: String::new(),
        goblinpay_token: String::new(),
        transfers: false,
        grin_node_url: String::new(),
    };
    let body = render_env(&a);
    // base_url and relays are derived so the validate() host==domain invariant
    // always holds; off-mode emits no price or goblinpay keys.
    assert!(body.contains("FLOONET_DOMAIN=names.example\n"));
    assert!(body.contains("FLOONET_BASE_URL=https://names.example\n"));
    assert!(body.contains("FLOONET_RELAYS=wss://names.example\n"));
    assert!(body.contains("FLOONET_NAMES_DB=/var/lib/floonet-authority/names.db\n"));
    assert!(body.contains("FLOONET_PAY_MODE=off\n"));
    assert!(!body.contains("GOBLINPAY_URL"));
    assert!(!body.contains("FLOONET_TRANSFERS"));
}

#[test]
fn render_env_paid_name_and_transfers() {
    let a = Answers {
        domain: "names.example".into(),
        bind_addr: "127.0.0.1:8191".into(),
        data_dir: "/data".into(),
        pay_mode: "name".into(),
        price_grin: "1".into(),
        goblinpay_url: "http://127.0.0.1:8192".into(),
        goblinpay_token: "tok".into(),
        transfers: true,
        grin_node_url: "https://api.grin.money/v2/foreign".into(),
    };
    let body = render_env(&a);
    assert!(body.contains("FLOONET_PAY_MODE=name\n"));
    assert!(body.contains("FLOONET_NAME_PRICE_GRIN=1\n"));
    assert!(body.contains("GOBLINPAY_URL=http://127.0.0.1:8192\n"));
    assert!(body.contains("GOBLINPAY_TOKEN=tok\n"));
    assert!(body.contains("FLOONET_TRANSFERS=true\n"));
    assert!(body.contains("FLOONET_GRIN_NODE_URL=https://api.grin.money/v2/foreign\n"));
    // write-only key must not leak into a name-mode file.
    assert!(!body.contains("FLOONET_WRITE_PRICE_GRIN"));
}

#[test]
fn db_path_joins_names_db() {
    assert_eq!(db_path_in("/var/lib/floonet-authority"), "/var/lib/floonet-authority/names.db");
}

/// Drive the interactive prompts with canned input over in-memory streams and
/// confirm the collected answers reflect the mix of typed values and defaults.
#[test]
fn collect_answers_uses_input_then_defaults() {
    // domain typed; bind + data-dir Enter (defaults); pay mode off; transfers no.
    let input = b"names.example\n\n\noff\nn\n";
    let mut reader = Cursor::new(&input[..]);
    let mut out: Vec<u8> = Vec::new();
    let a = collect_answers(&mut reader, &mut out).expect("wizard prompts");
    assert_eq!(a.domain, "names.example");
    assert_eq!(a.bind_addr, "127.0.0.1:8191");
    assert_eq!(a.data_dir, "/var/lib/floonet-authority");
    assert_eq!(a.pay_mode, "off");
    assert!(!a.transfers);
}

/// End to end over the file: run the wizard with canned input into a temp path,
/// then parse it back and confirm it is a config-present file (FLOONET_DOMAIN
/// set) with the derived, validate()-satisfying base_url/relays.
#[test]
fn run_wizard_writes_loadable_env_file() {
    let input = b"names.example\n0.0.0.0:9000\n/tmp/floonet-data\noff\nn\n";
    let mut reader = Cursor::new(&input[..]);
    let mut out: Vec<u8> = Vec::new();

    let target: PathBuf =
        std::env::temp_dir().join(format!("floonet-setup-test-{}.env", std::process::id()));
    let written = run_wizard(&mut reader, &mut out, &target).expect("write env file");
    assert_eq!(written, target);

    let text = std::fs::read_to_string(&target).expect("read back");
    let pairs = parse_env_file(&text);
    let get = |k: &str| pairs.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());

    assert_eq!(get("FLOONET_DOMAIN").as_deref(), Some("names.example"));
    assert_eq!(get("FLOONET_BASE_URL").as_deref(), Some("https://names.example"));
    assert_eq!(get("FLOONET_RELAYS").as_deref(), Some("wss://names.example"));
    assert_eq!(get("FLOONET_NAMES_BIND").as_deref(), Some("0.0.0.0:9000"));
    assert_eq!(get("FLOONET_NAMES_DB").as_deref(), Some("/tmp/floonet-data/names.db"));

    let _ = std::fs::remove_file(&target);
}

/// load_env_file is non-overriding: it fills variables that are unset but never
/// clobbers an already-set one (this is what keeps it safe next to the real
/// systemd/docker environment). Uses uniquely named keys to avoid touching
/// FLOONET_* and racing other tests.
#[test]
fn load_env_file_is_non_overriding() {
    let pid = std::process::id();
    let unset_key = format!("FLOONET_SETUP_TEST_UNSET_{pid}");
    let preset_key = format!("FLOONET_SETUP_TEST_PRESET_{pid}");

    std::env::set_var(&preset_key, "original");

    let target = std::env::temp_dir().join(format!("floonet-load-test-{pid}.env"));
    std::fs::write(
        &target,
        format!("{unset_key}=from_file\n{preset_key}=from_file\n"),
    )
    .expect("write");

    let set = load_env_file(&target).expect("load");
    assert_eq!(set, 1, "only the previously unset var should be set");
    assert_eq!(std::env::var(&unset_key).unwrap(), "from_file");
    assert_eq!(std::env::var(&preset_key).unwrap(), "original", "preset must not be overridden");

    let _ = std::fs::remove_file(&target);
    std::env::remove_var(&unset_key);
    std::env::remove_var(&preset_key);
}
