// First-run interactive setup wizard, a complement to the env-var config.
//
// The authority is normally configured entirely through FLOONET_* environment
// variables (see config.rs and .env.example): docker compose injects them and
// the systemd unit loads them from an EnvironmentFile, so those deploys are
// fully headless and this module never runs. But an operator who just runs the
// binary by hand, with nothing configured, would otherwise start on the
// `floonet.example` placeholders. For that case only, when stdin/stdout is an
// interactive terminal, we prompt for the handful of essentials, write a
// conventional env file, load it, and continue starting up.
//
// The rules, in order:
//   * FLOONET_DOMAIN already set (real deploy)  -> no wizard, headless as today.
//   * nothing set AND an interactive TTY        -> guided wizard.
//   * nothing set AND no TTY                     -> no wizard, headless as today.
//
// The env file we write is the same file the service convention consumes: the
// path in FLOONET_ENV_FILE if set, else /etc/floonet-authority.env when we can
// write it (the systemd EnvironmentFile default), else ./.env in the working
// directory (the docker-compose default). On the next run load_first_existing()
// finds it, sets FLOONET_DOMAIN, and the wizard stays out of the way.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

/// The bare-metal / systemd convention: deploy/systemd/floonet-authority.service
/// loads this exact file via `EnvironmentFile=`.
pub const DEFAULT_ENV_FILE: &str = "/etc/floonet-authority.env";

/// Env files we will load on startup, in priority order. The first one that
/// exists wins. This spans both deployment conventions (the systemd
/// `/etc` file and the docker-compose `./.env`) plus an explicit override.
pub fn env_file_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("FLOONET_ENV_FILE") {
        if !p.is_empty() {
            out.push(PathBuf::from(p));
        }
    }
    out.push(PathBuf::from(DEFAULT_ENV_FILE));
    out.push(PathBuf::from(".env"));
    out
}

/// Load the first existing candidate env file into the process environment
/// (non-overriding). Returns the path loaded, if any. Under systemd/docker the
/// real environment is already populated, so this is a harmless no-op there.
pub fn load_first_existing() -> Option<PathBuf> {
    for path in env_file_candidates() {
        if path.is_file() {
            // A parse/read hiccup on an optional file must not stop startup;
            // config validation still runs afterwards.
            let _ = load_env_file(&path);
            return Some(path);
        }
    }
    None
}

/// Is the authority already configured? True when the one variable every real
/// deployment sets, FLOONET_DOMAIN, is present in the environment. Call this
/// after load_first_existing() so a previously written env file counts.
pub fn config_present() -> bool {
    std::env::var("FLOONET_DOMAIN").map(|v| !v.is_empty()).unwrap_or(false)
}

/// Are we attached to an interactive terminal on both stdin and stdout?
pub fn is_interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

/// The single decision: run the wizard only when nothing is configured AND we
/// are interactive. Pulled out as a pure function so the headless guarantee
/// (config present => never a wizard, regardless of TTY) is directly testable.
pub fn decide_wizard(config_present: bool, interactive: bool) -> bool {
    !config_present && interactive
}

/// Where the wizard writes its env file. Honors FLOONET_ENV_FILE, else the
/// systemd `/etc` convention when that directory is writable (a root install),
/// else `./.env` in the working directory (the docker-compose convention).
pub fn wizard_target() -> PathBuf {
    if let Ok(p) = std::env::var("FLOONET_ENV_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let etc = PathBuf::from(DEFAULT_ENV_FILE);
    match etc.parent() {
        Some(dir) if dir_writable(dir) => etc,
        _ => PathBuf::from(".env"),
    }
}

/// Probe whether we can create files in `dir` by writing and removing a temp
/// file. Cheap and reliable across the root/unprivileged split, no extra deps.
fn dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".floonet-setup-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Parse env-file text into ordered key/value pairs. Blank lines and `#`
/// comments are skipped, a leading `export ` is tolerated, and a single layer
/// of matching single or double quotes around the value is stripped. Pure (no
/// environment side effects) so it can be unit tested directly.
pub fn parse_env_file(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = unquote(value.trim());
        out.push((key.to_string(), value));
    }
    out
}

fn unquote(v: &str) -> String {
    let bytes = v.as_bytes();
    if v.len() >= 2
        && ((bytes[0] == b'"' && bytes[v.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[v.len() - 1] == b'\''))
    {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// Load an env file into the process environment WITHOUT overriding variables
/// already set. Returns how many variables it set. Non-overriding is what keeps
/// this safe alongside systemd/docker: the real environment always wins.
pub fn load_env_file(path: &Path) -> io::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let mut set = 0;
    for (key, value) in parse_env_file(&text) {
        if std::env::var(&key).is_err() {
            std::env::set_var(&key, &value);
            set += 1;
        }
    }
    Ok(set)
}

/// The answers the wizard collects. Kept separate from rendering so the render
/// step is a pure, testable function.
#[derive(Debug, Clone)]
pub struct Answers {
    pub domain: String,
    pub bind_addr: String,
    pub data_dir: String,
    pub pay_mode: String,
    pub price_grin: String,
    pub goblinpay_url: String,
    pub goblinpay_token: String,
    pub transfers: bool,
    pub grin_node_url: String,
}

/// Render the answers into env-file text. Only emits the keys the answers touch,
/// mirroring .env.example wording. base_url and relays are DERIVED from the
/// domain so they always satisfy Config::validate() (base_url host must equal
/// the domain), which is why the wizard does not prompt for them separately.
pub fn render_env(a: &Answers) -> String {
    let mut s = String::new();
    s.push_str("# Generated by the floonet-name-authority first-run setup wizard.\n");
    s.push_str("# Edit freely; every key maps to a FLOONET_* variable (see .env.example).\n\n");
    s.push_str(&format!("FLOONET_DOMAIN={}\n", a.domain));
    s.push_str(&format!("FLOONET_BASE_URL=https://{}\n", a.domain));
    s.push_str(&format!("FLOONET_RELAYS=wss://{}\n", a.domain));
    s.push_str(&format!("FLOONET_NAMES_BIND={}\n", a.bind_addr));
    s.push_str(&format!(
        "FLOONET_NAMES_DB={}\n",
        db_path_in(&a.data_dir)
    ));
    s.push_str(&format!("FLOONET_PAY_MODE={}\n", a.pay_mode));
    match a.pay_mode.as_str() {
        "name" => s.push_str(&format!("FLOONET_NAME_PRICE_GRIN={}\n", a.price_grin)),
        "write" => s.push_str(&format!("FLOONET_WRITE_PRICE_GRIN={}\n", a.price_grin)),
        _ => {}
    }
    if a.pay_mode != "off" {
        s.push_str(&format!("GOBLINPAY_URL={}\n", a.goblinpay_url));
        s.push_str(&format!("GOBLINPAY_TOKEN={}\n", a.goblinpay_token));
    }
    if a.transfers {
        s.push_str("FLOONET_TRANSFERS=true\n");
        s.push_str(&format!("FLOONET_GRIN_NODE_URL={}\n", a.grin_node_url));
    }
    s
}

/// Join a data directory with the fixed `names.db` filename.
pub fn db_path_in(dir: &str) -> String {
    Path::new(dir).join("names.db").to_string_lossy().into_owned()
}

/// Drive the interactive prompts over the given reader/writer, returning the
/// collected answers. Generic over the streams so tests can feed canned input.
pub fn collect_answers<R: BufRead, W: Write>(
    r: &mut R,
    w: &mut W,
) -> io::Result<Answers> {
    writeln!(w, "\nFloonet name authority: first-run setup")?;
    writeln!(w, "No configuration found. A few questions and we are running.")?;
    writeln!(w, "Press Enter to accept each [default].\n")?;

    let domain = prompt(r, w, "Domain for names (the @domain in name@domain)", "floonet.example")?;
    let bind_addr = prompt(r, w, "HTTP bind address", "127.0.0.1:8191")?;
    let data_dir = prompt(r, w, "Data directory (SQLite database lives here)", "/var/lib/floonet-authority")?;

    writeln!(w, "\nCharging GRIN is optional; leave as `off` for a free authority.")?;
    let pay_mode = prompt_choice(r, w, "Pay mode (off/name/write)", "off", &["off", "name", "write"])?;

    let (mut price_grin, mut goblinpay_url, mut goblinpay_token) =
        (String::new(), String::new(), String::new());
    if pay_mode != "off" {
        let price_q = if pay_mode == "name" {
            "Price to claim a name, in GRIN"
        } else {
            "Price for write access, in GRIN"
        };
        // A paid mode with a zero price fails validation, so default to 1.
        price_grin = prompt(r, w, price_q, "1")?;
        goblinpay_url = prompt(r, w, "GoblinPay server URL", "http://127.0.0.1:8192")?;
        goblinpay_token = prompt(r, w, "GoblinPay API token", "")?;
    }

    writeln!(w, "\nName transfers are the optional non-custodial name marketplace.")?;
    let transfers = prompt_yes_no(r, w, "Enable name transfers?", false)?;
    let mut grin_node_url = String::new();
    if transfers {
        // Required when transfers are on, or the authority refuses to start.
        grin_node_url = prompt(r, w, "Grin node foreign-API URL", "https://api.grin.money/v2/foreign")?;
    }

    Ok(Answers {
        domain,
        bind_addr,
        data_dir,
        pay_mode,
        price_grin,
        goblinpay_url,
        goblinpay_token,
        transfers,
        grin_node_url,
    })
}

/// Collect answers over the streams, render, and write to `target`. Returns the
/// path written. Split from the process-env plumbing so it is fully testable.
pub fn run_wizard<R: BufRead, W: Write>(
    r: &mut R,
    w: &mut W,
    target: &Path,
) -> io::Result<PathBuf> {
    let answers = collect_answers(r, w)?;
    let body = render_env(&answers);
    if let Some(dir) = target.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    std::fs::write(target, body)?;
    writeln!(w, "\nWrote {}. Starting up...\n", target.display())?;
    Ok(target.to_path_buf())
}

/// Convenience entry point for main: pick the conventional target, run the
/// wizard over the real stdin/stdout, and return the file written.
pub fn run_first_run_wizard() -> io::Result<PathBuf> {
    let target = wizard_target();
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    run_wizard(&mut reader, &mut writer, &target)
}

fn prompt<R: BufRead, W: Write>(
    r: &mut R,
    w: &mut W,
    question: &str,
    default: &str,
) -> io::Result<String> {
    if default.is_empty() {
        write!(w, "{question}: ")?;
    } else {
        write!(w, "{question} [{default}]: ")?;
    }
    w.flush()?;
    let mut line = String::new();
    // EOF (0 bytes) falls back to the default rather than looping forever.
    if r.read_line(&mut line)? == 0 {
        return Ok(default.to_string());
    }
    let trimmed = line.trim();
    Ok(if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    })
}

fn prompt_choice<R: BufRead, W: Write>(
    r: &mut R,
    w: &mut W,
    question: &str,
    default: &str,
    choices: &[&str],
) -> io::Result<String> {
    // Re-ask a bounded number of times on an unrecognized answer, then accept
    // the default so a piped/misused stream can never wedge startup.
    for _ in 0..5 {
        let answer = prompt(r, w, question, default)?;
        let lower = answer.to_lowercase();
        if choices.contains(&lower.as_str()) {
            return Ok(lower);
        }
        writeln!(w, "  Please answer one of: {}", choices.join(", "))?;
    }
    Ok(default.to_string())
}

fn prompt_yes_no<R: BufRead, W: Write>(
    r: &mut R,
    w: &mut W,
    question: &str,
    default: bool,
) -> io::Result<bool> {
    let shown = if default { "Y/n" } else { "y/N" };
    let answer = prompt(r, w, question, shown)?;
    Ok(match answer.trim().to_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        // Anything else (including the echoed default token) keeps the default.
        _ => default,
    })
}
