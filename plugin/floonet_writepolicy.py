#!/usr/bin/env python3
"""floonet-strfry write policy: the modular event-admission plugin.

strfry streams one JSON request per line on stdin and expects one JSON reply
per line on stdout (see strfry docs/plugins.md). This plugin is the policy
layer of a Floonet relay: strfry core stays stock, and every admission rule
lives here as a small check function.

Checks run in order; the first rejection wins. All checks fail closed: any
malformed input, unexpected error, or unreachable dependency rejects the
event rather than letting it through.

    1. kind whitelist   default-deny; only FLOONET_ALLOWED_KINDS pass
    1b. public-note lock kinds 1 and 30023 (text notes, long-form articles)
                        are accepted only from FLOONET_AUTHORIZED_AUTHORS;
                        closed by default (no authors = these kinds rejected
                        for everyone). Every other kind is unaffected.
    1c. gift wrap retention/shape (kind 1059 only) rejects a NIP-40
                        `expiration` tag, so strfry's ~9s reaper can never
                        early-delete a payment gift wrap, and requires
                        exactly one well-formed `p` tag (32-byte hex
                        recipient) so a malformed gift wrap cannot slip
                        through. Every other kind is unaffected.
    2. auth requirement optional; with FLOONET_REQUIRE_AUTH=true an event is
                        rejected unless the connection completed NIP-42 AUTH
                        (also enable relay.auth in strfry.conf)
    3. paid write gate  optional; with FLOONET_PAY_MODE=write the AUTHed
                        pubkey must hold a confirmed payment grant, checked
                        against the bundled name authority (which talks to
                        GoblinPay); results are cached for a short TTL

NIP-42/NIP-70 note for checks 2 and 3: stock strfry (pinned ref) issues the
AUTH challenge when a client publishes a NIP-70 protected event (a `-` tag)
and attaches the authed pubkey to protected writes only, after enforcing
author == authed key. So with auth or paid-write enabled, clients publish
their events with a `-` tag: first attempt triggers the challenge, the
client AUTHs, then republishes. Verified end to end against strfry
b80cda3a812af1b662223edad47eb70b053508b6.

This relay serves two apps, so the whitelist is the union of their kinds
(default-deny for everything else). Goblin wallet kinds:

    0      profile metadata (NIP-01)
    3      contact list (NIP-02)
    5      event deletion (NIP-09)
    13     seal: inner sealed event of a gift wrap (NIP-59)
    1059   gift wrap: sealed DMs and payments (NIP-59)
    10002  relay list metadata (NIP-65)
    10050  DM relay list (NIP-17)
    27235  HTTP auth event for the name authority (NIP-98)

Magick Market marketplace kinds (also reuses 0/5/1059/10002 above):

    1      text note: bug reports, shared listings (NIP-01) [author-locked]
    7      reaction (NIP-25)
    14     order chat / general order message, plaintext (Gamma spec)
    16     order processing and status update (Gamma spec)
    17     payment receipt / confirmation (Gamma spec)
    1111   comment (NIP-22)
    10000  mute list, used as merchant/product blacklist (NIP-51)
    30000  people set: admins, editors, featured users, vanity, NIP-05 (NIP-51)
    30003  bookmark set: featured collections (NIP-51)
    30023  long-form article: news / posts (NIP-23) [author-locked]
    30078  app-specific data: cart, relay prefs, V4V (NIP-78)
    30402  product listing (NIP-99)
    30405  product collection / featured products (Gamma spec)
    30406  shipping option (Gamma spec)
    31990  handler information (NIP-89)
    24133  NIP-46 remote signing (Nostr Connect, ephemeral — Goblin wallet login)

Excluded on purpose: 25910 (ContextVM) only ever rides inside a 1059 gift
wrap, never raw; 30017/30018 (legacy NIP-15) are read from sellers' own relays
during migration, never written here; 9735 (Lightning zap receipt) is dead in
this GRIN-only fork.

Configuration is environment variables (set them on the strfry process; the
plugin inherits them, e.g. via docker compose or the systemd unit):

    FLOONET_ALLOWED_KINDS   comma-separated kind whitelist [default: the
                            Goblin + Magick Market set documented above]
    FLOONET_AUTHORIZED_AUTHORS
                            comma-separated author pubkeys (hex or npub)
                            allowed to publish the locked public-note kinds
                            (1, 30023) [default: empty = closed]. Invalid
                            entries are logged to stderr and skipped.
    FLOONET_REQUIRE_AUTH    true/false      [default: false]
    FLOONET_PAY_MODE        off|name|write  [default: off]
                            (only "write" changes plugin behavior; "name" is
                            enforced by the name authority itself)
    FLOONET_AUTHORITY_URL   base URL of the bundled name authority
                            [default: http://authority:8191]
    FLOONET_PAID_CACHE_SECS TTL for cached paid-status lookups [default: 60]

Configuration can also live in a plain KEY=VALUE file next to this script
(floonet.env, path overridable via FLOONET_ENV_FILE) for deployments where
the process environment cannot be changed without recreating the container.
Real environment variables take precedence over the file. strfry reloads the
plugin whenever this script's mtime changes, so `touch`ing the script after
editing floonet.env applies new config with no relay/container restart.

To add a kind: edit FLOONET_ALLOWED_KINDS and restart (or touch the plugin
file; strfry reloads it on mtime change). To add a policy: write a function
`def check_foo(req, cfg): return None or "reject reason"` and append it to
CHECKS. To replace the whole policy: point relay.writePolicy.plugin at your
own executable.
"""

import json
import os
import sys
import time
import urllib.request

DEFAULT_ALLOWED_KINDS = (
    "0,1,3,5,7,13,14,16,17,1059,1111,10000,10002,10050,24133,24140,27235,"
    "30000,30003,30023,30078,30402,30405,30406,31990"
)

# Public-note kinds that are accepted only from authorized authors. Closed by
# default: with no authors configured these kinds are rejected for everyone.
LOCKED_KINDS = frozenset({1, 30023})

# Default path for the optional KEY=VALUE config file, sitting next to this
# script. Used when a deployment cannot change the process environment.
_DEFAULT_ENV_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "floonet.env"
)

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _npub_to_hex(s):
    """Decode a bech32 npub to 64-char lowercase hex, or None if it is not a
    structurally valid, checksum-correct 32-byte npub. Pure Python, no deps."""
    if s != s.lower() and s != s.upper():
        return None  # bech32 forbids mixed case
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return None
    hrp, data_part = s[:pos], s[pos + 1:]
    if hrp != "npub":
        return None
    try:
        data = [_BECH32_CHARSET.index(c) for c in data_part]
    except ValueError:
        return None
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _bech32_polymod(expanded + data) != 1:
        return None
    acc = bits = 0
    out = bytearray()
    for value in data[:-6]:  # drop the 6-symbol checksum
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc & ((1 << bits) - 1)):
        return None  # leftover padding bits must be zero
    if len(out) != 32:
        return None
    return out.hex()


def _normalize_pubkey(s):
    """Accept a 64-char hex pubkey or an npub; return canonical lowercase hex
    or None if the entry is neither."""
    s = s.strip()
    if len(s) == 64:
        try:
            int(s, 16)
        except ValueError:
            return None
        return s.lower()
    if s.lower().startswith("npub1"):
        return _npub_to_hex(s)
    return None


def _read_env_file(path):
    """Parse a plain KEY=VALUE file: split on the first '=', strip both sides,
    ignore blank and #-comment lines. A missing/unreadable file yields {}."""
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


def load_config(env=os.environ):
    """Parse plugin configuration. Values come from the process environment,
    optionally backed by a KEY=VALUE file next to this script (real
    environment variables take precedence). Malformed kind/pay values fail
    fast at startup (never silently widen the policy); malformed authorized
    authors are skipped with a stderr log rather than taking the plugin down.
    """
    merged = _read_env_file(env.get("FLOONET_ENV_FILE", _DEFAULT_ENV_FILE))
    merged.update(env)  # real environment variables win over the file
    env = merged
    kinds_raw = env.get("FLOONET_ALLOWED_KINDS", DEFAULT_ALLOWED_KINDS)
    try:
        allowed = frozenset(int(k) for k in kinds_raw.split(",") if k.strip())
    except ValueError:
        raise SystemExit(
            "floonet-writepolicy: FLOONET_ALLOWED_KINDS must be a comma-"
            "separated list of integers, got %r" % kinds_raw
        )
    if not allowed:
        raise SystemExit("floonet-writepolicy: FLOONET_ALLOWED_KINDS is empty")
    pay_mode = env.get("FLOONET_PAY_MODE", "off").strip().lower()
    if pay_mode not in ("off", "name", "write"):
        raise SystemExit(
            "floonet-writepolicy: FLOONET_PAY_MODE must be off, name or "
            "write, got %r" % pay_mode
        )
    authorized_authors = set()
    for entry in env.get("FLOONET_AUTHORIZED_AUTHORS", "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        hex_pubkey = _normalize_pubkey(entry)
        if hex_pubkey is None:
            sys.stderr.write(
                "floonet-writepolicy: ignoring invalid authorized author %r\n"
                % entry
            )
            sys.stderr.flush()
            continue
        authorized_authors.add(hex_pubkey)
    return {
        "allowed_kinds": allowed,
        "authorized_authors": authorized_authors,
        "require_auth": env.get("FLOONET_REQUIRE_AUTH", "false").strip().lower()
        in ("1", "true", "yes", "on"),
        "pay_mode": pay_mode,
        "authority_url": env.get(
            "FLOONET_AUTHORITY_URL", "http://authority:8191"
        ).rstrip("/"),
        "paid_cache_secs": float(env.get("FLOONET_PAID_CACHE_SECS", "60")),
    }


# --- checks (each returns None to pass or a rejection message) ---


def check_kind(req, cfg):
    """The keystone: default-deny kind whitelist. Anything not explicitly
    allowed is rejected, including a missing or non-integer kind."""
    kind = req.get("event", {}).get("kind")
    # bool is an int subclass in Python; a JSON true/false kind is malformed.
    if not isinstance(kind, int) or isinstance(kind, bool):
        return "blocked: malformed event kind"
    if kind not in cfg["allowed_kinds"]:
        return "blocked: event kind not accepted by this relay"
    return None


def check_authorized_authors(req, cfg):
    """Public-note lockdown: the locked kinds (1 text note, 30023 long-form
    article) are accepted only from an operator-authorized author pubkey.
    Closed by default: with no authors configured these kinds are rejected
    for everyone. Every other kind (0 profiles, 1059 gift wraps, marketplace
    kinds, lists, ephemeral) is completely unaffected."""
    kind = req.get("event", {}).get("kind")
    if kind not in LOCKED_KINDS:
        return None
    pubkey = req.get("event", {}).get("pubkey")
    if not isinstance(pubkey, str) or pubkey.lower() not in cfg["authorized_authors"]:
        return "blocked: this relay accepts public notes only from authorized authors"
    return None


def check_auth(req, cfg):
    """Optional NIP-42 requirement: reject events from connections that have
    not completed AUTH. strfry only includes `authed` after a valid kind-22242
    flow, so presence of a well-formed pubkey is the proof."""
    if not cfg["require_auth"]:
        return None
    authed = req.get("authed")
    if not isinstance(authed, str) or len(authed) != 64:
        return "auth-required: publish after NIP-42 AUTH"
    return None


# paid-status cache: pubkey -> (paid: bool, expires_at: float)
_paid_cache = {}


def _paid_lookup(cfg, pubkey):
    """Ask the bundled name authority whether this pubkey holds a confirmed
    write grant. The authority owns the GoblinPay conversation; the plugin
    only reads the verdict. Raises on any transport/parse problem."""
    url = "%s/api/v1/paid/%s" % (cfg["authority_url"], pubkey)
    with urllib.request.urlopen(url, timeout=3) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return bool(body.get("paid"))


def check_paid(req, cfg, now=time.monotonic):
    """Optional pay-to-write gate. Requires an AUTHed pubkey (payment grants
    are keyed by pubkey), then requires a confirmed grant. Unreachable
    authority = reject (fail closed), with a short negative-cache so a dead
    authority cannot be hammered once per event."""
    if cfg["pay_mode"] != "write":
        return None
    authed = req.get("authed")
    if not isinstance(authed, str) or len(authed) != 64:
        return "auth-required: paid publishing needs NIP-42 AUTH"
    cached = _paid_cache.get(authed)
    t = now()
    if cached is not None and cached[1] > t:
        paid = cached[0]
    else:
        try:
            paid = _paid_lookup(cfg, authed)
            _paid_cache[authed] = (paid, t + cfg["paid_cache_secs"])
        except Exception as e:
            sys.stderr.write("floonet-writepolicy: paid lookup failed: %s\n" % e)
            sys.stderr.flush()
            # Negative-cache briefly, then fail closed.
            _paid_cache[authed] = (False, t + min(cfg["paid_cache_secs"], 10.0))
            return "blocked: payment status unavailable"
    if not paid:
        return "blocked: payment required to publish on this relay"
    return None


def check_giftwrap_expiration(req, cfg):
    """Gift-wrap retention guard (kind 1059 only): the only automatic
    deletion trigger strfry has is a NIP-40 `expiration` tag, reaped every
    ~9s. A gift-wrapped payment must never carry one, so reject at admission
    rather than trust the publishing client. Every other kind is
    unaffected."""
    event = req.get("event", {})
    if event.get("kind") != 1059:
        return None
    tags = event.get("tags")
    if not isinstance(tags, list):
        return "blocked: malformed event tags"
    for tag in tags:
        if isinstance(tag, list) and tag and tag[0] == "expiration":
            return "blocked: expiration not allowed on gift wraps"
    return None


def check_giftwrap_recipient(req, cfg):
    """Gift-wrap shape guard (kind 1059 only): a NIP-59 gift wrap carries its
    recipient in a single `p` tag. Reject a gift wrap with zero, more than
    one, or a malformed (non 32-byte-hex) `p` tag rather than relay junk the
    recipient's client cannot route. Every other kind is unaffected."""
    event = req.get("event", {})
    if event.get("kind") != 1059:
        return None
    tags = event.get("tags")
    if not isinstance(tags, list):
        return "blocked: malformed event tags"
    p_pubkeys = [
        tag[1] for tag in tags
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "p"
    ]
    if len(p_pubkeys) != 1:
        return "blocked: gift wrap missing recipient"
    pubkey = p_pubkeys[0]
    if not isinstance(pubkey, str) or len(pubkey) != 64:
        return "blocked: gift wrap missing recipient"
    try:
        int(pubkey, 16)
    except ValueError:
        return "blocked: gift wrap missing recipient"
    return None


CHECKS = [
    check_kind,
    check_giftwrap_expiration,
    check_giftwrap_recipient,
    check_authorized_authors,
    check_auth,
    check_paid,
]


def decide(req, cfg):
    """Map one plugin request to an accept/reject reply. Fails closed on any
    structurally unexpected input rather than trusting it. The checks apply
    to every request type: strfry currently only sends type "new" (including
    for sync ingest), and checking unconditionally means a future type can
    never slip an unwanted event past the policy."""
    event = req.get("event")
    if not isinstance(event, dict):
        return {"id": "", "action": "reject", "msg": "bad event structure"}
    event_id = event.get("id")
    if not isinstance(event_id, str):
        event_id = ""
    for check in CHECKS:
        try:
            msg = check(req, cfg)
        except Exception as e:
            sys.stderr.write("floonet-writepolicy: %s failed: %s\n" % (check.__name__, e))
            sys.stderr.flush()
            msg = "policy error"
        if msg is not None:
            return {"id": event_id, "action": "reject", "msg": msg}
    return {"id": event_id, "action": "accept", "msg": ""}


def main():
    cfg = load_config()
    sys.stderr.write(
        "floonet-writepolicy: allowed kinds %s, authorized_authors=%d, "
        "require_auth=%s, pay_mode=%s\n"
        % (
            sorted(cfg["allowed_kinds"]),
            len(cfg["authorized_authors"]),
            cfg["require_auth"],
            cfg["pay_mode"],
        )
    )
    sys.stderr.flush()
    # Use readline() in a loop rather than iterating stdin: the protocol is
    # synchronous (strfry blocks waiting for each reply), so the iterator's
    # read-ahead buffer must never stall the exchange. Flush every reply.
    while True:
        line = sys.stdin.readline()
        if not line:
            break  # strfry closed stdin (shutdown/restart); exit cleanly.
        line = line.strip()
        if not line:
            continue
        try:
            reply = decide(json.loads(line), cfg)
        except Exception as e:
            # A malformed request must never crash the loop and take the
            # relay's write path down with it. Fail closed and log.
            sys.stderr.write("floonet-writepolicy: %s\n" % e)
            sys.stderr.flush()
            reply = {"id": "", "action": "reject", "msg": "policy error"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
