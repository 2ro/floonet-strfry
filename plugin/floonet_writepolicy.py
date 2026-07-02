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

Configuration is environment variables (set them on the strfry process; the
plugin inherits them, e.g. via docker compose or the systemd unit):

    FLOONET_ALLOWED_KINDS   comma-separated kind whitelist
                            [default: 0,3,5,13,1059,10002,10050,27235]
    FLOONET_REQUIRE_AUTH    true/false      [default: false]
    FLOONET_PAY_MODE        off|name|write  [default: off]
                            (only "write" changes plugin behavior; "name" is
                            enforced by the name authority itself)
    FLOONET_AUTHORITY_URL   base URL of the bundled name authority
                            [default: http://authority:8191]
    FLOONET_PAID_CACHE_SECS TTL for cached paid-status lookups [default: 60]

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

DEFAULT_ALLOWED_KINDS = "0,3,5,13,1059,10002,10050,27235"


def load_config(env=os.environ):
    """Parse plugin configuration from environment variables. Malformed
    values fail fast at startup (never silently widen the policy)."""
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
    return {
        "allowed_kinds": allowed,
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


CHECKS = [check_kind, check_auth, check_paid]


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
        "floonet-writepolicy: allowed kinds %s, require_auth=%s, pay_mode=%s\n"
        % (sorted(cfg["allowed_kinds"]), cfg["require_auth"], cfg["pay_mode"])
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
