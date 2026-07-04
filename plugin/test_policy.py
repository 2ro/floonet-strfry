#!/usr/bin/env python3
"""Tests for the floonet write policy.

Run from the plugin directory:  python3 test_policy.py

Two layers:
  * unit tests over decide()/the check functions (whitelist, auth, paid,
    fail-closed behavior), with the paid lookup stubbed by a real local HTTP
    server standing in for the name authority;
  * a subprocess pipe test that runs the plugin exactly the way strfry does
    (JSONL on stdin, JSONL on stdout) and asserts accept/reject decisions.
"""

import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import floonet_writepolicy as wp

PLUGIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "floonet_writepolicy.py")
PK = "a" * 64
DEFAULT_KINDS = (
    0, 1, 3, 5, 7, 13, 14, 16, 17, 1059, 1111, 10000, 10002, 10050, 24133,
    27235, 30000, 30003, 30023, 30078, 30402, 30405, 30406, 31990,
)
# npub for PK (the 32-byte key 0xaa..aa); another key for "unauthorized".
PK_NPUB = "npub1424242424242424242424242424242424242424242424242424qamrcaj"
OTHER_PK = "b" * 64


def req(kind, authed=None, event_id="e1", pubkey=PK):
    """A request shaped exactly like strfry's plugin input."""
    r = {
        "type": "new",
        "event": {"id": event_id, "pubkey": pubkey, "kind": kind, "tags": [], "content": ""},
        "receivedAt": 1700000000,
        "sourceType": "IP4",
        "sourceInfo": "203.0.113.7",
    }
    if authed is not None:
        r["authed"] = authed
    return r


def cfg(**over):
    base = wp.load_config(env={})
    base.update(over)
    return base


class KindWhitelist(unittest.TestCase):
    def test_default_allowed_kinds_accepted(self):
        # Authorize PK so the locked public-note kinds (1, 30023) also pass;
        # this test only exercises the kind whitelist.
        c = cfg(authorized_authors={PK})
        for kind in DEFAULT_KINDS:
            reply = wp.decide(req(kind), c)
            self.assertEqual(reply["action"], "accept", "kind %d" % kind)
            self.assertEqual(reply["id"], "e1")

    def test_disallowed_kinds_rejected(self):
        # 25910 (ContextVM) rides inside 1059 gift wraps only;
        # 30017/30018 (legacy NIP-15) come from sellers' own relays;
        # 9735 (zap) is dead in the GRIN-only fork. All stay rejected.
        # (30023 is now whitelisted but author-locked; see PublicNoteLock.)
        for kind in (4, 6, 9735, 1058, 1060, 25910, 30017, 30018, 22242, -1):
            reply = wp.decide(req(kind), cfg())
            self.assertEqual(reply["action"], "reject", "kind %d" % kind)
            self.assertIn("kind not accepted", reply["msg"])

    def test_marketplace_kind_accepted_and_zap_rejected(self):
        # A newly-allowed Magick Market kind (NIP-89 handler info) is accepted.
        self.assertEqual(wp.decide(req(31990), cfg())["action"], "accept")
        # A still-rejected kind (Lightning zap receipt, disabled in the
        # GRIN-only marketplace) is refused by the default-deny whitelist.
        reply = wp.decide(req(9735), cfg())
        self.assertEqual(reply["action"], "reject")
        self.assertIn("kind not accepted", reply["msg"])

    def test_malformed_kind_fails_closed(self):
        for bad in (None, "1059", 3.5, True, [1059]):
            r = req(0)
            r["event"]["kind"] = bad
            self.assertEqual(wp.decide(r, cfg())["action"], "reject", repr(bad))

    def test_missing_or_bad_event_fails_closed(self):
        self.assertEqual(wp.decide({"type": "new"}, cfg())["action"], "reject")
        self.assertEqual(wp.decide({"event": "nope"}, cfg())["action"], "reject")

    def test_custom_kind_list_env(self):
        # Kind 1 is author-locked, so authorize PK to see the whitelist pass.
        c = wp.load_config(
            env={"FLOONET_ALLOWED_KINDS": "1,7", "FLOONET_AUTHORIZED_AUTHORS": PK}
        )
        self.assertEqual(wp.decide(req(1), c)["action"], "accept")
        self.assertEqual(wp.decide(req(0), c)["action"], "reject")

    def test_empty_or_garbage_kind_list_refused_at_startup(self):
        with self.assertRaises(SystemExit):
            wp.load_config(env={"FLOONET_ALLOWED_KINDS": ""})
        with self.assertRaises(SystemExit):
            wp.load_config(env={"FLOONET_ALLOWED_KINDS": "0,x"})


class AuthRequirement(unittest.TestCase):
    def test_off_by_default(self):
        self.assertEqual(wp.decide(req(1059), cfg())["action"], "accept")

    def test_unauthed_rejected_when_required(self):
        c = cfg(require_auth=True)
        reply = wp.decide(req(1059), c)
        self.assertEqual(reply["action"], "reject")
        self.assertIn("auth-required", reply["msg"])

    def test_authed_accepted_when_required(self):
        c = cfg(require_auth=True)
        self.assertEqual(wp.decide(req(1059, authed=PK), c)["action"], "accept")

    def test_malformed_authed_rejected(self):
        c = cfg(require_auth=True)
        self.assertEqual(wp.decide(req(1059, authed="short"), c)["action"], "reject")


class _Authority(BaseHTTPRequestHandler):
    """Stub name authority: /api/v1/paid/<paid-pubkey> answers paid."""

    paid_pubkeys = set()
    fail = False

    def do_GET(self):
        if _Authority.fail:
            self.send_response(500)
            self.end_headers()
            return
        pk = self.path.rsplit("/", 1)[-1]
        body = json.dumps({"pubkey": pk, "paid": pk in _Authority.paid_pubkeys})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *a):
        pass


class PaidWriteGate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Authority)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        wp._paid_cache.clear()
        _Authority.paid_pubkeys = set()
        _Authority.fail = False

    def c(self):
        return cfg(pay_mode="write", authority_url=self.url, paid_cache_secs=60.0)

    def test_unauthed_rejected_in_write_mode(self):
        reply = wp.decide(req(1059), self.c())
        self.assertEqual(reply["action"], "reject")
        self.assertIn("auth-required", reply["msg"])

    def test_unpaid_pubkey_rejected(self):
        reply = wp.decide(req(1059, authed=PK), self.c())
        self.assertEqual(reply["action"], "reject")
        self.assertIn("payment required", reply["msg"])

    def test_paid_pubkey_accepted(self):
        _Authority.paid_pubkeys = {PK}
        self.assertEqual(wp.decide(req(1059, authed=PK), self.c())["action"], "accept")

    def test_verdict_cached_within_ttl(self):
        _Authority.paid_pubkeys = {PK}
        c = self.c()
        self.assertEqual(wp.decide(req(1059, authed=PK), c)["action"], "accept")
        # Authority flips to unpaid, but the cached verdict still applies.
        _Authority.paid_pubkeys = set()
        self.assertEqual(wp.decide(req(1059, authed=PK), c)["action"], "accept")
        # Once the cache expires the fresh (unpaid) verdict is used.
        wp._paid_cache[PK] = (True, 0.0)
        self.assertEqual(wp.decide(req(1059, authed=PK), c)["action"], "reject")

    def test_authority_down_fails_closed(self):
        _Authority.fail = True
        reply = wp.decide(req(1059, authed=PK), self.c())
        self.assertEqual(reply["action"], "reject")
        self.assertIn("payment status unavailable", reply["msg"])

    def test_kind_check_still_first_in_write_mode(self):
        _Authority.paid_pubkeys = {PK}
        reply = wp.decide(req(9735, authed=PK), self.c())
        self.assertEqual(reply["action"], "reject")
        self.assertIn("kind not accepted", reply["msg"])


class PublicNoteLock(unittest.TestCase):
    """The public-note lockdown: kinds 1 and 30023 are accepted only from
    operator-authorized authors; everything else is unaffected."""

    def test_locked_kind_from_unauthorized_key_rejected(self):
        c = cfg(authorized_authors={PK})
        for kind in (1, 30023):
            reply = wp.decide(req(kind, pubkey=OTHER_PK), c)
            self.assertEqual(reply["action"], "reject", "kind %d" % kind)
            self.assertIn("authorized authors", reply["msg"])

    def test_locked_kind_from_authorized_hex_key_accepted(self):
        c = wp.load_config(env={"FLOONET_AUTHORIZED_AUTHORS": PK})
        for kind in (1, 30023):
            self.assertEqual(wp.decide(req(kind), c)["action"], "accept", "kind %d" % kind)

    def test_locked_kind_from_authorized_npub_accepted(self):
        # Same key, configured as an npub instead of hex.
        c = wp.load_config(env={"FLOONET_AUTHORIZED_AUTHORS": PK_NPUB})
        self.assertEqual(c["authorized_authors"], {PK})
        for kind in (1, 30023):
            self.assertEqual(wp.decide(req(kind), c)["action"], "accept", "kind %d" % kind)

    def test_non_locked_kinds_unaffected_by_random_keys(self):
        # No authors configured; profiles, gift wraps and marketplace listings
        # from arbitrary keys are still accepted (kind 0 must stay open).
        c = cfg()
        self.assertEqual(c["authorized_authors"], set())
        for kind in (0, 1059, 30402):
            self.assertEqual(
                wp.decide(req(kind, pubkey=OTHER_PK), c)["action"], "accept", "kind %d" % kind
            )

    def test_closed_by_default_when_no_authors(self):
        c = cfg()
        for kind in (1, 30023):
            reply = wp.decide(req(kind), c)
            self.assertEqual(reply["action"], "reject", "kind %d" % kind)
            self.assertIn("authorized authors", reply["msg"])

    def test_malformed_npub_skipped_without_crash(self):
        # A garbage npub, a too-short hex, and a good hex in one list: the
        # good one survives, the bad ones are dropped, the plugin lives.
        c = wp.load_config(
            env={"FLOONET_AUTHORIZED_AUTHORS": "npub1notvalid,dead,%s" % PK}
        )
        self.assertEqual(c["authorized_authors"], {PK})
        self.assertEqual(wp.decide(req(1), c)["action"], "accept")

    def test_mixed_hex_and_npub_and_whitespace(self):
        c = wp.load_config(
            env={"FLOONET_AUTHORIZED_AUTHORS": " %s , %s " % (PK_NPUB, OTHER_PK)}
        )
        self.assertEqual(c["authorized_authors"], {PK, OTHER_PK})


class EnvFileConfig(unittest.TestCase):
    """load_config also reads a KEY=VALUE file, with real env taking priority."""

    def _write(self, body):
        import tempfile
        fd, path = tempfile.mkstemp(prefix="floonet-env-")
        with os.fdopen(fd, "w") as fh:
            fh.write(body)
        self.addCleanup(os.remove, path)
        return path

    def test_env_file_supplies_config(self):
        path = self._write(
            "# floonet config\n"
            "FLOONET_ALLOWED_KINDS = 1,7\n"
            "\n"
            "FLOONET_AUTHORIZED_AUTHORS=%s\n" % PK
        )
        c = wp.load_config(env={"FLOONET_ENV_FILE": path})
        self.assertEqual(c["allowed_kinds"], frozenset({1, 7}))
        self.assertEqual(c["authorized_authors"], {PK})
        self.assertEqual(wp.decide(req(1), c)["action"], "accept")
        self.assertEqual(wp.decide(req(0), c)["action"], "reject")

    def test_real_env_overrides_file(self):
        path = self._write("FLOONET_ALLOWED_KINDS=1\n")
        c = wp.load_config(
            env={"FLOONET_ENV_FILE": path, "FLOONET_ALLOWED_KINDS": "7"}
        )
        self.assertEqual(c["allowed_kinds"], frozenset({7}))

    def test_missing_file_is_harmless(self):
        c = wp.load_config(env={"FLOONET_ENV_FILE": "/no/such/floonet.env"})
        self.assertIn(1059, c["allowed_kinds"])


class Bech32Decoder(unittest.TestCase):
    def test_known_npub_decodes(self):
        self.assertEqual(wp._npub_to_hex(PK_NPUB), PK)

    def test_invalid_npubs_return_none(self):
        for bad in (
            "npub1notvalid",
            "npub1424242424242424242424242424242424242424242424242424qamrcaX",  # bad checksum
            "nsec1qqqqq",  # wrong hrp
            "",
            "424242",
        ):
            self.assertIsNone(wp._npub_to_hex(bad), bad)


class StrfryPipeProtocol(unittest.TestCase):
    """Run the plugin as strfry does: one JSONL request per line on stdin,
    one JSONL reply per line on stdout, in order."""

    def run_plugin(self, lines, env=None):
        e = {"PATH": os.environ.get("PATH", ""), "FLOONET_PAY_MODE": "off"}
        if env:
            e.update(env)
        proc = subprocess.run(
            [sys.executable, PLUGIN],
            input="".join(json.dumps(l) + "\n" for l in lines),
            capture_output=True,
            text=True,
            timeout=30,
            env=e,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return [json.loads(out) for out in proc.stdout.splitlines()]

    def test_accept_and_reject_over_the_wire(self):
        replies = self.run_plugin([req(1059, event_id="ok1"), req(9735, event_id="no1"), req(0, event_id="ok2")])
        self.assertEqual(
            [(r["id"], r["action"]) for r in replies],
            [("ok1", "accept"), ("no1", "reject"), ("ok2", "reject" if 0 not in DEFAULT_KINDS else "accept")],
        )

    def test_malformed_line_fails_closed_and_loop_survives(self):
        proc = subprocess.run(
            [sys.executable, PLUGIN],
            input="this is not json\n" + json.dumps(req(1059, event_id="after")) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(proc.returncode, 0)
        replies = [json.loads(out) for out in proc.stdout.splitlines()]
        self.assertEqual(replies[0]["action"], "reject")
        self.assertEqual((replies[1]["id"], replies[1]["action"]), ("after", "accept"))

    def test_env_whitelist_respected_over_the_wire(self):
        replies = self.run_plugin(
            [req(1, event_id="now-ok")],
            env={"FLOONET_ALLOWED_KINDS": "1", "FLOONET_AUTHORIZED_AUTHORS": PK},
        )
        self.assertEqual((replies[0]["id"], replies[0]["action"]), ("now-ok", "accept"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
