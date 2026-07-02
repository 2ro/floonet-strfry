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
DEFAULT_KINDS = (0, 3, 5, 13, 1059, 10002, 10050, 27235)


def req(kind, authed=None, event_id="e1"):
    """A request shaped exactly like strfry's plugin input."""
    r = {
        "type": "new",
        "event": {"id": event_id, "pubkey": PK, "kind": kind, "tags": [], "content": ""},
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
        for kind in DEFAULT_KINDS:
            reply = wp.decide(req(kind), cfg())
            self.assertEqual(reply["action"], "accept", "kind %d" % kind)
            self.assertEqual(reply["id"], "e1")

    def test_disallowed_kinds_rejected(self):
        for kind in (1, 4, 6, 7, 14, 1058, 1060, 30023, 22242, -1):
            reply = wp.decide(req(kind), cfg())
            self.assertEqual(reply["action"], "reject", "kind %d" % kind)
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
        c = wp.load_config(env={"FLOONET_ALLOWED_KINDS": "1,7"})
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
        reply = wp.decide(req(1, authed=PK), self.c())
        self.assertEqual(reply["action"], "reject")
        self.assertIn("kind not accepted", reply["msg"])


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
        replies = self.run_plugin([req(1059, event_id="ok1"), req(1, event_id="no1"), req(0, event_id="ok2")])
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
            [req(1, event_id="now-ok")], env={"FLOONET_ALLOWED_KINDS": "1"}
        )
        self.assertEqual((replies[0]["id"], replies[0]["action"]), ("now-ok", "accept"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
