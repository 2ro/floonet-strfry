#!/usr/bin/env python3
"""Post-deploy smoke test for the public-note lockdown.

Signs four throwaway events with a fresh (unauthorized) key and publishes
them to a live relay, then checks the relay's OK responses:

    * kind 1     (text note)         -> expected BLOCKED  (author not authorized)
    * kind 0     (profile)           -> expected ACCEPTED (profiles stay open)
    * kind 1059  (gift wrap)         -> expected ACCEPTED (money path ungated)
    * kind 30023 (long-form article) -> expected BLOCKED  (author not authorized)

Exit 0 only if all four expectations hold. Zero third-party dependencies: a
compact BIP-340 Schnorr signer and a minimal RFC-6455 client, both stdlib.

Usage:
    ./smoke_test_lockdown.py wss://relay.example.com
    ./smoke_test_lockdown.py wss://relay.example.com --insecure   # skip TLS verify
"""

import base64
import hashlib
import json
import os
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

# --- BIP-340 Schnorr (secp256k1), reference-style, stdlib only ---------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _tagged_hash(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _inv(x):
    return pow(x, _P - 2, _P)


def _point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] != b[1]):
        return None
    if a == b:
        lam = (3 * a[0] * a[0] * _inv(2 * a[1])) % _P
    else:
        lam = ((b[1] - a[1]) * _inv(b[0] - a[0])) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    y = (lam * (a[0] - x) - a[1]) % _P
    return (x, y)


def _point_mul(point, k):
    r = None
    while k:
        if k & 1:
            r = _point_add(r, point)
        point = _point_add(point, point)
        k >>= 1
    return r


def _has_even_y(point):
    return point[1] % 2 == 0


def _lift_x(x):
    y_sq = (pow(x, 3, _P) + 7) % _P
    y = pow(y_sq, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != y_sq:
        return None
    return (x, y if y % 2 == 0 else _P - y)


def pubkey_xonly(seckey):
    d0 = int.from_bytes(seckey, "big")
    p = _point_mul(_G, d0)
    return p[0].to_bytes(32, "big")


def schnorr_sign(msg32, seckey, aux=b"\x00" * 32):
    d0 = int.from_bytes(seckey, "big")
    p = _point_mul(_G, d0)
    d = d0 if _has_even_y(p) else _N - d0
    t = (d ^ int.from_bytes(_tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    px = p[0].to_bytes(32, "big")
    rand = _tagged_hash("BIP0340/nonce", t + px + msg32)
    k0 = int.from_bytes(rand, "big") % _N
    r = _point_mul(_G, k0)
    k = k0 if _has_even_y(r) else _N - k0
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", rx + px + msg32), "big") % _N
    return rx + ((k + e * d) % _N).to_bytes(32, "big")


# --- Nostr event ------------------------------------------------------------


def make_signed_event(seckey, kind, content, tags=None):
    tags = tags or []
    pubkey = pubkey_xonly(seckey).hex()
    created_at = int(time.time())
    serial = json.dumps(
        [0, pubkey, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    eid = hashlib.sha256(serial.encode()).digest()
    sig = schnorr_sign(eid, seckey)
    return {
        "id": eid.hex(),
        "pubkey": pubkey,
        "created_at": created_at,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": sig.hex(),
    }


# --- Minimal RFC-6455 client (text frames only) -----------------------------


class WS:
    def __init__(self, url, insecure=False, timeout=15):
        u = urlparse(url)
        secure = u.scheme == "wss"
        host = u.hostname
        port = u.port or (443 if secure else 80)
        path = u.path or "/"
        raw = socket.create_connection((host, port), timeout=timeout)
        if secure:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        self.sock = raw
        key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, key)
        )
        self.sock.sendall(handshake.encode())
        resp = self._read_until(b"\r\n\r\n")
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            raise RuntimeError("websocket upgrade failed: %r" % resp[:120])
        self._buf = b""

    def _read_until(self, marker):
        data = b""
        while marker not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def send_text(self, text):
        payload = text.encode()
        header = bytearray([0x81])  # FIN + text opcode
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += n.to_bytes(2, "big")
        else:
            header.append(0x80 | 127)
            header += n.to_bytes(8, "big")
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("connection closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_text(self):
        b0, b1 = self._recv_exact(2)
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        if length == 126:
            length = int.from_bytes(self._recv_exact(2), "big")
        elif length == 127:
            length = int.from_bytes(self._recv_exact(8), "big")
        payload = self._recv_exact(length) if length else b""
        if opcode == 0x8:  # close
            raise RuntimeError("server closed the connection")
        if opcode in (0x9, 0xA):  # ping/pong: ignore, read next
            return self.recv_text()
        return payload.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def publish_expect(ws, event, want_accept, timeout=15):
    """Send one event, wait for its OK frame, return (accepted, message)."""
    ws.send_text(json.dumps(["EVENT", event]))
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = json.loads(ws.recv_text())
        if msg[0] == "OK" and msg[1] == event["id"]:
            return bool(msg[2]), (msg[3] if len(msg) > 3 else "")
    raise RuntimeError("no OK response for event %s" % event["id"])


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    insecure = "--insecure" in sys.argv
    if not args:
        sys.stderr.write("usage: smoke_test_lockdown.py wss://relay [--insecure]\n")
        return 2
    url = args[0]
    seckey = os.urandom(32)

    # A gift-wrap-shaped event: gift wraps are signed by throwaway keys
    # anyway (NIP-59), p-tag the recipient, content is an opaque ciphertext
    # blob (here random base64, ephemeral-ish; nobody will ever unwrap it).
    recipient = pubkey_xonly(os.urandom(32)).hex()
    wrap_blob = base64.b64encode(os.urandom(192)).decode()

    checks = [
        # (label, event, want_accept, failure explanation)
        (
            "kind 1 note",
            make_signed_event(seckey, 1, "floonet lockdown smoke test; please ignore"),
            False,
            "an unauthorized author's text note was accepted",
        ),
        (
            "kind 0 profile",
            make_signed_event(seckey, 0, json.dumps({"name": "floonet-smoke"})),
            True,
            "a profile was blocked; kind 0 must stay open",
        ),
        (
            "kind 1059 gift wrap",
            make_signed_event(seckey, 1059, wrap_blob, tags=[["p", recipient]]),
            True,
            "a gift wrap was blocked; the money path must stay ungated",
        ),
        (
            "kind 30023 long-form",
            make_signed_event(
                seckey,
                30023,
                "floonet lockdown smoke test article; please ignore",
                tags=[["d", "floonet-smoke-test"], ["title", "smoke test"]],
            ),
            False,
            "an unauthorized author's long-form article was accepted",
        ),
    ]

    print("relay:      %s" % url)
    print("throwaway:  %s (unauthorized by design)" % pubkey_xonly(seckey).hex())

    ws = WS(url, insecure=insecure)
    ok = True
    try:
        for label, event, want_accept, fail_msg in checks:
            accepted, why = publish_expect(ws, event, want_accept=want_accept)
            good = accepted == want_accept
            ok = ok and good
            print("%-22s %s  (expected %s) msg=%r"
                  % (label + ":",
                     "ACCEPTED" if accepted else "BLOCKED",
                     "ACCEPTED" if want_accept else "BLOCKED",
                     why))
            if not good:
                print("  FAIL: %s" % fail_msg)
    finally:
        ws.close()

    print("RESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
