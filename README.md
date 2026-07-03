# floonet-strfry

A hardened, easy-to-deploy [strfry](https://github.com/hoytech/strfry) relay
package for **Floonet**, the network of Nostr relays for the Grin community.
Anyone can run one, and anyone can run a name authority on it so people can
claim (and optionally pay GRIN for) a `name@domain` identity.

strfry core ships **stock**: the upstream C++ source is cloned at a pinned
commit and compiled unmodified. Everything Floonet-specific is layered on
through strfry's own extension points:

| Piece | What it is |
| --- | --- |
| `plugin/floonet_writepolicy.py` | The write policy plugin: default-deny kind whitelist, optional NIP-42 gate, optional paid-write gate |
| `name-authority/` | The bundled name authority (Rust/axum/SQLite): NIP-05 resolution, NIP-98 self-service registration, optional GoblinPay paywall — co-located on the relay's own domain by default |
| `mixexit/` | An optional, scoped mixnet exit so wallets can reach this relay over the mixnet |
| `deploy/` | strfry conf + Dockerfile + apply-spec.sh, Caddy TLS proxy, landing page, hardened systemd units |

## Deploy

Pick your comfort level. All three paths produce the same relay.

### 1. Docker Compose (recommended)

One command brings up the whole unit: relay + name authority + auto-TLS
proxy (and, if enabled, the mixnet exit).

```sh
cp .env.example .env    # set FLOONET_DOMAIN, FLOONET_BASE_URL, FLOONET_RELAYS
docker compose up -d
```

DNS for `FLOONET_DOMAIN` must already point at the host; Caddy obtains the
certificate on first start. That is all a free relay needs.

### 2. apply-spec.sh + systemd (no Docker)

Builds stock strfry at the pinned ref and lays the Floonet conf + plugin on
top:

```sh
./deploy/strfry/apply-spec.sh          # needs a C++ toolchain + strfry's libs
cd name-authority && cargo build --release
```

Then install the hardened units from `deploy/systemd/` (each unit's header
has the exact install commands): `floonet-strfry.service`,
`floonet-authority.service` and, optionally, `floonet-mixexit.service`.
Put Caddy or nginx in front (see `deploy/Caddyfile`); the proxy MUST set
`X-Real-IP`, the authority's rate limiting keys off it.

### 3. From source (developers)

`deploy/strfry/Dockerfile` and `apply-spec.sh` document the strfry build
exactly; the authority and the exit are plain `cargo build` crates; the
plugin is a single Python file with no dependencies. `plugin/test_policy.py`
and `cargo test` in `name-authority/` run the test suites.

## The kind whitelist (the keystone)

The relay is **default-deny**: the write policy rejects every event whose
kind is not explicitly allowed, at every ingest path (client publishes and
negentropy sync alike), failing closed on anything malformed. The shipped
set is exactly what the Goblin wallet uses:

| Kind | Meaning |
| --- | --- |
| 0 | profile metadata |
| 3 | contact list |
| 5 | deletion (NIP-09) |
| 13 | seal (NIP-59) |
| 1059 | gift wrap (NIP-59) |
| 10002 | relay list (NIP-65) |
| 10050 | DM relays (NIP-17) |
| 27235 | HTTP auth (NIP-98) |

To accept another kind, edit `FLOONET_ALLOWED_KINDS` in `.env` and restart
the relay. Nothing else changes.

## Authentication (NIP-42), optional

Set `FLOONET_REQUIRE_AUTH=true` in `.env` and flip `relay.auth.enabled` to
`true` in `deploy/strfry/strfry.conf`. strfry then issues AUTH challenges
and validates the kind-22242 responses; the plugin rejects writes from
unauthenticated connections with an `auth-required:` message.

Client flow on stock strfry (pinned ref): publish events with a NIP-70 `-`
tag. The first protected publish triggers the AUTH challenge; the client
answers with a signed kind-22242 event and republishes. strfry enforces that
the event author is the authenticated key and hands that key to the plugin.

## Charge GRIN for your relay

Getting paid is editing a few `.env` keys; prices are yours to set and
change, no code involved. You need a running
[GoblinPay](https://code.gri.mw/GRIN/GoblinPay) server (your own payment
processor; it holds the wallet, produces payment proofs, and hosts the pay
pages).

```sh
FLOONET_PAY_MODE=name          # or: write
FLOONET_NAME_PRICE_GRIN=1.5    # what a name costs, in GRIN
GOBLINPAY_URL=https://pay.your.domain
GOBLINPAY_TOKEN=<GP_API_TOKEN from your GoblinPay>
```

Modes:

- `off`: everything free (default).
- `name`: claiming `name@domain` requires payment. The register call answers
  `402` with a JSON body carrying `pay_url` (the hosted GoblinPay checkout),
  `invoice_id` and the price; the client sends the payer there and retries
  the same call once the invoice settles. Payment is confirmed against
  GoblinPay's REST API (which verifies the Grin payment on chain); a paid
  claim consumes its grant, so releasing the name and claiming another needs
  a fresh payment.
- `write`: publishing requires a one-time payment per pubkey. Clients NIP-42
  AUTH (grants are per pubkey, see the section above), obtain a quote from
  `POST /api/v1/quote` with `{"resource": "write"}` (NIP-98 signed), pay,
  and publish. The relay plugin checks grants against the authority and
  caches verdicts for `FLOONET_PAID_CACHE_SECS`.

Optionally set `GOBLINPAY_WEBHOOK_SECRET` and point a GoblinPay webhook at
`https://your.domain/api/v1/goblinpay/webhook`: payments then confirm the
moment GoblinPay sees them instead of on the next status poll. The webhook
is HMAC-verified and only ever triggers a re-check against the REST API, so
a replayed delivery grants nothing.

The relay's public NIP-11 metadata stays neutral in every mode; it carries
relay facts, nothing else.

## The name authority

Bundled in the package and consulted by the relay plugin; also usable on its
own. Names are lowercase `a-z0-9._-`, start and end alphanumeric, 3 to 20
characters, one active name per pubkey, with a reserved list (generic infra
and finance terms, your own domain labels, plus look-alike folding so
`g0blin` cannot impersonate `goblin`) and an anti-churn cooldown after
releasing a name.

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /.well-known/nostr.json?name=<name>` | none | NIP-05 resolution |
| `GET /api/v1/name/{name}` | none | availability check |
| `POST /api/v1/register` | NIP-98 | claim `{name, pubkey}`; `402` + pay URL in paid mode |
| `DELETE /api/v1/register/{name}` | NIP-98 | release (owner only) |
| `GET /api/v1/profile/{name}` | none | name to pubkey |
| `GET /api/v1/by-pubkey/{pubkey}` | none | reverse lookup |
| `GET /api/v1/paid/{pubkey}` | none | write-grant status (what the plugin polls) |
| `POST /api/v1/quote` | NIP-98 | price + pay URL for a paid resource |
| `POST /api/v1/goblinpay/webhook` | HMAC | payment confirmation nudge |
| `GET /api/v1/health` | none | liveness |

NIP-98 requests are verified fully: signature, kind 27235, `u`/`method`/
`payload` tags against `FLOONET_BASE_URL`, a freshness window, and one-time
event ids (replay rejection).

## Co-locating names on the relay domain

`FLOONET_AUTHORITY_COLOCATED` controls whether the authority's NIP-05 lookup
(`/.well-known/nostr.json`) is served on the **relay's own domain**, so
`name@relay.example` resolves without the authority needing its own hostname.

- **Docker Compose / Caddy: on by default.** The whole stack lives on one
  `FLOONET_DOMAIN`; `deploy/Caddyfile` routes `/.well-known/nostr.json` (and
  `/api/*`) to the authority and everything else to the relay, so
  `name@FLOONET_DOMAIN` just works. Nothing to configure.

- **Split nginx deploy: opt in.** When the relay and the authority run on
  separate subdomains (the `deploy/us-east/` pattern — relay on
  `relay.example`, the authority's own vhost on `nm.example`), enable it by
  including the shipped snippet in the relay vhost's `:443` server block,
  ahead of the WebSocket catch-all:

  ```nginx
  # inside  server { listen ...:443 ssl ...; server_name relay.example; }
  # BEFORE  location / { ...websocket... }
  include /etc/nginx/snippets/floonet-colocated-authority.conf;   # deploy/us-east/colocated-authority.conf
  ```

  Then `nginx -t && nginx -s reload`, and
  `https://relay.example/.well-known/nostr.json?name=<n>` returns the
  authority's JSON. Only the exact-match read path is co-located; registration
  and the rest of `/api/*` stay on the authority's own domain. The snippet sets
  `X-Real-IP` (load-bearing — the authority's per-IP rate limiter keys off it).

## Mixnet exit (optional)

Uncomment `COMPOSE_PROFILES=exit` in `.env` and the package also runs
`floonet-mixexit`: a small, unbonded mixnet client that accepts incoming
mixnet streams and pipes every one of them to this stack's own TLS front.
Wallets that prefer not to touch DNS or reveal their relay choice can then
reach this relay entirely over the mixnet, with end-to-end TLS; the exit
sees only ciphertext.

It is deliberately **scoped**: per-stream targets are never honored, the one
upstream is fixed by config, so it is structurally not an open proxy and
carries no open-proxy liability. No bonding, no tokens, no directory
listing.

On first start it prints its **stable mixnet address** (also written to the
data volume's `nym_address.txt`). Publish that address in your relay pool
listing (the `exit` field) so wallets can find it, and back the data
directory up: losing it rotates the address.

## Extending the policy (plugins, paid resources)

- **Add a kind:** edit `FLOONET_ALLOWED_KINDS`, restart.
- **Add a policy check:** the plugin is a small, documented Python file.
  Write `def check_foo(req, cfg): return None or "reason"`, append it to
  `CHECKS`, and it runs on every write, fail-closed. strfry reloads the
  plugin when the file's mtime changes.
- **Replace the policy entirely:** point `relay.writePolicy.plugin` in
  `strfry.conf` at any executable speaking strfry's stdin/stdout JSONL
  plugin protocol.
- **Add a paid resource:** the paywall is one mechanism applied to many
  resources. `name` and `write` ship today; the same pattern fits paid
  media/blob storage for GRIN (NIP-96 HTTP file storage or Blossom
  content-addressed blobs, advertised with a kind 10063 server list): pick a
  resource id, give it a price, gate the endpoint on `ensure_paid`, and the
  plugin/authority handle quoting, the hosted pay page, and confirmation
  unchanged. See `name-authority/src/paid.rs`.

## Security model

- **Fail closed everywhere.** Malformed events, plugin errors, unreachable
  payment backend, unparseable config: all reject rather than admit.
- **Stock + spec.** strfry is never patched; the upstream ref is pinned in
  `deploy/strfry/Dockerfile` and `apply-spec.sh`, so updating strfry is
  bumping one hash.
- **Containers** run non-root (fixed uids) with the data volume as the only
  writable state; **systemd units** use `DynamicUser`, `ProtectSystem=strict`,
  `NoNewPrivileges`, syscall filtering, and a single writable state dir.
- **Reverse proxy sets `X-Real-IP`** (load-bearing: all per-IP rate limits
  key off it); TLS terminates at Caddy.
- **Rate limits** per IP on the authority's read and write endpoints,
  NIP-98 replay protection, name-change cooldown, and a poll throttle so
  outsiders cannot hammer GoblinPay through the public paid endpoint.
- **No secrets in the repo.** The GoblinPay token comes from the environment
  or a `0400` file via `GOBLINPAY_TOKEN_FILE`; the authority never logs it.
  The relay itself holds no secrets at all.
- `events.maxEventSize` is sized so large gift-wrapped payloads fit.

## Configuration reference

Everything lives in `.env` (see `.env.example`, fully commented). The
essentials:

| Key | Default | Meaning |
| --- | --- | --- |
| `FLOONET_DOMAIN` | `floonet.example` | your domain (names + TLS cert) |
| `FLOONET_BASE_URL` | `https://floonet.example` | public base URL (NIP-98 verification) |
| `FLOONET_RELAYS` | `wss://floonet.example` | relays advertised in nostr.json |
| `FLOONET_ALLOWED_KINDS` | `0,3,5,13,1059,10002,10050,27235` | the whitelist |
| `FLOONET_REQUIRE_AUTH` | `false` | NIP-42 gate |
| `FLOONET_PAY_MODE` | `off` | `off` / `name` / `write` |
| `FLOONET_NAME_PRICE_GRIN` | `0` | price of a name, in GRIN |
| `FLOONET_WRITE_PRICE_GRIN` | `0` | price of write access, in GRIN |
| `GOBLINPAY_URL` / `GOBLINPAY_TOKEN` | unset | your GoblinPay server |
| `GOBLINPAY_WEBHOOK_SECRET` | unset | enables the webhook receiver |
| `COMPOSE_PROFILES` | unset | `exit` also runs the mixnet exit |

## Note for Goblin wallet users

One wallet can hold multiple Nostr identities (npubs). If you pay for a name
and want to keep it, load the same wallet in Goblin and switch to (or add)
that npub; different identities share one wallet.

## License

Apache-2.0 for everything in this repository. strfry itself (built from
upstream at the pinned ref, never vendored here) is licensed under GPL-3.0
by its authors.

---

🤖 Built with AI pair-programming assistance (Claude)
