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
| `name-authority/` | The bundled name authority (Rust/axum/SQLite): NIP-05 resolution, NIP-98 self-service registration, optional GoblinPay paywall - co-located on the relay's own domain by default |
| `deploy/tor/` | An optional Tor onion service so wallets can reach this relay over Tor without a Tor exit hop |
| `deploy/` | strfry conf + Dockerfile + apply-spec.sh, Caddy TLS proxy, landing page, hardened systemd units |

## Deploy

Pick your comfort level. All paths produce the same relay.

### 0. Guided installer (easiest, Grin-style)

```sh
sudo ./install.sh
```

One interactive script. It asks a single topology question - whether to run the
bundled name service **alongside the relay** (co-located on one domain), on a
**separate domain**, **relay only**, or the **name authority standalone** - then
builds what you chose, installs the hardened systemd units, and hands off to the
name authority's own setup wizard. Every prompt has a sensible default. Any
secret (the GoblinPay API token) is collected over a **hidden prompt** and
written to a root-only `0600` file, never the env file; the installer wires it
to the service as a systemd credential. Re-runnable, and it never clobbers an
existing config. Prefer this unless you want Docker.

The name authority also runs its wizard on its own: with nothing configured, a
bare `floonet-name-authority` on a terminal offers it, or run it explicitly with
`floonet-name-authority setup` (`--reconfigure` to redo an existing config). When
`FLOONET_DOMAIN` is set (compose/systemd), the wizard never fires - those deploys
stay fully headless.

### 1. Docker Compose (recommended)

One command brings up the whole unit: relay + name authority + auto-TLS
proxy (and, if enabled, a Tor onion).

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
has the exact install commands): `floonet-strfry.service` and
`floonet-authority.service`. Put Caddy or nginx in front (see
`deploy/Caddyfile`); the proxy MUST set `X-Real-IP`, the authority's rate
limiting keys off it. To also front the relay with a Tor onion, run a system
tor with the snippet in `deploy/tor/torrc` (see "Tor onion" below).

### 3. From source (developers)

`deploy/strfry/Dockerfile` and `apply-spec.sh` document the strfry build
exactly; the authority is a plain `cargo build` crate; the plugin is a single
Python file with no dependencies. `plugin/test_policy.py` and `cargo test` in
`name-authority/` run the test suites.

## The kind whitelist (the keystone)

The relay is **default-deny**: the write policy rejects every event whose
kind is not explicitly allowed, at every ingest path (client publishes and
negentropy sync alike), failing closed on anything malformed. The shipped
default set covers what the Goblin wallet and the Magick Market marketplace
use:

| Kind | Meaning |
| --- | --- |
| 0 | profile metadata |
| 1 | text note (**author-locked**, see below) |
| 3 | contact list |
| 5 | deletion (NIP-09) |
| 7 | reaction (NIP-25) |
| 13 | seal (NIP-59) |
| 14 / 16 / 17 | order chat / status / receipt (Gamma spec) |
| 1059 | gift wrap (NIP-59) |
| 1111 | comment (NIP-22) |
| 10000 | mute / blacklist set (NIP-51) |
| 10002 | relay list (NIP-65) |
| 10050 | DM relays (NIP-17) |
| 24133 | Nostr Connect / remote signing (NIP-46) |
| 27235 | HTTP auth (NIP-98) |
| 30000 / 30003 | people set / bookmark set (NIP-51) |
| 30023 | long-form article (NIP-23, **author-locked**, see below) |
| 30078 | app-specific data (NIP-78) |
| 30402 / 30405 / 30406 | product listing / collection / shipping (NIP-99 + Gamma spec) |
| 31990 | handler information (NIP-89) |

Kinds `1` and `30023` are additionally author-locked (next section); every
other kind here flows for everyone. To accept another kind, edit
`FLOONET_ALLOWED_KINDS` and restart the relay (or just `touch` the plugin,
since strfry reloads it on mtime change). Nothing else changes.

## Public notes are author-locked

Public-note kinds (`1` text notes, `30023` long-form articles) are accepted
**only** from an operator-chosen list of authors. This is closed by default:
with no authors configured, kinds `1` and `30023` are rejected for everyone,
so random notes cannot be spammed to your relay. Everything else (profiles,
gift wraps, marketplace listings, lists, ephemeral events) is unaffected, and
kind `0` profiles stay open so wallets can republish them.

You decide who can post. List the authors in `FLOONET_AUTHORIZED_AUTHORS`,
comma-separated, each entry a hex pubkey or an npub (your choice):

```sh
FLOONET_AUTHORIZED_AUTHORS=npub1abc...,fd3a...hex...,npub1def...
```

Invalid entries are logged to stderr and skipped; the rest still apply.

### Changing authors without recreating the container

Where the container's environment cannot be changed without recreating it,
drop a plain `KEY=VALUE` file named `floonet.env` next to the plugin script
(override the path with `FLOONET_ENV_FILE`) and set the same keys there:

```sh
# /usr/local/bin/floonet.env
FLOONET_AUTHORIZED_AUTHORS=npub1abc...,npub1def...
```

Real environment variables take precedence over the file. strfry reloads the
plugin whenever the script's modification time changes, so after editing
`floonet.env` just `touch` the plugin script and the next write picks up the
new list. No relay or container restart is needed.

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

The token is a secret. The guided installer and the `floonet-name-authority
setup` wizard collect it over a hidden prompt and store it in a root-only `0600`
file referenced by `GOBLINPAY_TOKEN_FILE`, so it never lands in the env file;
set `GOBLINPAY_TOKEN` inline only for a throwaway local test.

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
own. The Docker Compose stack runs it alongside the relay by default (the
`authority` service), and the same `name-authority/` crate builds and runs
standalone for a systemd or bare-metal deploy. When the authority binary starts
with nothing configured and an interactive terminal, a first-run setup wizard
prompts for the essentials (domain, bind address, data dir, pay mode, name
transfers) and writes an env file; set `FLOONET_DOMAIN` (as Docker Compose and
the systemd unit both do) and it stays headless. To run a relay with **no** name
service, drop the `authority` service (and its `/.well-known/nostr.json` +
`/api/*` proxy routes) from your deploy; the relay itself needs it for nothing.

Names are lowercase `a-z0-9._-`, start and end alphanumeric, 3 to 20
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

### Name transfers (optional, off by default)

Mounted only when `FLOONET_TRANSFERS` is set; otherwise these routes do not
exist and requests 404. Independent of `FLOONET_PAY_MODE`: the two features
toggle in any combination.

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/transfer/offer` `{offer}` | NIP-98 (seller) | lodge a signed kind-3402 sale offer |
| `GET /api/v1/transfer/offer/{id}` | none | read an offer + its status (CORS `*`) |
| `DELETE /api/v1/transfer/offer/{id}` | NIP-98 (seller) | revoke a live offer |
| `POST /api/v1/transfer/claim` `{offer_id, proof}` | NIP-98 (buyer) | claim the name with a Grin payment proof |

A **name transfer** reassigns an active name from the seller's pubkey to the
buyer's. It is **strictly non-custodial and has zero GoblinPay involvement**:
the buyer pays the seller directly, wallet to wallet in Grin, and the authority
never holds funds. The seller lodges a signed offer (a kind-3402 event binding
name, buyer pubkey, price, receiving address, and expiry); the buyer pays on
chain and submits the six-field Grin payment proof; the authority verifies both
signatures over the canonical 73-byte message, confirms the kernel on chain
(`FLOONET_TRANSFER_MIN_CONF` deep) via a read-only node foreign API, checks the
exact amount and receiving address, ensures the kernel excess was never used
before, and then swaps one database row in a single atomic transaction. Keys
never move - only the name's pubkey changes. Enabling this needs a reachable
Grin node foreign API (`FLOONET_GRIN_NODE_URL`). The full protocol is specified
in the Goblin Name Transfer Protocol v1 spec.

## Co-locating names on the relay domain

`FLOONET_AUTHORITY_COLOCATED` controls whether the authority's NIP-05 lookup
(`/.well-known/nostr.json`) is served on the **relay's own domain**, so
`name@relay.example` resolves without the authority needing its own hostname.

- **Docker Compose / Caddy: on by default.** The whole stack lives on one
  `FLOONET_DOMAIN`; `deploy/Caddyfile` routes `/.well-known/nostr.json` (and
  `/api/*`) to the authority and everything else to the relay, so
  `name@FLOONET_DOMAIN` just works. Nothing to configure.

- **Split nginx deploy: opt in.** When the relay and the authority run on
  separate subdomains (the `deploy/us-east/` pattern - relay on
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
  `X-Real-IP` (load-bearing - the authority's per-IP rate limiter keys off it).

## Tor onion (optional)

Goblin wallets connect to relays over Tor: the client opens a Tor circuit and
reaches the relay's ordinary clearnet endpoint (`FLOONET_DOMAIN`) through a
Tor exit, so the relay never sees the user's real IP. That works against any
Floonet relay with no extra setup here, and it is the whole transport story:
Tor hides the user's network location; the kind whitelist and gift-wrapped
(kind 1059) payloads hide everything else from the relay itself. The relay
needs no privacy component of its own.

An operator who wants to remove the Tor-exit hop entirely can front the relay
with a **Tor onion service**. Uncomment `COMPOSE_PROFILES=tor` in `.env` and
the package also runs the `tor` service: a stock system tor daemon whose
hidden service forwards straight to strfry's websocket listener (no TLS on
that hop, since the onion transport is already encrypted and authenticated end
to end). Wallets then reach the relay over an `.onion` with no exit hop at all.

tor prints the `.onion` address to its logs on first start and stores its key
on the `tor-data` volume; back that volume up, since losing it rotates the
address. Publish the `.onion` so wallets can find it. Without Docker, run a
system tor with the snippet in `deploy/tor/torrc` (a `HiddenServiceDir` plus a
`HiddenServicePort` pointed at the relay's local websocket port) alongside the
`floonet-strfry.service` unit.

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
- **No secrets in the repo, and none in world-readable files.** The GoblinPay
  token is collected by the setup wizard over a hidden prompt and written to a
  root-only `0600` file that `GOBLINPAY_TOKEN_FILE` names (the systemd unit
  exposes it to the service as a credential, so the dynamic user reads a copy
  without the file being broadly readable). It is never written to the env file
  and never logged. A free authority holds no secret at all, and the relay
  itself holds none in any mode.
- `events.maxEventSize` is sized so large gift-wrapped payloads fit.

## Configuration reference

Everything lives in `.env` (see `.env.example`, fully commented). The
essentials:

| Key | Default | Meaning |
| --- | --- | --- |
| `FLOONET_DOMAIN` | `floonet.example` | your domain (names + TLS cert) |
| `FLOONET_BASE_URL` | `https://floonet.example` | public base URL (NIP-98 verification) |
| `FLOONET_RELAYS` | `wss://floonet.example` | relays advertised in nostr.json |
| `FLOONET_ALLOWED_KINDS` | Goblin + Magick Market set (see the whitelist section) | the kind whitelist |
| `FLOONET_AUTHORIZED_AUTHORS` | unset (closed) | authors (hex or npub) allowed to post kinds `1`/`30023` |
| `FLOONET_ENV_FILE` | `floonet.env` next to the plugin | optional `KEY=VALUE` config file (env vars win) |
| `FLOONET_REQUIRE_AUTH` | `false` | NIP-42 gate |
| `FLOONET_PAY_MODE` | `off` | `off` / `name` / `write` |
| `FLOONET_NAME_PRICE_GRIN` | `0` | price of a name, in GRIN |
| `FLOONET_WRITE_PRICE_GRIN` | `0` | price of write access, in GRIN |
| `GOBLINPAY_URL` | unset | your GoblinPay server base URL |
| `GOBLINPAY_TOKEN_FILE` / `GOBLINPAY_TOKEN` | unset | API token; prefer the `0600` `_FILE` form the wizard writes over the inline value |
| `GOBLINPAY_WEBHOOK_SECRET_FILE` / `GOBLINPAY_WEBHOOK_SECRET` | unset | enables the webhook receiver; `_FILE` keeps the secret out of the env file |
| `FLOONET_TRANSFERS` | `false` | enable the name-transfer routes (off = they 404) |
| `FLOONET_GRIN_NODE_URL` | unset | Grin node foreign API(s) for payment confirmation (**required** when transfers are on) |
| `FLOONET_TRANSFER_MIN_CONF` | `10` | confirmations a payment kernel needs before a claim |
| `FLOONET_TRANSFER_MAX_OFFER_TTL` | `2592000` | longest offer time-to-live in seconds (30 days) |
| `FLOONET_TRANSFER_CLAIM_GRACE` | `86400` | grace window in seconds for a claim after an offer dies (1 day) |
| `COMPOSE_PROFILES` | unset | `tor` also runs a Tor onion in front of the relay |

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
