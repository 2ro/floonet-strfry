# Floonet Tor Migration Plan

**Status:** Ready to execute · **Date:** 2026-07-04 · **Scope:** the FLOONET side (relay, exit, name authority, deploy/ops) of Goblin's move from the Nym mixnet back to Tor.
**Companion document (read first):** `goblin/docs/PRIVACY-TRANSPORT-REDESIGN.md` — the wallet-side plan, and the source of truth for *why* we're doing this and how the wallet's transport is built. This document does not repeat that reasoning; it covers everything on the relay/infra side that the wallet plan depends on or triggers.

**The one line to carry through every decision below:** Tor hides the user's IP from the relay; the relay + protocol hide everything else (content, sender, timing).

---

## Decision & scope

Goblin is dropping the Nym mixnet and returning to Tor, for the reasons laid out in full in the wallet plan: the free bandwidth tier Goblin relied on is testnet scaffolding Nym is actively deleting on a schedule, and the only supported replacement requires holding NYM tokens — a foundation a payments wallet can't stand on. Tor has none of those failure modes.

This document is scoped to **Floonet** — the relay, the co-located mixnet exit, the name authority, and the deploy/ops layer around them. It does not cover the wallet's Tor client (arti, the transport trait, UI copy, locales) — that's entirely the wallet plan's job. Where this document depends on wallet work landing first, it says so and points back rather than re-describing it.

Floonet's job in this migration is small and mostly subtractive: the onion that replaces the old mixnet exit is **already live**. What's left is pinning it where the wallet looks for it, retiring the exit once the wallet no longer needs it, deleting the now-dead mixnet code from two repos, and a couple of deploy-layer additions (a second onion for the name authority, some ops hygiene). The one piece of real new work — relay-side Poisson delay — is called out separately as a fast-follow that nothing else here is blocked on.

---

## Where things stand today: the onion is already live

The keystone is done. A Tor onion service already fronts the production relay:

- Address: `m2ji5o6p6qapd4ies4wua64skjx2emd6lrp7hhvrib33ogveyihopryd.onion`
- It forwards plain `ws://` straight to the relay's local websocket listener (`127.0.0.1:8292`) — no TLS needed on that hop, since the onion transport is already encrypted and authenticated end to end.
- Proven working: a plain Nostr client can complete a handshake through it today.

This satisfies the wallet plan's "Phase 1 — Onion service on the relay" for Floonet's production relay. Everything in this document is what surrounds that fact: pinning it, cutting over to it, and retiring what it replaces.

---

## Orientation: two relay repos, one production deployment

Floonet ships two independent, open-source relay packages, and it matters which one this plan is really about:

- **floonet-strfry** — wraps stock, unpatched upstream [strfry](https://github.com/hoytech/strfry) (C++) with a write-policy plugin, a bundled name authority, and (until this migration) the mixnet exit. **This is production.** It runs today as the Docker container `floonet-relay-new` on the us-east box, serving `wss://relay.floonet.dev`, websocket listening locally on `127.0.0.1:8292`. The live onion, the Poisson work in Phase 7, and the exit retirement in Phase 4 all land here, for real.
- **floonet-rs** — a Rust fork of `nostr-rs-relay` with the same feature set (kind whitelist, NIP-42 auth, built-in name authority, the same optional co-located mixnet exit). It is not what's serving `relay.floonet.dev` traffic, but it's a maintained, publicly distributed sibling package that vendors the identical mixnet-exit design — so it needs the same cleanup (Phase 5) or it's left carrying a dead code path and a stale `nym-sdk` dependency that nobody is using.
- **goblin-nip05d** — the name authority behind `goblin.st`, a separate service entirely (deployed standalone, `127.0.0.1:8191`, its own nginx vhost). It has no mixnet/exit code to remove — it never had any — but wallet lookups against it currently leak the wallet's IP the same way relay traffic used to, so it gets its own onion in Phase 8.

Keep this straight while executing: "strip the exit" is real work in two repos (floonet-rs and floonet-strfry) for the sake of code hygiene and every future operator who deploys them, but only floonet-strfry's production instance is on the live money path.

---

## The phased checklist

- [x] **Phase 1** — Onion service live in front of the production relay (done, proven)
- [ ] **Phase 2** — Pin the onion in the relay-pool gist
- [ ] **Phase 3** — Gate: wait for the wallet's Tor build to ship and prove a payment over the onion
- [ ] **Phase 4** — Retire the Nym exit in production (`floonet-mixexit-fdev.service` + archive `floonet-mixexit`)
- [ ] **Phase 5** — Strip mixexit out of floonet-rs
- [ ] **Phase 6** — Strip mixexit out of floonet-strfry, document Tor as the replacement deploy option
- [ ] **Phase 7 (fast-follow, non-blocking)** — Relay-side Poisson delay
- [ ] **Phase 8** — goblin-nip05d gets its own onion
- [ ] **Phase 9** — Ops & health-probe follow-ups

---

## Phase 1 — Onion service live (done)

Nothing to execute here. Recorded for completeness and because Phases 2 onward assume it: the onion above is live, stable, and has already handled a proven handshake.

One thing worth a five-minute check before moving on, since it's cheap insurance and was part of the wallet plan's own Phase 1 recommendation: confirm **Vanguards** is enabled on the onion service's Tor configuration. It hardens the service side against guard-discovery attacks and costs nothing once set. If it isn't on yet, turning it on is a one-line torrc addition, not a re-architecture — fold it in whenever you're next touching that box's Tor config.

---

## Phase 2 — Pin the onion in the relay-pool gist

The wallet finds a relay's onion the same way it already finds a co-located Nym exit: a per-relay field in the relay-pool gist (`https://gist.github.com/2ro/79cd885540c88d074fe52f8388a3e5b4`).

**Verified state as of this writing** (fetched directly, not assumed):

- The wallet's parsing code is *already done*. `goblin/src/nostr/pool.rs` defines `PoolRelay.onion: Option<String>`, plus `onion_for()` / `has_onion()` accessors that mirror the existing `exit` plumbing exactly, and a unit test already pins this exact onion address for `wss://relay.floonet.dev`. The wallet's in-binary pinned fallback pool (the `PINNED_POOL` constant in that same file, dated `2026-07-02`) already carries the onion field too.
- The **live gist does not yet match.** A direct fetch of the raw gist just now shows `"updated": "2026-07-03"` with an `exit` field for `relay.floonet.dev` but **no `onion` field** — the gist is a revision behind what's already staged in the wallet's own pinned fallback.

So the action here is narrow and low-risk: sync the live gist to what the code already expects.

```json
{
  "url": "wss://relay.floonet.dev",
  "roles": ["dm", "discovery"],
  "vetted": "2026-07-02",
  "exit": "EqbUPt7aYkar2CTmjBVnyWaKzb2WT8NdojUGXU4mrfNG.AF5YCD8hgEUqByamrPqZz72h7GE599LbqQrhaew9bBip@HfyUPUv4z8uMQoZYuZGMWf6oe2vaKBVPrfgHk6WvwFPe",
  "onion": "m2ji5o6p6qapd4ies4wua64skjx2emd6lrp7hhvrib33ogveyihopryd.onion"
}
```

- Edit via the existing path (`gh gist edit`), bump `updated`, keep `version: 1`.
- **Leave `exit` in place for now** — don't remove it until Phase 4. Older, still-live Nym-only wallet builds still read it; removing it early stops them from reaching this relay at all, for no benefit.
- This is safe to do **right now**, independent of the wallet Tor build shipping. The gist schema is deliberately tolerant (no `deny_unknown_fields`, `version` stays `1`), so any build that doesn't understand `onion` yet just ignores it — confirmed by the same test coverage in `pool.rs`. There's no flag day and no risk to today's traffic.

---

## Phase 3 — Gate: ship the wallet's Tor build

This phase is entirely the wallet plan's to execute (its Phases 0–2: copy GRIM's arti engine, implement the onion-dialing `WebSocketTransport`, re-point readiness/warm-up, keep the confirm-before-sent guard verbatim, no clearnet fallback). Nothing to do on the Floonet side here except wait for it — and not skip ahead.

**Everything from Phase 4 onward is gated on this.** Don't disable the Nym exit before the wallet's Tor build has shipped and been watched carrying a real payment over the onion (the wallet plan's own Phase 2 validation criterion). Disabling the exit early would cut off the only working path for any user still on an old, Nym-only build, before they have anywhere else to go.

---

## Phase 4 — Retire the Nym exit in production

Two separate things retire here, and they're independent enough to do one at a time.

**1. The running service.** `floonet-mixexit-fdev.service` is the live systemd unit on the us-east box — the unbonded Nym client piping mixnet streams to `relay.floonet.dev`. Once Phase 3's gate has cleared:

```sh
systemctl disable --now floonet-mixexit-fdev
```

Nothing else on the box depends on it. The relay's own websocket listener, its Docker container, and the nginx/TLS front for the clearnet hostname are untouched by this — the exit was always a side door, not part of the main path.

**2. The standalone repo.** `floonet-mixexit/` — the ~185-line unbonded Nym client this service is built from — gets archived, not deleted outright. Mark it read-only / archived wherever it's hosted. It's small and self-contained, and other Floonet operators may have taken their own copy to run their own exit; deleting it out from under them is unnecessary and unkind. Archiving communicates "retired, don't build new things on this" without breaking anyone already relying on the source being there.

**Housekeeping:** it's clean to pull the now-pointless `exit` field for `relay.floonet.dev` out of the gist in the same pass (nothing depends on it anymore once the service is down), but it isn't load-bearing either way — `exit_for()` on the wallet side already treats a missing or blank value as "no exit" and nothing breaks if it's just left to go stale.

**Before you flip the switch:** there is no clean "everyone's already moved off Nym" state to wait for — per the wallet plan, Nym itself is failing on its own schedule regardless of what Floonet does, so there's no working baseline being taken away out from under anyone. The bar is simply: the wallet's Tor build is out and proven (Phase 3), not that every last Nym-only install has upgraded.

---

## Phase 5 — Strip mixexit out of floonet-rs

Delete:

- `mixexit/` — the entire vendored subcrate (its own `Cargo.toml`, `Cargo.lock`, `rustfmt.toml`, `src/`). Being a separate crate rather than a dependency of the main binary, deleting the directory drops the `nym-sdk` dependency chain automatically — nothing else to chase.
- `src/exit.rs` — the in-process supervisor (`validate()`, which fails startup fast if `exit.enabled` is set but the binary is missing; `spawn()`, which forks the `floonet-mixexit` child and restarts it with a 10s backoff on exit).

Un-wire the remaining touch points, all small:

| File | What to remove |
|---|---|
| `src/lib.rs` | `pub mod exit;` |
| `src/config.rs` | The `MixnetExit` struct, the `pub exit: MixnetExit` field on `Settings`, and its entry in the `Default` impl |
| `src/server.rs` | The two call sites: `exit::validate(settings)?` and `exit::spawn(&settings)` |
| `config.toml` | The commented `[exit]` block |

End state: floonet-rs builds and runs as a fully-working public relay with none of this. The exit was always optional and default-off, so this is pure subtraction — no behavior changes for anyone not already running the exit.

---

## Phase 6 — Strip mixexit out of floonet-strfry

Same shape as Phase 5, different repo, plus one addition. Delete:

- `mixexit/` — its own `Cargo.toml`, `Dockerfile`, `src/`. (Worth knowing while you're in there: this is the same ~185-line program as floonet-rs's copy and the standalone `floonet-mixexit` repo, not a from-scratch reimplementation — the only real difference between the three copies is which hostname is baked in as the default upstream. "Vendored" is the right word for it.)
- `deploy/systemd/floonet-mixexit.service` — the hardened bare-metal unit template (the pattern `floonet-mixexit-fdev.service` on us-east was built from).
- The `mixexit` service block in `docker-compose.yml` (gated behind `COMPOSE_PROFILES=exit`) and its `mixexit-data` volume declaration; update the top-of-file comment, which currently lists the exit as one of the four things the compose file brings up.
- The "Mixnet exit (optional)" block in `.env.example` (`COMPOSE_PROFILES=exit`, `FLOONET_EXIT_UPSTREAM`).
- The "Mixnet exit (optional)" section in `README.md`, and the `COMPOSE_PROFILES` row in its configuration-reference table.

**Add Tor as the replacement, first-class deploy option** for anyone standing up their own Floonet relay from this package — this is documentation, not custom code, since the underlying mechanism (system Tor hosting an onion service in front of a local listener) is exactly what's already proven live on us-east:

- For the Docker Compose path: a `tor` compose service (a minimal image running `tor` against a mounted `torrc`), analogous to how `caddy` already fronts the stack for TLS.
- For the `apply-spec.sh` + systemd path: a `torrc` snippet — `HiddenServiceDir` + `HiddenServicePort <port> 127.0.0.1:<relay-port>` — documented alongside the existing `floonet-strfry.service` / `floonet-authority.service` units.

Write up the recipe that's already running on us-east rather than describing it in the abstract, so the next operator doesn't have to rediscover it from first principles.

End state: same as Phase 5 — a fully-working relay with no mixnet code, and a documented, supported way to front it with an onion instead of the retired exit.

---

## Phase 7 (fast-follow, non-blocking) — Relay-side Poisson delay

**This does not block anything above.** The wallet is fully functional and privacy-preserving over Tor without it — the gift-wrap already hides content, sender, and recipient from the relay's write policy; Tor already hides the user's IP. Poisson delay is the one property a real mixnet had that plain Tor doesn't: timing unlinkability between "sender uploaded" and "recipient downloaded." It's valuable, but it's an enhancement on top of a working system, not a dependency of one.

**Why it's real engineering and not a config toggle:** production is strfry, and strfry is C++. There's no `[poisson_delay]` key to flip. Scope it as its own piece of work, on its own timeline, separate from the rest of this migration.

**The two honest options:**

- **(a) Patch strfry itself** — modify the broadcast fan-out path so a newly-accepted event, once matched against a live subscription, is held for a randomized delay before being pushed to that subscriber. This is the most "native" answer, but it cuts against something floonet-strfry's own README states as a deliberate property: strfry ships **stock and unpatched**, pinned at an upstream commit, specifically so "updating strfry is bumping one hash." Patching the core relay trades that property away and means carrying a fork forward across every future strfry upgrade.
- **(b) A small delay-queue proxy in front of strfry** — a thin, NIP-01-aware process that sits between the public/onion listener and strfry, passing everything through immediately (publishes, `OK` acks, `REQ`/`EOSE` backfill, `CLOSE`) *except* one specific category: a live push of a newly-matching event to a subscription that's already past its initial `EOSE` (i.e., an already-open, already-caught-up listener receiving something new in real time). Only that category gets held for the randomized delay. This keeps strfry itself untouched, at the cost of one more small service to run and maintain — but it's a service in the same spirit as the exit it's replacing conceptually (a small, purpose-built piece Floonet already owns and runs), not a new kind of operational burden.

**A design question worth resolving before scoping either option**, based on how strfry is actually built (not a confirmed finding, just reasoning worth writing down): does "release" need to mean *only* delaying the live push to an already-open subscription, or does it also need to delay the event becoming visible to a **backfill** query (a recipient's own `REQ` after coming back online)? The wallet plan's own framing suggests the narrower reading is sufficient — the threat being closed is an observer correlating a live send with a live receive, and a recipient who was offline at send-time and catches up hours later was never at risk of that correlation regardless of when their catch-up query resolves. If that reading holds, option (b) above only ever needs to touch the live-push path, which is a meaningfully smaller and safer piece of surgery than anything that reaches into strfry's storage or negentropy-sync semantics. Confirm this reading explicitly before scoping the work — it changes the shape of the fix.

**Whichever option is chosen, the acceptance bar is unchanged from the wallet plan:** the sender's "Sent" must still fire the moment the relay confirms it holds the message, not when the recipient actually receives it — the delay has to land entirely inside the gap that's already invisible to the user. The wallet's confirm-before-sent read-back logic is not to be touched or waited on by this work.

---

## Phase 8 — goblin-nip05d gets its own onion

**No code change in goblin-nip05d.** This is a deploy-layer addition only, following the exact pattern already proven for the relay.

- Add a **second** Tor hidden service on the same box (us-east) as the relay's onion, pointed at the authority's local listener (`127.0.0.1:8191`) instead of the relay's (`127.0.0.1:8292`). One Tor daemon hosts any number of onion services — this is an additional `HiddenServiceDir`/`HiddenServicePort` stanza in the same `torrc`, not a second Tor install.
- It needs its own address (rather than riding the relay's) because it's a genuinely separate service: different local port, different nginx vhost, different backend entirely.
- Once live, this closes the same gap for name lookups that the relay's onion already closed for messages: today, resolving or claiming `name@goblin.st` over Tor still means dialing goblin.st's *clearnet* host from inside the Tor circuit (a Tor exit hop), which works but is one more hop than necessary and puts a Tor exit node in a position to see the destination. An onion goes straight there instead, matching the wallet plan's stated aim for this seam (`http_request`/`http_request_bytes`: "Tor→onion for the goblin.st name authority").
- Validate the same way the relay's onion was validated: `torify curl` (or equivalent) against `https://<new-onion>/.well-known/nostr.json?name=<test>` and confirm it resolves.
- Hand the resulting address to wherever the wallet pins its goblin.st onion once that lands (likely alongside the relay-pool gist, or a build-time constant — confirm the actual mechanism when the wallet side gets there, since it may not be the same gist the relay onion uses).

---

## Phase 9 — Ops & health-probe follow-ups

- **Back up the onion service's identity.** A hidden service's address is derived from a key inside its `HiddenServiceDir`; lose that directory and the address rotates, exactly like losing the old mixexit's data directory rotated its mixnet address and stranded pins. Both the relay's `HiddenServiceDir` and (once Phase 8 lands) the authority's need the same care the old exit's state directory got.
- **Extend health checks to the onion path, not just the clearnet hostname.** Today's monitoring only has to prove `relay.floonet.dev` answers. Once the onion is a real, wallet-facing path (not just a proven-once side channel), add a periodic probe — a torified websocket handshake or equivalent — so a regression there is caught the same day, not from a user report.
- **This matters more than usual on us-east specifically.** The box has a known failure mode: toggling `firewalld` breaks Docker's iptables chains, and any container that restarts afterward silently loses its port mapping until a full `systemctl restart docker` rebuilds them. An onion service pointed at a port that quietly stopped listening behind it would go dark exactly the same way, just as silently. A health probe on the onion itself is the only thing that catches that before a user does.
- **Monitor the Tor daemon as its own signal**, distinct from "is strfry up." A healthy relay behind a wedged or stopped system Tor process looks completely fine on clearnet and is simply unreachable over the onion — a new failure mode this migration introduces that didn't exist when the only path in was clearnet + nginx.
- **Documentation loose end:** `floonet-docs` (the mdBook site) has a `concepts/nym.md` page describing the mixnet exit. Once this migration lands, that page needs a Tor-equivalent written (or an explicit retirement notice pointing to one), so the published docs don't keep describing a path that no longer exists.

---

## Risks & notes

- **Sequencing is the main risk, and it's self-inflicted if skipped.** Don't disable the Nym exit (Phase 4) before the wallet's Tor build is shipped and proven (Phase 3). Don't strip the mixexit source out of either relay repo (Phases 5–6) before the production service is actually off (Phase 4) — otherwise you can end up with running infra whose source has already been deleted out from under it, which is a bad place to be if you need to roll back in a hurry.
- **Keep the public relay hostname working throughout.** Nothing in this migration touches `relay.floonet.dev`'s clearnet listener, its nginx/TLS front, or its DNS. The onion is additive in front of the same backend, not a replacement for the clearnet path — anything that still depends on clearnet (monitoring, NIP-11 probes, other clients, non-Goblin Nostr tooling) keeps working exactly as it does today, unaffected by any phase here.
- **The us-east Docker/firewall fragility is a standing gotcha, not new to this migration, but it now has a new victim if triggered.** Toggling `firewalld` or bouncing a single container can silently drop port mappings across the box; the fix is a full `systemctl restart docker`, which bounces everything (~17 containers, including this relay). Keep that in mind before touching firewalld or restarting containers on that box during any phase above, and see Phase 9 for making the onion's exposure to this failure mode actively monitored rather than a silent risk.
- **No clearnet fallback on the money path, ever.** This is primarily wallet-side discipline (the wallet plan is explicit: "fail loudly," never silently degrade to clearnet), but Floonet's job is to make sure that discipline is never actually tested by an outage — keep the onion solid (Phase 9's monitoring) so a wallet never has a reason to reach for a fallback that shouldn't exist.
- **Archive, don't delete, `floonet-mixexit`.** It's small, self-contained, and other Floonet operators may have their own copy or their own exit running against it. Archiving signals "retired" without pulling the rug out from under someone else's working deployment.
- **Phase 7 (Poisson) is explicitly not a gate on anything else.** Don't let its scoping or its C++-vs-proxy decision stall Phases 1–6, 8, or 9 — those are independent, lower-risk, and most of them are already de-risked by direct verification (see Phase 2's gist check).

---

## Quick reference: what to touch, per repo

| Repo | Touch |
|---|---|
| **floonet-strfry** (production) | Delete `mixexit/`, `deploy/systemd/floonet-mixexit.service`; remove the `mixexit` service + volume from `docker-compose.yml`; remove the exit block from `.env.example` and `README.md`; add a documented Tor deploy option (compose `tor` service or `torrc` snippet) |
| **floonet-rs** | Delete `mixexit/`, `src/exit.rs`; remove `pub mod exit;` (`lib.rs`), the `MixnetExit` struct + `Settings.exit` field + its `Default` entry (`config.rs`), the two `exit::validate`/`exit::spawn` call sites (`server.rs`), the commented `[exit]` block (`config.toml`) |
| **floonet-mixexit** (standalone) | Archive the repo once `floonet-mixexit-fdev.service` is disabled; do not delete |
| **goblin-nip05d** | No code change; add a second onion hidden service at the deploy layer, pointed at its local port |
| **us-east (ops)** | `systemctl disable --now floonet-mixexit-fdev`; add the authority's `HiddenServiceDir`/`HiddenServicePort`; extend health probes to the onion path and the Tor daemon itself; back up both `HiddenServiceDir`s |
| **relay-pool gist** (`2ro/79cd885540c88d074fe52f8388a3e5b4`) | Add `"onion": "m2ji5o6p6qapd4ies4wua64skjx2emd6lrp7hhvrib33ogveyihopryd.onion"` to the `relay.floonet.dev` entry now (Phase 2); remove its `exit` field once Phase 4 is done |
| **floonet-docs** | Add a Tor-equivalent of `concepts/nym.md`, or a retirement notice, once the migration lands |
