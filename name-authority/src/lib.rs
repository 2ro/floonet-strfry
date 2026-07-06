// floonet-name-authority — the name authority bundled with a Floonet relay.
//
// `name@yourdomain` -> nostr pubkey, with NIP-98-authenticated self-service
// registration, and an optional GoblinPay paywall for paid names and paid
// relay write access. Avatars are not stored here: clients render them
// deterministically from the pubkey. The relay is a separate service; this
// crate advertises it in `/.well-known/nostr.json` and answers the relay
// write policy plugin's paid-status lookups.
//
// The crate is split so HTTP integration tests can build the same router the
// binary serves: construct an `App` (use `:memory:` for the db), then
// `handlers::routes(app)`.

pub mod auth;
pub mod config;
pub mod db;
pub mod handlers;
pub mod names;
pub mod node;
pub mod paid;
pub mod proof;
pub mod ratelimit;
pub mod setup;
pub mod util;

pub use config::Config;
pub use db::App;
pub use handlers::routes;
