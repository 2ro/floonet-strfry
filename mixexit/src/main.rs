// Copyright 2026 The Goblin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! floonet-mixexit — the SCOPED Nym exit bundled with a Floonet relay.
//!
//! An ordinary UNBONDED mixnet client (no nym-node, no pledge, no directory
//! listing) that accepts incoming [`MixnetStream`]s and pipes each one to ONE
//! fixed upstream — the operator's own relay. No per-stream target or host
//! header is honored, so this is structurally NOT an open proxy: the only
//! thing it can ever reach is the configured relay, which is why operators
//! carry zero open-proxy liability and need no exit policy.
//!
//! The mixnet identity persists in `FLOONET_MIXEXIT_DIR`, so `nym_address()`
//! is STABLE across restarts — that address is what wallets pin (relay-pool
//! `exit` field / NIP-11 `nym_exit`). Wallets run hostname-validated TLS
//! (SNI = the relay host) end-to-end THROUGH the pipe, so this exit sees only
//! ciphertext. Design: ~/.claude/plans/floonet-nym-exit.md.

use std::path::PathBuf;

use nym_sdk::mixnet::{MixnetClientBuilder, MixnetStream, StoragePaths};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

const USAGE: &str = "\
floonet-mixexit — scoped Nym exit for a Floonet relay

Accepts incoming mixnet streams and pipes each one to ONE fixed upstream
(the co-located relay). Per-stream targets are never honored, so this is
structurally not an open proxy. The mixnet identity persists in the data
dir, keeping the nym address stable across restarts.

USAGE:
    floonet-mixexit [--help | --selftest]

MODES:
    (none)      serve: accept mixnet streams, pipe each to the upstream
    --selftest  connect to the mixnet, print the (stable) nym address and
                exit — never touches the upstream
    --help      this text

ENVIRONMENT:
    FLOONET_MIXEXIT_DIR    data dir for the persistent mixnet identity;
                           the nym address is also written to
                           <dir>/nym_address.txt   [default: ./mixexit-data]
    FLOONET_EXIT_UPSTREAM  fixed host:port every stream is piped to
                           [default: relay.goblin.st:443]
    RUST_LOG               nym-sdk log filter                [default: warn]
";

/// Data dir for the persistent mixnet identity (`FLOONET_MIXEXIT_DIR`).
fn data_dir() -> PathBuf {
	std::env::var_os("FLOONET_MIXEXIT_DIR")
		.map(Into::into)
		.unwrap_or_else(|| PathBuf::from("./mixexit-data"))
}

/// The ONE upstream every stream is piped to (`FLOONET_EXIT_UPSTREAM`).
fn upstream() -> String {
	std::env::var("FLOONET_EXIT_UPSTREAM").unwrap_or_else(|_| "relay.goblin.st:443".to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
	let mode = std::env::args().nth(1);
	match mode.as_deref() {
		Some("--help" | "-h") => {
			print!("{USAGE}");
			return Ok(());
		}
		None | Some("--selftest") => {}
		Some(other) => {
			eprintln!("unknown argument: {other}\n\n{USAGE}");
			std::process::exit(2);
		}
	}
	tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
		)
		.init();

	// Persistent identity: same data dir → same keystore (generated on first
	// run) → the SAME nym address across restarts. That address is what
	// wallets pin, so back this directory up — losing it rotates the address
	// and strands wallet pins until the next pool/NIP-11 refresh.
	let dir = data_dir();
	std::fs::create_dir_all(&dir)?;
	let storage_paths = StoragePaths::new_from_dir(&dir)?;
	let mut client = MixnetClientBuilder::new_with_default_storage(storage_paths)
		.await?
		.build()?
		.connect_to_mixnet()
		.await?;

	let address = *client.nym_address();
	let address_file = dir.join("nym_address.txt");
	std::fs::write(&address_file, format!("{address}\n"))?;
	println!("=============================================================");
	println!(" floonet-mixexit is on the mixnet. Nym address (STABLE — pin");
	println!(" this in the relay pool `exit` field / NIP-11 `nym_exit`):");
	println!("   {address}");
	println!(" also written to {}", address_file.display());
	println!("=============================================================");

	if mode.as_deref() == Some("--selftest") {
		println!("selftest OK");
		client.disconnect().await;
		return Ok(());
	}

	let upstream = upstream();
	println!("piping every accepted stream to fixed upstream {upstream}");

	let mut listener = client.listener()?;
	loop {
		tokio::select! {
			_ = shutdown_signal() => {
				println!("shutdown signal received; stopping");
				break;
			}
			accepted = listener.accept() => match accepted {
				Some(stream) => {
					let upstream = upstream.clone();
					tokio::spawn(pipe(stream, upstream));
				}
				None => {
					eprintln!("mixnet stream router stopped; exiting");
					break;
				}
			}
		}
	}

	client.disconnect().await;
	println!("floonet-mixexit stopped");
	Ok(())
}

/// One accepted stream: TCP to the FIXED upstream (never a caller-chosen
/// target), then bytes both ways until either side closes. Errors are logged
/// and drop only this stream — the accept loop keeps serving.
async fn pipe(mut mix: MixnetStream, upstream: String) {
	let mut tcp = match TcpStream::connect(&upstream).await {
		Ok(tcp) => tcp,
		Err(e) => {
			eprintln!("stream dropped: upstream {upstream} connect failed: {e}");
			return;
		}
	};
	match copy_bidirectional(&mut mix, &mut tcp).await {
		Ok((up, down)) => println!("stream closed ({up} B in → relay, {down} B relay → out)"),
		Err(e) => eprintln!("stream ended with error: {e}"),
	}
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM (systemd/docker stop).
async fn shutdown_signal() {
	let ctrl_c = tokio::signal::ctrl_c();
	#[cfg(unix)]
	{
		let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
			.expect("SIGTERM handler");
		tokio::select! {
			_ = ctrl_c => {}
			_ = term.recv() => {}
		}
	}
	#[cfg(not(unix))]
	{
		let _ = ctrl_c.await;
	}
}
