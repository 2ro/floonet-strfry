# Builds the bundled mixnet exit (floonet-mixexit): a scoped, unbonded mixnet
# client that accepts incoming mixnet streams and pipes every one of them to
# ONE fixed upstream, the TLS front of this very stack. It is structurally not
# an open proxy: per-stream targets are never honored, so running it carries
# no open-proxy liability and needs no exit policy.
#
# Enabled by the `exit` compose profile (COMPOSE_PROFILES=exit in .env).
# Note: the first build compiles the pinned nym-sdk from source; expect it to
# take a while.
FROM rust:1-bookworm AS builder
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Non-root; the persistent mixnet identity lives under /data. Back that
# directory up: losing it rotates the exit's mixnet address and strands
# wallet pins until their next relay-pool refresh.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin mixexit \
    && mkdir -p /data \
    && chown -R mixexit:mixexit /data
COPY --from=builder /build/target/release/floonet-mixexit /usr/local/bin/floonet-mixexit
USER mixexit
WORKDIR /data
VOLUME ["/data"]
ENV FLOONET_MIXEXIT_DIR=/data
ENTRYPOINT ["/usr/local/bin/floonet-mixexit"]
