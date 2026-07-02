# Multi-stage build: a Rust builder produces a static-ish binary, then a slim
# Debian runtime runs it as a non-root user. SQLite is bundled into the binary
# (the `bundled` rusqlite feature), so the runtime needs no system DB library.

# ---- builder ----
FROM rust:1-bookworm AS builder
WORKDIR /build

# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
# A throwaway lib + main so `cargo build` can compile dependencies before the
# real sources are present.
RUN mkdir -p src \
    && echo "pub fn _stub() {}" > src/lib.rs \
    && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked || true
RUN rm -rf src

# Real sources.
COPY src ./src
# Touch so cargo rebuilds the bin/lib with the actual code.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

# ---- runtime ----
FROM debian:bookworm-slim AS runtime

# ca-certificates for outbound TLS (GoblinPay); curl for the healthcheck.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user; data lives under /data.
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin floonet \
    && mkdir -p /data \
    && chown -R floonet:floonet /data

COPY --from=builder /build/target/release/floonet-name-authority /usr/local/bin/floonet-name-authority

USER floonet
WORKDIR /data

# Persist the database.
VOLUME ["/data"]

# Defaults can be overridden at run time; bind on all interfaces inside the
# container (the reverse proxy is the only thing in front of it).
ENV FLOONET_NAMES_BIND=0.0.0.0:8191 \
    FLOONET_NAMES_DB=/data/names.db

EXPOSE 8191

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8191/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/floonet-name-authority"]
