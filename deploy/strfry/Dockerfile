# Builds the floonet-strfry relay: STOCK strfry (https://github.com/hoytech/
# strfry), cloned fresh at a pinned commit and compiled UNMODIFIED (no fork,
# no patches), plus python3 and the Floonet write policy plugin. The only
# Floonet-specific bits are strfry.conf + floonet_writepolicy.py, layered on
# via strfry's own config and plugin mechanisms. docker-compose builds this
# as the `relay` service (build context = repo root).
#
# Pinned for reproducibility. Bump STRFRY_REF to a newer upstream commit to
# update strfry; nothing else changes, since the source is never touched.
#
# TLS library: OpenSSL, in both stages. strfry builds against either OpenSSL
# or LibreSSL without source changes (upstream's own ubuntu.Dockerfile and
# its documented build deps use OpenSSL's libssl-dev). Alpine's base image,
# apk and python3 already depend on OpenSSL's libssl3/libcrypto3, so this
# keeps one TLS stack in the image, and those package names are stable for
# the whole OpenSSL 3.x line. LibreSSL's runtime packages are named after
# its version (libressl4.3-libssl on Alpine 3.24), which breaks the build at
# every LibreSSL bump; the plain `libressl` package no longer ships the
# shared libraries at all. The `ldd` step below turns any future mismatch
# into a failed build rather than a relay that dies at start.
FROM alpine:3.24 AS build
ENV TZ=Europe/London
WORKDIR /build
RUN apk --no-cache add \
        linux-headers git g++ make perl pkgconfig libtool ca-certificates \
        openssl-dev zlib-dev lmdb-dev flatbuffers-dev libsecp256k1-dev zstd-dev
ARG STRFRY_REF=4cd3cf64850caf47dda46c2a2abbbf3525a64d10
RUN git clone https://github.com/hoytech/strfry . \
    && git checkout "${STRFRY_REF}" \
    && git submodule update --init \
    && make setup-golpe \
    && make -j"$(nproc)"

FROM alpine:3.24
WORKDIR /app
# PYTHONUNBUFFERED keeps the write policy plugin's stdio prompt; it also
# flushes explicitly, so this is belt-and-suspenders against buffering stalls.
ENV PYTHONUNBUFFERED=1
RUN apk --no-cache add \
        lmdb flatbuffers libsecp256k1 libb2 zstd libssl3 libcrypto3 python3 \
    && rm -rf /var/cache/apk/*
COPY --from=build /build/strfry /app/strfry
# Fail the build, not the deploy, if a shared library the binary needs is
# missing from this stage (musl's ldd exits non-zero on an unresolved
# library or symbol).
RUN ldd /app/strfry && /app/strfry --version
COPY plugin/floonet_writepolicy.py /usr/local/bin/floonet_writepolicy.py
# Run as a fixed non-root uid: the relay takes untrusted network input, so
# drop privilege. Only the db dir needs to be owned by that uid (the binary
# and plugin are world-readable and executable already); a named volume
# inherits this ownership, and a bind mount must be chowned to 10001.
RUN addgroup -g 10001 -S strfry \
    && adduser -u 10001 -S -G strfry strfry \
    && chmod +x /usr/local/bin/floonet_writepolicy.py \
    && mkdir -p /strfry-db \
    && chown -R strfry:strfry /strfry-db
USER strfry
EXPOSE 7777
ENTRYPOINT ["/app/strfry"]
CMD ["relay"]
