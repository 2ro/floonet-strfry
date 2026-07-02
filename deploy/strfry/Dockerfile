# Builds the floonet-strfry relay: STOCK strfry (https://github.com/hoytech/
# strfry), cloned fresh at a pinned commit and compiled UNMODIFIED (no fork,
# no patches), plus python3 and the Floonet write policy plugin. The only
# Floonet-specific bits are strfry.conf + floonet_writepolicy.py, layered on
# via strfry's own config and plugin mechanisms. docker-compose builds this
# as the `relay` service (build context = repo root).
#
# Pinned for reproducibility. Bump STRFRY_REF to a newer upstream commit to
# update strfry; nothing else changes, since the source is never touched.
FROM alpine:3.18 AS build
ENV TZ=Europe/London
WORKDIR /build
RUN apk --no-cache add \
        linux-headers git g++ make perl pkgconfig libtool ca-certificates \
        libressl-dev zlib-dev lmdb-dev flatbuffers-dev libsecp256k1-dev zstd-dev
ARG STRFRY_REF=b80cda3a812af1b662223edad47eb70b053508b6
RUN git clone https://github.com/hoytech/strfry . \
    && git checkout "${STRFRY_REF}" \
    && git submodule update --init \
    && make setup-golpe \
    && make -j"$(nproc)"

FROM alpine:3.18
WORKDIR /app
# PYTHONUNBUFFERED keeps the write policy plugin's stdio prompt; it also
# flushes explicitly, so this is belt-and-suspenders against buffering stalls.
ENV PYTHONUNBUFFERED=1
RUN apk --no-cache add \
        lmdb flatbuffers libsecp256k1 libb2 zstd libressl python3 \
    && rm -rf /var/cache/apk/*
COPY --from=build /build/strfry /app/strfry
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
