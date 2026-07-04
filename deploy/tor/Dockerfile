# Minimal Tor daemon that fronts the Floonet relay with an onion service.
# Stock tor from Alpine, no patches; all config lives in the mounted torrc.
FROM alpine:3.20
RUN apk add --no-cache tor
# tor starts as root only long enough to create/own its data dir, then drops
# to the unprivileged `tor` user named in torrc (`User tor`).
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
