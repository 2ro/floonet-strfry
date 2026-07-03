#!/usr/bin/env bash
# Deploy / re-deploy the Floonet name authority on the us-east box behind nginx
# at https://nm.floonet.dev, in paid-name mode wired to the local GoblinPay.
#
# Idempotent: safe to re-run. Run as root on the box. It does NOT touch the
# goblin.st production name service (goblin-nip05d) and never toggles firewalld.
#
# Prereqs already satisfied on us-east (documented for reproducibility):
#   * DNS: nm.floonet.dev A -> 167.17.77.8  (pdnsutil add-record floonet.dev nm A 14400 167.17.77.8)
#   * Rust 1.95 toolchain; GoblinPay live on 127.0.0.1:8192 (GP_API_TOKEN in goblinpay.env)
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/goblin/gpbuild/floonet-name-authority}"   # crate checkout
DATA_DIR="/opt/goblin/floonet-authority"
BIN=/usr/local/bin/floonet-name-authority
ENV_FILE=/etc/floonet-authority.env
UNIT_SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"                      # deploy/
GP_ENV=/opt/goblin/goblinpay/goblinpay.env
DOMAIN=nm.floonet.dev
PORT=8193

echo "==> build (on-box, glibc-matched)"
( cd "$REPO_DIR" && . "$HOME/.cargo/env" 2>/dev/null || true; cargo build --release --locked )
install -m0755 "$REPO_DIR/target/release/floonet-name-authority" "$BIN"

echo "==> data dir"
install -d -m0750 -o goblin -g goblin "$DATA_DIR"

echo "==> env file (token pulled from GoblinPay's env, never echoed)"
if [ ! -f "$ENV_FILE" ]; then
    GP_TOKEN="$(sed -n 's/^GP_API_TOKEN=//p' "$GP_ENV" | tr -d '\r\n')"
    sed "s#__REPLACE_WITH_GP_API_TOKEN__#${GP_TOKEN}#" \
        "$UNIT_SRC_DIR/us-east/floonet-authority.env.example" > "$ENV_FILE"
    chown root:goblin "$ENV_FILE"; chmod 0640 "$ENV_FILE"
fi

echo "==> systemd unit + us-east drop-in"
install -m0644 "$UNIT_SRC_DIR/systemd/floonet-authority.service" /etc/systemd/system/
install -d -m0755 /etc/systemd/system/floonet-authority.service.d
install -m0644 "$UNIT_SRC_DIR/us-east/floonet-authority.service.d/10-us-east.conf" \
    /etc/systemd/system/floonet-authority.service.d/
systemctl daemon-reload

echo "==> nginx: acme (:80) first, then certbot, then TLS (:443)"
VHOST=/etc/nginx/sites-available/$DOMAIN.conf
if [ ! -f /etc/letsencrypt/live/$DOMAIN/fullchain.pem ]; then
    # Stand up a temporary :80-only vhost so the HTTP-01 webroot resolves.
    cat > "$VHOST" <<EOF
server {
    listen 167.17.77.8:80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/acme-challenge; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
    ln -sf ../sites-available/$DOMAIN.conf /etc/nginx/sites-enabled/$DOMAIN.conf
    nginx -t && nginx -s reload
    certbot certonly --webroot -w /var/www/acme-challenge -d $DOMAIN \
        --key-type ecdsa --non-interactive --agree-tos -m hostmaster@floonet.dev
fi
# Full vhost (:80 redirect + :443 proxy).
install -m0644 "$UNIT_SRC_DIR/us-east/$DOMAIN.conf" "$VHOST"
ln -sf ../sites-available/$DOMAIN.conf /etc/nginx/sites-enabled/$DOMAIN.conf
nginx -t && nginx -s reload

echo "==> start the authority (paid-name mode)"
systemctl enable --now floonet-authority
sleep 1
systemctl --no-pager --full status floonet-authority | head -5
curl -fsS "http://127.0.0.1:$PORT/api/v1/health" && echo " <- local health ok"
echo "==> done: https://$DOMAIN"
