#!/usr/bin/env bash
# Guided, Grin-style installer for a Floonet relay + its bundled name authority.
#
# Run it with nothing configured and it asks a handful of questions, then does
# the work: builds what you chose, installs the hardened systemd units, and
# hands off to the name authority's own setup wizard (which collects any secret
# over a hidden prompt and writes it to a root-only 0600 file, never the env
# file). Everything it asks has a sensible default; press Enter to accept.
#
# The one topology question decides whether the bundled name service runs
# alongside the relay, on its own, or not at all:
#
#   1) Relay + name authority, co-located on ONE domain   (recommended)
#   2) Relay + name authority, on SEPARATE domains
#   3) Relay only                                         (name service off)
#   4) Name authority only                                (standalone; you run
#                                                          the relay elsewhere)
#
# Re-runnable: it upgrades binaries and units idempotently and never overwrites
# an existing /etc/floonet-authority.env (the wizard has its own --reconfigure
# guard). Requires root for the install steps, and a Rust toolchain (cargo) to
# build the authority. The relay is stock upstream strfry; building it needs a
# C++ toolchain and strfry's libs, so this script offers to build it via
# deploy/strfry/apply-spec.sh or points you at the Docker path instead.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AUTH_BIN=/usr/local/bin/floonet-name-authority
AUTH_ENV=/etc/floonet-authority.env
AUTH_UNIT=/etc/systemd/system/floonet-authority.service
AUTH_SECRETS_DIR=/etc/floonet-authority/secrets
AUTH_DROPIN_DIR=/etc/systemd/system/floonet-authority.service.d

RELAY_BIN=/usr/local/bin/strfry
RELAY_PLUGIN=/usr/local/bin/floonet_writepolicy.py
RELAY_CONF_DIR=/etc/floonet-strfry
RELAY_UNIT=/etc/systemd/system/floonet-strfry.service

say()  { printf '\033[1;33m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;31m!!\033[0m  %s\n' "$1" >&2; }

if [[ $EUID -ne 0 ]]; then
	SUDO=sudo
else
	SUDO=""
fi

ask() {
	# ask "Question" "default" -> echoes the answer (default on empty/no TTY)
	local q="$1" def="$2" reply=""
	if [[ -t 0 ]]; then
		read -r -p "$(printf '\033[1;33m==>\033[0m %s [%s] ' "$q" "$def")" reply || reply=""
	fi
	printf '%s' "${reply:-$def}"
}

yesno() {
	# yesno "Question" "Y|N" -> returns 0 for yes, 1 for no
	local q="$1" def="$2" reply=""
	local hint="y/N"
	[[ "$def" == "Y" ]] && hint="Y/n"
	if [[ -t 0 ]]; then
		read -r -p "$(printf '\033[1;33m==>\033[0m %s [%s] ' "$q" "$hint")" reply || reply=""
	fi
	reply="${reply:-$def}"
	case "$reply" in
		[Yy]*) return 0 ;;
		*) return 1 ;;
	esac
}

# --- topology --------------------------------------------------------------

cat <<'EOF'

Floonet installer
=================
A Floonet relay is stock strfry plus a small policy plugin. The package also
BUNDLES a name authority (name@domain identities). Choose how to run them:

  1) Relay + name authority, co-located on ONE domain   (recommended)
  2) Relay + name authority, on SEPARATE domains
  3) Relay only                                         (name service off)
  4) Name authority only                                (standalone)

EOF

CHOICE="$(ask 'Topology (1/2/3/4)' '1')"
case "$CHOICE" in
	1) INSTALL_RELAY=yes; INSTALL_AUTH=yes; COLOCATED=yes ;;
	2) INSTALL_RELAY=yes; INSTALL_AUTH=yes; COLOCATED=no ;;
	3) INSTALL_RELAY=yes; INSTALL_AUTH=no;  COLOCATED=no ;;
	4) INSTALL_RELAY=no;  INSTALL_AUTH=yes; COLOCATED=no ;;
	*) warn "Unrecognized choice '$CHOICE'; defaulting to 1 (relay + co-located authority)."
	   INSTALL_RELAY=yes; INSTALL_AUTH=yes; COLOCATED=yes ;;
esac

# --- name authority --------------------------------------------------------

if [[ "$INSTALL_AUTH" == yes ]]; then
	if ! command -v cargo >/dev/null 2>&1; then
		warn "cargo (Rust toolchain) not found; needed to build the name authority."
		warn "Install Rust from https://rustup.rs and re-run, or pick topology 3 (relay only)."
		exit 1
	fi

	say "Building the name authority (cargo build --release --locked)"
	( cd "$REPO_DIR/name-authority" && cargo build --release --locked )

	say "Installing the authority binary to $AUTH_BIN"
	$SUDO install -m0755 "$REPO_DIR/name-authority/target/release/floonet-name-authority" "$AUTH_BIN"

	say "Creating the root-only secrets directory $AUTH_SECRETS_DIR (0700)"
	$SUDO install -d -m0700 /etc/floonet-authority
	$SUDO install -d -m0700 "$AUTH_SECRETS_DIR"

	say "Installing the systemd unit to $AUTH_UNIT"
	$SUDO install -m0644 "$REPO_DIR/deploy/systemd/floonet-authority.service" "$AUTH_UNIT"

	if [[ -f "$AUTH_ENV" ]]; then
		say "An existing $AUTH_ENV was found; leaving it untouched."
		say "To reconfigure:  $SUDO floonet-name-authority setup --reconfigure"
	elif yesno 'Run the name authority setup wizard now?' 'Y'; then
		# The wizard writes $AUTH_ENV plus, for a paid mode, the 0600 token file.
		$SUDO env FLOONET_ENV_FILE="$AUTH_ENV" floonet-name-authority setup
	else
		say "Skipped the wizard. Run it later:  $SUDO floonet-name-authority setup"
	fi

	# When a paid mode wrote a token file, wire it as a systemd credential so the
	# DynamicUser can read it without the 0600 file being world-readable. The
	# drop-in keeps the base unit valid for a free (no-secret) authority.
	if [[ -f "$AUTH_ENV" ]] && grep -q '^GOBLINPAY_TOKEN_FILE=' "$AUTH_ENV"; then
		say "Paid mode detected; installing the GoblinPay token credential drop-in"
		$SUDO install -d -m0755 "$AUTH_DROPIN_DIR"
		tokfile="$(grep '^GOBLINPAY_TOKEN_FILE=' "$AUTH_ENV" | head -n1 | cut -d= -f2-)"
		{
			printf '[Service]\n'
			printf 'LoadCredential=goblinpay_token:%s\n' "$tokfile"
			printf 'Environment=GOBLINPAY_TOKEN_FILE=%%d/goblinpay_token\n'
			if grep -q '^GOBLINPAY_WEBHOOK_SECRET_FILE=' "$AUTH_ENV"; then
				hookfile="$(grep '^GOBLINPAY_WEBHOOK_SECRET_FILE=' "$AUTH_ENV" | head -n1 | cut -d= -f2-)"
				printf 'LoadCredential=goblinpay_webhook_secret:%s\n' "$hookfile"
				printf 'Environment=GOBLINPAY_WEBHOOK_SECRET_FILE=%%d/goblinpay_webhook_secret\n'
			fi
		} | $SUDO tee "$AUTH_DROPIN_DIR/10-goblinpay-credential.conf" >/dev/null
	fi
fi

# --- relay -----------------------------------------------------------------

if [[ "$INSTALL_RELAY" == yes ]]; then
	if [[ -x "$REPO_DIR/deploy/strfry/strfry-build/strfry" ]]; then
		say "Found a prebuilt strfry at deploy/strfry/strfry-build/strfry."
	elif yesno 'Build stock strfry now via deploy/strfry/apply-spec.sh? (needs a C++ toolchain)' 'N'; then
		say "Building stock upstream strfry (this takes a while)"
		( cd "$REPO_DIR" && ./deploy/strfry/apply-spec.sh )
	else
		say "Skipping the strfry build. Two ways to get the relay running:"
		say "  Docker:   cp .env.example .env && docker compose up -d"
		say "  No Docker: ./deploy/strfry/apply-spec.sh   then re-run this installer"
	fi

	if [[ -x "$REPO_DIR/deploy/strfry/strfry-build/strfry" ]]; then
		say "Installing the relay binary to $RELAY_BIN"
		$SUDO install -m0755 "$REPO_DIR/deploy/strfry/strfry-build/strfry" "$RELAY_BIN"
		say "Installing the write-policy plugin to $RELAY_PLUGIN"
		$SUDO install -m0755 "$REPO_DIR/plugin/floonet_writepolicy.py" "$RELAY_PLUGIN"
		say "Installing the relay config to $RELAY_CONF_DIR/strfry.conf"
		$SUDO install -m0644 -D "$REPO_DIR/deploy/strfry/strfry.conf" "$RELAY_CONF_DIR/strfry.conf"
		say "Installing the systemd unit to $RELAY_UNIT"
		$SUDO install -m0644 "$REPO_DIR/deploy/systemd/floonet-strfry.service" "$RELAY_UNIT"
	fi
fi

# --- finish ----------------------------------------------------------------

say "Reloading systemd"
$SUDO systemctl daemon-reload || true
[[ "$INSTALL_AUTH"  == yes ]] && $SUDO systemctl enable floonet-authority >/dev/null 2>&1 || true
[[ "$INSTALL_RELAY" == yes && -x "$RELAY_BIN" ]] && $SUDO systemctl enable floonet-strfry >/dev/null 2>&1 || true

echo
say "Install complete. Next steps:"
if [[ "$INSTALL_RELAY" == yes ]]; then
	echo "  Relay:     $SUDO systemctl start floonet-strfry && journalctl -fu floonet-strfry"
fi
if [[ "$INSTALL_AUTH" == yes ]]; then
	echo "  Authority: $SUDO systemctl start floonet-authority && journalctl -fu floonet-authority"
fi
echo "  Put a TLS proxy in front (see deploy/Caddyfile); it MUST set X-Real-IP."
if [[ "$INSTALL_AUTH" == yes && "$COLOCATED" == yes ]]; then
	echo
	echo "  Co-located: serve the authority's NIP-05 lookup on the relay domain so"
	echo "  name@<relay-domain> resolves. Docker/Caddy do this automatically; for a"
	echo "  split nginx deploy include deploy/us-east/colocated-authority.conf in the"
	echo "  relay vhost. See the README section 'Co-locating names on the relay domain'."
elif [[ "$INSTALL_AUTH" == yes ]]; then
	echo
	echo "  Standalone: give the authority its own hostname/vhost (deploy/us-east/)"
	echo "  and point FLOONET_DOMAIN / FLOONET_BASE_URL at it."
fi
