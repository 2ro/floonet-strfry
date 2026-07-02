#!/usr/bin/env sh
# Build a Floonet relay = STOCK upstream strfry + the Floonet spec in this dir.
#
# No fork, no patches, no vendored source: this clones hoytech/strfry fresh at
# a pinned commit, compiles it UNTOUCHED, then drops in strfry.conf and the
# write policy plugin, both of which use strfry's own native config + plugin
# mechanisms. The result is a ready-to-run Floonet relay.
#
# The Docker path (`docker compose up -d relay`) does the same thing and
# bundles the build deps; this script is the no-Docker equivalent. Needs a C++
# toolchain plus strfry's libs (liblmdb, flatbuffers, libsecp256k1, libb2,
# zstd, openssl, perl); see https://github.com/hoytech/strfry#compile-strfry
#
# Usage: ./apply-spec.sh [target-dir]      (default: ./strfry-build)
set -eu

STRFRY_REPO="https://github.com/hoytech/strfry"
# Pinned for reproducibility. Keep in sync with the Dockerfile's STRFRY_REF.
STRFRY_REF="b80cda3a812af1b662223edad47eb70b053508b6"

SPEC_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(cd "$SPEC_DIR/../../plugin" && pwd)"
TARGET="${1:-$SPEC_DIR/strfry-build}"

echo ">> Cloning stock strfry into $TARGET"
if [ ! -d "$TARGET/.git" ]; then
    git clone "$STRFRY_REPO" "$TARGET"
fi
cd "$TARGET"
git fetch origin
git checkout "$STRFRY_REF"
git submodule update --init

echo ">> Building strfry (unmodified upstream source @ $STRFRY_REF)"
make setup-golpe
make -j"$(nproc 2>/dev/null || echo 2)"

echo ">> Applying the Floonet spec (config + write policy plugin)"
cp "$SPEC_DIR/strfry.conf"                "$TARGET/strfry.conf"
cp "$PLUGIN_DIR/floonet_writepolicy.py"   "$TARGET/floonet_writepolicy.py"
chmod +x "$TARGET/floonet_writepolicy.py"
# The shipped conf uses container paths; repoint db + plugin at this local
# build (edits only the COPY in the build dir; the canonical spec files are
# untouched).
mkdir -p "$TARGET/strfry-db"
sed -i 's#^db = .*#db = "'"$TARGET"'/strfry-db/"#' "$TARGET/strfry.conf"
sed -i 's#/usr/local/bin/floonet_writepolicy.py#'"$TARGET"'/floonet_writepolicy.py#' "$TARGET/strfry.conf"

cat <<EOF

Done. Stock strfry + the Floonet spec is built at:
  $TARGET/strfry

Run the relay (binds :7777 by default; see strfry.conf):
  cd "$TARGET" && ./strfry relay

Policy configuration (kind whitelist, auth, paid mode) is environment
variables on the strfry process; see .env.example at the repo root and the
systemd units in deploy/systemd/ for a hardened bare-metal setup.
EOF
