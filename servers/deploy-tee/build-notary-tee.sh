#!/usr/bin/env bash
# Build the notary-in-TEE image on Fly's remote builder (no local docker) and push it to
# registry.fly.io/rep-notary-tee. A later step mirrors it to a registry Phala can pull.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Build from a clean checkout by setting SERVERS (e.g. a worktree of choly/tee-notary); the dirty-tree
# guard below then passes and the image is reconstructable from that commit.
SERVERS="${SERVERS:-$HOME/dev/tlsn-extension/servers}"
STAGE="$(mktemp -d)"

echo "staging servers/ + kit in $STAGE"
cp "$SERVERS/Cargo.toml" "$SERVERS/Cargo.lock" "$STAGE/"
rsync -a --exclude target --exclude '.git' "$SERVERS/verifier" "$SERVERS/swissbank" "$STAGE/"
mkdir -p "$STAGE/deploy-tee"
cp "$HERE/Dockerfile.tee" "$HERE/keygen.sh" "$HERE/entrypoint.sh" "$HERE/attestation_server.py" "$STAGE/deploy-tee/"
cat > "$STAGE/fly.toml" <<'EOF'
app = "rep-notary-tee"
primary_region = "fra"
[build]
  dockerfile = "deploy-tee/Dockerfile.tee"
EOF

TOKEN="$(printf 'protocol=https\nhost=github.com\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p')"
[ -n "$TOKEN" ] || { echo "no github token"; exit 1; }
export FLY_API_TOKEN="$(cat "$HOME/.rep-secrets/fly.token")"

# Reproducibility: the image must record the exact source commit it was built from, and that source
# must be COMMITTED. Refuse a dirty tree unless explicitly overridden, so we never mint another
# image whose source exists nowhere but this Mac (see README-REPRO.md).
GIT_HASH="${GIT_HASH:-$(git -C "$SERVERS" rev-parse HEAD 2>/dev/null || echo UNPINNED-dirty-build)}"
if [ -n "$(git -C "$SERVERS" status --porcelain 2>/dev/null)" ] && [ "${ALLOW_DIRTY:-0}" != "1" ]; then
  echo "ERROR: $SERVERS is dirty. A reproducible image must be built from a committed snapshot."
  echo "       Commit the notary source (branch choly/tee-notary) first, or set ALLOW_DIRTY=1 to"
  echo "       knowingly build an UNVERIFIABLE image. GIT_HASH would be: $GIT_HASH"
  exit 1
fi
echo "building at GIT_HASH=$GIT_HASH"

cd "$STAGE"
fly apps create rep-notary-tee --org personal 2>/dev/null || true
fly deploy --build-only --push -a rep-notary-tee --build-secret ghtoken="$TOKEN" --build-arg GIT_HASH="$GIT_HASH"
