#!/usr/bin/env bash
# TEE notary entrypoint (runs INSIDE the dstack CVM).
#   1. generate/seal the secp256k1 key in-enclave (never injected by an operator)
#   2. bind the pubkey into a TDX quote and cache the attestation report
#   3. serve GET /notary/attestation (sidecar) so relying parties can raise trust
#   4. start the notary (tlsn-verifier-server) with NOTARY_SIGNING_KEY from the sealed key
set -euo pipefail
DATA="${DATA_DIR:-/data}"
mkdir -p "$DATA"

# 1. in-enclave key. keygen prints SCALAR=.. and PUBKEY=..
eval "$(/app/keygen.sh "$DATA/notary-key.pem")"
export NOTARY_SIGNING_KEY="$SCALAR"
echo "$PUBKEY" > "$DATA/notary-pubkey.hex"
echo "notary pubkey (pin this): $PUBKEY"

# 2. quote binds the pubkey; measurement is the audited image. Best-effort so the notary
#    still boots for local/dev runs outside a CVM (attestation just won't be available).
PUBKEY="$PUBKEY" python3 /app/attestation_server.py --refresh --out "$DATA/attestation.json" \
  || echo "warn: quote refresh failed (not in a dstack CVM, or confirm the guest-agent API)"

# 3. attestation endpoint in the background.
PUBKEY="$PUBKEY" python3 /app/attestation_server.py --serve --out "$DATA/attestation.json" \
  --port "${ATTEST_PORT:-7048}" &

# Optional egress proxy for the notary's Proxy-mode outbound dial. The no-code path is to
# route the CVM's egress through EGRESS_PROXY at the network layer (see dstack-app-compose
# and README). These vars are exported for tooling that honors them.
if [ -n "${EGRESS_PROXY:-}" ]; then
  export HTTPS_PROXY="$EGRESS_PROXY" HTTP_PROXY="$EGRESS_PROXY"
  echo "egress proxy set: $EGRESS_PROXY"
fi

# 4. the notary.
exec /app/tlsn-verifier-server
