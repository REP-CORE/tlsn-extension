#!/usr/bin/env bash
# Generate (once) a secp256k1 NOTARY key INSIDE the enclave and print, for eval:
#   SCALAR=<32-byte private scalar hex>   -> NOTARY_SIGNING_KEY the notary reads
#   PUBKEY=<33-byte compressed pubkey hex> -> what relying parties pin + the quote binds
#
# The key is created in-enclave and persisted to $1 on the CVM's sealed volume, so no
# operator ever injects or reads it. Errors go to STDERR (never stdout) so a caller doing
# eval "$(keygen)" only ever sees the SCALAR=/PUBKEY= lines. Regenerates if the persisted
# file is missing OR unreadable, so a stale/corrupt key on the volume cannot wedge boot.
set -euo pipefail
KEY_PEM="${1:-/data/notary-key.pem}"
mkdir -p "$(dirname "$KEY_PEM")"

if [ ! -f "$KEY_PEM" ] || ! openssl ec -in "$KEY_PEM" -noout >/dev/null 2>&1; then
  openssl ecparam -name secp256k1 -genkey -noout -out "$KEY_PEM" 2>/tmp/genkey.err \
    || { echo "keygen: genkey failed: $(cat /tmp/genkey.err 2>/dev/null)" >&2; exit 1; }
  chmod 600 "$KEY_PEM"
fi

# Private scalar: the bytes between the "priv:" and "pub:" blocks of -text, stripped.
SCALAR=$(openssl ec -in "$KEY_PEM" -text -noout 2>/tmp/ec.err \
  | awk '/priv:/{f=1;next} /pub:/{f=0} f{gsub(/[ :]/,"");printf "%s",$0}')
# openssl may prepend a 00 sign byte; keep the low 32 bytes (64 hex).
SCALAR="${SCALAR: -64}"

# Compressed public point: last 33 bytes of the DER SubjectPublicKeyInfo.
# Use `od` (coreutils, always present) rather than `xxd` (often missing in slim images).
PUBKEY=$(openssl ec -in "$KEY_PEM" -pubout -conv_form compressed -outform DER 2>/tmp/pub.err \
  | tail -c 33 | od -An -v -tx1 | tr -d ' \n')

if [ "${#SCALAR}" -ne 64 ] || [ "${#PUBKEY}" -ne 66 ]; then
  echo "keygen: bad lengths scalar=${#SCALAR} pub=${#PUBKEY}; ec.err=$(cat /tmp/ec.err 2>/dev/null); pub.err=$(cat /tmp/pub.err 2>/dev/null)" >&2
  exit 1
fi
echo "SCALAR=$SCALAR"
echo "PUBKEY=$PUBKEY"
