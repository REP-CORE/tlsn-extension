#!/usr/bin/env python3
"""Notary attestation sidecar for a Phala dstack TDX CVM.

Two jobs:
  --refresh  Ask the dstack guest agent for a TDX quote whose report_data BINDS the
             notary pubkey, read the CVM measurement, and write an attestation report
             JSON in the shape the relying party (prove_public_fact / rep-verify) checks:
               {"evidence":"intel-tdx-quote","measurement":<hex>,
                "report_data":<hex, contains the pubkey hex>,"quote":<hex>}
  --serve    Serve that JSON at GET /notary/attestation so an agent can fetch it and
             raise trust from operator-pinned to hardware-attested.

The guest-agent API name/socket differs across dstack versions, so we try a few known
endpoints and stop at the first that answers. CONFIRM the exact prpc method + measurement
field against the dstack version you deploy (docs: docs.phala.network/dstack) before prod.
The pubkey is passed via env PUBKEY (from keygen.sh)."""
import argparse, hashlib, http.client, json, os, socket, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# (unix socket, quote path, info path) endpoint candidates across dstack/tappd versions. The exact
# GetQuote path + report_data field + format differs by dstack version and a wrong one silently
# yields a zeroed/hashed report_data, so we brute-force endpoint x body and KEEP only a quote that
# actually binds our value (see _quote_binds). Confirmed live: dstack-dev-0.5.9 on Phala prod5.
GUEST_AGENTS = [
    ("/var/run/dstack.sock", "/GetQuote", "/Info"),
    ("/var/run/dstack.sock", "/prpc/Dstack.GetQuote?json", "/prpc/Dstack.Info?json"),
    ("/var/run/dstack.sock", "/prpc/Tappd.TdxQuote?json", "/prpc/Tappd.Info?json"),
    ("/var/run/tappd.sock", "/prpc/Tappd.TdxQuote?json", "/prpc/Tappd.Info?json"),
]

def _bodies(rd_hex: str):
    """report_data request-body variants to try (snake/camel, 0x/bare, 64B/32B, tappd raw-hash)."""
    rd32 = rd_hex[:64]
    return [
        {"report_data": rd_hex}, {"report_data": "0x" + rd_hex},
        {"reportData": rd_hex}, {"reportData": "0x" + rd_hex},
        {"report_data": rd_hex, "hash_algorithm": "raw"},
        {"report_data": "0x" + rd_hex, "hash_algorithm": "raw"},
        {"report_data": rd32, "hash_algorithm": "raw"}, {"report_data": rd32},
    ]

def _unix_post(sock_path, path, body):
    """Minimal HTTP POST over a unix socket, returns parsed JSON or raises."""
    conn = http.client.HTTPConnection("localhost")
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.sock.settimeout(10)
    conn.sock.connect(sock_path)
    payload = json.dumps(body)
    conn.request("POST", path, payload, {"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    if resp.status // 100 != 2:
        raise RuntimeError(f"{path} -> HTTP {resp.status}: {data[:200]!r}")
    return json.loads(data or "{}")

def _report_data_hex(pubkey_hex: str) -> str:
    """64-byte report_data (128 hex): sha256(notary_pubkey_bytes) in the first 32 bytes, zero-padded.
    Standard convention: the quote cryptographically binds sha256(pubkey), so a verifier recomputes
    sha256(bundle.notary_key) and matches it against the quote's report_data field."""
    try:
        h = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()  # 64 hex = 32 bytes
    except ValueError:
        h = hashlib.sha256(pubkey_hex.encode()).hexdigest()
    return (h + "0" * (128 - len(h)))[:128]

def _first(d, keys):
    for k in keys:
        v = d.get(k) if isinstance(d, dict) else None
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

def _quote_binds(quote_hex: str, rd_hex: str) -> bool:
    """True iff the returned TDX quote actually embeds our report_data (sha256(pubkey) in the first
    32 bytes). dstack API name/format varies by version and a wrong format silently yields a zero
    report_data quote, so we VERIFY the bytes rather than trust that GetQuote honored the field."""
    try:
        qb = bytes.fromhex(quote_hex.strip().removeprefix("0x"))
    except ValueError:
        return False
    want32 = bytes.fromhex(rd_hex)[:32]  # sha256(pubkey)
    if want32 == b"\x00" * 32:
        return False
    # TDX v4: 48-byte header + TD10 report; report_data is its last 64 bytes -> offset 568.
    if len(qb) >= 632 and qb[568:600] == want32:
        return True
    # version-robust fallback: the 32-byte binding appears somewhere in the quote body.
    return want32 in qb

def refresh(pubkey_hex: str, out_path: str):
    rd = _report_data_hex(pubkey_hex)                 # 128 hex = 64 bytes, sha256(pk) left-aligned
    rd32 = rd[:64]                                    # just the 32-byte sha256(pubkey)
    quote, measurement, event_log, last_err = "", "", None, None
    # DSTACK_SOCK overrides the socket (e.g. the local TEE simulator for offchain testing).
    agents = list(GUEST_AGENTS)
    override = os.environ.get("DSTACK_SOCK")
    if override:
        agents.insert(0, (override, "/GetQuote", "/Info"))
    for sock_path, quote_method, info_method in agents:
        if not os.path.exists(sock_path):
            continue
        # Try each report_data body format and KEEP the quote only if it actually binds our value.
        got = None
        for body in _bodies(rd):
            try:
                q = _unix_post(sock_path, quote_method, body)
            except Exception as e:
                last_err = e
                continue
            cand = _first(q, ["quote", "tdx_quote", "Quote"])
            if cand and _quote_binds(cand, rd):
                got, quote = q, cand
                event_log = q.get("event_log") or q.get("eventlog") or q.get("event_log_json")
                break
            last_err = RuntimeError(f"{quote_method}: quote did not bind report_data (tried {list(body)})")
        if got is None:
            continue
        try:
            info = _unix_post(sock_path, info_method, {})
            measurement = _first(info, ["compose_hash", "mr_aggregated", "os_image_hash",
                                        "mrtd", "measurement", "rtmr3"])
        except Exception as e:  # info is best-effort
            last_err = e
        break
    if not quote:
        raise SystemExit(f"attestation: no dstack guest agent produced a quote that BINDS the pubkey "
                         f"({last_err}). Refusing to serve a cosmetic (unbound) attestation. "
                         "Confirm the dstack socket + GetQuote reportData contract.")
    report = {
        "evidence": "intel-tdx-quote",
        "measurement": measurement,
        "report_data": rd,
        "report_data_binding": "sha256(notary_pubkey_bytes) in the first 32 bytes",
        "notary_pubkey": pubkey_hex,
        "quote": quote,
        "event_log": event_log,  # RTMR3 event log for replay against the quote
    }
    with open(out_path, "w") as f:
        json.dump(report, f)
    print(f"attestation: wrote {out_path} (measurement={measurement[:16]}..., "
          f"binds pubkey {pubkey_hex[:12]}...)", file=sys.stderr)

def serve(out_path: str, port: int):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.rstrip("/") != "/notary/attestation":
                self.send_response(404); self.end_headers(); return
            try:
                with open(out_path, "rb") as f:
                    body = f.read()
            except OSError:
                self.send_response(503); self.end_headers()
                self.wfile.write(b'{"error":"attestation not ready"}'); return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):  # quiet
            pass
    HTTPServer(("0.0.0.0", port), H).serve_forever()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--out", default="/data/attestation.json")
    ap.add_argument("--port", type=int, default=7048)
    args = ap.parse_args()
    pubkey = os.environ.get("PUBKEY", "").strip().lower()
    if args.refresh:
        if not pubkey:
            raise SystemExit("PUBKEY env required for --refresh")
        refresh(pubkey, args.out)
    if args.serve:
        serve(args.out, args.port)
