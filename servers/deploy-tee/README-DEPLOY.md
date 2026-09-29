# Deploy the REP notary in a NEAR AI / Phala TEE (dstack), ready-to-use for verifiable proofs

This kit makes the zkTLS public-fact engine deploy-ready on a TDX TEE and usable by agents. It
removes the one soft trust assumption in a REP proof (that REP runs an honest, non-colluding notary):
the notary runs inside a Phala dstack TDX enclave, generates and seals its own signing key, and binds
that key into a TDX attestation quote. A relying party (an agent) verifies the quote + a pinned image
measurement and then trusts the fact from hardware + audited code, not from trusting REP.

## Pieces

- `keygen.sh` - in-enclave secp256k1 key (never operator-injected). Prints scalar (the notary's
  `NOTARY_SIGNING_KEY`) + compressed pubkey (what agents pin, what the quote binds). Tested: stable,
  64-hex scalar / 66-hex pubkey.
- `attestation_server.py` - `--refresh` asks the dstack guest agent for a TDX quote whose report_data
  binds the pubkey and writes the report; `--serve` exposes `GET /notary/attestation`. Tested: serve
  path returns the report.
- `entrypoint.sh` - key -> quote -> sidecar -> notary.
- `Dockerfile.tee` - notary image (from `servers/`) + openssl + python3 + the kit.
- `dstack-app-compose.yml` - the CVM's compose (notary + optional egress proxy). Its measurement is
  what agents pin.
- The agent client is the engine: `packages/tlsn-mobile/src/bin/prove_public_fact.rs` (durable copy in
  the parent dir).

## 1. Build + push the image

    cd <tlsn-extension>/servers
    cp -r <this kit> ./deploy-tee            # so the COPY paths in Dockerfile.tee resolve
    docker build -f deploy-tee/Dockerfile.tee -t <registry>/rep-notary-tee:v1 .
    docker push <registry>/rep-notary-tee:v1
    # set that image in dstack-app-compose.yml

## 2. Deploy on Phala dstack

    phala auth login <api-key>
    phala cvms create --name rep-notary-tee --compose deploy-tee/dstack-app-compose.yml \
        --vcpu 2 --memory 4096
    # (confirm flags for your Phala Cloud / dstack version)

The CVM boots: entrypoint mints the in-enclave key, prints the pubkey to pin, refreshes the quote,
serves `/notary/attestation`, and starts the notary on :7047.

## 3. Read the attestation and PIN it

    curl https://<cvm-host>:7048/notary/attestation
    # -> {"evidence":"intel-tdx-quote","measurement":"<hex>","report_data":"<hex incl pubkey>","quote":"<hex>"}

Pin two things for agents: the notary PUBKEY (from the CVM log / notary-pubkey.hex, and it must appear
inside report_data) and the MEASUREMENT. Set `PINNED_NOTARY_MEASUREMENT` in the engine (or pass
`--measurement=<hex>`), and set `NOTARY_KEY` to the enclave pubkey (replacing the current fly key).

## 4. Agent usage (this is the "easy to verify and use" surface)

Prove a public fact, machine output:

    prove_public_fact https://api.github.com/repos/tlsnotary/tlsn \
      --reveal='"full_name":\s*"[^"]*"|"stargazers_count":\s*[0-9]+|"created_at":\s*"[^"]*"' \
      --out=/tmp/p.bin --json
    # stdout: {"ok":true,"facts":[...],"server_name":"api.github.com","time_secs":...,
    #          "key_matches":true,"notary_key":"...","trust":"operator-pinned","presentation_file":"/tmp/p.bin"}

Verify a proof (offline, pure crypto) and raise trust with the notary attestation:

    curl -s https://<cvm-host>:7048/notary/attestation > /tmp/att.json
    prove_public_fact verify /tmp/p.bin --attestation=/tmp/att.json --measurement=<pinned> --json
    # stdout includes "trust":"hardware-tee","tee_measurement":"<hex>"  when the quote binds this
    # notary's key under the pinned image. Add --require-tee to a prove call to FAIL CLOSED unless
    # the proof is hardware-attested.

An agent flow is: call prove -> get the fact + presentation_file + notary_key; call verify with the
notary attestation -> get trust=hardware-tee before acting on the fact. Both are one command, JSON in
/ JSON out, no REP in the loop for verification.

## 5. The proxy (egress)

The notary in Proxy mode dials the target itself, from the CVM's IP. Public sources split into:
- OPEN (APIs, simple pages): work from the CVM directly; a clean/residential egress proxy just makes
  rate-limited sources reliable and keeps the exit IP off flagged datacenter ranges. Point
  `EGRESS_PROXY` / the `egress-proxy` compose service at a residential/rotating upstream.
- CHALLENGE (AWS WAF / Cloudflare / Datadome, e.g. booking): a clean IP is NOT enough. These need a
  real browser to solve the JS challenge and hold the token. That is a headless-browser solver service
  (device WKWebView already does it) that harvests the token and hands it to a token-bearing notarized
  request. Scope that as its own service; the engine already CLASSIFIES and refuses to mint a proof of
  a challenge page (egress: NeedsBrowser / challenge-or-block).

Note: `tokio::TcpStream::connect` does not honor `HTTPS_PROXY`. Two ways to actually route through the
proxy: (a) no code - route the CVM's egress through the proxy at the network layer (transparent proxy
+ default route in the compose network); (b) small code change - in `verifier.rs` Proxy branch, dial
the proxy and issue an HTTP CONNECT to `host:443` before the TLS `connect`. (a) is the deploy-only path
and is recommended first.

## Honest status / TODO before prod

- Attestation is a report-level PRE-FILTER today (same as `rep-concierge src/agent/attestation.ts`):
  it enforces TDX evidence + pinned measurement + pubkey binding, fail closed. Still to add for a full
  cryptographic gate: verify the TDX quote SIGNATURE against Intel PCS collateral, echo a client NONCE
  for freshness/anti-replay, and bind the quote to the notary session key. Do this once and share the
  verifier between the private-inference TEE and the notary TEE.
- Confirm the dstack guest-agent socket path + prpc method + measurement field for your dstack version
  (attestation_server.py tries the known candidates and flags if none answer).
- Confirm openssl's secp256k1 compressed pubkey equals the notary's k256 pubkey for the same scalar
  (standard SEC1; verify once on first boot by comparing notary-pubkey.hex to a signed presentation's
  notary_key).
- The notary source (`servers/verifier`) is unchanged by this kit except the boot path (key from
  enclave instead of the `NOTARY_SIGNING_KEY` Fly secret) and the optional Proxy-mode dial patch.
