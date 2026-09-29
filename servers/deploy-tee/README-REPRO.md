# TEE notary reproducibility (rep-notary-app)

Read this before trusting the pinned measurement.

## Honest state of the LIVE enclave (2026-09-29)

The currently running `rep-notary-app` image (Phala dstack TDX CVM, app-id
`e4cfd1c097b4a2d46bf37b1c855ece1acc68da25`, enclave key
`03c742652aa8ab879002e1dbe82731025cc13cc49c4de8b5f4770dcaf0cbd67d9e`, measurement
`734bb62ff16f0e179770d0fab4345d084b9cb935840c1a97c70051a030c4499b`) **corresponds to NO committed
source state.** It was built from a dirty local working tree (`~/dev/tlsn-extension/servers`) whose
build staging went to a `mktemp` dir with no log. So today **nobody can rebuild that measurement from
source** — which is what a pinned measurement is supposed to let an auditor do. This branch does NOT
imply the live enclave matches it. The number becomes verifiable only after the step-3 rebuild below,
which mints a new key + measurement and is gated on an explicit founder go (it breaks the public-fact
track until all pins are updated).

## What the notary actually is

The reviewed minimal notary source = `tlsn-extension` `servers/verifier` + `servers/swissbank` at
commit `20d91bd` PLUS these deliberately-written notary changes (the 5b `/attest-digest` fast-path):

- `servers/verifier/src/present_verify.rs` — `attest_digest_handler` + `AttestQuery`/`AttestResult`:
  the notary re-signs a compact domain-separated statement binding `blake3(presentation)` so an agent
  can verify with only secp256k1 + blake3. NOT an oracle: it signs only a presentation that verifies
  (WebPKI + this notary's own co-signature).
- `servers/verifier/src/main.rs` — the `/attest-digest` route.
- `servers/verifier/Cargo.toml`, `packages/tlsn-mobile/build-ios.sh`, `servers/fly.verifier.toml`.

The deploy kit is this `deploy-tee/` directory (`Dockerfile.tee`, `entrypoint.sh`, `keygen.sh`
[in-enclave secp256k1 keygen], `attestation_server.py` [DCAP sidecar], `dstack-app-compose.yml`,
`build-notary-tee.sh`, `README-DEPLOY.md`). No secrets live here: no `notary.env`, no keys. The
on-chain anchor (the NEAR contract, its script and README) is deliberately NOT in this branch — it is
separate R&D, not part of the TEE notary or its reproducibility.

## Build pinning (done) and what remains (validated at rebuild)

DONE in `Dockerfile.tee`:
- both base images pinned by `@sha256:` digest instead of floating `bookworm` tags,
- `ARG GIT_HASH` wired: `build-notary-tee.sh` passes the real commit SHA and REFUSES a dirty tree
  (`ALLOW_DIRTY=1` to override knowingly), so no future image records an unknown source again.

REMAINING (do at the rebuild, where it can actually be build-tested): the two `apt-get install`
lines are not version-pinned, so apt mirror drift can still perturb the binary. Pin via
`snapshot.debian.org` (fixed timestamp) or exact package versions, then confirm determinism by
building twice and getting an identical measurement. Not done blind here because this kit builds only
on Fly's remote builder and cannot be validated locally.

## Step 3 — the rebuild that makes the number defensible (GATED, founder go required)

1. Commit the source above + this kit to branch `choly/tee-notary` in `REP-CORE/tlsn-extension`
   (never `main`/`production`).
2. Finish apt pinning; rebuild ONLY from the committed tree (`build-notary-tee.sh` enforces this).
3. Re-attest and publish the triple a third party checks: **commit SHA + image digest + measurement**.
4. Re-pin the new key + measurement everywhere they appear (`prove_public_fact.rs`,
   `prove-anything/src/policy.mjs`, `notary-tee-migration/APP-PATCH.md`, the HANDOFF) and redeploy
   flexrep — as ONE landing so nothing runs on a stale pin.

Until step 3 lands, treat `734bb62f…` as an operational pin, not an auditable one.
