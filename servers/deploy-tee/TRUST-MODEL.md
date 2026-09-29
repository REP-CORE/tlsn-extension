# REP notary: trust model and how to verify it

This notary runs inside an Intel TDX enclave (a Phala dstack CVM) so that a relying party can VERIFY a
REP proof instead of trusting REP. This file is the "what / why / how" of the trust story. Deploy
mechanics are in `README-DEPLOY.md`; reproducibility rules are in `README-REPRO.md`.

## The claim, in one line

A REP public-fact proof lets you confirm that a real server (github, a bank, and so on) served a
specific fact over TLS, that only the revealed fields were disclosed, and that the notary which
co-signed it was audited, open-source code running in hardware that never saw your plaintext and whose
signing key never left the enclave. You do not have to trust REP for any of that.

## What you do NOT have to trust, and what closes each gap

| You might otherwise have to trust... | What actually closes it |
| --- | --- |
| that the server really served this | TLS plus the server's certificate chain. The notary cannot forge what the server's TLS keys signed. |
| that REP's notary is honest and non-colluding | the signing key is BORN inside the TDX enclave and never leaves it; a DCAP quote binds it to the hardware. |
| that the enclave runs the honest notary code, not a tampered build | the MEASUREMENT in the quote, compared against the published value for the audited code. |

The last row is the one that is easy to get wrong, so the rest of this file is about it.

## Why the measurement is load-bearing (do not drop it)

Three separately-true facts add up to a trap:

1. The enclave key is sealed to the CVM's volume and SURVIVES a redeploy.
2. It therefore also survives a redeploy of DIFFERENT code.
3. Anyone who can deploy to the CVM (us today, whoever holds the credentials tomorrow) could run a
   notary that logs your plaintext, keep the same key, and pass every check that only looks at the key.

So a quote that binds only the key proves CUSTODY of a key and says nothing about what the enclave is
running. The image digest and the source commit (`GIT_HASH`) do not close this either: they describe
an artifact WE built, not the artifact the enclave LOADED. The MEASUREMENT is the only value that is
reported BY the enclave and derived FROM the code it loaded. Skip it and the TDX quote is decoration,
and the trust model silently degrades to "trust REP".

Key-only verification is "trust us". Measurement verification is "verify it yourself", which is the
entire point of REP.

## The measurement is a CURRENT, DATED fact, not an immutable pin

The dstack measurement CHANGES ON EVERY (RE)DEPLOY, even for identical source, because dstack wraps
the app-compose per deploy and `phala deploy` and `phala cvms upgrade` wrap it differently. Therefore:

- Do NOT hard-compile one measurement as if it were permanent. That is what makes a pin "fragile", and
  the fragility is a property of the constant, not of the concept.
- DO publish the measurement as a current, dated value together with the commit and image digest it
  corresponds to (see the history table at the bottom).
- A verifier reads the LIVE attestation, compares its measurement to the published current value, and
  on a mismatch concludes "this enclave is not running the code REP published as of <date>", rather
  than passing silently.
- Every published measurement keeps its row in the history, next to the commit and image digest that
  produced it, so a specific dated proof can be walked back to the code that was running when it was
  minted.

## How to verify a REP public-fact proof, end to end

1. Recompute `blake3(presentation_b64)` and check it equals the bundle's digest (the on-chain anchor id).
2. POST the raw presentation bytes to the independent verifier with the bundle's own `notary_key`;
   expect `key_matches=true`. This checks the TLS binding and the notary co-signature.
3. Read the on-chain anchor for that digest.
4. Fetch the live notary attestation (`/notary/attestation`), verify the TDX quote to the Intel PCS
   root, confirm `report_data` binds `sha256(notary_pubkey)`, and compare the quote's MEASUREMENT to
   the published current measurement for the date the proof was minted (history below). A match means
   the enclave was running the audited, open-source notary at that commit.

## Build and deploy rules (so the measurement means something)

- Base images are pinned by `sha256` digest in `Dockerfile.tee`, not floating tags.
- `GIT_HASH` (the source commit) is passed at build, and `build-notary-tee.sh` REFUSES a dirty tree, so
  no image is ever built from source that exists nowhere but one laptop.
- Reference the image in the compose in a form dstack ACCEPTS (a plain deployment tag). A combined
  `tag@sha256:digest` reference was rejected on 2026-09-29 and the CVM failed to create a container.
- On a deploy: change ONE thing at a time from the last known-good compose, get dstack to CONFIRM it
  accepted the compose, and confirm the enclave BOOTS and attests, BEFORE publishing the new
  measurement. Do not infer acceptance from a boot, or a boot from a successful build.
- After a successful deploy: read the live `{measurement, notary_pubkey}` off the attestation, add a
  history row (measurement, date, commit, image digest), update the published current measurement, and
  only then point relying parties at it.

## Operational lessons (2026-09-29)

- A same-image rollback via `phala cvms upgrade` produced a different measurement than the original
  `phala deploy`, so measurement `734bb62f` is gone and not recoverable by rolling the image back.
- The enclave key `03c742` persisted across a failed upgrade and the rollback (sealed volume), which is
  exactly why key-only is not enough (see "Why the measurement is load-bearing").
- flexrep verifies each proof against the key carried in its own bundle, so it kept serving throughout;
  the measurement in the published policy is a REFERENCE for third-party diligence, not a per-proof gate.
- App proxy proofs run against a separate Fly notary and were not involved.

## History of published measurements

Append one row per deploy. A `notary_measurement` published in the policy MUST have a row here.

| date started | measurement | commit | image digest | notes |
| --- | --- | --- | --- | --- |
| (pending next verified rebuild) | | | | `734bb62f` and `18c5c572` are superseded and were never published as verified; see README-REPRO |
