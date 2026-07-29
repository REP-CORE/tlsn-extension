# Disclosure levels: what the new prover entry points do, and the rule that binds them

Added on `feat/disclosure-levels`. Additive: `notarize()` is unchanged and every
existing caller keeps working.

Cross-repo rollout order is in `rep-context-mcp/ROLLOUT.md`. The part that matters
here: **this branch and `Product` `feat/disclosure-levels` move together.** The app
calls `notarizeLevels`, the symbol only exists once the xcframework is rebuilt from
this branch, and the xcframework is gitignored so it does not travel with a merge.
Merging the app without rebuilding produces a compile error naming `notarizeLevels` —
which is the good outcome. Rebuilding from the WRONG branch produces a framework that
links and lacks the symbols, which is worse.

```
bash build-ios.sh
cp -R target/TlsnMobile.xcframework target/swift/tlsn_mobile.swift \
      <Product>/mobile-app/test-kit/tlsn-build/ios/
```

The previous framework should be kept beside the new one as
`TlsnMobile.xcframework.bak-<stamp>`; that is the rollback.

## The entry points

| Function | Use it when | Keeps |
| --- | --- | --- |
| `notarize` | unchanged behaviour | one presentation |
| `notarize_levels(req, opts, levels)` | **the default for new work** | one presentation per level, no plaintext |
| `notarize_capture` + `open_presentation` | a level must be chosen later, at unknown times | the FULL transcript on the device |

Prefer `notarize_levels`. `Secrets` contains the whole transcript, cookies and bearer
tokens included, so the capture path moves session plaintext to rest inside the app —
a different security posture, and hard to distinguish from a credential stealer by
anyone reading what the binary keeps. The levels a template presents at are known when
the template is written, so build them while the openings are in memory and let them
die with the call.

## The rule that decides what is possible

**A hash commitment is atomic.** An opening must tile exactly with WHOLE committed
ranges, so a later presentment can drop entire committed ranges and nothing finer.
Asking for half of one fails with the uncovered bytes named.

Reading `TranscriptProofBuilder::reveal_inner` suggests otherwise — its `is_subset`
check passes for a sub-range and `build()` fails afterwards, in `cover_by`. That
misreading is how this was first sized, and it was wrong.

So **commit granularity, chosen at proof time, is the hard ceiling on every disclosure
level that proof will ever support**:

- a template WITH a reveal regex commits one range per match, so whole alternation
  branches can be dropped later (`"amount"` kept, `|\},"name"` dropped);
- a template WITHOUT one commits the response as a single range and can never be
  narrowed afterwards — it has to be re-cut at proof time first.

When adding a template, decide the narrowest thing anyone will ever want to show and
commit at least that finely. It cannot be fixed later without a new proof.

## Checking it

```
cargo run -p tlsn-mobile --bin reopen-check
```

Mints a real notary-signed session from a laptop and re-opens it narrower, offline. No
device, no login, one small HTTPS request. It asserts the narrowed proof carries the
same connection and notary, reveals strictly less, reveals the same bytes at the same
offsets, and that opening a never-committed field is refused rather than silently
producing a smaller proof.

Note `src/bin/` is covered by `.gitignore` (`bin/`), so a new binary needs
`git add -f`, same as `rep_verify.rs`.
