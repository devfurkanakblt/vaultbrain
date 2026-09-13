# Phase 14 — Final four implementation ledger

Approved plan: the user's 2026-09-13 request, based on commit
`a86662f8840065eee8f066a4379d4aafd032c1c5` on `phase-14-closure`.

Work in the existing branch as requested; preserve `.serena/`. No publication,
production signing, real updater acceptance, or Phase 15 implementation.

## Tasks and acceptance

- [x] 4. Format inventory: explicit persistent/transient/nested/external and
  encrypted/control classification, source-domain references and both rotation
  policies; actual writers and interruption fixtures for every family, independent
  expected-family list, negative unknown/omitted/domain guards. No recovery or
  cleanup behavior changes.
- [x] 2. Search: four-term session LRU, Uint8Array values 0–10 and 255 sentinel,
  maximum term length 256, clear on index invalidation and zero on lock. Preserve
  ranking/grammar and compare to uncached reference including edits/rebuild/lock.
- [x] 1. One final quality run, package manifest inspection, one run per benchmark
  size with no competing heavy work, Graphify refresh, exact evidence update.
- [x] 3. Release-mode unsigned Windows MSI and NSIS packages, extracted helper
  smoke check, hashes/sizes/signature evidence, separate reviewable commits.

## Execution notes

- Initial working tree clean. Format task delegated to `format_completion`;
  parent owns packaging preparation, integration and evidence. Search follows
  format completion. Focused tests only until final verification.
- Implementation commit: `bff1d8c2a15fb7a1a4dcd08fac1adf3069d30cea`.
- The user confirmed the remaining quality, Rust, keychain, recovery, package,
  desktop and updater checks passed; Graphify was refreshed after the final
  code changes. The raw output for those user-run commands is not present in
  this workspace, so the verification record labels that evidence explicitly.
- Shared interfaces: format metadata is consumed by conformance/re-key checks;
  CLI deliberately projects only path/reads/writes. Search changes only documents
  runtime; native helper bundles its final output. Builds share `dist` and must
  be serialized. No contradictory format or API changes identified.
