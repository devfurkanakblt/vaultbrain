# Phase 14 verification record

Date: 2026-09-13. Host: Windows x64. Branch: `phase-14-closure`.
Implementation commit: `bff1d8c2a15fb7a1a4dcd08fac1adf3069d30cea`.
Parent: `a86662f8840065eee8f066a4379d4aafd032c1c5`.
The pre-existing `.serena/` directory and ignored measurement logs were preserved.
Rows marked user-confirmed record the user's completed commands; their raw
terminal output was not captured in this workspace.

## Execution evidence

Local raw output is retained in ignored `phase14-*.log` files. Exit codes, rather
than absence of visible errors, determine pass/fail. No skipped native check is
counted as a pass.

| Command / check | Result | Evidence |
| --- | --- | --- |
| `npm run quality` | User-confirmed pass | Local portion recorded 429 Node, 8 platform-artifact and 12 release tests; user confirmed updater acceptance, desktop tests and desktop build completed successfully |
| `npm run quality:rust` | User-confirmed pass | Clippy with warnings denied and Rust library tests completed successfully |
| Key lifetime regression tests | Passed | `test/sync-epoch.test.mjs`; retiring/legacy buffers cleared and epoch-key copies reused then cleared |
| `npm run recovery:drill` | User-confirmed pass | Backup, signed checkpoint, relay catch-up and idempotent recovery completed successfully |
| `npm run benchmark` | User-confirmed pass | 1,000-note performance gate passed; local run recorded quick-switch p95 0.90 ms and title-shaped p95 4.87 ms |
| `npm run benchmark:10k` | User-confirmed pass | 10,000-note performance gate passed; local run recorded quick-switch p95 4.81 ms and title-shaped p95 18.13 ms |
| `npm run benchmark:100k` | Passed | Final local run: quick-switch p95 26.01 ms, title-shaped p95 71.23 ms, full-text p95 29.36 ms, note-open p95 2.53 ms, backlinks p95 0.028 ms; all gates passed |
| `VBRAIN_REQUIRE_NATIVE_KEYCHAIN=1 node --test test/native-keychain.test.mjs` | User-confirmed pass | Windows DPAPI create/read/delete check completed successfully |
| Isolated packaged sync helper | Passed | Sidecar ran from an external temporary directory with bundled Node, YAML and ES-module metadata |
| Windows release package build | User-confirmed pass | MSI and NSIS artifacts were produced; see hashes below. Packages are unsigned local artifacts. |
| `npm run package:check` | User-confirmed pass | Package manifest check completed successfully and excluded retired source/tests/local vault data |
| `graphify update .` | User-confirmed pass | `graphify-out/` refreshed after final code changes; output is ignored generated state |

### Windows package evidence

| Artifact | Size | SHA-256 | Signature |
| --- | ---: | --- | --- |
| `src-tauri/target/release/bundle/msi/Vault Brain_0.2.0_x64_en-US.msi` | 43,196,454 bytes | `3B6A87830E95408075BC315131F1E8B74FF23779975D5C04D1466EEDD44792D9` | unsigned local package |
| `src-tauri/target/release/bundle/nsis/Vault Brain_0.2.0_x64-setup.exe` | 29,295,855 bytes | `A57AEAD1EC54D503B9359CE55788B5E3441F19FC4E721E8D60BF9790CA6D820D` | unsigned local package |

## Ownership and acceptance

| Source obligation | Owner | Implemented/tested evidence | Remaining acceptance |
| --- | --- | --- | --- |
| Phase 6 portable sync and device lifecycle | 14.1 | Canonical protocol, sync/epoch/blob/transaction tests, portable recovery drill, desktop sync tests | Actual two-desktop enrollment, transfer, revoke/re-enroll, offline/cancel/lock walkthrough with platform evidence |
| Phase 7.7 retention classification | 14.2 | `test/rekey-vault.test.mjs`: retention survives re-key | Included in full final verification |
| Phase 7.7 Rust legacy identity | 14.2 | Rust keyring conformance and re-wrap tests, 89-test suite | Independent review of final pinned commit |
| Phase 7.7 authenticated audit events | 14.2 | Pending/allowed/denied and interrupted audit tests in `test/rekey-vault.test.mjs` | Independent review of final pinned commit |
| Phase 7.7 unsupported keysets | 14.2 | TypeScript keyset tests and Rust fail-closed handling | Ordinary re-key still explicitly refuses epoch >=2 sync changes; Rust refuses an unfinished transitional keyset |
| Phase 7.7 recovery current/retiring keys | 14.2 | `test/keyring-recovery.test.mjs`, including newly covered epoch-2 recovery verification | Exhaustive transition-by-transition coverage mapping remains to be signed off |
| Phase 7.6 identity rotation and lock recovery | 14.2 | Existing separate rotation/backup tests plus live PID reuse and concurrent recovery regression tests | Same-host dead-process-only policy retained; no forced unlock acceptance |
| Phase 13 duplicate sync | 14.3 | Deleted `src/sync/change-log.ts`; wire functions owned by `src/sync/protocol.ts` and exported through `src/sync.ts`; type-only engine dependency; clean-dist/package checks passed | Independent review remains a release-governance item |
| Phase 13 crypto domains | 14.3 | Central AAD values, explicit frozen JSON expectations, TS/Rust literal audit and negative omitted-domain test | Scanner is a guard, not an independent cryptographic audit |
| Phase 13 encrypted inventory | 14.3 | Persistent/transient/nested/external metadata, all observed writer families, interruption fixture, re-key classification and unknown/omitted artifact negatives | Independent review of the final pinned commit |
| Phase 7.6 personal memory product integration | 15 | Modules/tests retained; separate Phase 15 design and implementation plan | Native broker, explicit pairing, unlocked session lifecycle, MCP/desktop controls, review/forget, restore/re-key compatibility |
| Phase 12 release acceptance and security audit | 14.5 | Existing release contract tests and updated audit/release documentation | Independent auditor, pinned final commit, production key/backup/Actions setup, verified draft packages/SBOM/provenance, real signed vN→vN+1 on Windows x64/macOS ARM64/Linux x64 |

## Review corrections

A separate agent reviewed the protocol, recovery resolver, inventory, native helper
and desktop changes. Two medium findings concerned secret-buffer lifetime and
were reproduced by failing tests before repair. The reviewer checked the repairs
and reported no remaining substantive finding in that scoped review. This is development review,
not the independent security audit required for 1.0.

The installed helper regression reproduced `ERR_MODULE_NOT_FOUND` for `yaml` in a
clean external directory. The builder now includes its runtime dependency and an
ES-module package marker. Generated binaries remain ignored by Git.

## Release boundary

Phase 13 and the 14.3 conformance work are closed on the implementation commit.
No production key or secret was generated/changed, no tag/push/publication was
performed, and no real signed updater transition has been claimed. General 1.0
readiness still requires the independent security audit, protected production
signing setup, and real signed vN→vN+1 acceptance on Windows x64, macOS ARM64
and Linux x64. Personal memory remains an open Phase 15 product task.
