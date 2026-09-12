# Phase 14 verification record

Date: 2026-09-12. Host: Windows x64. Branch: `phase-14-closure`.
Base commit: `83a1dd1190ab7ba7cc77baa70b68029bdb8ab3c8`.
These results describe the uncommitted working-tree changes, not a published or
audit-pinned commit. The pre-existing untracked `.serena/` directory was preserved.

## Execution evidence

Local raw output is retained in ignored `phase14-*.log` files. Exit codes, rather
than absence of visible errors, determine pass/fail. No skipped native check is
counted as a pass.

| Command / check | Result | Evidence |
| --- | --- | --- |
| `npm run quality` | Passed before the final key-lifetime fix; final rerun pending | 424 Node tests, 8 platform-artifact tests, 12 release tests, 4 updater acceptance contract tests, 143 desktop tests; lint, formatting, typecheck and desktop build passed |
| `npm run quality:rust` | Passed | Clippy with warnings denied; 89 library tests |
| Key lifetime regression tests | Passed after reproducing both failures | Two tests in `test/sync-epoch.test.mjs`; retiring/legacy buffers cleared and epoch-key copies reused then cleared |
| `npm run recovery:drill` | Passed | Verified encrypted backup, signed checkpoint and relay catch-up; seven live objects, duplicate apply idempotence, bookmarks/layouts/views retained |
| `npm run benchmark` | Passed | 1,000 notes; unlock/index 414.23 ms, quick-switch p95 0.39 ms, full-text p95 0.76 ms |
| `npm run benchmark:10k` | Passed | 10,000 notes; unlock/index 372.68 ms, quick-switch p95 3.60 ms, full-text p95 3.93 ms |
| `npm run benchmark:100k` | Failed performance gate | 100,000 notes: quick-switch p95 26.23 ms and full-text p95 29.07 ms passed; title-shaped search p95 128.56 ms exceeded the 100 ms tier limit. No threshold was relaxed. |
| `VBRAIN_REQUIRE_NATIVE_KEYCHAIN=1 node --test test/native-keychain.test.mjs` | Passed | Windows DPAPI: create/read/delete isolated synthetic credential; sandbox initially denied profile write, authorized elevated rerun passed |
| Isolated packaged sync helper | Passed | Copied sidecar to a temporary directory outside the repository; bundled Node starts without repository dependencies; caught and fixed missing YAML dependency |
| Native Windows package build | Interrupted during dependency compilation | The unsigned package was not produced; this does not establish production signature or updater acceptance |
| `npm run package:check` | Pending | Clean build must exclude the retired change-log module |
| `graphify update .` | Passed; refresh after final fix pending | AST-only update: 3,185 nodes, 8,909 edges, 181 communities |

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
| Phase 13 duplicate sync | 14.3 | Deleted `src/sync/change-log.ts`; wire functions owned by `src/sync/protocol.ts` and exported through `src/sync.ts`; type-only engine dependency; clean-dist package regression | Final quality/package checks |
| Phase 13 crypto domains | 14.3 | Central AAD values, explicit frozen JSON expectations, TS/Rust literal audit and negative omitted-domain test | Review any domain construction beyond the literal scanner's coverage; scanner is a guard, not a cryptographic audit |
| Phase 13 encrypted inventory | 14.3 | Index, plugin-policy, workspace/views and sync artifact metadata; actual writers checked against re-key plan; unknown/omitted artifact negative tests | Complete temporary journal/staging classification and a real-writer fixture covering every catalogue family; current writer fixture alone does not prove exhaustive coverage |
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

No production key or secret was generated/changed, no tag/push/publication was
performed, and no real signed updater transition has been claimed. Passing local
tests does not close Phase 14 or 1.0 readiness. Phase 13 remains open until its
remaining conformance coverage is complete. Personal memory remains an open
Phase 15 product task.
