# Phase 6 — Encrypted Sync and Multi-Device Implementation Plan

> **For Codex:** REQUIRED SUB-SKILLS: use `subagent-driven-development` to
> execute this plan task-by-task, `test-driven-development` for every behavior
> change, and `verification-before-completion` at each phase gate.

**Goal:** Deliver recoverable encrypted sync, portable vault state, authenticated
multi-device membership, one untrusted relay artifact, desktop parity, and the
evidence required for an audited 1.0 format freeze.

**Architecture:** Preserve the protocol-v1 TypeScript API while separating its
protocol, snapshot, log, transaction, and engine responsibilities. Add a
recoverable local transaction and apply-receipt model before widening object
coverage. Introduce manifest-v2 wrapped keys and signed membership epochs, then
an opaque Axum relay and a shared Rust protocol crate. Expose only narrow Tauri
commands and reuse the common React UI in the desktop shell.

**Tech stack:** TypeScript/Node.js, Vitest, Rust stable, Cargo, Tauri v2, React,
Axum, SQLite, PostgreSQL adapter, object-store adapter, Docker/Compose.

**Design authority:**
`docs/superpowers/specs/2026-08-31-phase-6-sync-multi-device-design.md`

## Global constraints

- Legacy vaults and protocol-v1 envelopes remain readable after every task.
- `src/sync.ts` stays a compatibility barrel; existing public exports and
  low-level CLI diagnostics remain available.
- Portable state is notes, canvases, attachments, plugin packages,
  `plugin-policy`, `saved-views`, and `workspace` including bookmarks. Grants,
  audit, plugin storage, theme, enabled state, and device preferences stay local.
- A received plugin is disabled and cannot execute without local enablement.
- The relay never receives plaintext, keys, object types, client timestamps, or
  searchable metadata.
- No roadmap checkbox closes before its focused tests and phase acceptance gate
  pass. Do not set version 1.0 or recommend sensitive data before independent
  audit remediation is complete.
- Every behavioral task must record an observed RED test before production code,
  then the focused GREEN run. Refactors use characterization/golden tests first.
- Sync-enabled incremental save p95 is below 20 ms, 100k-note unlock below 2 s,
  and acknowledged writes have RPO 0.
- Application code never logs passphrases, root/document/epoch keys, invite
  secrets, recovery words, bearer capabilities, decrypted snapshots, or raw
  envelope contents.
- Cross-language fixtures are byte-for-byte authoritative. A TypeScript/Rust
  disagreement is a release blocker, never resolved by accepting both outputs.

## Phase 6A — Sync foundation hardening

### Task 1: Split protocol modules and freeze v1 fixtures

**Files:**

- Create: `src/sync/protocol.ts`
- Create: `src/sync/snapshots.ts`
- Create: `src/sync/change-log.ts`
- Modify: `src/sync.ts`
- Create: `test/fixtures/sync-v1/golden.json`
- Create: `test/fixtures/sync-v1/adversarial.json`
- Create: `test/sync-protocol.test.mjs`
- Modify: `docs/superpowers/specs/2026-08-31-phase-6-sync-multi-device-design.md`

**Steps:**

1. Add characterization tests for every current public v1 export, canonical
   body, keyed ID, encrypted-open result, graph verification result, and error
   class/message relied on by CLI tests. Check in deterministic golden inputs;
   randomness must be injected or fixtures must compare the deterministic body,
   ID, and opened value rather than nonce bytes.
2. Add adversarial cases for wrong key, tamper, noncanonical plaintext/base64,
   unsafe keys, surrogate errors, limit boundaries, malformed IDs, duplicate
   parents, missing parents, cycle, device fork, and revision jump. Observe the
   focused tests before moving code.
3. Move canonicalization/envelope/body validation into `protocol.ts`, snapshot
   conversion/parsing into `snapshots.ts`, and immutable graph/log behavior into
   `change-log.ts`. Do not change behavior in this task.
4. Re-export the existing symbols from `src/sync.ts`. Keep the compatibility
   import path green and avoid circular dependencies.
5. Update the normative spec only where fixture evidence reveals a missing exact
   value. Run focused protocol tests, the existing sync suite, typecheck, lint,
   and format check; commit code, fixtures, and documentation together.

### Task 2: Make local capture a recoverable transaction

**Files:**

- Create: `src/sync/transaction.ts`
- Modify: `src/sync/snapshots.ts`
- Modify: `src/sync.ts`
- Modify: `src/documents.ts` only for a narrow mutation/fault seam if required
- Create: `test/sync-transaction.test.mjs`
- Modify: `test/sync.test.mjs`

**Steps:**

1. Add failing tests proving a missing/invalid device ID leaves zero disk changes
   for note, canvas, attachment put/delete and `putMany`.
2. Add a deterministic fault injector at each durable phase: intent prepared,
   storage written, envelope installed, cursor written, and intent cleared.
   Restart/unlock after each injected failure and assert one logical mutation,
   one envelope, one cursor advance, and no orphan intent.
3. Define an encrypted pending-intent schema and AAD. Prevalidate the unlocked
   session, device ID, snapshot, size, object ID, expected revision, and batch
   before the first storage mutation.
4. Implement the durable phase machine with atomic writes/fsync and roll-forward
   recovery on unlock. Preserve ordinary non-sync vault behavior.
5. Make `putMany` one acknowledged batch transaction: prevalidation failure
   changes nothing; crash recovery completes every member exactly once.
6. Run focused fault tests, all sync/document tests, typecheck, lint, and format
   check; commit with RED/GREEN evidence.

### Task 3: Apply asymmetric DAGs exactly once

**Files:**

- Create: `src/sync/engine.ts`
- Modify: `src/sync/change-log.ts`
- Modify: `src/sync/transaction.ts`
- Modify: `src/sync.ts`
- Create: `test/sync-apply.test.mjs`

**Steps:**

1. Add a failing asymmetric-DAG fixture where the clean winner merges a branch
   not descended from the current cursor. Assert deterministic ancestry order
   and successful apply.
2. Add failing crash tests for storage success before apply-receipt/cursor write
   on notes, canvases, attachments, puts, and deletes. Assert replay never adds
   a second revision/history entry.
3. Implement a deterministic same-object ancestry planner from the winner back
   to the already applied frontier. Reject cycles/missing revisions without live
   writes; do not filter away required ancestors by cursor descendants alone.
4. Persist an encrypted apply receipt containing target change ID, expected live
   identity/revision, operation, and phase. Recovery recognizes an already
   materialized target and advances the cursor without a second storage call.
5. Return an explicit conflict result without live writes when more than one
   head remains.
6. Run focused DAG/crash tests and all sync/document suites; commit.

### Task 4: Prevalidate snapshots and harden public APIs

**Files:**

- Modify: `src/sync/snapshots.ts`
- Modify: `src/sync/change-log.ts`
- Modify: `src/sync/engine.ts`
- Modify: `src/sync.ts`
- Modify: `src/cli.ts`
- Create: `test/sync-prevalidation.test.mjs`
- Modify: `test/cli.test.mjs`

**Steps:**

1. Add failing tests for attachment content-ID mismatch, invalid note/canvas
   snapshot fields late in a batch, and cursor movement to a sibling/ancestor.
   Assert no live artifact, history, admitted envelope, or cursor remains.
2. Parse and semantically validate the entire apply set before the first live
   write. Compute attachment content IDs from decoded bytes before calling the
   storage API.
3. Make cursor mutation internal/protected and enforce monotonic causal advance
   inside the transaction/apply path.
4. Preserve `verifySyncChanges` as a structural compatibility alias. Export and
   use an explicitly named authenticated-envelope verifier for cryptographic
   verification; update CLI help/output so the distinction is unambiguous.
5. Expand `SyncApplyResult.objectType` to the complete portable union without
   claiming unsupported live apply behavior.
6. Run focused tests, all CLI/sync/document tests, typecheck, lint, and format;
   commit.

### Task 5: Close the Phase 6A integration gate

**Files:**

- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ROADMAP.md`
- Create: `test/sync-cli-e2e.test.mjs`
- Create: `scripts/benchmark-sync.mjs`
- Modify: `package.json`

**Steps:**

1. Add a CLI end-to-end test that captures locally, exchanges encrypted objects
   between two vault copies, applies remotely, survives a fault/restart, and
   resolves a conflict without exposing plaintext in the exchange directory.
2. Add a repeatable incremental-save benchmark with sync enabled and a recorded
   p50/p95 result. Fail the gate at p95 20 ms or above after warm-up.
3. Correct README/architecture drift about 10k/100k measurements, Rust lookup
   maps, IPC terminology, and the actual sync guarantees/limitations.
4. Run `npm run lint`, `npm run format:check`, `npm run typecheck`, `npm test`,
   `npm run desktop:test`, `npm run desktop:build`, existing benchmarks, the new
   sync benchmark, Cargo fmt/clippy/test, and package checks.
5. Close only the Phase 6A roadmap entries whose evidence is present. Commit the
   integration/docs change.

## Phase 6B — Portable vault state and complete protocol

### Task 6: Synchronize plugin packages and fail-closed policy

**Files:**

- Modify: `src/documents.ts`
- Modify: `src/cli.ts`
- Modify: `src/sync/snapshots.ts`
- Modify: `src/sync/engine.ts`
- Create: `test/sync-plugin.test.mjs`

**Steps:**

1. Add failing capture/apply tests for plugin install, signed update, remove,
   signer change, and a receiving device that remains disabled.
2. Add failing concurrent-policy tests proving restricted mode is OR and revoked
   signer/device collections are unions; a weakening restore must name every
   head and require an explicit resolution input.
3. Route CLI plugin mutations through the sync-aware mutation service. Capture
   portable package bytes/metadata and the fixed `vault/plugin-policy` object;
   never capture plugin storage, grants, or enabled state.
4. Prevalidate signatures and package identity before live apply. Conflicts in
   package update/remove stay manual and execute no plugin code.
5. Run focused plugin/policy tests and the full TypeScript gate; commit.

### Task 7: Synchronize saved views, workspace, and safe note merges

**Files:**

- Modify: `src/documents.ts`
- Modify: `src/sync/snapshots.ts`
- Modify: `src/sync/engine.ts`
- Create: `src/sync/conflicts.ts`
- Create: `test/sync-vault-state.test.mjs`
- Create: `test/sync-conflicts.test.mjs`

**Steps:**

1. Add failing round-trip tests for fixed `saved-views` and `workspace` objects,
   including bookmarks, and negative tests proving theme/grants/audit/plugin
   storage/device preferences never enter snapshots.
2. Add three-way note fixtures for non-overlapping/overlapping body edits,
   property/path/title comparisons, delete-vs-edit, and no common base.
3. Implement common-base discovery and auto-merge only non-overlapping note body
   or field changes. Canvas, delete-vs-edit, attachment, and plugin conflicts
   remain explicit manual resolutions.
4. Expose `listConflicts()` and `resolveConflict()` through the engine while
   retaining every head as parents of the resolution change.
5. Run focused state/conflict tests and the full TypeScript gate; commit.

### Task 8: Add resumable encrypted blob transport and checkpoint GC

**Files:**

- Create: `src/sync/blobs.ts`
- Create: `src/sync/checkpoints.ts`
- Modify: `src/sync/snapshots.ts`
- Modify: `src/sync/engine.ts`
- Create: `test/sync-blobs.test.mjs`
- Create: `test/sync-checkpoints.test.mjs`

**Steps:**

1. Add failing tests for 1 MiB chunk boundaries, wrong chunk/order/size/hash,
   resume after every chunk, duplicate upload, and full 250 MiB attachment
   round-trip using generated deterministic data without checking it in.
2. Implement independently encrypted keyed chunks and an authenticated manifest
   with whole-content integrity. Preserve inline protocol-v1 attachment reads.
3. Add checkpoint fixtures for long histories. GC is allowed only after every
   active device in the membership snapshot acknowledges the same checkpoint.
4. Test interrupted checkpoint install and a removed device changing the active
   acknowledgement set without deleting ciphertext prematurely.
5. Run focused tests plus long-history and save/unlock benchmarks; commit.

### Task 9: Close the Phase 6B integration gate

**Files:**

- Modify: `src/cli.ts`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ROADMAP.md`
- Create: `test/sync-conflict-cli-e2e.test.mjs`

**Steps:**

1. Finish engine-backed `sync status|run|conflicts|resolve` local/offline CLI
   behavior and retain low-level commands.
2. Exercise long histories, portable vault state, plugin fail-closed behavior,
   a 250 MiB resumed blob, and manual/automatic conflicts end to end.
3. Document conflict UX contracts and measured limits. Run the complete
   TypeScript/desktop/Rust/benchmark gate and close only evidenced roadmap items.
4. Commit the Phase 6B integration slice.

## Phase 6C — Device enrollment, removal, and key rotation

### Task 10: Introduce manifest v2 wrapped-key hierarchy

**Files:**

- Modify: `src/manifest.ts` or the repository's manifest module
- Modify: `src/document-crypto.ts`
- Modify: `src/documents.ts`
- Create: `src/key-hierarchy.ts`
- Create: `test/fixtures/manifest-v1/`
- Create: `test/manifest-v2.test.mjs`

**Steps:**

1. Add failing fixtures for opening v1, successful backed-up migration, wrong
   passphrase, tampered wrapping, crash at every migration phase, and rollback.
2. Implement passphrase KEK → random vault root → wrapped random document keys.
   Zero temporary key buffers and make v1 migration atomic and repeatable.
3. Verify all legacy fixtures before switching the live manifest; restore the
   exact backup on injected failure.
4. Run crypto/manifest/document/recovery suites and commit.

### Task 11: Add signed membership epochs and secure device keys

**Files:**

- Create: `crates/sync-protocol/`
- Create: `src/sync/membership.ts`
- Modify: `src/sync/protocol.ts`
- Modify: `src/sync/engine.ts`
- Modify: `src-tauri/Cargo.toml`
- Create: `src-tauri/src/device_keys.rs`
- Create: `test/sync-membership.test.mjs`

**Steps:**

1. Add protocol-v2 golden inputs for membership epoch, device signature, and
   rejection of unknown/removed/wrong-epoch signers.
2. Create per-device Ed25519 signing and X25519 exchange keys in native secure
   storage; expose operations, never key material, to higher layers.
3. Sign and verify v2 bodies against the authenticated membership snapshot.
   Continue reading v1 while new enrolled devices default to v2 writes.
4. Establish the shared Rust crate's canonical types/validation and prove the
   initial TS↔Rust fixtures agree. Run both language gates and commit.

### Task 12: Enroll, remove, rotate, and recover devices

**Files:**

- Modify: `src/sync/membership.ts`
- Modify: `src/sync/engine.ts`
- Modify: `src/cli.ts`
- Create: `src/sync/recovery.ts`
- Create: `test/sync-enrollment.test.mjs`
- Create: `test/sync-rotation.test.mjs`
- Create: `test/sync-recovery.test.mjs`

**Steps:**

1. Add failing tests for ten-minute expiry, replay, wrong vault, interrupted
   handshake, inactive inviter, removed-device denial, interrupted rotation,
   and recovery-word checksum errors.
2. Implement one-use invitation and authenticated ephemeral exchange exposing
   only relay URL, opaque vault ID, and handshake material.
3. Removal creates a new membership epoch, sync key, and relay capability and
   wraps them only to active devices. CLI/UI text explicitly states that
   previously downloaded ciphertext cannot be revoked.
4. Generate a checksum-protected 24-word offline recovery kit and test a fresh
   device restore without relay-held recovery material.
5. Complete `sync init|invite|enroll|devices|remove|rotate|recovery`; run all
   security/fault/cross-language suites and commit.

### Task 13: Close the Phase 6C migration and parity gate

**Files:**

- Modify: `test/fixtures/sync-v2/`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ROADMAP.md`

**Steps:**

1. Freeze v2 TS/Rust byte-for-byte fixtures for canonical bodies, IDs,
   signature verification, envelope open, and conflict results.
2. Run v1 read/v2 write, migration rollback, removal/rotation, and fresh-device
   recovery drills. Run the full phase gate and document measured evidence.
3. Close only evidenced Phase 6C roadmap items and commit.

## Phase 6D — Untrusted relay and self-hosting

### Task 14: Build the opaque Axum relay core

**Files:**

- Create: `Cargo.toml` workspace definition if absent
- Create: `relay/Cargo.toml`
- Create: `relay/src/lib.rs`
- Create: `relay/src/main.rs`
- Create: `relay/src/api.rs`
- Create: `relay/src/storage.rs`
- Create: `relay/tests/api.rs`

**Steps:**

1. Add failing black-box tests for idempotent object create, batch atomicity,
   fetch-by-ID, bounded cursor pagination, duplicate retry, malformed opaque IDs,
   and payload/metadata size rejection.
2. Implement an Axum API accepting only opaque vault/object IDs, ciphertext, and
   protocol-required cursors/acknowledgements. Reject object type, plaintext,
   client timestamp, and arbitrary searchable metadata fields.
3. Define a storage trait whose contract prevents overwrite of an existing ID
   with different bytes and makes page cursors stable.
4. Run Rust unit/integration tests, fmt, and clippy; commit.

### Task 15: Add relay backends, capabilities, quotas, and detection evidence

**Files:**

- Create: `relay/src/sqlite_fs.rs`
- Create: `relay/src/postgres_object_store.rs`
- Create: `relay/src/auth.rs`
- Create: `relay/src/quota.rs`
- Modify: `relay/src/api.rs`
- Create: `relay/tests/compatibility.rs`
- Create: `relay/tests/adversarial.rs`

**Steps:**

1. Add one compatibility suite run against in-memory, SQLite/filesystem, and
   PostgreSQL/object-store adapters. Add duplicate, omission, equivocation,
   quota, rate, invalid capability, and removed-capability tests.
2. Store only hashes of high-entropy device-scoped bearer capabilities and
   rotate them with membership removal.
3. Enforce configurable byte/object/rate/page quotas before durable allocation.
4. Add device-chain/checkpoint comparison evidence surfaced to clients without
   trusting the relay's completeness claim.
5. Run the Rust and client integration suites; commit.

### Task 16: Package one hosted/self-host relay artifact

**Files:**

- Create: `relay/Dockerfile`
- Create: `relay/compose.yaml`
- Create: `relay/migrations/`
- Create: `relay/README.md`
- Create: `relay/scripts/backup.*`
- Create: `relay/scripts/restore.*`
- Modify: `.github/workflows/ci.yml`

**Steps:**

1. Add tests that boot the same binary in self-host and hosted profiles and run
   the compatibility suite against each.
2. Add versioned migrations and verified backup/restore, including interrupted
   restore and checksum failure tests.
3. Build a minimal non-root Docker image and Compose example. Document TLS
   termination, storage ownership, quotas, updates, backup, and restore.
4. Add CI jobs for relay integration and image build. Run the full phase gate,
   update architecture/roadmap, and commit.

## Phase 6E — Rust parity and desktop multi-device release

### Task 17: Complete the shared Rust protocol crate

**Files:**

- Modify: `crates/sync-protocol/`
- Modify: `src-tauri/Cargo.toml`
- Modify: `relay/Cargo.toml`
- Create: `crates/sync-protocol/tests/fixtures.rs`
- Modify: `test/fixtures/sync-v1/`
- Modify: `test/fixtures/sync-v2/`

**Steps:**

1. Port all canonicalization, limits, v1/v2 envelope, membership, DAG, conflict,
   chunk-manifest, and checkpoint validation into the shared crate.
2. Consume it from both relay and Tauri; forbid duplicate protocol validation in
   either binary.
3. Run the complete fixture corpus from TypeScript and Rust and fail on any byte
   or verdict mismatch. Add fuzz targets for canonical JSON, envelope opening,
   and DAG admission.
4. Run Rust fmt/clippy/test and fixture suites; commit.

### Task 18: Give Rust vault mutations recoverable sync capture

**Files:**

- Create: `src-tauri/src/sync.rs`
- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/src/vault.rs` or the actual storage module
- Create: `src-tauri/tests/sync_transactions.rs`

**Steps:**

1. Add failing Rust fault-injection tests matching every TypeScript pending
   transaction and apply-receipt phase.
2. Route Rust note/canvas/attachment/plugin/portable-vault mutations through one
   prevalidated capture service with identical intent/recovery semantics.
3. Permit only bounded opaque staging while locked. Decrypt, verify, admit, and
   apply after unlock.
4. Prove TS-produced pending/envelope/checkpoint fixtures recover identically in
   Rust where formats are shared. Run both language gates and commit.

### Task 19: Add narrow desktop IPC and multi-device UI

**Files:**

- Modify: `src-tauri/src/lib.rs`
- Modify: `src-tauri/capabilities/main.json`
- Modify: `desktop/src/types.ts`
- Modify: `desktop/src/bridge.ts`
- Create: `desktop/src/SyncSettings.tsx`
- Create: `desktop/src/SyncConflicts.tsx`
- Modify: `desktop/src/App.tsx`
- Create: `desktop/src/SyncSettings.test.tsx`
- Create: `desktop/src/SyncConflicts.test.tsx`

**Steps:**

1. Add failing capability/serialization tests proving the webview can request
   bounded status, device operations, manual sync, conflict resolution,
   recovery, and rotation but cannot request keys, bearer tokens, raw envelopes,
   or Stronghold primitives.
2. Add device list/removal warnings, last-sync/status, manual run, bounded error
   display, conflict queue/resolution, recovery, and rotation flows.
3. Wipe decrypted UI state on lock and stage nothing beyond bounded opaque
   counts/status while locked.
4. Run desktop unit/build, Rust IPC/capability tests, and security tests; commit.

### Task 20: Pass the two-desktop release drill

**Files:**

- Create: `test/e2e/two-device-sync.mjs`
- Create: `docs/drills/desktop-multi-device.md`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ROADMAP.md`

**Steps:**

1. Automate or record reproducibly two independent desktop profiles performing
   offline edit/reconnect, blob resume, automatic/manual conflicts,
   removal/rotation, locked staging, and recovery-kit restore.
2. Record exact build IDs, commands, expected evidence, and redacted results.
3. Run the full TypeScript/Rust/relay/desktop/benchmark gate. Do not mark desktop
   sync released until the real two-device drill passes. Commit evidence/docs.

## Phase 6F — Audit, recovery drill, and 1.0

### Task 21: Prove legacy migration and disaster recovery

**Files:**

- Create: `test/fixtures/legacy-vaults/`
- Create: `test/e2e/recovery-drills/`
- Create: `docs/drills/phase-6-recovery.md`
- Modify: migration and recovery modules as test failures require

**Steps:**

1. Add every historic manifest/document/sync fixture and migrate/open it with
   the new release. Inject failure at every migration phase and verify exact
   backup restoration.
2. Run and record corrupted local disk, lost device, malicious relay,
   interrupted rotation, recovery-kit fresh restore, and self-host backup/
   restore drills.
3. Treat any silent data loss, duplicate revision, unrecoverable acknowledged
   write, or plaintext leakage as a release-blocking failure. Commit fixtures,
   fixes, and evidence.

### Task 22: Assemble and remediate the independent audit package

**Files:**

- Create: `docs/security/phase-6-threat-model.md`
- Create: `docs/security/phase-6-normative-crypto.md`
- Create: `docs/security/phase-6-dependencies.md`
- Create: `docs/security/phase-6-test-evidence.md`
- Create: `fuzz/` or workspace fuzz targets
- Modify: `SECURITY.md`

**Steps:**

1. Document assets, trust boundaries, attacker capabilities, abuse cases,
   protocol/key lifecycle, metadata leakage, forward-removal limitation, and
   recovery tradeoffs.
2. Package normative formats, golden/adversarial fixtures, fuzz corpus,
   dependency/SBOM inventory, build reproduction, test outputs, and drills for
   independent review.
3. Track every audit finding with severity, owner, fix commit, regression test,
   and independent remediation retest. No open critical/high finding is
   acceptable.
4. External audit contracting and verdict are human/external coordination;
   record the blocker precisely rather than manufacturing approval.

### Task 23: Freeze the 1.0 format only after all gates

**Files:**

- Modify: `package.json`
- Modify: `src-tauri/Cargo.toml`
- Modify: relay/crate manifests
- Modify: `CHANGELOG.md`
- Modify: `SECURITY.md`
- Modify: `README.md`
- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/ROADMAP.md`

**Steps:**

1. Confirm every prior phase gate, real platform drill, and external remediation
   retest is complete with no critical/high findings.
2. Re-run lint, format, typecheck, all TypeScript/desktop/Rust/relay tests
   and builds, package/image checks, migration/recovery drills, fuzz smoke runs,
   and performance budgets from a clean checkout.
3. Only then set package/Tauri/relay/crate versions to `1.0.0`, freeze documented
   formats, write the changelog/security support policy, and close the roadmap.
4. Request final whole-branch review, fix all blocking findings, rerun the clean
   gate, and use `finishing-a-development-branch` to present integration choices.
