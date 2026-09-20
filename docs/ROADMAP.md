# Delivery Roadmap

Each phase must ship a usable vertical slice and keep older vaults readable.

## Phase 0 — Product and security contract

- [x] Define positioning, non-negotiables and measurable performance budgets
- [x] Select desktop security boundary and target storage architecture
- [x] Map Obsidian-class baseline capabilities

## Phase 1 — Hardened compatibility core

- [x] Block traversal and symlink-based vault escape
- [x] Make encrypted writes crash-safe and atomic
- [x] Round-trip quotes, backslashes and multiline values
- [x] Generate collision-resistant UTC note keys
- [x] Automatically refresh the safe catalog after CLI writes
- [x] Add passphrase-authenticated audit chaining and verification command
- [x] Add build-backed regression tests
- [x] Version the encrypted envelope and add migration fixtures
- [x] Add masked/keychain-backed unlock and explicit lock lifecycle
- [x] Add concurrency-safe transactions and recovery simulation

## Phase 2 — Encrypted document engine

- [x] Stable note IDs, revisions, Markdown bodies and typed properties
- [x] Content-addressed, chunked encrypted attachments with integrity verification
- [x] Wikilink, heading, block reference and tag parser
- [x] Incremental backlink/unresolved-link index with rename invalidation
- [x] In-memory full-text search with ranking, filters and snippets
- [x] Encrypted revision history and deleted-note recovery
- [x] Idempotent daily notes and variable-driven encrypted templates
- [x] Obsidian-style YAML frontmatter semantic import/export
- [x] Comment/style-preserving frontmatter round-trip
- [x] Repeatable 1k-note performance corpus and CI-style p95 gates
- [x] 10k/100k production index gates

## Phase 3 — Desktop workspace

- [x] Tauri 2 application with capability-scoped commands
- [x] Polished Markdown editor and reading view
- [x] File explorer, outline, properties and backlinks
- [x] Tabs and pane splitting
- [x] Global search and command palette
- [x] Keyboard-driven quick switcher
- [x] Lock screen and explicit session lock
- [x] Inactivity lock and safe clipboard handling
- [x] Core keyboard shortcuts, responsive layout and reduced-motion support
- [x] Theme editor and virtualized large-vault UI

## Phase 4 — Knowledge views

- [x] Value-minimized local graph baseline from the encrypted link index
- [x] Global graph clustering and large-graph virtualization
- [x] Content-addressed encrypted attachments in the desktop core
- [x] Canvas/whiteboard with encrypted assets
- [x] Database-like property table with local filtering and column sorting
- [x] Saved property queries and editable cells
- [x] Bookmarks, workspaces, aliases and unlinked mentions
- [x] Optional on-device semantic recall

## Phase 5 — Controlled ecosystem and AI

- [x] Capability manifest and sandboxed plugin runtime
- [x] Signed plugin packages, restricted mode and revocation
- [x] Per-agent scoped grants with expiry and confirmation policies
- [x] Redaction-aware MCP results
- [x] Local-model adapter
- [x] Importer for Obsidian vaults with integrity report

## Phase 6 — Encrypted sync (desktop multi-device)

Sync is desktop-to-desktop. Vault Brain stays local-first: the passphrase — the
vault's only real security boundary — never leaves a machine the owner controls,
and no hosted service is ever required.

- [x] Immutable encrypted change protocol and conflict resolution
  - [x] Content-addressed encrypted envelopes, device chains, causal DAG validation and deterministic conflict inspection
  - [x] Emit changes automatically from note/canvas/attachment transactions and apply resolved remote changes to live storage
  - [x] Capture plugin package and plugin-policy transactions
  - [x] Portable workspace state. Notes, canvases, attachments, plugin packages,
        `plugin-policy`, `saved-views` and `workspace` including bookmarks are
        captured through the shared TypeScript/Rust encrypted state contract.
        Device paths, credentials and transient window state remain local.
- [x] Owner-signed device enrollment and sequence-bounded removal
  - [x] Ed25519 proof-of-possession requests, signed certificates and encrypted registry exchange
  - [x] Per-change device signatures, authority pinning, rollback rejection and revocation cutoffs
- [x] Epoch-based content-key rotation
  - [x] Random per-epoch content keys wrapped to each active device's X25519 key
  - [x] Automatic rotation on owner-signed device revocation
  - [x] Forward-only: a revoked device retains pre-rotation read access
- [x] Owner-signed freshness checkpoints with explicit first-pin verification
- [x] Authenticated opaque relay server and self-hosted option
- [x] Desktop multi-device release
  - [x] Native-packaged TypeScript sync helper with private, bounded IPC
  - [x] Desktop-driven enrollment, revocation, conflict resolution and relay exchange
  - [x] Manual push/pull flushes pending editor writes and keeps local work available offline
- [x] Resumable chunked transport for large attachment blobs
  - [x] Version 3 change bodies carry an attachment manifest; the bytes
        travel as content-addressed, AEAD-sealed 1 MiB blobs
  - [x] Per-chunk idempotent push and pull, and an apply that fails closed
        while a chunk is missing
  - [x] `sync blobs status/fetch/prune` and relay-free bundle transport via
        `sync export --bundle` / `sync import`
- [x] Automated encrypted-backup plus relay catch-up recovery drill
- [ ] External security audit and stable 1.0 format
  - [x] Stable 1.0 on-disk format with committed conformance fixtures
  - [x] Frozen format inventory covers the keyring: `keyring.json` is in
        `FORMAT_COMPATIBILITY` and the artifact catalogue, and the version 2
        manifest tombstone is a stated 1.x carve-out rather than an undeclared
        version bump
  - [ ] External security audit (readiness package in `docs/AUDIT-SCOPE.md`)

## Phase 7 — Key wrapping, passphrase change and re-key

The passphrase unwraps a keyring instead of deriving the content key directly,
so it can change without re-encrypting the vault and the key-derivation cost
can be raised per vault. Design contract:
[`docs/superpowers/specs/2026-09-03-vault-keyring-design.md`](superpowers/specs/2026-09-03-vault-keyring-design.md).

- [x] 7.1 Keyring format and migration (TypeScript)
  - [x] `keyring.json` with a scrypt-wrapped keyset, kv envelope v2 and `vbrain migrate`
  - [x] Committed v1 fixtures migrate with byte-identical attachment and sync change IDs
- [x] 7.2 Rust read parity
  - [x] The desktop core opens keyring vaults; new vaults are keyring-native in both cores
  - [x] A manifest version tombstone makes an older build fail closed, not misread
  - [x] A deterministic cross-core test vector pins the wire format
- [x] 7.3 `vbrain passphrase change`
  - [x] Re-wrap the keyset under a new passphrase at the current key-derivation cost
  - [x] Verify before writing, refresh a remembered OS credential, zeroize on every path
- [x] 7.4 `vbrain rekey`
  - [x] Fresh data keys and a re-encrypted vault, so a leaked passphrase has an answer
  - [x] Resumable: interrupt a re-key at a random object, resume, and assert the
        vault is complete and consistent
- [x] 7.5 Survivable keyrings: a second way in, a way to look inside, and a record of every change
  - [x] Recovery slot, so one forgotten passphrase or one damaged `keyring.json` is not
        the permanent loss of every note. The format already carries a slot list and
        reserves this slot; nothing writes one yet, and the keyring concentrated into
        one small file what used to be derived from the passphrase directly.
  - [x] `vbrain keyring status`, listing every slot with its id, label, creation time
        and KDF cost. Without it a slot someone else added is invisible — a passphrase
        change deliberately preserves the slots it cannot open — and a user has no way
        to learn their vault still sits at the old cost, which makes the upgrade path
        undiscoverable.
  - [x] Audit entries for `migrate` and `passphrase change`. Every content command
        already appends to the passphrase-authenticated chain; the two commands that
        touch key material append nothing, so "when did this vault's passphrase last
        change" has no answer. The `audit` key is permanent, so entries written before
        and after a change verify in the same chain.
- [x] 7.6 What the re-key leaves behind
  - [x] Optional `vbrain rekey --rotate-identities --backup <file>` verifies an
        encrypted backup first, rotates attachment and sync identities, rewrites
        attachment references through parsed formats, starts a new owner epoch,
        and requires peers to enroll again. Old backups and relay copies remain
        untouched.
  - [x] `vbrain vault-lock status` and `vbrain vault-lock recover` provide a
        token-checked, same-host dead-process recovery path. Live, unknown,
        remote and malformed locks fail closed; re-key journals and staging are
        left alone.

- [x] 7.7 Re-key interoperability and recovery corrections
  - [x] Retention policies are classified and preserved during re-key (Task 0).
  - [x] Rust keyset re-wrapping preserves `legacyChangeIdentity` (Task 1).
  - [x] Authenticated pending, allowed and denied re-key audit events are tested (Task 2).
  - [x] Unsupported keysets fail with the documented recovery path (Task 3).
  - [x] Recovery kits verify against current and retiring keys (Task 4).

Follow-up work outside the five corrections:

- [ ] Phase 13: enforce encrypted-artifact inventory coverage against the format
      catalogue, so adding a new artifact cannot silently omit re-key support.
- [x] Assign the personal-memory modules under `src/memory/` to Phase 15.
      The current modules remain experimental; product integration is still open.

## Phase 8 — Key management the desktop can reach

Keyring status, passphrase change and recovery-kit creation are already
available in the desktop core. Restore and re-key remain CLI operations because
they must validate or replace the whole vault; this phase tracks whether those
remaining recovery paths should gain a desktop surface.

**The decision, recorded.** The work is split by how much audited surface it
adds, not by convenience. `src-tauri/src/keyring.rs` already carries the whole
keyring write path — `wrap_key_set`, `unwrap_keyring`, `read`, `write` — over
`scrypt`, `aes-gcm`, `sha2`, `hmac` and `rand`. Keyring status, passphrase
change and recovery-kit creation therefore need no cryptographic primitive the
desktop core does not already have, and are implemented natively. Recovery
_restore_ and re-key are not: restore verifies vault ciphertext before
replacing a damaged keyring, which would mean a second `openSyncChange`, and
re-key rewrites every object. Both stay in the CLI, and the application's job
is to name the exact command. Restore in particular runs when `keyring.json`
is already damaged — the moment the application cannot open the vault at all —
so a graphical path to it would mostly be unreachable when it is needed.

- [x] The audit chain in the Rust core. Key-material commands and desktop note,
      canvas, attachment and plugin writes append to the same
      passphrase-authenticated chain. A committed cross-core vector pins the
      entry and head constructions, the way `keyring-vector.json` pins the
      keyset.
- [x] `keyring status` in the application: every slot with its id, label,
      creation time and key-derivation cost, so a user can see a slot they did
      not add and can learn their vault still sits at the old work factor.
- [x] Passphrase change from the application, including the key-derivation cost
      upgrade the CLI command already performs.
- [x] Recovery-kit creation in the application, with first-run guidance that
      asks for one before the vault holds anything worth losing. A recovery slot
      nobody is told about protects nobody.
- [x] Recovery restore and re-key remain CLI operations. The application
      detects when one is needed and shows the exact command, rather than
      pretending to offer what it cannot safely perform.

## Phase 9 — Getting the data out, and back

A local-first product that cannot hand back a plain copy of its contents is
lock-in by another name. Export was one note or one canvas at a time. Backup was
"copy the directory": the recovery drill did exactly that with `fs.cpSync`, and
no command or documented procedure said so to a user.

- [x] `vbrain export`: the whole vault as a folder of Markdown with
      frontmatter, attachments beside the notes that reference them, and
      canvases as JSON Canvas. The Obsidian importer already reads that shape,
      so export and import would describe one format rather than two.
- [x] `vbrain backup` and `vbrain restore`: a verified, self-contained
      encrypted copy carrying the key-derivation metadata a restore needs, and
      a restore that refuses a backup it cannot open rather than replacing a
      working vault with one.
- [x] A stated backup procedure in the documentation, and a drill that restores
      from that artifact rather than from a directory copy.

## Phase 10 — Deletion that deletes, and history that ends

`remove` archived a revision before it unlinked the object, so a deleted note's
content stayed under `documents/history/` for the life of the vault. For a
product that invites medical, financial and identity data, "I need this gone"
had no answer. Nothing pruned revisions either, so a note edited daily grew a
file per edit forever.

- [x] `vbrain purge`: permanent removal of a note, canvas or attachment and
      every revision of it. Distinct from `remove`, and refusing to run without
      an explicit confirmation.
- [x] A revision retention policy the vault carries and both cores honour, with
      a command that applies it to history that already exists.
- [x] Say plainly what a purge cannot reach: a purged object still exists in any
      backup taken before it, in any sync change already pushed to a relay, and
      on any device that pulled it. Whether a purge propagates as a tombstone is
      a separate decision, and this phase records which one is taken.
      [`docs/DELETION.md`](DELETION.md) states the limits and records the
      decision: a purge is local, and 1.x ships no tombstone.

## Phase 11 — macOS and Linux

CI builds and validates native Windows, macOS and Linux bundles, and runs both
the TypeScript durability suite and Rust suite across their supported hosts.
Native credential-store smoke tests exercise full DPAPI, Keychain and libsecret
round trips without placing the passphrase in a child process argument vector.

- [x] Bundle and test the desktop application on macOS and Linux.
- [x] Run the Rust suite on all three platforms in CI, and exercise the
      `security` and `secret-tool` keychain backends where they are real.
- [x] Verify path handling, permissions and atomic replacement per platform.
      The vault's durability guarantees are filesystem-specific and are
      exercised by the native Node and Rust jobs rather than inferred from one
      development filesystem.

## Phase 12 — Actually shipping

The release workflow builds Tauri-signed updater packages, checksums them,
produces an SPDX SBOM and attests build provenance, then prepares an immutable
draft release for a maintainer to publish. The native updater and its UI are
implemented, but Phase 12 acceptance still depends on the real two-version
installation drill on every supported platform.

- [x] Build and stage signed installers with their checksums, SBOM and provenance
      in an immutable draft-release workflow.
- [x] An update path, with a recorded decision that it is never automatic.
      An updater is also a code-delivery channel into a vault holding the
      user's secrets, so that choice is a security decision, not a convenience.
- [x] Put recovery, 10k/100k benchmark, release-contract and synthetic two-version
      native package-transition evidence into CI.
- [ ] Provision and back up the production signing key, execute the draft workflow,
      and record real signed vN-to-vN+1 updater installation on Windows x64, macOS
      ARM64 and Linux x64 before the maintainer publishes the draft.

## Phase 13 — One implementation of each thing

Every protocol defect this project has found in itself came from two pieces of
code that were meant to agree and did not. The TypeScript and Rust cores are a
deliberate, audited pair. These three are not.

- [x] Retire `src/sync/change-log.ts`. The public `src/sync.ts` API now uses
      the single wire implementation in `sync/protocol.ts`; canonical API and
      clean-distribution regression tests cover the consolidation (14.3).
- [x] Freeze the domain-separation inventory, including KV v2, local transaction
      and apply receipt domains. Explicit expected values and TS/Rust source
      checks catch omitted or divergent literals (14.3).
- [ ] Complete encrypted-artifact conformance (14.3). Index and plugin-policy
      are now catalogued and real writers are checked against re-key plans.
      Exhaustive family and temporary-transition coverage remains open; see
      [verification evidence](PHASE-14-VERIFICATION.md).

## Phase 14 — Closure and evidence reconciliation

The closure baseline is `83a1dd1` on `phase-14-closure`. This phase reconciles
documentation with the existing sync and re-key implementation, records evidence
ownership, and keeps external gates visible. Phase 13's three items are owned by
Phase 14.3. Implementation and remaining acceptance evidence are tracked in
[the verification record](PHASE-14-VERIFICATION.md); an unchecked historical
task does not imply its implementation is still absent.

- [ ] 14.0 Reconcile stale roadmap, README, architecture and security descriptions
      with the implemented Phase 7.7, sync, re-key, recovery and desktop surfaces.
- [ ] 14.1 Verify portable workspace state, explicit enrollment, revocation,
      forward-only epoch rotation, bounded relay operations and clean peer
      re-enrollment after identity rotation.
- [ ] 14.2 Verify resumable identity migration, recovery compatibility and audit
      evidence. Ambiguous lock state remains fail-closed with no override.
- [ ] 14.3 Consolidation and domain tests are implemented; finish the complete
      artifact/transition coverage audit before closing Phase 13.
- [x] 14.4 Keep personal-memory modules experimental and disabled by default;
      production-import audit found no imports beyond internal/test surfaces.
      Productization is deferred to [`Phase 15`](superpowers/plans/2026-09-11-phase-15-personal-memory.md).
- [ ] 14.5 Independent security audit, real native acceptance and production
      signing/release evidence remain external gates.

## Phase 15 — Personal-memory integration (planned)

The design and implementation plan is [`docs/superpowers/plans/2026-09-11-phase-15-personal-memory.md`](superpowers/plans/2026-09-11-phase-15-personal-memory.md),
grounded in the Phase 7.6 contract. It covers the native broker, explicit pairing,
unlocked sessions, secure queue, MCP/desktop controls, sensitive review/forget and
rekey restore behavior. No live integration is enabled by this roadmap entry.

- [ ] Native broker and unlocked-session lifecycle
- [ ] Safe capture and isolated local worker boundary
- [ ] Owner-controlled MCP, desktop review and forget/relearn lifecycle
- [ ] Synthetic acceptance evidence and explicit product-owner release decision

## Phase 16 — What the verification run found

A full local verification of `c0236d3` on a real Windows developer machine
surfaced defects and verification gaps that CI does not catch, two of them
because a Linux runner structurally cannot. The plan is
[`docs/superpowers/plans/2026-09-14-phase-16-verification-findings.md`](superpowers/plans/2026-09-14-phase-16-verification-findings.md).
Phase 15's own unfinished work stays with Phase 15, and the external gates stay
with Phases 12 and 14.

- [ ] 16.1 Decide what a symlinked interpreter path means to `memory setup`, and
      implement it. `src/memory/setup.ts` now resolves `nodeExecutable`,
      `nativeExecutable` and `cliPath` with `fs.realpathSync` before checking and
      writing them, so a vault owner whose Node is managed by nvm-windows can pair
      a client; `configPath` still refuses a symbolic-link component. The CLI
      prints every resolution and the nvm-version-switch note. The library and
      the formatter are covered by tests; the CLI wiring is covered by
      inspection and by the library's `givenPaths` tests, since no test loads
      `src/memory/cli.ts`. A test also shows the library refuses a pre-resolved
      path whose component has since become a link. Not run end-to-end against
      a real nvm-windows Node or a paired desktop native executable on this
      host. The plan is
      [`docs/superpowers/plans/2026-09-14-phase-16-1-symlinked-interpreter.md`](superpowers/plans/2026-09-14-phase-16-1-symlinked-interpreter.md).
      Implemented and tested; closes after one live `memory setup` run on an
      nvm-windows host with a paired desktop.
- [x] 16.2 Make `clean-dist` prove it cleaned. A removal that silently failed left
      a retired `dist/sync/change-log.js` in a build that reported success — the
      duplicate-implementation failure Phase 13 exists to prevent, caught only
      because one test happened to assert the file's absence.
- [x] 16.3 Document and diagnose the four host-dependent checks: `fs.cpSync`
      crashing Node under a cloud-synced checkout, GNU `tar` refusing Windows
      paths under Git Bash, `format:check` reporting carriage returns as style
      violations, and `quality:rust` being unrunnable without MSVC Build Tools.
      A check that cannot run stays a gap, never a skip.
- [ ] 16.4 Diagnose the one flaky test: the portable recovery drill's relay
      download reset under concurrent suite load.
- [x] 16.5 Triage the twelve open dependency updates, five of which are major
      bumps of crates under the keyring, audit chain and sync envelope. The
      crypto majors (`aes-gcm` 0.11, `rand` 0.10, `sha2` 0.11, `hmac` 0.13,
      `ed25519-dalek` 3) landed in #10 and #57 with every cross-core vector
      unchanged; the npm side landed in #59 with `typescript` 7 and
      `@types/node` 26 declined through Dependabot `ignore` entries. The
      updates Dependabot opened afterwards landed in #61, #64, #65, #66
      (superseding #62 and #63 without lockfile churn) and #67 (`scrypt` 0.12,
      superseding #60, plus a `rand` feature trim and a new cross-core vector
      for `verifier` and `attachment_id`). #68 fixed the leak assertion in
      `test/sync-transaction.test.mjs` that matched random base64 ciphertext.
      The plans are
      [`docs/superpowers/plans/2026-09-15-phase-16-5-crypto-majors.md`](superpowers/plans/2026-09-15-phase-16-5-crypto-majors.md)
      and
      [`docs/superpowers/plans/2026-09-15-phase-16-5-npm-updates.md`](superpowers/plans/2026-09-15-phase-16-5-npm-updates.md).
- [x] 16.6 Make every removal under `src/` remove. Under a non-ASCII vault path
      `fs.rmSync` silently removes nothing, so `purgeAttachment` reports a purge
      that did not happen, a committed re-key keeps its journal and blocks every
      later re-key, and a failed identity rotation leaves a second wrapped keyset
      and sync private keys on disk. The plan is
      [`docs/superpowers/plans/2026-09-14-phase-16-6-non-ascii-vault-removal.md`](superpowers/plans/2026-09-14-phase-16-6-non-ascii-vault-removal.md).
      The follow-up moved the non-build scripts onto `scripts/fs-tree.mjs` and
      extended the source scan to cover `scripts/`; see
      [`docs/superpowers/plans/2026-09-15-phase-16-6-non-ascii-scripts.md`](superpowers/plans/2026-09-15-phase-16-6-non-ascii-scripts.md).
      A second follow-up moved every test file onto the same helpers and
      extended the scan to cover `test/`; see
      [`docs/superpowers/plans/2026-09-15-phase-16-6-non-ascii-tests.md`](superpowers/plans/2026-09-15-phase-16-6-non-ascii-tests.md).
      A third follow-up found no banned call under `desktop/` and extended the
      scan to cover `desktop/`; see
      [`docs/superpowers/plans/2026-09-15-phase-16-6-non-ascii-desktop.md`](superpowers/plans/2026-09-15-phase-16-6-non-ascii-desktop.md).
      A fourth follow-up proved the Rust core's removals work under a non-ASCII
      path on the Windows runner, made a failed removal of the memory pairing
      secret fail `disconnect` instead of reporting success, and stopped the
      lock-transition reclaim from spinning forever on an unremovable stale file;
      see
      [`docs/superpowers/plans/2026-09-15-phase-16-6-rust-non-ascii-removal.md`](superpowers/plans/2026-09-15-phase-16-6-rust-non-ascii-removal.md).
      A fifth follow-up replaced Vite's `emptyOutDir`, which left stale files in
      `desktop-dist/` under a non-ASCII path, with the verified `clean-dist`
      script; see
      [`docs/superpowers/plans/2026-09-15-phase-16-6-desktop-dist-clean.md`](superpowers/plans/2026-09-15-phase-16-6-desktop-dist-clean.md).

## Phase 17 — Incremental index persistence

Found by adding the measurement the 2026-09-19 CLI review asked for
([finding 11](CLI-AUDIT-2026-09-19.md)): saving one note re-serialised and
re-encrypted the entire index, so the cost grew with the vault rather than with
the edit. The desktop core carried the same defect plus two more of its own.

### What was wrong, and what each fix bought

Three separate passes over the whole vault ran on every desktop save, and one
on every CLI save:

| Cause | Fixed by |
| --- | --- |
| `saveIndex` / `save_index` rewrote the whole index | an encrypted change log; a save appends one sealed record |
| Rust `rebuild_derived` rebuilt every owner, link and backlink map | `apply_indexed_note`, the incremental counterpart — 0.3% of a save, and absent from a profile at 16,000 notes |
| Rust `refresh_session_index` re-read and decrypted the whole snapshot before every write | a size-and-mtime stamp, plus tailing only the log records appended since |
| Rust fsynced the advisory vault lock twice per save | it is written, not fsynced, as the TypeScript implementation always has been |

Measured p95, same harness before and after:

p95 on the CI Linux runner, 200 samples, before and after:

| Vault | TypeScript | Rust (desktop) |
| ---: | ---: | ---: |
| 1,000 | 16.6 → **3.5 ms** | 34.4 → **4.95 ms** |
| 10,000 | 141.7 → **3.5 ms** | 2,553 → **5.03 ms** |
| 100,000 | → **4.55 ms** | → **5.98 ms** |

(The two "before" figures for the desktop core are from a development machine,
which reports roughly three times the runner's numbers; there was no CI
measurement of that core to compare against, which is the gap #77 recorded.)

Both cores are flat in vault size rather than linear in it: a save costs the
same at 100,000 notes as at 1,000. The 1k and 10k tiers are gated on every pull
request; 100k runs on pushes to `main`.

### The design, as built

`documents/index-log.enc`, one JSON object per line, each an independently
sealed payload. Line 0 is a header binding the log to one snapshot generation;
lines 1..n are records. Every line's AAD carries the generation and the line
number, so a record cannot be reordered, duplicated, dropped from the middle or
replayed against a different snapshot without failing authentication.

- A save appends one record and fsyncs it. "Saved" is answered only once that
  record is durable; nothing is deferred to make the number look smaller.
- Records describe notes only. Canvas and plugin writes commit a full snapshot,
  which is always correct and is not on the path the budget measures. One
  record type is what lets both cores replay the log with one small code path
  each.
- The snapshot is refreshed when the log passes its threshold and when a
  session closes, so the vault is self-contained at rest — which is what
  re-key, backup and the other core need.
- The snapshot lands before the log is removed. A crash in between leaves a log
  whose generation no longer matches, which is discarded rather than replayed
  onto a snapshot that already contains it.
- The log is vault content: catalogued in `src/format-version.ts`, refused by
  `planRekey` (which compacts first), carried by backup, and version-gated.

### Acceptance

- [x] Save p95 measured at the 1k, 10k and 100k tiers, in both cores
- [x] Measurement spans compaction rather than excluding the slow samples it
      produces — the threshold is exercised by
      `test/index-log.test.mjs`
- [x] No acknowledged save is lost across a crash or concurrent writers.
      Checked off once on crash evidence alone. The concurrent-writer half was
      false in the TypeScript core and is covered by
      `test/concurrent-sessions.test.mjs` below.
- [x] Unlock stays within budget with a log present
- [x] A vault written by one core is read correctly by the other, log included
      (`test/cross-core-index-log.test.mjs` drives both binaries over one vault)
- [x] Both cores meet the budget at 100,000 notes, the size it is written for
- [ ] Promote `performance-budgets` to a required status check — a repository
      setting, and the last thing holding this phase open

### The session cache, and what the acceptance list missed

Phase 17 gave the Rust core `refresh_session_index`: before every write it
compares the snapshot's size and modification time and, when nothing replaced
it, applies only the log records appended since. That was written as an
optimisation — it removed a full decrypt per save — but it is also what makes a
write see the previous lock holder's work.

The TypeScript core never got it. `loadIndex()` returned the session's cached
index unconditionally, so a session's first read of the index was its only one.
A second process could save a note, and the first session's next save would
commit on top of a state that no longer existed: the note object stayed on disk
and the index stopped referencing it. Reproduced with two real processes, and
the note was unreachable afterwards.

The vault lock was never the missing piece. It was always taken, and it
serialises the writes correctly. What was missing is re-reading what the
previous holder left behind once the lock changes hands.

This was not a Phase 17 regression — the unconditional cache is older than the
change log, and the whole-snapshot rewrite it replaced lost the same note the
same way. What Phase 17 did was fix it in one core and leave the other, which
is the cross-implementation divergence Phase 13 exists to prevent, and the
acceptance list above said "no acknowledged save is lost across a crash or
concurrent writers" on crash evidence alone.

`src/documents.ts` now carries the same stamp comparison and log tail.
`test/concurrent-sessions.test.mjs` drives a second Node process against one
vault and covers the four shapes: a save that compacted, a save that only
reached the log, a removal, and a read with no write of its own. All four fail
without the change.

One difference from the Rust core is deliberate and stays: TypeScript refreshes
in `loadIndex()`, which covers reads as well as writes, because it is the one
place every write path passes through — the TypeScript core has no single
`with_vault_write` choke point to hang it on, and touching each write site
individually is the version of this that misses one. Rust refreshes on writes
only, so a long-lived Rust session can still serve a stale read. Named here
rather than left to be rediscovered.

### What is left

Only the repository setting: `performance-budgets` passes in both cores at
every tier and can now be made a required status check.

A profile puts the incremental index maintenance at 0.3% of a save, so what a
save costs now is the four durable file operations it makes — the write-ahead
journal, the archived revision, the note object and the log append. That is a
fixed cost rather than one that grows with the vault, and reducing the count is
an optimisation with its own crash-safety argument rather than a budget miss.

## Phase 18 candidates — context semantics (not scheduled)

Adopted from the context-format evaluation in
[`docs/CONTEXT-FORMAT-DECISION-2026-09-19.md`](CONTEXT-FORMAT-DECISION-2026-09-19.md),
which rejected a bespoke `.ctx` file format and kept three of its semantics.
Candidates only: nothing here is counted against an open phase.

- [ ] Temporal supersession: `valid-from`, `valid-until` and `supersedes` as
      reserved frontmatter properties, indexed and filterable
- [ ] `priority` property weighted by the search ranker
- [ ] Budget-aware context assembly at the MCP layer, if and when grant-controlled
      Markdown discovery/resolve tools are added

The first two depend on the `[key:value]` property filter from finding 9 of
[`docs/CLI-AUDIT-2026-09-19.md`](CLI-AUDIT-2026-09-19.md) and should follow it.

## Which open phases still need code

A classification of every unchecked item above, so a reader can tell implementation
work from evidence work without opening five documents. It is a routing note, not a
new obligation: nothing here adds scope to a phase or moves an item between owners.

**Needs code.**

- **17** — the incremental-save defect above. It is a measured budget miss with a
  named cause, not evidence work.
- **14.2** — the transition-by-transition coverage mapping is still to be signed off
  ([verification record](PHASE-14-VERIFICATION.md)). If the mapping exposes an
  uncovered transition, closing it means new tests in `test/keyring-recovery.test.mjs`
  and `test/rekey-transitions.test.mjs`, not a document change. The rest of 14.2 is
  independent review of the pinned commit.
- **14.3** — the remaining encrypted-artifact conformance audit. Phase 13's third
  item and the Phase 7 follow-up on inventory coverage enforcement both land here.
- **15** — the worker adapter (the installed `codex-cli 0.154.0-alpha.6.2` is not the
  `0.153.1` the runner accepts), native lifecycle and generation cancellation, and
  restore/re-key compatibility. The broker, hook capture and MCP surface are written;
  their acceptance results are recorded as NOT RUN in
  [the Phase 15 ledger](PHASE-15-IMPLEMENTATION.md), which is evidence work, not
  implementation.
- **16** — 16.1 through 16.4 are defects with named fixes. 16.5 is dependency triage
  rather than feature work, but the five crypto crate majors sit under the keyring,
  audit chain and sync envelope, so adapting to a changed API is in scope.

**Does not need code.**

- **Phase 6** external security audit and **14.5** — external gates with named owners.
- **Phase 12** production signing key, its backup, and the real signed vN→vN+1
  installation on each platform — operational evidence.
- **14.0** — reconciling stale roadmap, README, architecture and security prose.
- **14.1** — the two-desktop enrollment, revocation and offline walkthrough. Manual
  acceptance; it produces code only if the walkthrough finds a defect.
