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

## Phase 17 — Incremental index persistence (open defect)

Found by adding the measurement the 2026-09-19 CLI review asked for
([finding 11](CLI-AUDIT-2026-09-19.md)), not by a report from the field: the
"incremental save acknowledgement < 20 ms" budget in [`PRODUCT.md`](PRODUCT.md)
is missed, and the cost grows with the vault rather than with the edit.

Measured by the `performance-budgets` CI job: 1,000 notes 14.2 ms p50 /
16.6 ms p95 (met); 10,000 notes 105.8 ms p50 / 141.7 ms p95 (missed by about
seven times). The budget is specified at 100,000 notes, where the encrypted
index is roughly 120 MiB.

### Where the time goes

Profiled on Windows / Node 22.20.0, p50 per save, with the corpus the
benchmark builds:

| Notes  | save | rewrite | other | index size |
| -----: | ---: | ------: | ----: | ---------: |
|  1,000 |  19.0 ms |   6.2 ms | 12.7 ms |  1.2 MiB |
|  2,000 |  27.9 ms |  12.1 ms | 15.8 ms |  2.4 MiB |
|  4,000 |  45.0 ms |  23.8 ms | 21.2 ms |  4.9 MiB |
|  8,000 | 120.4 ms |  62.2 ms | 58.3 ms |  9.8 MiB |
| 16,000 | 142.7 ms | 113.1 ms | 29.6 ms | 19.8 MiB |

`rewrite` is `JSON.stringify` + `encryptDocument` + atomic write and fsync of
the whole index — what this phase removes from the save path. It grows linearly
with index size and is 33% of the save at 1,000 notes, 79% at 16,000.

`other` is everything else a save does: the journal, the link and backlink
maps, resolved-source refresh, canvas reference refresh. This phase does **not**
address it, and at small vaults it is the larger half.

A CPU profile settles what `other` actually is, and the answer is reassuring.
Self time inside the save path, at 4,000 and 16,000 notes:

| Frame                                  | 4,000 | 16,000 |
| -------------------------------------- | ----: | -----: |
| `fsync`                                | 35.3% |  71.7% |
| `saveIndex` (serialising the index)    | 37.9% |  11.1% |
| `writeFileUtf8`                        |  3.6% |  12.0% |
| `putIntoIndex` (all the derived maps)  |  0.3% | absent |

(Absolute times under `--cpu-prof` are inflated; the shares are the point.)

The index maintenance is 0.3% of a save and does not appear at all at 16,000
notes, so `other` holds no term that scales — it is the three further durable
writes a save makes (journal, archived revision, note object) and their
fsyncs. Everything that grows with the vault is serialising, encrypting,
writing and fsyncing the whole index, which is why `fsync` climbs to 71.7% as
the index reaches 20 MiB: fsync cost follows the bytes being synced.

The index is roughly 1.2 MiB per 1,000 notes, so the rewrite at 100,000 notes
is a ~120 MiB serialise-and-encrypt on every keystroke-batch save. Removing it
leaves a cost that is constant in vault size. That is what makes the change-log
design sufficient rather than merely necessary.

### The figures above are the TypeScript library, not the desktop

`scripts/benchmark.mjs` measures `src/documents.ts`, which is the CLI and MCP
path. Every budget in [`PRODUCT.md`](PRODUCT.md) is a desktop interaction, and
the desktop's note lifecycle runs in the Rust core — `save_note` reaches
`save_index` in `src-tauri/src/lib.rs`, which serialises, encrypts and rewrites
the whole index exactly as the TypeScript path does.

So the desktop carries the same defect, on a path nothing measures: there is no
Rust benchmark in this repository. Two consequences for this phase:

- **Measurement comes first.** A Rust-side save measurement at the 1k, 10k and
  100k tiers has to exist before either implementation changes. Designing
  against an unmeasured target is precisely the mistake finding 11 records, and
  Rust's `serde_json` and AES may put the real desktop number somewhere this
  phase's scope depends on.
- **The log format is shared, or it is a correctness bug.** Both
  implementations write `index.enc`. A change log only the TypeScript side
  understands would leave the desktop reading a snapshot that omits the CLI's
  recent saves, and overwriting it from that stale state. Whatever this phase
  writes, both cores must read.

### Now — measure honestly, do not claim the target

These ship ahead of the fix and are deliberately merged without closing it.

- [x] Report the measurement and the `BUDGET MISS` result on every benchmark run
- [x] Enforce the strict threshold in a separate `performance-budgets` CI job:
      visibly red, and not a required status check, so it does not block merges
- [x] State in the README, `PRODUCT.md` and here that the save-latency target is
      not met

### Step 1 — measure the desktop save path

Before either implementation changes.

- [ ] A Rust-side save measurement at the 1k, 10k and 100k tiers, producing
      p50/p95 the same way `scripts/benchmark.mjs` does
- [ ] Wired into CI beside `performance-budgets`, reported and not gated until
      it passes
- [ ] Record the numbers here, and revisit this phase's scope against them

### Step 2 — encrypted change log plus periodic index compaction

Implemented in both cores, against a shared format. The preferred design, in
the order a save executes:

1. A save persists only the changed note and the index delta it implies.
2. The delta is applied to the in-memory index; the whole index is never
   re-encrypted on the save path.
3. When the log passes a size threshold, a fresh index snapshot is written.
4. The old log is removed only once that snapshot is durable.
5. After a crash, snapshot and log are read together to rebuild a consistent
   index.

Constraints that are part of the design, not optimisations to add later:

- "Saved" is answered only after the data it acknowledges is durable on disk.
  Moving the write to the background to make the number look smaller is not a
  solution and is not acceptable here.
- The log is vault content: it must be encrypted and integrity-protected, be
  catalogued in `src/format-version.ts`, be classified by `planRekey`, be
  carried by backup and restore, and carry a version this build can refuse.

### Acceptance — not speed alone

- [ ] Save p95 measured at the 1k, 10k and 100k tiers, in **both** the
      TypeScript library and the Rust core
- [ ] Measurement spans compaction rather than excluding the slow samples it
      produces
- [ ] No acknowledged save is lost across a crash or concurrent writers
- [ ] Unlock time stays within budget with a large log, not only just after a
      compaction
- [ ] A vault written by one core is read correctly by the other, log included
- [ ] Only once all of the above hold: promote `performance-budgets` to a
      required check and fold the budget into the default `--assert` gates

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
