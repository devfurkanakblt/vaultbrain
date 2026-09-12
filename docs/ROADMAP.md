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
