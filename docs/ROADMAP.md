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

- [ ] Immutable encrypted change protocol and conflict resolution
  - [x] Content-addressed encrypted envelopes, device chains, causal DAG validation and deterministic conflict inspection
  - [x] Emit changes automatically from note/canvas/attachment transactions and apply resolved remote changes to live storage
  - [x] Capture plugin package and plugin-policy transactions
  - [ ] Portable workspace state. The Phase 6 plan defines portable state as
    notes, canvases, attachments, plugin packages, `plugin-policy`,
    `saved-views` and `workspace` including bookmarks. Only `plugin-policy` is
    captured. Saved views, bookmarks and layouts live solely in the Rust core's
    `workspace.enc`, which the TypeScript core — the one that owns sync —
    cannot read at all, so a second device silently loses them.
- [x] Owner-signed device enrollment and sequence-bounded removal
  - [x] Ed25519 proof-of-possession requests, signed certificates and encrypted registry exchange
  - [x] Per-change device signatures, authority pinning, rollback rejection and revocation cutoffs
- [x] Epoch-based content-key rotation
  - [x] Random per-epoch content keys wrapped to each active device's X25519 key
  - [x] Automatic rotation on owner-signed device revocation
  - [x] Forward-only: a revoked device retains pre-rotation read access
- [x] Owner-signed freshness checkpoints with explicit first-pin verification
- [x] Authenticated opaque relay server and self-hosted option
- [ ] Desktop multi-device release
  - [x] Read-only desktop sync status; mutation remains CLI-only
  - [ ] Desktop-driven enrollment, revocation and relay exchange
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
- [ ] 7.4 `vbrain rekey`
  - [ ] Fresh data keys and a re-encrypted vault, so a leaked passphrase has an answer
  - [ ] Resumable: interrupt a re-key at a random object, resume, and assert the
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

## Phase 8 — Key management the desktop can reach

Every command that decides whether a vault survives — create a recovery kit,
look at what the keyring holds, change the passphrase, re-key after a leak —
exists only in the CLI. The desktop application is the product's primary
surface, so for the people who use it "I forgot my passphrase" still means the
permanent loss of every note, even though 7.5 shipped the answer. This phase
absorbs the desktop passphrase-change and re-key interface Phase 7 listed.

**The decision, recorded.** The work is split by how much audited surface it
adds, not by convenience. `src-tauri/src/keyring.rs` already carries the whole
keyring write path — `wrap_key_set`, `unwrap_keyring`, `read`, `write` — over
`scrypt`, `aes-gcm`, `sha2`, `hmac` and `rand`. Keyring status, passphrase
change and recovery-kit creation therefore need no cryptographic primitive the
desktop core does not already have, and are implemented natively. Recovery
*restore* and re-key are not: restore verifies vault ciphertext before
replacing a damaged keyring, which would mean a second `openSyncChange`, and
re-key rewrites every object. Both stay in the CLI, and the application's job
is to name the exact command. Restore in particular runs when `keyring.json`
is already damaged — the moment the application cannot open the vault at all —
so a graphical path to it would mostly be unreachable when it is needed.

- [ ] The audit chain in the Rust core. Phase 7.5 requires every key-material
      command to append to the passphrase-authenticated chain, and the
      application has no way to. This is the larger bug underneath: `audit.log`
      is written only by `src/cli.ts`, so every note, canvas, attachment and
      plugin change made in the application today is absent from the chain
      entirely. A committed cross-core vector pins the entry and head
      constructions, the way `keyring-vector.json` pins the keyset.
- [ ] `keyring status` in the application: every slot with its id, label,
      creation time and key-derivation cost, so a user can see a slot they did
      not add and can learn their vault still sits at the old work factor.
- [ ] Passphrase change from the application, including the key-derivation cost
      upgrade the CLI command already performs.
- [ ] Recovery-kit creation in the application, with first-run guidance that
      asks for one before the vault holds anything worth losing. A recovery slot
      nobody is told about protects nobody.
- [ ] Recovery restore and re-key remain CLI operations. The application
      detects when one is needed and shows the exact command, rather than
      pretending to offer what it cannot safely perform.

## Phase 9 — Getting the data out, and back

A local-first product that cannot hand back a plain copy of its contents is
lock-in by another name. Export is one note or one canvas at a time. Backup is
"copy the directory": the recovery drill does exactly that with `fs.cpSync`,
and no command or documented procedure says so to a user.

- [ ] `vbrain export`: the whole vault as a folder of Markdown with
      frontmatter, attachments beside the notes that reference them, and
      canvases as JSON Canvas. The Obsidian importer already reads that shape,
      so export and import would describe one format rather than two.
- [ ] `vbrain backup` and `vbrain restore`: a verified, self-contained
      encrypted copy carrying the key-derivation metadata a restore needs, and
      a restore that refuses a backup it cannot open rather than replacing a
      working vault with one.
- [ ] A stated backup procedure in the documentation, and a drill that restores
      from that artifact rather than from a directory copy.

## Phase 10 — Deletion that deletes, and history that ends

`remove` archives a revision before it unlinks the object, so a deleted note's
content stays under `documents/history/` for the life of the vault. For a
product that invites medical, financial and identity data, "I need this gone"
has no answer. Nothing prunes revisions either, so a note edited daily grows a
file per edit forever.

- [ ] `vbrain purge`: permanent removal of a note, canvas or attachment and
      every revision of it. Distinct from `remove`, and refusing to run without
      an explicit confirmation.
- [ ] A revision retention policy the vault carries and both cores honour, with
      a command that applies it to history that already exists.
- [ ] Say plainly what a purge cannot reach: a purged object still exists in any
      backup taken before it, in any sync change already pushed to a relay, and
      on any device that pulled it. Whether a purge propagates as a tombstone is
      a separate decision, and this phase records which one is taken.

## Phase 11 — macOS and Linux

The desktop bundles only `msi` and `nsis`, the Rust job runs only on
`windows-latest`, and `docs/AUDIT-SCOPE.md` records as an accepted risk that
only the Windows credential-store path is exercised by tests. The macOS and
Linux keychain backends are written but unproven.

- [ ] Bundle and test the desktop application on macOS and Linux.
- [ ] Run the Rust suite on all three platforms in CI, and exercise the
      `security` and `secret-tool` keychain backends where they are real.
- [ ] Verify path handling, permissions and atomic replacement per platform.
      The vault's durability guarantees are filesystem-specific and are
      currently demonstrated on one filesystem only.

## Phase 12 — Actually shipping

The release workflow signs, checksums, produces an SPDX SBOM and attests build
provenance, then uploads the result as a workflow artifact, which expires.
Nothing is published, and there is no update path, so a security fix cannot
reach anyone who already installed a build.

- [ ] Publish signed installers with their checksums, SBOM and provenance as
      release assets.
- [ ] An update path, with a recorded decision about whether it is automatic.
      An updater is also a code-delivery channel into a vault holding the
      user's secrets, so that choice is a security decision, not a convenience.
- [ ] Put the evidence that matters into CI. `recovery:drill` runs nowhere, and
      only the 1,000-note benchmark gates a change while the roadmap claims 10k
      and 100k gates.

## Phase 13 — One implementation of each thing

Every protocol defect this project has found in itself came from two pieces of
code that were meant to agree and did not. The TypeScript and Rust cores are a
deliberate, audited pair. These three are not.

- [ ] Retire `src/sync/change-log.ts`. `src/sync.ts` has its own change log and
      is the one in use; the extracted copy is reached only by tests. The
      epoch 1 change-identity defect existed precisely because
      `sync/protocol.ts` sealed under the right key while `sync.ts` did not,
      and nothing compared them.
- [ ] Complete the frozen domain-separation inventory.
      `secondbrain-vault:kv:v2` (`src/crypto.ts`),
      `secondbrain-vault:sync-local-transaction:v1` and
      `secondbrain-vault:sync-apply-receipt:v1` (`src/sync/transaction.ts`)
      live outside `src/format-version.ts`, so
      `test/format-conformance.test.mjs` does not freeze them and a refactor
      could change one without failing a test — the exact accident the
      inventory exists to prevent.
- [ ] Close the format catalogue gap `docs/AUDIT-SCOPE.md` already records:
      `documents/index.enc` and `documents/plugin-policy.enc` are real
      encrypted artifacts with no entry in `FORMAT_COMPATIBILITY`, and so sit
      outside the 1.x compatibility policy that covers everything beside them.
