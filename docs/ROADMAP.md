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
- [ ] Desktop passphrase-change and re-key interface
