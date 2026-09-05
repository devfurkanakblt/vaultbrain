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

## Phase 6 — Encrypted sync and mobile

- [ ] Immutable encrypted change protocol and conflict resolution
  - [x] Content-addressed encrypted envelopes, device chains, causal DAG validation and deterministic conflict inspection
  - [x] Emit changes automatically from note/canvas/attachment transactions and apply resolved remote changes to live storage
  - [ ] Capture plugin package and plugin-policy transactions
- [ ] Device enrollment, removal and key rotation
- [ ] Untrusted relay server and self-hosted option
- [ ] Desktop multi-device release, then iOS/Android clients
- [ ] External security audit, recovery drill and stable 1.0 format

## Phase 7 — Key wrapping, passphrase change and re-key

- [x] Encrypted keyring: passphrase-wrapped keyset, adopting migration, keyed key-value envelope
  - [x] Keyring format, vault format detection and cached keyset resolution
  - [x] Key-value and grant files encrypted by the keyset and bound to their file identity
  - [x] Document, attachment-identity and sync-change keys separated
  - [x] `vbrain migrate` upgrades an existing vault without re-encrypting an object
  - [x] Rust core opens a keyring vault, and both cores create new vaults keyring-native
- [x] Passphrase change, including the KDF cost upgrade path
- [x] Full re-key after a compromised passphrase
- [ ] Survivable keyrings: a second way in, a way to look inside, and a record of every change
  - [ ] Attachment identity migration, closing the confirmation oracle a
        re-key leaves behind. Rotating `attachmentId` renames every attachment
        directory and rewrites every canvas object, canvas history revision
        and index reference that names one, and every peer must run it at the
        same time or their attachment IDs diverge.
  - [ ] A deliberate lock-break path. Nothing in the CLI can reclaim a vault
        lock on purpose; a crashed `vbrain rekey` holds it for up to 15
        minutes (`REKEY_STALE_MS`), and until it expires or a person deletes
        `.sbrain.lock` by hand, every other command refuses to run.
  - [ ] Recovery slot, so one forgotten passphrase or one damaged `keyring.json` is not
        the permanent loss of every note. The format already carries a slot list and
        reserves this slot; nothing writes one yet, and the keyring concentrated into
        one small file what used to be derived from the passphrase directly.
  - [ ] `vbrain keyring status`, listing every slot with its id, label, creation time
        and KDF cost. Without it a slot someone else added is invisible — a passphrase
        change deliberately preserves the slots it cannot open — and a user has no way
        to learn their vault still sits at the old cost, which makes the upgrade path
        undiscoverable.
  - [ ] Audit entries for `migrate` and `passphrase change`. Every content command
        already appends to the passphrase-authenticated chain; the two commands that
        touch key material append nothing, so "when did this vault's passphrase last
        change" has no answer. The `audit` key is permanent, so entries written before
        and after a change verify in the same chain.
