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
- [ ] Global graph clustering and large-graph virtualization
- [ ] Canvas/whiteboard with encrypted assets
- [x] Database-like property table with local filtering and column sorting
- [ ] Saved property queries and editable cells
- [ ] Bookmarks, workspaces, aliases and unlinked mentions
- [ ] Optional on-device semantic recall

## Phase 5 — Controlled ecosystem and AI

- [ ] Capability manifest and sandboxed plugin runtime
- [ ] Signed plugin packages, restricted mode and revocation
- [ ] Per-agent scoped grants with expiry and confirmation policies
- [ ] Redaction-aware MCP results and local-model adapter
- [ ] Importer for Obsidian vaults with integrity report

## Phase 6 — Encrypted sync and mobile

- [ ] Immutable encrypted change protocol and conflict resolution
- [ ] Device enrollment, removal and key rotation
- [ ] Untrusted relay server and self-hosted option
- [ ] Desktop multi-device release, then iOS/Android clients
- [ ] External security audit, recovery drill and stable 1.0 format

## Known gaps carried forward

Recorded here rather than lost: both come from the TypeScript core and the Rust
desktop core being two implementations of one on-disk format.

- The desktop core does not maintain the index lookup maps the CLI core added
  for large vaults. The format stays compatible, but a vault last written by
  the desktop app pays one index rebuild the next time the CLI opens it.
- The desktop core has no `frontmatterSource` field, so a note whose YAML was
  imported with comments loses that preserved source if the desktop app
  rewrites it. The CLI round-trip keeps it.
