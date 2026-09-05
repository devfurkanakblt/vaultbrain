# Changelog

All notable changes will be documented here. The project follows Semantic
Versioning once the encrypted storage format reaches 1.0.

## Unreleased

- A sync change's identity no longer depends on a key a re-key rotates. An
  epoch 1 change used to be sealed under the bare documents key, which made its
  id depend on that key; rotating it would have renamed every change in the
  causal DAG along with every parent reference, cursor and pinned checkpoint.
  New epoch 1 changes take their id from the permanent `syncChange` key and
  their body from `syncEnvelope`. Changes an earlier build wrote keep their old
  ids and still open.
- Attachment transport blobs are sealed under a key derived from the permanent
  `syncChange` key rather than the documents key, for the same reason: a blob
  id is the SHA-256 of its sealed bytes and those ids travel inside a version 3
  change body. A blob staged by an earlier build still opens.
- Groundwork for `vbrain rekey`, which has not shipped: the keyset can carry the
  outgoing rotatable keys while a re-key is in flight, and every read path tries
  the key in force before falling back to the retiring one, so a vault caught
  mid-re-key stays fully readable. Nothing writes such a keyset yet.
- iOS and Android clients are no longer carried as planned work. Vault Brain is
  a desktop product and sync is desktop-to-desktop; the phase plan and design
  spec lost their mobile sections and `docs/AUDIT-SCOPE.md` records the boundary
  for reviewers.

- Added `vbrain keyring status` plus offline recovery-kit create, restore and
  remove commands. Recovery uses a checksummed 256-bit code stored separately
  from the wrapped keyset and verifies available vault ciphertext before a
  damaged keyring is replaced.
- Keyring migration, passphrase changes and recovery mutations now add paired,
  value-free operation records to the permanent authenticated audit chain.
- Brought the frozen 1.0 format inventory in line with the keyring, which
  Phase 7 had added without declaring: `keyring.json` is now a catalogue entry
  with its slot format, AAD construction and keyset layout specified, the
  keyring slot's domain-separation string lives with every other one in
  `src/format-version.ts`, and the version 2 document manifest — the tombstone
  that makes a pre-keyring build fail closed — is a stated carve-out in the
  compatibility policy instead of an undeclared artifact version bump.
- Renamed the command-line program and its environment variables from `sbrain`
  to `vbrain` and from `SBRAIN_*` to `VBRAIN_*`, which breaks existing scripts
  and MCP configurations. The advisory writer lock stays `.sbrain.lock` on
  purpose, so a renamed build and an older one still serialize against each
  other.
- Moved attachment bytes out of the sync change envelope: a `version: 3` change
  body carries a manifest of content-addressed, AEAD-sealed 1 MiB blobs, so an
  attachment of any size the vault accepts can now synchronize. Push and pull
  are per-chunk and idempotent, an apply fails closed while a chunk is missing,
  and `vbrain sync blobs status/fetch/prune` covers the recovery paths.
  `sync export --bundle` and `sync import` move the same ciphertext without a
  relay.
- Bound each per-change device signature to the change body version, so a
  version 3 body cannot be replayed as a version 2 one.
- The desktop sync panel now reports whether the device registry carries a
  valid owner signature, and keeps its "mutation is CLI-only" guidance visible
  even for a vault whose format the build cannot display.
- A failed agreement-key write during sync enrollment no longer leaves a
  half-written device behind: the identity key is rolled back, so simply
  asking again works instead of tripping the pending-key guard.
- `vbrain passphrase change`: re-wraps the vault keyring under a new passphrase
  at the current key-derivation cost, without re-encrypting any object.
- Taught the Rust desktop core to open passphrase-wrapped keyring vaults, and
  made new vaults keyring-native in both the TypeScript and Rust cores, with a
  manifest version tombstone that makes an older build fail closed instead of
  silently misreading the vault. A vault whose `keyring.json` is missing or
  corrupted now reports that the keyring is unreadable rather than a generic
  missing-field error. The wire format is pinned by a deterministic cross-core
  test vector shared by both cores' test suites.
- Froze the on-disk format at 1.0, documented it artifact by artifact in
  `docs/FORMAT-1.0.md`, added `vbrain format` for the version matrix, and
  committed conformance fixtures that both cores read.
- Added a read-only sync status panel to the desktop app: authority
  fingerprint, active epoch, registry revision, device list, pinned checkpoint
  and change counts. Sync mutation stays in the CLI.
- Added epoch-based content-key rotation: each epoch gets a random content key
  wrapped to every active device's X25519 key, revoking an owner-signed device
  rotates automatically, and rotation is forward-only — a revoked device keeps
  read access to everything written before it.
- Added an automated recovery drill that restores an encrypted backup and then
  catches the vault up from the relay.
- Added an authenticated opaque relay server and a self-hosted deployment
  guide: it checks bearer tokens and content addresses and never holds a key.
- Added owner-signed freshness checkpoints with explicit first-pin
  verification, so a relay cannot silently withhold history.
- Added owner-signed device enrollment and sequence-bounded removal: Ed25519
  proof-of-possession requests, signed certificates, an encrypted registry
  exchange, per-change device signatures, authority pinning and rollback
  rejection.
- Extended sync capture to plugin packages and the plugin policy.
- Added synchronized document sessions that automatically capture note, canvas
  and attachment puts/deletes, keep an encrypted per-object application cursor,
  and idempotently apply conflict-free remote histories to the live vault.
- Added optimistic revision checks to TypeScript note writes, matching canvas
  writes and preventing a stale synced edit from silently overwriting a note.
- Started Phase 6 with a transport-independent encrypted immutable change log:
  keyed content IDs, per-device chains, causal DAG validation, fail-closed
  imports, deterministic conflict inspection, and CLI import/export tooling.
- Kept the Rust desktop and TypeScript CLI on the same derived index layout,
  including Unicode-normalized note lookup maps and canvas text-link refreshes,
  so a desktop write no longer forces a full CLI index rebuild.
- Added the capability manifest and sandboxed plugin runtime: plugins are stored
  encrypted in the vault, run in a network-less worker without `eval`, and reach
  only the host methods their manifest declared.
- Added Ed25519-signed plugin packages, signed-only restricted mode, and an
  encrypted per-vault signer revocation list enforced by both application cores.
- Fixed the desktop content-security policy, which blocked the `blob:` URLs
  attachment previews depend on.
- Added per-agent scoped grants with expiry, out-of-band single-use confirmation
  and immediate revocation, enforced by the MCP server.
- Added redaction-aware MCP results, and audit entries that sign who asked,
  under which grant, and how much of the value came back.
- Added opt-in semantic document recall with a revision-aware in-memory index,
  plus a loopback-only Ollama adapter for embedding and local generation.
- Added a whole-vault Obsidian importer for Markdown, encrypted attachments and
  JSON Canvas, with symlink refusal and a machine-readable integrity report for
  malformed files, ambiguous assets and unresolved links.
- Added the desktop note lifecycle: move/retitle, delete with recovery,
  encrypted revision history, and restore-forward.
- Added desktop templates and idempotent daily notes, matching the CLI's
  variable grammar.
- Added the encrypted canvas document format and the desktop canvas workspace,
  with text, group, link, note and attachment nodes on one spatial surface.
- Added the desktop attachment library: encrypt on add, decrypt only on preview
  or download, with revoked object URLs.
- Added cross-process desktop writer locking, write-journal recovery, and stale
  revision protection.
- Added sanitized npm packaging and Windows MSI/NSIS installer generation.
- Added CI, formatting, linting, dependency updates, and release quality gates.

## 0.2.0

- Added the encrypted document engine, native desktop workspace, knowledge views,
  attachments, templates, daily notes, and large-vault performance gates.
