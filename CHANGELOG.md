# Changelog

All notable changes will be documented here. The project follows Semantic
Versioning once the encrypted storage format reaches 1.0.

## Unreleased

- Re-key now includes the encrypted retention policy and preserves its values.
- The Rust core preserves the optional `legacyChangeIdentity` key when
  re-wrapping a keyset. A second cross-core vector covers this format field.
- Re-key records authenticated pending and success events, or a denial for a
  safely refused operation. Interrupted operations can remain pending; passphrase-free
  recovery does not append events because it has no signing key.
- Recovery verification supports a kit carrying current and retiring keys.
  Unsupported keysets have a distinct desktop error, and the format guide now
  names `vbrain rekey` rather than the nonexistent `--resume` option.

- `vbrain purge note|canvas|attachment` permanently removes an object and every
  archived revision of it. `docs remove` archives the outgoing revision before
  it unlinks, so a removed note's content stayed in the vault for its lifetime
  and "this should never have been written down" had no answer at all. Without
  `--yes` the command is a preview that changes nothing. It records the object
  id in the audit chain, and says what it does not reach — including, on a
  synchronized vault, the change log it did not rewrite.
- A retention policy the vault carries and both cores honour: `vbrain retention
  set --keep-revisions N --keep-days D` bounds how much history every object
  keeps and applies that bound to the history that already exists, and the
  desktop core prunes to the same bound as it writes. Nothing pruned revisions
  before, so a note edited daily grew one encrypted file per edit forever. The
  default stays unlimited, because silently discarding history someone already
  has would be the worse failure. The policy lives encrypted in
  `documents/retention.enc` and is declared in the frozen 1.0 inventory.
- `docs/DELETION.md` states what `remove`, `purge` and retention each do, what a
  purge cannot reach — earlier backups, the local sync change log, a relay the
  changes reached, a device that already pulled them, unreferenced blocks on the
  disk — and records the decision that a purge is local: 1.x ships no deletion
  tombstone, because a change cannot leave the causal DAG without invalidating
  the checkpoints that make withheld history detectable, and a delete
  instruction over an untrusted relay cannot be confirmed.
- `vbrain backup <archive>` and `vbrain restore <archive> <destination>` give
  the vault a real backup procedure, and the documentation now states it.
  "Copy the directory" was the whole story until now, and nothing said so. The
  archive is one self-contained file: a readable preamble carrying the vault's
  keyring, a sealed file list, and every file sealed under a key derived from
  the vault's permanent audit key and bound to its index and path. It opens
  with the vault passphrase and nothing else. `backup` reads its own output
  back through the restore path before reporting success; `restore
  --verify-only` checks a stored archive and writes nothing; a restore stages
  the whole verified vault and moves it into place only once every entry has
  checked out, and refuses a destination that already holds files. A host
  storing the archive sees its size and the keyring header — not how many notes
  the vault holds, their paths, or how many revisions each one has. The
  recovery drill now restores from this artifact instead of `fs.cpSync`.

- `vbrain export <destination>` writes the whole vault out as plain Markdown
  with frontmatter, JSON Canvas boards and an assets folder of attachments —
  the same shape `docs import-obsidian` reads, so export and import describe
  one format and a round trip keeps note identity. Export previously worked one
  note or one canvas at a time, which made "hand me back my data" a manual
  exercise. Note paths a filesystem cannot take (`Q3: results.md`, `aux.md`)
  and attachments that share a filename are renamed rather than dropped, and
  the report names every rename. The copy is plaintext, so the command refuses
  a destination inside the vault or one that already holds files, and the audit
  chain records that an export happened without recording where it went.

- `vbrain rekey`: a new vault keyset with every object re-encrypted under it,
  for when a passphrase has leaked and re-wrapping the same keys is not
  enough. Staged beside the live vault, verified, then committed through a
  journal, so an interrupted run either rolls back or is finished by the next
  one. `documents`, `kv` and `syncEnvelope` rotate; `attachmentId`,
  `syncChange` and `audit` are pinned, so attachment identities, sync change
  IDs and the audit chain survive.
- The desktop application can now manage the keys that decide whether a vault
  survives. It shows what the keyring holds — every slot with its label,
  creation time and key-derivation cost — changes the passphrase, and writes a
  recovery kit. Until now all three existed only in the command line, so for
  anyone who only opens the application "I forgot my passphrase" still meant
  the permanent loss of every note. A vault with no recovery kit now says so on
  unlock rather than waiting to be asked. Recovery restore and re-key stay in
  the CLI on purpose, and the application names the exact commands: a restore
  is wanted precisely when the application cannot open the vault at all.
- Every change made in the desktop application now appends to the
  passphrase-authenticated audit chain. It never did: `audit.log` was written
  only by the command line, so notes, canvases, attachments and plugins edited
  in the application were absent from the chain entirely. A committed
  cross-core vector pins the entry and head constructions so the two cores
  cannot drift. A legacy vault appends nothing, because its chain key is
  derived from the passphrase and the session does not keep one; `vbrain
  migrate` is the way out.

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
- The keyset can carry the outgoing rotatable keys while a re-key is in flight,
  and every read path tries the key in force before falling back to the retiring
  one, so a vault caught mid-re-key stays fully readable.
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
