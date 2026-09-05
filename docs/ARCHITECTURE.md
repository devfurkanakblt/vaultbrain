# Target Architecture

## Direction

The current TypeScript CLI remains the compatibility and automation surface.
The desktop product will use a Tauri 2 shell with a React/TypeScript frontend
and a Rust security core. The webview never receives filesystem access or a
vault master key. It invokes a small set of typed commands whose permissions
are scoped to the main application window.

Tauri's runtime authority checks origins, capabilities and command scopes before
dispatching IPC calls. We will still validate every path and identifier inside
the command implementation; framework ACLs are one layer, not the whole boundary.

Reference: <https://v2.tauri.app/security/runtime-authority/>

## Component boundaries

```text
Desktop webview
  editor · navigation · graph · command palette
                  │ typed, capability-scoped IPC
                  ▼
Rust application core
  session keys · note service · policy engine · audit · migrations
        │                 │                   │
        ▼                 ▼                   ▼
encrypted objects   encrypted search DB   encrypted event journal
        │
        └── optional Markdown import/export boundary

MCP/CLI ──► policy engine ──► narrow note/field operation ──► audit
Sync    ◄── encrypted immutable change objects only ─────────┘
```

## Storage model

The target vault is versioned and self-describing:

```text
vault/
  manifest.json              # format/KDF versions; no content
  keyring.json               # wrapped keyset; every new and migrated vault; lost keyring loses vault
  objects/                   # encrypted notes and attachments
  index.db.enc               # encrypted derived search/link index
  views.enc                  # encrypted saved property queries
  workspace.enc              # encrypted bookmarks and named layouts
  journal/                   # encrypted crash-recovery operations
  audit.log                  # value-free authenticated chain
  audit.meta.json            # public salt/version metadata
  catalog.json               # optional least-exposure AI catalog
```

Saved property queries name columns and carry filter text the user typed about
their own notes, so they get the same envelope as the index rather than a
plaintext settings file. They are unreadable, and unlistable, while locked. The
same holds for bookmarks and named layouts: which notes someone pins, and what
they called a workspace, is vault content by another name.

A note answers to its title and to every alias, in search, link resolution and
the quick switcher. Notes that name another in plain text without linking it are
reported as unlinked mentions, computed from the decrypted index at read time
rather than stored.

Canonical notes contain an immutable ID, title, Markdown body, typed properties,
tags, aliases, links, creation/update timestamps and revision number. User-facing
paths are mutable labels, not identity. Attachments are chunk-encrypted and
content-addressed so large edits do not rewrite the whole vault.

The current `.kv.enc` format stays readable and receives a one-way, backed-up
migration into the document model. Markdown is a first-class import/export
format, but plaintext Markdown is not the default at-rest representation because
that would break the product's security promise.

Whole-vault Obsidian migration is a boundary operation rather than a second
storage mode. The importer scans a user-selected source without following
symbolic links, validates Markdown/frontmatter before the bulk note write,
encrypts non-note files through the content-addressed attachment store, then
imports JSON Canvas after note and attachment identities exist. It leaves source
links untouched for portability and emits a plaintext integrity report covering
malformed inputs, missing or ambiguous assets, and unresolved local links. The
encrypted destination must live outside the source tree, so the scanner cannot
ingest its own output.

## Search design

SQLite FTS5 supports prefix, phrase, NEAR and boolean queries plus BM25 ranking
and snippets. A normal FTS5 database exposes tokens on disk, so it must not be
used unencrypted. During the transition, the app builds an incremental in-memory
index after unlock. The production desktop core will persist the same logical
index only behind a reviewed encrypted SQLite integration.

Semantic recall is a separate, explicit path rather than a silent replacement
for lexical search. `DocumentVault.semanticSearch` sends bounded note text to an
embedding adapter only when called, caches normalized vectors by note revision
in the unlocked process, and overwrites them on lock. It does not add an
embedding file to the vault, so a locked or copied vault gains no new plaintext
or vector sidecar. The first query after each process start pays the embedding
cost; later queries embed only the query and notes whose revisions changed.

The first local-model adapter targets Ollama's embedding and generation APIs.
It accepts only literal HTTP loopback hosts (`127.0.0.1`, `localhost`, `[::1]`),
refuses redirects, bounds time and response size, and validates vector shape and
finite values before ranking by cosine similarity. This protects against an
accidental remote endpoint; it does not make an untrusted local model process
safe. The caller also controls the per-note character ceiling, 16,000 by
default, so model exposure and recall depth are explicit tradeoffs.

Reference: <https://www.sqlite.org/fts5.html>

The link index is updated in the same logical transaction as a note revision:

- outgoing and unresolved wikilinks
- backlinks by stable note ID
- headings and block anchors
- normalized tags and property values
- full-text terms and ranking statistics

## Cryptographic model

- `keyring.json` holds the passphrase-wrapped keyset. A memory-hard KDF
  (scrypt, N=2^17) derives a wrapping key from the passphrase; the wrapping key
  unwraps six independent 32-byte data keys: `documents`, `kv`, `attachmentId`,
  `syncChange`, `syncEnvelope` and `audit`. No data key is derived from the
  passphrase, which is what makes changing the passphrase cheap and re-keying
  possible. Both the TypeScript and Rust cores read this file; only the
  TypeScript core migrates a legacy vault into it. See
  `docs/superpowers/specs/2026-09-03-vault-keyring-design.md` for the full key
  hierarchy and wire format. A passphrase change re-wraps the keyset in place:
  the slot gets a fresh salt at the current cost, the keys inside it do not
  move, and no object is rewritten.
- Notes and attachment chunks use an authenticated encryption mode with unique nonces.
- Changing the passphrase re-wraps the keyset and rewrites no object. Re-keying
  (`vbrain rekey`) replaces the keyset and rewrites every object, which is what
  a leaked passphrase requires.

  Three of the six keys rotate: `documents`, `kv` and `syncEnvelope`. They
  protect content, and every envelope they cover binds an AAD that is a pure
  function of the artifact's own path, so a re-key can reproduce each identity
  byte for byte while changing the key underneath it.

  Three do not. `attachmentId` and `syncChange` derive identities rather than
  protecting content — a content address that names a directory, an AAD, a
  canvas node and a sync object; a change ID that every descendant lists as a
  parent — so rotating either is an identity migration that diverges from any
  peer that has not run it. `audit` signs a chain the format gives no key epoch,
  so rotating it would invalidate every entry written before the rotation.

  Pinning the two identity keys leaves a confirmation oracle: someone holding
  the old keyset can compute a candidate file's content address and check
  whether a directory of that name exists, learning that the vault holds that
  exact file without decrypting anything. Closing it is an identity migration
  and has not been done.
- Session keys are kept only in the privileged core and zeroized on lock.
- Per-device sync keys and per-agent grants are derived/separated by purpose.
- Every encrypted record authenticates its format version and logical identity as associated data.

The existing AES-256-GCM/scrypt implementation remains supported while a versioned
envelope and migration path are introduced. Cryptographic changes require test
vectors and review; custom primitives are forbidden.

The `secondbrain-vault:*` associated-data and signature namespaces are canonical
storage/protocol identifiers. Changing one requires an intentional format reset
or version bump because it invalidates encrypted records, sync changes and
signed plugins created with that identifier.

## Trust boundaries

| Principal       | Default access                                                  |
| --------------- | --------------------------------------------------------------- |
| Desktop webview | Rendered active-note data only; no raw filesystem or key access |
| CLI direct mode | Explicit user-requested operation                               |
| MCP agent       | Catalog discovery only; content requires a scoped grant         |
| Plugin          | No capabilities until declared and approved                     |
| Sync server     | Ciphertext, opaque object IDs and minimal routing metadata      |
| Exporter        | Selected decrypted notes for a user-confirmed destination       |

## Performance strategy

- Unlock once, derive once, then keep bounded working keys in locked memory where supported.
- Incrementally index changed notes instead of rebuilding the vault.
- Debounced journal append gives instant editor acknowledgement; durable object compaction follows.
- Virtualize file trees, result lists and graph rendering.
- Parse Markdown off the UI thread and cache by content hash.
- Benchmark 1k/10k/100k-note fixtures in CI and fail material regressions.

## Current secure-core improvements

The TypeScript compatibility core now establishes patterns the desktop core must preserve:

- category/path confinement and symlink refusal
- crash-safe atomic encrypted writes
- escaped multiline/quoted values with legacy read compatibility
- cryptographically random UTC note IDs
- passphrase-authenticated, chained audit entries
- regression tests for encryption, traversal, indexing, dates and audit integrity

The first document-engine slice is also operational:

- one scrypt derivation per unlocked document-vault session
- stable UUID note identity with path-independent revisions
- AES-GCM note objects and an encrypted derived search/link index
- Markdown wikilinks, embeds, headings, block references and inline tags
- ranked phrase/tag/path search with result excerpts
- resolved outgoing links, backlinks and rebuildable indexes
- portable Markdown plus JSON-compatible YAML frontmatter export/import
- encrypted index v2 with direct backlink, resolved-link and unresolved-link maps
- encrypted immutable revision objects and recovery after deletion
- keyed content-addressed attachments encrypted in independent 1 MiB chunks
- a repeatable benchmark harness with p95 failure thresholds
- YAML 1.2 frontmatter with nested properties, block scalars, tags and aliases
- safe template substitution without code evaluation or arbitrary expressions
- idempotent, folder/format/template-aware daily-note creation

The 1,000-note reference run on the current development machine records warm
p95 values below 10 ms for title search, below 5 ms for full-text search, below
1 ms for note opening and below 1 ms for backlink lookup. These are evidence for
the current corpus only; the 10k/100k targets remain release gates, not claims.

YAML input is parsed with duplicate-key rejection, aliases disabled, a 256 KiB
frontmatter ceiling, bounded nesting/collection sizes and explicit rejection of
prototype-shaping keys. Export preserves property values semantically in standard
YAML; preserving the source document's comments and stylistic formatting remains
a separate round-trip milestone.

## Index layout and scale

The encrypted index is the file that decides whether a large vault feels
instant. Building the 10,000- and 100,000-note gates exposed three quadratic
paths that a 1,000-note corpus had comfortably hidden:

- resolving a note by path scanned every note and re-normalized its strings,
  once per write, so a bulk import was O(n²);
- resolving a wikilink did the same scan, once per link;
- removing a note from the link map walked every bucket in it.

The index now carries reverse lookups — `pathOwners`, `nameOwners` and
`basenameOwners` — maintained incrementally alongside the existing link map, so
each of those is a hash lookup. Link-map removal uses the note's own previous
links instead of a scan.

Search had a second problem: it normalized every note's body inside the query
loop, so every keystroke paid an NFKC pass over the entire vault. Normalized
search text is now computed once per note per session and memoized against the
note's revision, and the filter loop allocates no per-note closures. Those
normalized fields are deliberately **not** written to disk — a second copy of
every body would double what unlock has to decrypt.

The on-disk index therefore stays at version 2, the layout both application
cores read and write. A `derived` marker records that the reverse lookup maps
are present. Both the TypeScript CLI and Rust desktop core now maintain
`pathOwners`, `nameOwners` and `basenameOwners` with the same NFKC
normalization rules. The Rust core also re-derives canvas text-link references
when note identities change. An index written by an older build is rebuilt
from the encrypted note and canvas objects once, then saved in the shared
layout on the next write.

### Measured at 100,000 notes

Development machine, one run, after the work above. Budgets are from
`docs/PRODUCT.md`; every figure is p95 unless noted.

| Interaction                         |     Budget | 10,000 notes | 100,000 notes |
| ----------------------------------- | ---------: | -----------: | ------------: |
| Cold unlock to usable index         | < 2,000 ms |        77 ms |         97 ms |
| Quick switch over titles/aliases    |    < 30 ms |       1.2 ms |       22.0 ms |
| Full-text query (selective)         |   < 100 ms |       5.7 ms |       20.3 ms |
| Full-text query matching every note |   < 100 ms |       9.3 ms |       74.5 ms |
| Open an indexed note                |    < 50 ms |       0.3 ms |        0.3 ms |
| Backlink query                      |    < 50 ms |      0.01 ms |       0.01 ms |

Two numbers are reported rather than gated, because hiding them would be
misleading:

- **First query after unlock: 344 ms at 100k.** That is the one-time pass that
  normalizes search text for the whole vault. Every later query is the number
  in the table. Moving that work into the index would trade it for a larger
  file to decrypt at unlock, and would break the layout the desktop core reads.
- **Building the corpus: 315 s for 100,000 notes.** Each note is a separate
  encrypted object, fsynced before it is renamed into place. That cost is the
  crash-safety guarantee, not an accident, and it is paid by bulk imports
  rather than by ordinary editing.

## Encrypted sync change protocol

Phase 6 begins with a transport-independent append-only log under
`documents/sync/changes/`. Each change contains a device sequence, the prior
change from that device, causal parents, one logical object mutation and its
base/new revision. The complete body is canonical JSON, encrypted with the
vault document key, and authenticated against its keyed content ID. The relay
surface therefore consists only of random-looking IDs and AES-GCM envelopes;
object types, IDs, timestamps, device identities and values remain encrypted.

Change IDs are HMAC-SHA256 values with a sync-specific domain separator. This
prevents offline guessing from the filename while making retries idempotent.
Each ID derives a separate envelope subkey, isolating AES-GCM nonce domains
across changes and devices that share the vault key.
Envelope files are installed with an exclusive hard link from a fully written,
fsynced sibling temporary file, so an existing change is never overwritten and
a crash cannot publish a half-written final object.

Every import is validated as a set before anything is written: content IDs,
device sequence forks, missing parents, cycles and causal object revision jumps
all fail closed. Concurrent object heads remain in the log. Resolution chooses
a deterministic display winner by revision, tombstone precedence and keyed
change ID, while returning every other head as a conflict. A later change that
parents all heads records an explicit causal merge and removes the conflict.

The second slice adds `SyncedDocumentVault`, a write session that mirrors
successful note, canvas and attachment puts/deletes into the causal log while
holding the same cross-process vault lock as the underlying storage operation.
Existing objects receive a revision-1 sync baseline before their first captured
edit, so enabling sync on a mature vault does not lose its pre-sync state.

Conflict-free imported histories can be applied to the real encrypted object,
attachment and derived-index storage. Application walks the winning causal
history in revision order and advances an encrypted per-object cursor only
after each storage transaction succeeds. Repeating an application is therefore
idempotent, and unresolved heads fail before touching live storage. Attachment
bytes are carried inside v1 snapshots and consequently share the 8 MiB change
limit; larger-attachment blob transport remains a later slice.

Plugin transaction capture, enrollment and rotation, relay transport and
compaction checkpoints remain later Phase 6 slices. The format contract and
threat analysis are recorded in
`docs/superpowers/specs/2026-08-31-encrypted-sync-change-protocol-design.md`.

## Durability and session lifecycle

A note object and the search/link index are separate encrypted files, so a
crash between the two writes could leave the index describing a vault that no
longer exists. Three mechanisms keep that from becoming data loss:

- **Atomic single-file writes.** Every encrypted file is written to a sibling
  temporary file, fsynced, then renamed, so a file is either wholly the old
  version or wholly the new one.
- **A write journal.** Before a transaction touches an object, a plaintext
  `documents/journal.json` names the note IDs about to change. The next unlock
  replays those notes out of the objects on disk and rewrites the index, then
  deletes the journal. The journal holds only UUIDs that are already visible as
  filenames in `objects/`, so it leaks nothing a directory listing does not —
  and staying readable without the key is exactly what makes it usable for
  recovery. A bulk import cannot name its notes up front, so it journals its
  scope instead and recovery does a full rebuild.
- **An advisory vault lock.** `.sbrain.lock` serializes writers between
  Vault Brain processes, is reentrant within one process, and is
  reclaimed when the recorded holder has gone stale, so a crashed session
  cannot wedge a vault permanently. It does not defend against someone editing
  the files by hand — nothing advisory can.

The Rust desktop core now uses the same `.sbrain.lock` protocol and plaintext
write-journal shape as the TypeScript core. Every desktop mutation refreshes the
encrypted index while holding that cross-process lock, note writes announce
their stable IDs before touching the object, and unlock replays an interrupted
object write into the index. A stale editor revision is rejected instead of
overwriting a newer CLI or desktop write. The Rust serializer also preserves
unknown canvas index fields and `frontmatterSource`; it removes the TypeScript
lookup-map marker until Rust maintains those maps itself, so the CLI rebuilds
once rather than trusting stale derived data.

Recovery is covered by fault-injection tests that reproduce a crash at the
exact point between the object write and the index write, and assert that the
next unlock heals the index; a control case without the journal shows the index
would otherwise stay stale.

## The plugin sandbox

Extensibility is where a local-first encrypted app usually gives up its threat
model. Obsidian's plugins are arbitrary Node in the app process; that is a
reasonable trade for a plaintext vault and an unreasonable one here.

A plugin is a manifest plus one JavaScript file, stored as a third encrypted
object type (`objects/<id>.plugin.enc`) beside notes and canvases, with its own
AAD — so opening a plugin as a note fails authentication rather than needing a
check that could be forgotten. Its settings live in a separate object again, so
writing a setting never rewrites the code and reading settings never decrypts
it.

Three layers, in increasing order of how much they are trusted:

1. **The manifest**, validated in both cores. It says what a plugin may ask for.
   An unknown capability is refused rather than dropped: dropping it would
   install a plugin whose reach cannot be described to the person approving it.
2. **The worker sandbox.** The plugin runs in a Worker with `fetch`,
   `XMLHttpRequest`, `WebSocket`, `importScripts`, `indexedDB` and friends
   removed before its first line. It is _loaded_ as a worker script rather than
   evaluated from a string — which is why the app's CSP gains only
   `worker-src blob:` and never `'unsafe-eval'`. The host checks each call
   against the shared capability table and refuses an unlisted method, so a host
   method added without a capability entry is unreachable rather than public.
   A plugin that will not stop calling is terminated, not throttled in silence.
3. **The Rust command layer**, which is the actual boundary and trusts neither
   of the first two. A full escape from the worker into the webview would still
   hold only what the webview holds, and the vault key is never there.

The capability table lives in one file, `src/plugins.ts`, imported by both the
Node core and the browser host. The Rust core keeps its own copy so it can
refuse an unknown capability at install time; a test reads the TypeScript list
and asserts the two agree, because a table that drifts by one entry is exactly
how this model would fail quietly.

What the sandbox does not do is protect against a plugin abusing what it was
granted. `notes:read` means the plugin reads notes. The control there is the
capability list shown before installation, and the switch that stops it.

Plugin packages may additionally carry an Ed25519 signature over a canonical,
length-prefixed encoding of the normalized manifest and the exact JavaScript
source. The signature envelope contains the raw public key; both cores derive
its SHA-256 key ID and independently verify the same payload. Verification is
repeated when an encrypted plugin object is loaded, not trusted only because an
earlier installer accepted it. The signer key is pinned on first signed install:
an update may move an unsigned plugin to a signed package, but a signed plugin
cannot move back to unsigned or change signer without explicit removal and a
fresh install consent step.

The encrypted `plugin-policy.enc` object holds two vault-wide controls:

- **Restricted mode** refuses unsigned installation and makes every unsigned
  installed plugin non-runnable without deleting it.
- **Signer revocation** blocks one public-key fingerprint, immediately making
  every package from that key non-runnable. Restoration is explicit and does
  not silently turn a stopped plugin back on.

This is package integrity and local trust continuity, not a public identity
system. A self-contained public key does not prove the publisher's real-world
identity; users still need an out-of-band reason to trust it the first time.

## Per-agent grants and redaction

Mode 2 used to be all-or-nothing: an agent holding the passphrase could resolve
any key. `grants.enc` narrows that without changing the trust boundary.

The file's presence is the switch. A vault without one behaves exactly as
before, so nothing that works today stops working; adding the first grant makes
the vault enforcing, and the CLI says so at that moment rather than in a
release note.

A grant binds one agent name to scopes of `file:keys:actions:redaction`, with an
optional expiry and an optional per-resolution confirmation policy. Evaluation
has three properties worth naming:

- **Strictest wins.** Where several scopes cover one key, the most restrictive
  redaction applies, so a later broad grant cannot widen an earlier narrow one.
- **Revocation is immediate.** The MCP server reloads the policy per call rather
  than caching it, and revoking a grant also drops that agent's outstanding
  approvals, so a revoked agent cannot spend a "yes" it was already given.
- **Confirmation is out of band.** A stdio MCP server has nobody to prompt, so a
  held resolution is parked in the vault and the owner approves it from their
  own terminal. The approval is single-use and short-lived: it is deleted as it
  is spent.

Redaction has `none`, `partial` and `full` levels. `partial` masks the
identifiers it recognizes — IBANs, card numbers, emails, phone numbers, long
opaque strings — keeping a short tail so an agent can confirm it found the right
field; a value it cannot classify is masked anyway rather than passed through.
`full` returns a description of the value's shape and none of its characters.

What this is not: a boundary. A redacted value still crosses into the calling
model's context as a redacted value, and `VBRAIN_AGENT` is a name the agent
chooses, not a credential — anything that can start the server can pick any
name. The security boundary remains the passphrase and the encrypted files, and
Mode 1 remains the only path that involves no model at all.

The audit log carries the new facts — agent, grant, redaction level, and whether
the call was allowed, denied or held — and signs them. They are folded into the
signed payload only when present, so a log written before grants existed hashes
byte-for-byte as it did and keeps verifying.

Unlocking is an explicit lifecycle in the core, not only in the desktop shell.
`DocumentVault.lock()` overwrites the derived key in place and drops the
decrypted index; every later operation on that session fails until a new one is
opened with the passphrase. The CLI mirrors it: `vbrain unlock --remember`
places the passphrase in the OS credential store, `vbrain lock` removes it.

The credential backends are Windows DPAPI (through PowerShell, with the secret
crossing on stdin rather than argv), macOS Keychain via `security`, and
libsecret via `secret-tool`. Only the Windows backend is exercised by the test
suite, and `security` takes the secret as a command-line argument, which is
briefly visible to that user's own processes. All three protect the secret from
other users and other machines; none protects it from code already running as
the user.

## Current desktop slice

The first native desktop slice is operational on Windows:

- a Tauri 2 shell with a strict content-security policy and no filesystem, shell,
  network or dialog plugin exposed to the webview
- forty-six explicitly allowlisted IPC commands for unlock, lock, list, open,
  save, create, move, delete, history, restore, templates, daily notes, search,
  backlinks, value-minimized graph data, typed property rows, saved views,
  workspace state, unlinked mentions, canvases, attachments and plugins
- a Rust session that derives the scrypt key once, keeps it outside the webview
  and zeroizes it when the vault locks
- authenticated AES-GCM note/index objects compatible with the TypeScript
  document format, plus Windows-native atomic replacement with write-through
- content-addressed attachments in the same layout the CLI writes: one encrypted
  manifest beside 1 MiB chunks, each chunk authenticating its own index, and an
  address that is an HMAC of the bytes under the vault key rather than a bare
  digest, so a directory listing does not identify a known file. Bytes cross the
  IPC boundary base64-encoded; the webview never touches the filesystem
- a React workspace with an encrypted-vault lock screen, file tree, CodeMirror
  Markdown editing, reading view, search, command palette, properties, outline
  and backlinks, plus local graph and property-table views
- the full note lifecycle over one journalled write path: a move keeps the note
  ID so history and ID-resolved links survive it, a delete archives the live
  revision before unlinking the object so the note stays recoverable, and a
  restore writes the historical content forward as a new revision instead of
  rewinding the counter. History lookups accept an ID the live index no longer
  knows, but only an ID — the titles a deleted note answered to may since have
  moved to another note
- template rendering and idempotent daily notes in Rust, with the same variable
  grammar and local-clock semantics as the TypeScript core, so a note created in
  the desktop app and one created by the CLI are indistinguishable on disk
- encrypted canvas documents in the same object layout as notes, holding text,
  group, link and file nodes plus directed edges. A file node stores the note or
  attachment id, never a decrypted path, so a deleted target degrades to a
  missing reference instead of leaking what it used to point at; a canvas write
  carries its base revision and is rejected if the stored one has moved on
- a tab strip over an editable primary pane and a read-only split pane, with a
  swap action that promotes the split document into the editor
- a keyboard-driven quick switcher over titles, paths and aliases that opens a
  note in the editor or, with `alt`, straight into the split pane
- navigation guards that persist dirty notes before switching documents,
  closing a tab or locking the vault
- an inactivity timer that locks the session after a configurable idle window
  (1/5/15 minutes, or disabled) and reports the reason on the lock screen
- clipboard copies that the workspace owns and revokes: it rewrites the
  clipboard to empty after 30 seconds, and again on lock, but only while the
  clipboard still holds the value it wrote
- fixed-height row windowing for the file tree and the property view, so the
  number of DOM nodes follows the viewport rather than the vault
- a theme editor that derives every CSS token from four editable colours plus a
  reading size and typeface, reports WCAG contrast for the pair a reader
  actually looks at, and persists per device outside the vault

The initial UI bundle is code-split: the application shell is about 240 KiB
minified (75 KiB gzip), while CodeMirror and Markdown preview code load only
when required.

The idle lock and clipboard revocation are webview-side guards, not core
guarantees: the session key still lives only in Rust and is zeroized by the
same `lock_vault` command the button calls, but a webview whose clipboard read
permission is denied cannot verify ownership, and in that case the copied value
simply stays where the operating system put it.

Windowing bounds what the _interface_ costs, not what the core costs: the tree
and property view now render a viewport's worth of rows out of any number, but
the unlock, search and index budgets are still only enforced against the 1,000-
note benchmark corpus. The 10k/100k index gates and large-graph virtualization
remain open, and the theme is a per-device preference in `localStorage`, never
part of the encrypted vault.
