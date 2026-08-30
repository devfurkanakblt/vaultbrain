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
  objects/                   # encrypted notes and attachments
  index.db.enc               # encrypted derived search/link index
  views.enc                  # encrypted saved property queries
  journal/                   # encrypted crash-recovery operations
  audit.log                  # value-free authenticated chain
  audit.meta.json            # public salt/version metadata
  catalog.json               # optional least-exposure AI catalog
```

Saved property queries name columns and carry filter text the user typed about
their own notes, so they get the same envelope as the index rather than a
plaintext settings file. They are unreadable, and unlistable, while locked.

Canonical notes contain an immutable ID, title, Markdown body, typed properties,
tags, aliases, links, creation/update timestamps and revision number. User-facing
paths are mutable labels, not identity. Attachments are chunk-encrypted and
content-addressed so large edits do not rewrite the whole vault.

The current `.kv.enc` format stays readable and receives a one-way, backed-up
migration into the document model. Markdown is a first-class import/export
format, but plaintext Markdown is not the default at-rest representation because
that would break the product's security promise.

## Search design

SQLite FTS5 supports prefix, phrase, NEAR and boolean queries plus BM25 ranking
and snippets. A normal FTS5 database exposes tokens on disk, so it must not be
used unencrypted. During the transition, the app builds an incremental in-memory
index after unlock. The production desktop core will persist the same logical
index only behind a reviewed encrypted SQLite integration.

Reference: <https://www.sqlite.org/fts5.html>

The link index is updated in the same logical transaction as a note revision:

- outgoing and unresolved wikilinks
- backlinks by stable note ID
- headings and block anchors
- normalized tags and property values
- full-text terms and ranking statistics

## Cryptographic model

- A memory-hard KDF derives a wrapping key from the passphrase.
- Random data-encryption keys are wrapped by the wrapping key.
- Notes and attachment chunks use an authenticated encryption mode with unique nonces.
- Key rotation re-wraps data keys instead of rewriting every object.
- Session keys are kept only in the privileged core and zeroized on lock.
- Per-device sync keys and per-agent grants are derived/separated by purpose.
- Every encrypted record authenticates its format version and logical identity as associated data.

The existing AES-256-GCM/scrypt implementation remains supported while a versioned
envelope and migration path are introduced. Cryptographic changes require test
vectors and review; custom primitives are forbidden.

## Trust boundaries

| Principal | Default access |
|---|---|
| Desktop webview | Rendered active-note data only; no raw filesystem or key access |
| CLI direct mode | Explicit user-requested operation |
| MCP agent | Catalog discovery only; content requires a scoped grant |
| Plugin | No capabilities until declared and approved |
| Sync server | Ciphertext, opaque object IDs and minimal routing metadata |
| Exporter | Selected decrypted notes for a user-confirmed destination |

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

The on-disk index therefore stays at version 2, the layout the Rust desktop
core also reads and writes. The lookup maps are additive fields that the
desktop core ignores, and a `derived` marker records that they are present; an
index written without them (an older build, or the desktop app) is rebuilt from
the note objects rather than trusted. The consequence is honest and worth
knowing: a vault last written by the desktop app pays one index rebuild the
next time the CLI opens it. Teaching the Rust core to maintain the same lookups
would remove that, and is the natural follow-up.

One interop gap in the same area: the desktop core has no `frontmatterSource`
field, so a note whose YAML was imported with comments loses that preserved
source if the desktop app rewrites the note. The CLI round-trip keeps it.

### Measured at 100,000 notes

Development machine, one run, after the work above. Budgets are from
`docs/PRODUCT.md`; every figure is p95 unless noted.

| Interaction | Budget | 10,000 notes | 100,000 notes |
|---|---:|---:|---:|
| Cold unlock to usable index | < 2,000 ms | 77 ms | 97 ms |
| Quick switch over titles/aliases | < 30 ms | 1.2 ms | 22.0 ms |
| Full-text query (selective) | < 100 ms | 5.7 ms | 20.3 ms |
| Full-text query matching every note | < 100 ms | 9.3 ms | 74.5 ms |
| Open an indexed note | < 50 ms | 0.3 ms | 0.3 ms |
| Backlink query | < 50 ms | 0.01 ms | 0.01 ms |

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
  secondbrain-vault processes, is reentrant within one process, and is
  reclaimed when the recorded holder has gone stale, so a crashed session
  cannot wedge a vault permanently. It does not defend against someone editing
  the files by hand — nothing advisory can.

Recovery is covered by fault-injection tests that reproduce a crash at the
exact point between the object write and the index write, and assert that the
next unlock heals the index; a control case without the journal shows the index
would otherwise stay stale.

Unlocking is an explicit lifecycle in the core, not only in the desktop shell.
`DocumentVault.lock()` overwrites the derived key in place and drops the
decrypted index; every later operation on that session fails until a new one is
opened with the passphrase. The CLI mirrors it: `sbrain unlock --remember`
places the passphrase in the OS credential store, `sbrain lock` removes it.

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
- ten explicitly allowlisted IPC commands for unlock, lock, list, open, save,
  create, search, backlinks, value-minimized graph data and typed property rows
- a Rust session that derives the scrypt key once, keeps it outside the webview
  and zeroizes it when the vault locks
- authenticated AES-GCM note/index objects compatible with the TypeScript
  document format, plus Windows-native atomic replacement with write-through
- a React workspace with an encrypted-vault lock screen, file tree, CodeMirror
  Markdown editing, reading view, search, command palette, properties, outline
  and backlinks, plus local graph and property-table views
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

Windowing bounds what the *interface* costs, not what the core costs: the tree
and property view now render a viewport's worth of rows out of any number, but
the unlock, search and index budgets are still only enforced against the 1,000-
note benchmark corpus. The 10k/100k index gates and large-graph virtualization
remain open, and the theme is a per-device preference in `localStorage`, never
part of the encrypted vault.
