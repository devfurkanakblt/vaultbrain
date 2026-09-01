# Canvas Document Format — Design

- Date: 2026-08-30
- Status: approved for planning
- Roadmap item: Phase 4, "Canvas/whiteboard with encrypted assets"

## Scope

This slice delivers the canvas **format** and its TypeScript core: the encrypted
object, its AAD contract, the `DocumentVault` API, index integration, CLI
commands, JSON Canvas import/export, tests and a migration fixture.

The Rust desktop core and the canvas editor UI are deliberately separate later
slices, mirroring how chunked attachments shipped: TypeScript core first
(Phase 2), desktop core after (Phase 4).

## Settled decisions

| Decision | Choice | Rejected alternative and why |
|---|---|---|
| Scope | Format + TypeScript core | Full vertical slice with UI — too large for one spec; would force format choices under editor pressure |
| Schema base | JSON Canvas 1.0 field names plus identity-carrying extensions | Pure JSON Canvas — its `file` node is path-keyed, which contradicts "user-facing paths are mutable labels, not identity" |
| Index integration | Canvas references enter the index as new additive fields | Mixing canvas IDs into `backlinks` — the Rust core reads that map expecting note IDs |
| Asset lifecycle | Reference by ID, no refcount, no cascade delete; a report plus an explicit cleanup command | In-format refcounting — a crashed write desynchronizes the counter, and both cores would have to maintain it |
| Revision history | Same as notes: one archived revision object per write | Coalescing — the core has no session concept, and the real risk (a revision per drag) belongs to the editor slice |

## 1. Document model and on-disk layout

A canvas is a **sibling object type** to a note: the same UUID identity space, a
distinct file suffix, a distinct AAD.

```
documents/objects/<uuid>.canvas.enc           AAD: vault-brain:canvas:v1:<id>
documents/history/<uuid>/<rev>.canvas.enc     AAD: vault-brain:canvas-history:v1:<id>:<rev>
```

```ts
export interface CanvasDocument {
  version: 1;
  id: string;                 // UUID
  path: string;               // "Boards/Roadmap.canvas" — a mutable label, not identity
  title: string;
  nodes: CanvasNode[];
  edges: CanvasEdge[];
  createdAt: string;
  updatedAt: string;
  revision: number;
}

interface CanvasNodeBase {
  id: string;                 // canvas-local short ID, required by JSON Canvas
  x: number; y: number; width: number; height: number;
  color?: string;
}

export type CanvasNode =
  | ({ type: "text";  text: string } & CanvasNodeBase)
  | ({ type: "file";  noteId?: string; attachmentId?: string; file: string; subpath?: string } & CanvasNodeBase)
  | ({ type: "group"; label?: string; background?: string } & CanvasNodeBase)
  | ({ type: "link";  url: string } & CanvasNodeBase);

export interface CanvasEdge {
  id: string;
  fromNode: string; fromSide?: "top" | "right" | "bottom" | "left"; fromEnd?: "none" | "arrow";
  toNode: string;   toSide?:   "top" | "right" | "bottom" | "left"; toEnd?:   "none" | "arrow";
  color?: string; label?: string;
}

/** The listing shape, mirroring NoteSummary: identity and labels, no content. */
export interface CanvasSummary {
  id: string; path: string; title: string;
  nodeCount: number; edgeCount: number;
  updatedAt: string; revision: number;
}
```

`title` defaults to the path's basename without its extension, the way
`NoteInput.title` already does.

Two properties of this model carry most of its value:

**Identity lives in `noteId` / `attachmentId`, not in `file`.** The `file` field
is a derived label kept only for JSON Canvas export, rewritten from the identity
at read time. Renaming or moving a note therefore cannot break a canvas, and no
disk write is needed to repair one. Exactly one of `noteId` and `attachmentId`
may be set on a `file` node.

**Type confusion is caught cryptographically.** Because the AAD names the object
type, decrypting a canvas object as a note fails GCM authentication. No separate
type check is needed, and none can be bypassed.

**`link` nodes never reach the network.** Obsidian fetches a preview for this
node type; here the URL is stored text and nothing more. This is a product
boundary, not a format one, and it is stated so the editor slice inherits it.

## 2. Index integration, migration and recovery

All index additions are additive. The on-disk index stays `version: 2`; the
derived-layout marker moves `4 → 5`.

```ts
interface IndexedCanvas {
  id: string; path: string; title: string;
  updatedAt: string; revision: number;
  noteRefs: string[];         // file nodes plus resolved wikilinks inside text nodes
  attachmentRefs: string[];
  unresolved: WikiLink[];
}

canvases:             Record<string, IndexedCanvas>;
canvasRefs:           Record<string, string[]>;   // noteId       -> canvasIds
canvasAttachmentRefs: Record<string, string[]>;   // attachmentId -> canvasIds
canvasPathOwners:     Record<string, string[]>;   // normalized path -> canvasIds
```

`backlinks`, `resolvedLinks`, `linkSources` and `unresolved` are untouched: the
Rust desktop core reads those maps assuming note IDs inside them.

`canvasPathOwners` is what makes `getCanvas(reference)` resolve a path or title
in one hash lookup instead of scanning every canvas — the same reason
`pathOwners` exists for notes, and the same quadratic import cost it avoids.

A text node's body is run through `analyzeMarkdown`, so the wikilinks a user
types into a sticky note resolve exactly as they would inside a note. Resolved
targets land in `noteRefs`; the rest land in `unresolved`. Headings and block
anchors inside text nodes are parsed but not indexed: nothing can link *into* a
canvas in this slice.

**No migration code is written.** `DocumentVault.loadIndex` already rebuilds the
index from the objects when `derived !== DERIVED_LAYOUT` (`src/documents.ts:372`).
The bump therefore migrates in both directions and heals itself:

- a new build opening an older vault sees `derived: 4 ≠ 5`, rebuilds once, and
  populates the canvas fields;
- an older build opening a new vault sees `derived: 5 ≠ 4`, rebuilds, produces a
  correct note index and drops the canvas fields; the next open by a new build
  restores them.

`rebuildIndex` gains one addition: a second pass over `objects/` filtered on
`.canvas.enc`. The existing loop already filters `.note.enc`
(`src/documents.ts:944`), so note indexing is unaffected.

**Journal.** A new scope `"canvases"` is added to `WriteJournal`. Recovery
mirrors the note path: reload the canvas object from disk and refresh its
`canvases` / `canvasRefs` entries, or drop the entries if the object never
landed.

There is no backward-compatibility hazard here, despite appearances. `readJournal`
(`src/documents.ts:390`) returns `undefined` for an unrecognized scope, and
`loadIndex` (`:377`) treats that as "no journal" and skips recovery — but an
older build opening such a vault sees `derived: 5` and enters a full rebuild
anyway, which is strictly stronger and which deletes the journal.

One targeted hardening is still in scope, in code this slice touches: an
unrecognized journal scope should be treated as `"bulk"` rather than as no
journal. This changes no behaviour today and closes the hazard for any scope
added later.

**History directories do not collide.** `archivedRevisionNumbers`
(`src/documents.ts:547`) filters `^\d+\.note\.enc$`; canvas revisions are scanned
with `^\d+\.canvas\.enc$`. Canvas and note IDs are distinct UUIDs, so the
directories do not overlap in the first place.

**Rename and delete.** Renaming a note leaves the `file` label stale and the
`noteId` correct; the label is re-derived on read. Deleting a note does not
delete nodes — the node becomes a **broken reference**, the same treatment
unresolved wikilinks receive, and `canvasRefs` locates every affected board in
one hash lookup.

**Unreferenced attachments.** `canvasAttachmentRefs` is scanned together with
`![[...]]` embeds in notes to produce `unreferencedAttachments()`. Deletion is
never automatic and never cascades.

## 3. API, CLI, validation and tests

### `DocumentVault` surface

```ts
putCanvas(input: CanvasInput): CanvasDocument      // { path, title?, nodes, edges, id?, baseRevision? }
getCanvas(reference: string): CanvasDocument       // id | path | title
listCanvases(): CanvasSummary[]
removeCanvas(reference: string): CanvasDocument
renameCanvas(reference: string, newPath: string): CanvasDocument
canvasRevisions(reference: string): RevisionInfo[]
getCanvasRevision(reference: string, revision: number): CanvasDocument
restoreCanvas(reference: string, revision: number): CanvasDocument
canvasesReferencing(noteReference: string): CanvasSummary[]
importCanvas(path: string, jsonCanvasText: string): CanvasDocument
exportCanvas(reference: string): string
unreferencedAttachments(): AttachmentInfo[]
```

`CanvasInput.baseRevision` gives canvases the same optimistic-concurrency check
notes have.

### Validation limits

Every limit is explicit and its error message says what was violated, following
`validateProperty` (`src/documents.ts:196`).

| Field | Rule |
|---|---|
| `path` | Twin of `normalizeNotePath` with a `.canvas` extension: at most 512 chars, no absolute path, drive letter or control characters |
| node `id` | `^[A-Za-z0-9_-]{1,64}$`, unique within the canvas |
| counts | At most 5,000 nodes, 10,000 edges, 8 MiB serialized |
| geometry | `x/y/width/height` finite integers, `width`/`height` at least 1, absolute coordinate at most 10^7 |
| `color` | `^([1-6]\|#[0-9a-fA-F]{6})$` |
| `text` node | At most 256 KiB UTF-8 |
| `group.label` | At most 160 chars, single line (the tag/alias rule) |
| `link.url` | At most 2048 chars, scheme `http:` or `https:` only; `file:`, `data:` and `javascript:` are rejected |
| `file` node | `noteId` matches `^[a-f0-9-]{36}$` or `attachmentId` matches `^[a-f0-9]{64}$`; exactly one is set |
| `subpath` | `#heading` or `#^block`, at most 512 chars |
| edge | Endpoints reference existing node IDs; edge IDs unique |

**Unknown node types are rejected.** JSON Canvas may add types later, but
carrying an unvalidatable node through the vault would be a way around the table
above. Import fails and names the offending node.

### JSON Canvas mapping

Export resolves `noteId` to the note's current path and `attachmentId` to
`<assets>/<filename>`. Writing those asset bytes to disk requires an explicit
`--assets <dir>`; decrypting vault content onto the filesystem is never a
default.

Import resolves each `file` path through `pathOwners` and binds it to a
`noteId`. A path that does not resolve is preserved as a broken reference with
its `file` label intact, so import is lossless.

### CLI

Added under the existing `docs` group, following the `attachment-*` naming:

```
docs canvas-import <path> <source.canvas>     docs canvas-history <reference>
docs canvases                                 docs canvas-revision <reference> <n>
docs canvas-get <reference>                   docs canvas-restore <reference> <n>
docs canvas-export <reference> <dest> [--assets <dir>]
docs canvas-remove <reference>                docs canvas-refs <note-reference>
docs canvas-rename <reference> <new-path>     docs attachments-unreferenced
```

Every writing command appends an audit entry with `file: "canvases"`, matching
how note and attachment commands already call `appendAudit`.

### Tests

Following `test/documents.test.mjs` and `test/durability.test.mjs`:

1. Round trip: node/edge preservation, revision increment, `baseRevision` conflict
2. AAD type separation: opening a canvas object as a note fails, and the reverse
3. Validation: one rejection case per row of the limits table
4. Identity durability: rename re-derives the `file` label and keeps `noteId`; delete produces a broken reference rather than a lost node
5. Index: rebuild restores canvases, `canvasRefs` reverse lookup is correct, the `derived` bump triggers exactly one rebuild
6. Journal fault injection: a crash after the canvas object write and before the index write heals on next unlock; a control case without the journal shows the index would stay stale
7. JSON Canvas golden file: import, export, normalized equality; unknown node type rejected
8. Unreferenced attachment report: a referenced attachment is absent, deleting the canvas makes it appear, and nothing is ever deleted automatically
9. Fixture `test/fixtures/documents-canvas-v1/`, added to `scripts/make-fixtures.mjs` as a **new** directory, with a row in the fixtures README; existing fixtures are not edited

`unreferencedAttachments()` scans every note and is therefore O(n). That is
deliberate: it is a maintenance command the user runs explicitly, not a hot
path, and it is not part of the benchmark budgets.

## Out of scope

Canvas editor UI; the Rust desktop core and its IPC commands; reference
counting; canvas content entering full-text search; canvases as nodes in the
knowledge graph; `![[board.canvas]]` embeds; link-node network previews; canvas
templates.

## Known consequences

- A vault written by this build carries `derived: 5`, so the Rust desktop core
  and any older CLI build rebuild the index once on open. This extends the
  existing, already-documented rebuild gap rather than creating a new one.
- Canvases are invisible to search in this slice. A board's title is findable
  through `docs canvases` and `docs canvas-refs`, not through `docs search`.
- A canvas rewritten on every node drag would archive one revision per drag. The
  core does not defend against this; the editor slice must debounce, and that
  constraint is inherited from this document.
