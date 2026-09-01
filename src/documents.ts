import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  decryptDocument,
  decryptDocumentBytes,
  encryptedDocumentPath,
  encryptDocument,
  encryptDocumentBytes,
  openDocumentKey,
  type DocumentKeySession,
  type DocumentPayload,
} from "./document-crypto.js";
import { assertNoSymlinkComponents, assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import {
  analyzeMarkdown,
  makeExcerpt,
  normalizeLinkTarget,
  normalizeNotePath,
  type MarkdownHeading,
  type WikiLink,
} from "./markdown.js";
import { resolveInside } from "./safety.js";
import { applyFrontmatter, parseFrontmatter, stringifyFrontmatter } from "./frontmatter.js";
import { withVaultLock } from "./vault-lock.js";
import {
  SemanticNoteIndex,
  type EmbeddingAdapter,
  type SemanticSearchHit,
  type SemanticSearchOptions,
} from "./semantic.js";
import {
  assertCanvasSize,
  canvasBasename,
  DEFAULT_ASSETS_DIR,
  normalizeCanvasEdges,
  normalizeCanvasNodes,
  normalizeCanvasPath,
  normalizeCanvasTitle,
  parseJsonCanvas,
  serializeJsonCanvas,
  type CanvasDocument,
  type CanvasInput,
  type CanvasNode,
  type CanvasSummary,
} from "./canvas.js";

import {
  MAX_PLUGIN_STORAGE_BYTES,
  MAX_PLUGINS,
  parsePluginManifest,
  summarizePlugin,
  validatePluginSource,
  type PluginPackage,
  type PluginSecurityPolicy,
  type PluginSummary,
} from "./plugins.js";
import { verifyPluginSignature } from "./plugin-signatures.js";

export type { CanvasDocument, CanvasEdge, CanvasInput, CanvasNode, CanvasSummary } from "./canvas.js";

export type {
  PluginCapability,
  PluginManifest,
  PluginPackage,
  PluginSecurityPolicy,
  PluginSummary,
} from "./plugins.js";

export type PropertyValue =
  | string
  | number
  | boolean
  | null
  | PropertyValue[]
  | {
      [key: string]: PropertyValue;
    };

export interface NoteDocument {
  version: 1;
  id: string;
  path: string;
  title: string;
  body: string;
  aliases: string[];
  tags: string[];
  properties: Record<string, PropertyValue>;
  createdAt: string;
  updatedAt: string;
  revision: number;
  /** Imported YAML kept verbatim so an export can preserve comments and style. */
  frontmatterSource?: string;
}

/**
 * Search fields normalized once per note per session. Normalizing bodies
 * inside the query loop meant every search paid an NFKC pass over the whole
 * vault; at 10,000 notes that alone was most of the query time. They are not
 * written to disk: the index has to stay in the layout the desktop core reads,
 * and a second copy of every body would double what unlock has to decrypt.
 */
interface SearchFields {
  /** Guards the memo: a rewritten note must not keep stale search text. */
  revision: number;
  title: string;
  aliases: string[];
  tags: string[];
  path: string;
  properties: string;
  /** Everything except the body, joined — what most queries actually hit. */
  head: string;
  body: string;
}

interface IndexedNote extends NoteDocument {
  links: WikiLink[];
  headings: MarkdownHeading[];
}

/**
 * A canvas in the index carries labels and references, never geometry or node
 * content: the board itself stays in its own encrypted object. `nodeCount` and
 * `edgeCount` are the two numbers `listCanvases()` needs, and keeping them here
 * is what stops a listing from decrypting every board on disk.
 */
interface IndexedCanvas {
  id: string;
  path: string;
  title: string;
  updatedAt: string;
  revision: number;
  nodeCount: number;
  edgeCount: number;
  /** File nodes plus the wikilinks resolved out of text nodes. */
  noteRefs: string[];
  attachmentRefs: string[];
  unresolved: WikiLink[];
}

/**
 * The on-disk index stays at version 2, the layout the Rust desktop core also
 * reads and writes: both implementations must be able to open the same vault.
 * The lookup maps below are additive, so the desktop core simply ignores them,
 * and `derived` records that they are present — an index written by a build
 * without them is rebuilt rather than trusted.
 */
interface DocumentIndex {
  version: 2;
  derived: 5;
  generatedAt: string;
  notes: Record<string, IndexedNote>;
  backlinks: Record<string, string[]>;
  resolvedLinks: Record<string, Array<string | null>>;
  unresolved: Record<string, WikiLink[]>;
  linkSources: Record<string, string[]>;
  /**
   * Reverse lookups from the labels a note answers to. Resolving a path, a
   * title or a wikilink used to scan every note and re-normalize its strings,
   * which is quadratic during a bulk import and the reason a 10,000-note
   * corpus took minutes. These maps make each resolution a hash lookup.
   */
  pathOwners: Record<string, string[]>;
  nameOwners: Record<string, string[]>;
  basenameOwners: Record<string, string[]>;
  /**
   * Canvases live in their own maps rather than inside `backlinks`,
   * `resolvedLinks`, `linkSources` or `unresolved`: the Rust desktop core reads
   * those four assuming every ID inside them names a note, so mixing canvas IDs
   * in would corrupt it. `canvasPathOwners` is the canvas twin of `pathOwners`
   * — it resolves a path, a basename or a title in one hash lookup instead of
   * scanning every board.
   */
  canvases: Record<string, IndexedCanvas>;
  canvasRefs: Record<string, string[]>;
  canvasAttachmentRefs: Record<string, string[]>;
  canvasPathOwners: Record<string, string[]>;
  /**
   * Optional because an index written before plugins existed simply has no such
   * field, and that is not a reason to rebuild: nothing derived depends on it.
   */
  plugins?: Record<string, PluginSummary>;
}

const DERIVED_LAYOUT = 5;

/** Any index layout this build no longer reads directly; rebuilt on open. */
interface LegacyDocumentIndex {
  version: number;
  generatedAt: string;
}

/**
 * A note object and the search/link index are two files. A crash between them
 * would leave the index describing a vault that no longer exists, so a write
 * transaction announces itself first: the journal names the notes about to
 * change, and the next unlock replays them out of the objects on disk.
 *
 * It holds note IDs only — the same UUIDs already visible as filenames in
 * objects/ — so it reveals nothing that a directory listing does not, and it
 * stays readable without the key, which is what makes recovery possible.
 */
interface WriteJournal {
  version: 1;
  startedAt: string;
  scope: "notes" | "canvases" | "plugins" | "bulk";
  ids: string[];
}

export interface NoteInput {
  path: string;
  title?: string;
  body: string;
  aliases?: string[];
  tags?: string[];
  properties?: Record<string, PropertyValue>;
  id?: string;
  createdAt?: string;
  baseRevision?: number;
  /** Original YAML text to preserve on export, when importing a file. */
  frontmatterSource?: string;
}

/**
 * A sync capture may persist its intent before calling the ordinary storage
 * API. This protected dry-run result freezes generated identities, creation
 * timestamps and revisions without exposing document keys or a second public
 * write path.
 */
interface PreparedNotePut {
  document: NoteDocument;
}

interface PreparedCanvasPut {
  document: CanvasDocument;
}

interface PreparedAttachmentPut {
  data: Buffer;
  info: AttachmentInfo;
  existed: boolean;
}

/**
 * Convert portable/Obsidian-style Markdown into the canonical note input used
 * by both one-file and whole-vault imports. Keeping this conversion outside
 * `DocumentVault` lets an importer validate every source file before it writes
 * the first encrypted object.
 */
export function parseMarkdownNote(notePath: string, markdown: string): NoteInput {
  const parsed = parseFrontmatter(markdown);
  const metadata = { ...parsed.attributes };
  const legacyProperties =
    metadata.properties && typeof metadata.properties === "object" && !Array.isArray(metadata.properties)
      ? (metadata.properties as Record<string, PropertyValue>)
      : {};
  const portableId =
    typeof metadata.vbrain_id === "string"
      ? metadata.vbrain_id
      : typeof metadata.sbrain_id === "string"
        ? metadata.sbrain_id
        : typeof metadata.id === "string" && /^[a-f0-9-]{36}$/u.test(metadata.id)
          ? metadata.id
          : undefined;
  const reserved = new Set([
    "sbrain_id",
    "vbrain_id",
    "title",
    "aliases",
    "tags",
    "created",
    "createdAt",
    "modified",
    "updatedAt",
    "properties",
  ]);
  if (portableId) reserved.add("id");
  const properties: Record<string, PropertyValue> = { ...legacyProperties };
  for (const [key, value] of Object.entries(metadata)) {
    if (!reserved.has(key)) properties[key] = value;
  }

  const stringList = (value: PropertyValue | undefined, split: boolean): string[] => {
    if (typeof value === "string") {
      return split ? value.split(/[\s,]+/gu).filter(Boolean) : [value];
    }
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
  };
  return {
    path: notePath,
    title: typeof metadata.title === "string" ? metadata.title : undefined,
    body: parsed.body,
    aliases: stringList(metadata.aliases, false),
    tags: stringList(metadata.tags, true).map((tag) => tag.replace(/^#/u, "")),
    properties,
    frontmatterSource: parsed.hasFrontmatter ? parsed.source : undefined,
    id: portableId,
    createdAt:
      typeof metadata.created === "string"
        ? metadata.created
        : typeof metadata.createdAt === "string"
          ? metadata.createdAt
          : undefined,
  };
}

export interface NoteSummary {
  id: string;
  path: string;
  title: string;
  aliases: string[];
  tags: string[];
  updatedAt: string;
  revision: number;
}

export interface SearchHit extends NoteSummary {
  score: number;
  excerpt: string;
}

export type { EmbeddingAdapter, SemanticSearchHit, SemanticSearchOptions } from "./semantic.js";

export interface OutgoingLink extends WikiLink {
  resolvedId?: string;
  resolvedPath?: string;
}

export interface RevisionInfo {
  revision: number;
  updatedAt: string;
  current: boolean;
}

export interface AttachmentInfo {
  id: string;
  filename: string;
  mime: string;
  size: number;
  chunks: number;
  createdAt: string;
}

const INDEX_AAD = "secondbrain-vault:document-index:v1";
const PLUGIN_POLICY_AAD = "secondbrain-vault:plugin-policy:v1";
const ATTACHMENT_CHUNK_SIZE = 1024 * 1024;
const MAX_ATTACHMENT_SIZE = 250 * 1024 * 1024;

function noteAad(id: string): string {
  return `secondbrain-vault:note:v1:${id}`;
}

function historyAad(id: string, revision: number): string {
  return `secondbrain-vault:note-history:v1:${id}:${revision}`;
}

/**
 * The AAD names the object type, so decrypting a canvas object as a note fails
 * GCM authentication outright. Type confusion between the two sibling object
 * types is therefore caught cryptographically: no separate check is needed, and
 * none can be bypassed.
 */
function canvasAad(id: string): string {
  return `secondbrain-vault:canvas:v1:${id}`;
}

/** Same type-confusion argument as `canvasAad`, for the third object type. */
function pluginAad(id: string): string {
  return `secondbrain-vault:plugin:v1:${id}`;
}

/**
 * A plugin's own settings live in a separate object from its code, so writing a
 * setting never rewrites the code — and a reader that only wants the settings
 * never decrypts the code at all.
 */
function pluginStoreAad(id: string): string {
  return `secondbrain-vault:plugin-store:v1:${id}`;
}

function canvasHistoryAad(id: string, revision: number): string {
  return `secondbrain-vault:canvas-history:v1:${id}:${revision}`;
}

function attachmentManifestAad(id: string): string {
  return `secondbrain-vault:attachment-manifest:v1:${id}`;
}

function attachmentChunkAad(id: string, index: number): string {
  return `secondbrain-vault:attachment-chunk:v1:${id}:${index}`;
}

function normalizeText(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US");
}

function normalizeStringList(values: string[] | undefined, max = 100): string[] {
  const result = new Set<string>();
  for (const raw of values ?? []) {
    const value = raw.trim().normalize("NFKC");
    if (!value || value.length > 160 || /[\r\n\u0000]/u.test(value)) {
      throw new Error("Tags and aliases must be non-empty single-line strings up to 160 characters.");
    }
    result.add(value);
    if (result.size > max) throw new Error(`A note cannot contain more than ${max} items in one list.`);
  }
  return [...result];
}

function validateProperty(value: PropertyValue, depth = 0): void {
  if (depth > 8) throw new Error("Property nesting cannot exceed 8 levels.");
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > 1024 * 1024) throw new Error("Property string is too large.");
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Property numbers must be finite.");
    return;
  }
  if (typeof value === "boolean" || value === null) return;
  if (Array.isArray(value)) {
    if (value.length > 10_000) throw new Error("Property array is too large.");
    for (const item of value) validateProperty(item, depth + 1);
    return;
  }
  const entries = Object.entries(value);
  if (entries.length > 1_000) throw new Error("Property object is too large.");
  for (const [key, item] of entries) {
    if (!key || key.length > 160 || /[\r\n\u0000]/u.test(key)) throw new Error("Invalid property key.");
    validateProperty(item, depth + 1);
  }
}

function normalizeProperties(properties: Record<string, PropertyValue> | undefined): Record<string, PropertyValue> {
  const normalized = properties ?? {};
  validateProperty(normalized);
  return structuredClone(normalized);
}

function searchFields(note: NoteDocument): SearchFields {
  const revision = note.revision;
  const title = normalizeText(note.title);
  const aliases = note.aliases.map(normalizeText);
  const tags = note.tags.map(normalizeText);
  const notePath = normalizeText(note.path);
  const properties = normalizeText(JSON.stringify(note.properties));
  return {
    revision,
    title,
    aliases,
    tags,
    path: notePath,
    properties,
    head: `${title}\n${aliases.join(" ")}\n${tags.join(" ")}\n${notePath}\n${properties}`,
    body: normalizeText(note.body),
  };
}

function summary(note: NoteDocument): NoteSummary {
  return {
    id: note.id,
    path: note.path,
    title: note.title,
    aliases: note.aliases,
    tags: note.tags,
    updatedAt: note.updatedAt,
    revision: note.revision,
  };
}

function canvasSummary(canvas: IndexedCanvas): CanvasSummary {
  return {
    id: canvas.id,
    path: canvas.path,
    title: canvas.title,
    nodeCount: canvas.nodeCount,
    edgeCount: canvas.edgeCount,
    updatedAt: canvas.updatedAt,
    revision: canvas.revision,
  };
}

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let offset = 0;
  while ((offset = haystack.indexOf(needle, offset)) >= 0) {
    count += 1;
    offset += needle.length;
    if (count >= 20) break;
  }
  return count;
}

export class DocumentVault {
  private readonly session: DocumentKeySession;
  private indexCache?: DocumentIndex;
  private notesCache?: IndexedNote[];
  private readonly searchCache = new Map<string, SearchFields>();
  private readonly semanticIndexes = new Map<EmbeddingAdapter, SemanticNoteIndex>();
  private sessionGeneration = 0;
  private locked = false;

  constructor(
    private readonly vaultDir: string,
    passphrase: string,
  ) {
    this.session = openDocumentKey(vaultDir, passphrase);
  }

  /**
   * Ends the session: the derived key is overwritten in place and the decrypted
   * index is dropped, so nothing readable survives in this process. Every
   * subsequent operation fails until a new DocumentVault is constructed with
   * the passphrase again — locking is a state change, not a UI gesture.
   */
  lock(): void {
    this.sessionGeneration += 1;
    for (const index of this.semanticIndexes.values()) index.clear();
    this.semanticIndexes.clear();
    this.session.key.fill(0);
    this.indexCache = undefined;
    this.notesCache = undefined;
    this.searchCache.clear();
    this.locked = true;
  }

  get isLocked(): boolean {
    return this.locked;
  }

  private assertUnlocked(): void {
    if (this.locked) throw new Error("This vault session is locked. Unlock it again to continue.");
  }

  private indexPath(): string {
    return resolveInside(this.session.rootDir, "index.enc");
  }

  private pluginPolicyPath(): string {
    return resolveInside(this.session.rootDir, "plugin-policy.enc");
  }

  private objectsDir(): string {
    const dir = resolveInside(this.session.rootDir, "objects");
    assertNoSymlinkComponents(this.session.rootDir, dir);
    return dir;
  }

  private attachmentDir(id: string): string {
    if (!/^[a-f0-9]{64}$/u.test(id)) throw new Error("Invalid attachment ID.");
    const root = resolveInside(this.session.rootDir, "attachments");
    const dir = resolveInside(root, id);
    assertNoSymlinkComponents(this.session.rootDir, dir);
    return dir;
  }

  private attachmentManifestPath(id: string): string {
    return resolveInside(this.attachmentDir(id), "manifest.enc");
  }

  private canvasObjectPath(id: string): string {
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid canvas ID.");
    return resolveInside(this.objectsDir(), `${id}.canvas.enc`);
  }

  private pluginObjectPath(id: string): string {
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid plugin ID.");
    return resolveInside(this.objectsDir(), `${id}.plugin.enc`);
  }

  private pluginStorePath(id: string): string {
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid plugin ID.");
    return resolveInside(this.objectsDir(), `${id}.pluginstore.enc`);
  }

  private readAttachmentManifest(id: string): AttachmentInfo {
    this.assertUnlocked();
    const manifestPath = this.attachmentManifestPath(id);
    if (!fs.existsSync(manifestPath)) throw new Error(`Attachment not found: ${id}`);
    assertNotSymlink(manifestPath);
    const payload = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as DocumentPayload;
    const info = JSON.parse(decryptDocument(payload, this.session.key, attachmentManifestAad(id))) as AttachmentInfo;
    if (info.id !== id || !Number.isSafeInteger(info.chunks) || info.chunks < 1) {
      throw new Error("Invalid attachment manifest.");
    }
    return info;
  }

  private loadIndex(): DocumentIndex {
    this.assertUnlocked();
    if (this.indexCache) return this.indexCache;
    const indexPath = this.indexPath();
    if (!fs.existsSync(indexPath)) return this.rebuildIndex();
    assertNotSymlink(indexPath);
    const payload = JSON.parse(fs.readFileSync(indexPath, "utf8")) as DocumentPayload;
    const parsed = JSON.parse(decryptDocument(payload, this.session.key, INDEX_AAD)) as
      DocumentIndex | LegacyDocumentIndex;
    if (!Number.isInteger(parsed.version) || parsed.version < 1 || parsed.version > 2) {
      throw new Error("Unsupported or invalid document index.");
    }
    // An index written by an older build, or by the desktop core (which does
    // not maintain the lookup maps), is rebuilt from the note objects rather
    // than trusted: the objects are the source of truth. Slower once, correct.
    if (parsed.version !== 2 || (parsed as DocumentIndex).derived !== DERIVED_LAYOUT) {
      return this.rebuildIndex();
    }
    const index = parsed as DocumentIndex;
    if (typeof index.notes !== "object") throw new Error("Unsupported or invalid document index.");
    this.indexCache = index;
    if (!this.readJournal()) return index;
    return withVaultLock(this.vaultDir, () => this.recoverFromJournal(index) ?? index);
  }

  private journalPath(): string {
    return resolveInside(this.session.rootDir, "journal.json");
  }

  private readJournal(): WriteJournal | undefined {
    const journalPath = this.journalPath();
    if (!fs.existsSync(journalPath)) return undefined;
    try {
      const journal = JSON.parse(fs.readFileSync(journalPath, "utf8")) as WriteJournal;
      if (journal?.version !== 1) return undefined;
      // A scope this build does not know still means "the index may be stale",
      // so it degrades to the strongest recovery rather than to none. Nothing
      // changes today; it closes the hazard for any scope added later.
      const scope: WriteJournal["scope"] =
        journal.scope === "notes" || journal.scope === "canvases" || journal.scope === "plugins"
          ? journal.scope
          : "bulk";
      const ids = Array.isArray(journal.ids) ? journal.ids.filter((id) => /^[a-f0-9-]{36}$/u.test(id)) : [];
      return { version: 1, startedAt: String(journal.startedAt), scope, ids };
    } catch {
      // An unreadable journal still means "the index may be stale"; treat it
      // as the most conservative case rather than ignoring it.
      return { version: 1, startedAt: new Date(0).toISOString(), scope: "bulk", ids: [] };
    }
  }

  private beginJournal(scope: WriteJournal["scope"], ids: string[]): void {
    const journal: WriteJournal = { version: 1, startedAt: new Date().toISOString(), scope, ids };
    writeFileAtomic(this.journalPath(), JSON.stringify(journal), { mode: 0o600 });
  }

  private endJournal(): void {
    const journalPath = this.journalPath();
    if (fs.existsSync(journalPath)) fs.unlinkSync(journalPath);
  }

  /**
   * A plugin write touches one object and one listing entry, so recovery only
   * has to make the listing agree with what is actually on disk.
   */
  private recoverPluginsFromJournal(index: DocumentIndex, ids: string[]): DocumentIndex {
    const plugins = { ...(index.plugins ?? {}) };
    for (const id of ids) {
      if (fs.existsSync(this.pluginObjectPath(id))) {
        plugins[id] = summarizePlugin(this.loadPluginById(id));
      } else {
        delete plugins[id];
      }
    }
    index.plugins = plugins;
    this.saveIndex(index);
    this.endJournal();
    return index;
  }

  /** Re-derive the index entries an interrupted transaction may have left stale. */
  private recoverFromJournal(index: DocumentIndex): DocumentIndex | undefined {
    const journal = this.readJournal();
    if (!journal) return undefined;
    if (journal.scope === "bulk") return this.rebuildIndex();
    if (journal.scope === "canvases") return this.recoverCanvasesFromJournal(index, journal.ids);
    if (journal.scope === "plugins") return this.recoverPluginsFromJournal(index, journal.ids);

    const affected = new Set<string>();
    const collect = (note: IndexedNote | undefined) => {
      if (!note) return;
      for (const label of this.identityLabels(note)) {
        for (const sourceId of index.linkSources[label] ?? []) affected.add(sourceId);
      }
    };

    for (const id of journal.ids) {
      const previous = index.notes[id];
      const canvasLabels = previous ? this.identityLabels(previous) : [];
      collect(previous);
      const filePath = encryptedDocumentPath(this.session.rootDir, id);
      const stale = previous;
      if (fs.existsSync(filePath)) {
        const note = this.loadById(id);
        const analysis = analyzeMarkdown(note.body);
        const indexed: IndexedNote = { ...note, links: analysis.links, headings: analysis.headings };
        this.searchCache.delete(id);
        if (stale) this.removeOwnerLabels(index, stale);
        index.notes[id] = indexed;
        this.addOwnerLabels(index, indexed);
        this.removeSourceFromLinkMap(index, id, stale);
        this.addSourceToLinkMap(index, indexed);
        collect(indexed);
        affected.add(id);
        canvasLabels.push(...this.identityLabels(indexed));
      } else {
        // The object never landed, or the transaction was a delete that got
        // as far as unlinking. Either way the index must stop claiming it.
        this.removeSourceFromLinkMap(index, id, stale);
        if (stale) this.removeOwnerLabels(index, stale);
        this.clearResolvedSource(index, id);
        delete index.notes[id];
        delete index.backlinks[id];
        affected.delete(id);
      }
      this.refreshCanvasesForNoteChange(index, id, canvasLabels);
    }
    for (const sourceId of affected) {
      if (index.notes[sourceId]) this.refreshResolvedSource(index, sourceId);
    }
    this.saveIndex(index);
    this.endJournal();
    return index;
  }

  /**
   * The canvas half of journal replay: reload each named board from disk and
   * refresh its index entries, or drop them when the object never landed.
   */
  private recoverCanvasesFromJournal(index: DocumentIndex, ids: string[]): DocumentIndex {
    for (const id of ids) {
      const stale = index.canvases[id];
      if (fs.existsSync(this.canvasObjectPath(id))) {
        const canvas = this.loadCanvasById(id);
        this.detachCanvas(index, stale);
        this.attachCanvas(index, this.indexCanvasEntry(index, canvas));
      } else {
        // The object never landed, or the transaction was a delete that got as
        // far as unlinking. Either way the index must stop claiming it.
        this.detachCanvas(index, stale);
      }
    }
    this.saveIndex(index);
    this.endJournal();
    return index;
  }

  private searchFieldsFor(note: IndexedNote): SearchFields {
    const cached = this.searchCache.get(note.id);
    if (cached && cached.revision === note.revision) return cached;
    const fields = searchFields(note);
    this.searchCache.set(note.id, fields);
    return fields;
  }

  /** The scan list for search, materialized once per index rather than per query. */
  private indexedNotes(): IndexedNote[] {
    const index = this.loadIndex();
    if (!this.notesCache) this.notesCache = Object.values(index.notes);
    return this.notesCache;
  }

  private saveIndex(index: DocumentIndex): void {
    this.assertUnlocked();
    this.notesCache = undefined;
    index.generatedAt = new Date().toISOString();
    const payload = encryptDocument(JSON.stringify(index), this.session.key, INDEX_AAD);
    writeFileAtomic(this.indexPath(), JSON.stringify(payload), { mode: 0o600 });
    this.indexCache = index;
  }

  private loadById(id: string): NoteDocument {
    this.assertUnlocked();
    const filePath = encryptedDocumentPath(this.session.rootDir, id);
    if (!fs.existsSync(filePath)) throw new Error(`Note object is missing: ${id}`);
    assertNotSymlink(filePath);
    const payload = JSON.parse(fs.readFileSync(filePath, "utf8")) as DocumentPayload;
    const note = JSON.parse(decryptDocument(payload, this.session.key, noteAad(id))) as NoteDocument;
    if (note.version !== 1 || note.id !== id) throw new Error(`Invalid note object: ${id}`);
    return note;
  }

  private loadCanvasById(id: string): CanvasDocument {
    this.assertUnlocked();
    const filePath = this.canvasObjectPath(id);
    if (!fs.existsSync(filePath)) throw new Error(`Canvas object is missing: ${id}`);
    assertNotSymlink(filePath);
    const payload = JSON.parse(fs.readFileSync(filePath, "utf8")) as DocumentPayload;
    const canvas = JSON.parse(decryptDocument(payload, this.session.key, canvasAad(id))) as CanvasDocument;
    if (canvas.version !== 1 || canvas.id !== id) throw new Error(`Invalid canvas object: ${id}`);
    return canvas;
  }

  private historyDir(id: string): string {
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid note ID.");
    const dir = resolveInside(path.join(this.session.rootDir, "history"), id);
    assertNoSymlinkComponents(this.session.rootDir, dir);
    return dir;
  }

  private historyPath(id: string, revision: number): string {
    if (!Number.isSafeInteger(revision) || revision < 1) throw new Error("Invalid revision.");
    return resolveInside(this.historyDir(id), `${revision}.note.enc`);
  }

  private canvasHistoryPath(id: string, revision: number): string {
    if (!Number.isSafeInteger(revision) || revision < 1) throw new Error("Invalid revision.");
    return resolveInside(this.historyDir(id), `${revision}.canvas.enc`);
  }

  private archiveRevision(note: NoteDocument): void {
    const historyPath = this.historyPath(note.id, note.revision);
    if (fs.existsSync(historyPath)) return;
    fs.mkdirSync(this.historyDir(note.id), { recursive: true, mode: 0o700 });
    const payload = encryptDocument(JSON.stringify(note), this.session.key, historyAad(note.id, note.revision));
    writeFileAtomic(historyPath, JSON.stringify(payload), { mode: 0o600 });
  }

  private archiveCanvasRevision(canvas: CanvasDocument): void {
    const historyPath = this.canvasHistoryPath(canvas.id, canvas.revision);
    if (fs.existsSync(historyPath)) return;
    fs.mkdirSync(this.historyDir(canvas.id), { recursive: true, mode: 0o700 });
    const payload = encryptDocument(
      JSON.stringify(canvas),
      this.session.key,
      canvasHistoryAad(canvas.id, canvas.revision),
    );
    writeFileAtomic(historyPath, JSON.stringify(payload), { mode: 0o600 });
  }

  private loadRevisionById(id: string, revision: number): NoteDocument {
    const current = this.loadIndex().notes[id];
    if (current?.revision === revision) return this.loadById(id);
    const historyPath = this.historyPath(id, revision);
    if (!fs.existsSync(historyPath)) throw new Error(`Revision not found: ${id}@${revision}`);
    assertNotSymlink(historyPath);
    const payload = JSON.parse(fs.readFileSync(historyPath, "utf8")) as DocumentPayload;
    const note = JSON.parse(decryptDocument(payload, this.session.key, historyAad(id, revision))) as NoteDocument;
    if (note.id !== id || note.revision !== revision) throw new Error("Invalid revision object.");
    return note;
  }

  private loadCanvasRevisionById(id: string, revision: number): CanvasDocument {
    const current = this.loadIndex().canvases[id];
    if (current?.revision === revision) return this.loadCanvasById(id);
    const historyPath = this.canvasHistoryPath(id, revision);
    if (!fs.existsSync(historyPath)) throw new Error(`Canvas revision not found: ${id}@${revision}`);
    assertNotSymlink(historyPath);
    const payload = JSON.parse(fs.readFileSync(historyPath, "utf8")) as DocumentPayload;
    const canvas = JSON.parse(
      decryptDocument(payload, this.session.key, canvasHistoryAad(id, revision)),
    ) as CanvasDocument;
    if (canvas.version !== 1 || canvas.id !== id || canvas.revision !== revision) {
      throw new Error("Invalid canvas revision object.");
    }
    return canvas;
  }

  private resolveHistoryId(reference: string): string {
    try {
      return this.resolveId(reference);
    } catch (error) {
      if (/^[a-f0-9-]{36}$/u.test(reference) && fs.existsSync(this.historyDir(reference))) {
        return reference;
      }
      throw error;
    }
  }

  private archivedRevisionNumbers(id: string): number[] {
    const historyDir = this.historyDir(id);
    if (!fs.existsSync(historyDir)) return [];
    return fs
      .readdirSync(historyDir)
      .filter((name) => /^\d+\.note\.enc$/u.test(name))
      .map((name) => Number.parseInt(name, 10))
      .sort((a, b) => a - b);
  }

  private archivedCanvasRevisionNumbers(id: string): number[] {
    const historyDir = this.historyDir(id);
    if (!fs.existsSync(historyDir)) return [];
    return fs
      .readdirSync(historyDir)
      .filter((name) => /^\d+\.canvas\.enc$/u.test(name))
      .map((name) => Number.parseInt(name, 10))
      .sort((a, b) => a - b);
  }

  private resolveId(reference: string): string {
    const index = this.loadIndex();
    if (index.notes[reference]) return reference;
    let notePath: string | undefined;
    try {
      notePath = normalizeNotePath(reference);
    } catch {
      notePath = undefined;
    }
    const normalizedReference = normalizeText(reference.replace(/\.md$/iu, ""));
    const matches = [
      ...new Set([
        ...(notePath ? (index.pathOwners[normalizeLinkTarget(notePath)] ?? []) : []),
        ...(index.nameOwners[normalizedReference] ?? []),
      ]),
    ].filter((id) => index.notes[id]);
    if (matches.length === 0) throw new Error(`Note not found: ${reference}`);
    if (matches.length > 1) throw new Error(`Ambiguous note reference: ${reference}`);
    return matches[0];
  }

  private canvasLabels(canvas: Pick<IndexedCanvas, "path" | "title">): string[] {
    return [
      ...new Set([normalizeText(canvas.path), normalizeText(canvasBasename(canvas.path)), normalizeText(canvas.title)]),
    ];
  }

  private resolveCanvasId(reference: string): string {
    const index = this.loadIndex();
    if (index.canvases[reference]) return reference;
    let canvasPath: string | undefined;
    try {
      canvasPath = normalizeCanvasPath(reference);
    } catch {
      canvasPath = undefined;
    }
    const labels = new Set([
      normalizeText(reference.replace(/\.canvas$/iu, "")),
      ...(canvasPath ? [normalizeText(canvasPath)] : []),
    ]);
    const matches = [...new Set([...labels].flatMap((label) => index.canvasPathOwners[label] ?? []))].filter(
      (id) => index.canvases[id],
    );
    if (matches.length === 0) throw new Error(`Canvas not found: ${reference}`);
    if (matches.length > 1) throw new Error(`Ambiguous canvas reference: ${reference}`);
    return matches[0];
  }

  private resolveCanvasHistoryId(reference: string): string {
    try {
      return this.resolveCanvasId(reference);
    } catch (error) {
      if (/^[a-f0-9-]{36}$/u.test(reference) && this.archivedCanvasRevisionNumbers(reference).length > 0) {
        return reference;
      }
      throw error;
    }
  }

  private indexCanvasEntry(index: DocumentIndex, canvas: CanvasDocument): IndexedCanvas {
    const noteRefs = new Set<string>();
    const attachmentRefs = new Set<string>();
    const unresolved: WikiLink[] = [];
    for (const node of canvas.nodes) {
      if (node.type === "file") {
        if (node.noteId) noteRefs.add(node.noteId);
        if (node.attachmentId) attachmentRefs.add(node.attachmentId);
        continue;
      }
      if (node.type !== "text") continue;
      for (const link of analyzeMarkdown(node.text).links) {
        const target = this.resolveLinkTargetInIndex(index, link);
        if (target) noteRefs.add(target.id);
        else unresolved.push(link);
      }
    }
    return {
      id: canvas.id,
      path: canvas.path,
      title: canvas.title,
      updatedAt: canvas.updatedAt,
      revision: canvas.revision,
      nodeCount: canvas.nodes.length,
      edgeCount: canvas.edges.length,
      noteRefs: [...noteRefs],
      attachmentRefs: [...attachmentRefs],
      unresolved,
    };
  }

  private attachCanvas(index: DocumentIndex, canvas: IndexedCanvas): void {
    index.canvases[canvas.id] = canvas;
    for (const label of this.canvasLabels(canvas)) this.addOwner(index.canvasPathOwners, label, canvas.id);
    for (const noteId of canvas.noteRefs) this.addOwner(index.canvasRefs, noteId, canvas.id);
    for (const attachmentId of canvas.attachmentRefs) {
      this.addOwner(index.canvasAttachmentRefs, attachmentId, canvas.id);
    }
  }

  private detachCanvas(index: DocumentIndex, canvas?: IndexedCanvas): void {
    if (!canvas) return;
    for (const label of this.canvasLabels(canvas)) this.removeOwner(index.canvasPathOwners, label, canvas.id);
    for (const noteId of canvas.noteRefs) this.removeOwner(index.canvasRefs, noteId, canvas.id);
    for (const attachmentId of canvas.attachmentRefs) {
      this.removeOwner(index.canvasAttachmentRefs, attachmentId, canvas.id);
    }
    delete index.canvases[canvas.id];
  }

  private materializeCanvas(canvas: CanvasDocument): CanvasDocument {
    const index = this.loadIndex();
    const nodes = canvas.nodes.map((node): CanvasNode => {
      if (node.type !== "file") return structuredClone(node);
      if (node.noteId && index.notes[node.noteId]) {
        return { ...node, file: index.notes[node.noteId].path };
      }
      if (node.noteId) {
        const revisions = this.archivedRevisionNumbers(node.noteId);
        if (revisions.length > 0) {
          return { ...node, file: this.loadRevisionById(node.noteId, revisions[revisions.length - 1]).path };
        }
      }
      if (node.attachmentId && fs.existsSync(this.attachmentManifestPath(node.attachmentId))) {
        const info = this.readAttachmentManifest(node.attachmentId);
        return { ...node, file: path.posix.join(DEFAULT_ASSETS_DIR, info.filename) };
      }
      return { ...node };
    });
    return { ...structuredClone(canvas), nodes };
  }

  private refreshCanvasesForNoteChange(index: DocumentIndex, noteId: string, identityLabels: string[]): void {
    const candidates = new Set(index.canvasRefs[noteId] ?? []);
    const labels = new Set(identityLabels.map(normalizeLinkTarget));
    for (const label of labels) {
      const owners = new Set([
        ...(index.pathOwners[label] ?? []),
        ...(index.nameOwners[label] ?? []),
        ...(index.basenameOwners[label] ?? []),
      ]);
      for (const ownerId of owners) {
        for (const canvasId of index.canvasRefs[ownerId] ?? []) candidates.add(canvasId);
      }
    }
    for (const canvas of Object.values(index.canvases)) {
      if (canvas.unresolved.some((link) => labels.has(normalizeLinkTarget(link.target)))) {
        candidates.add(canvas.id);
      }
    }
    for (const canvasId of candidates) {
      if (!fs.existsSync(this.canvasObjectPath(canvasId))) continue;
      const stale = index.canvases[canvasId];
      const canvas = this.loadCanvasById(canvasId);
      this.detachCanvas(index, stale);
      this.attachCanvas(index, this.indexCanvasEntry(index, canvas));
    }
  }

  private resolveLinkTargetInIndex(index: DocumentIndex, link: WikiLink): IndexedNote | undefined {
    const target = normalizeLinkTarget(link.target);
    const exactPath = (index.pathOwners[target] ?? [])[0];
    if (exactPath && index.notes[exactPath]) return index.notes[exactPath];
    const candidates = [
      ...new Set([...(index.nameOwners[target] ?? []), ...(index.basenameOwners[target] ?? [])]),
    ].filter((id) => index.notes[id]);
    return candidates.length === 1 ? index.notes[candidates[0]] : undefined;
  }

  private identityLabels(note: IndexedNote): string[] {
    return [
      ...new Set([
        normalizeLinkTarget(note.path),
        normalizeLinkTarget(path.posix.basename(note.path, ".md")),
        normalizeText(note.title),
        ...note.aliases.map(normalizeText),
      ]),
    ];
  }

  /**
   * Drops a source from the link map using the links it actually had. Scanning
   * every bucket instead would make each write cost the size of the vault.
   */
  private removeSourceFromLinkMap(index: DocumentIndex, sourceId: string, previous?: IndexedNote): void {
    // A note the index did not have cannot appear in the link map, so a new
    // note costs nothing here instead of a walk over every bucket.
    if (!previous) return;
    for (const target of new Set(previous.links.map((link) => normalizeLinkTarget(link.target)))) {
      const sources = index.linkSources[target];
      if (!sources) continue;
      const next = sources.filter((id) => id !== sourceId);
      if (next.length === 0) delete index.linkSources[target];
      else index.linkSources[target] = next;
    }
  }

  private ownerLabels(note: IndexedNote): { path: string; names: string[]; basename: string } {
    return {
      path: normalizeLinkTarget(note.path),
      names: [...new Set([normalizeText(note.title), ...note.aliases.map(normalizeText)])],
      basename: normalizeLinkTarget(path.posix.basename(note.path, ".md")),
    };
  }

  private addOwner(map: Record<string, string[]>, label: string, id: string): void {
    const owners = map[label] ?? [];
    if (!owners.includes(id)) owners.push(id);
    map[label] = owners;
  }

  private removeOwner(map: Record<string, string[]>, label: string, id: string): void {
    const owners = map[label];
    if (!owners) return;
    const next = owners.filter((owner) => owner !== id);
    if (next.length === 0) delete map[label];
    else map[label] = next;
  }

  private addOwnerLabels(index: DocumentIndex, note: IndexedNote): void {
    const labels = this.ownerLabels(note);
    this.addOwner(index.pathOwners, labels.path, note.id);
    this.addOwner(index.basenameOwners, labels.basename, note.id);
    for (const name of labels.names) this.addOwner(index.nameOwners, name, note.id);
  }

  private removeOwnerLabels(index: DocumentIndex, note: IndexedNote): void {
    const labels = this.ownerLabels(note);
    this.removeOwner(index.pathOwners, labels.path, note.id);
    this.removeOwner(index.basenameOwners, labels.basename, note.id);
    for (const name of labels.names) this.removeOwner(index.nameOwners, name, note.id);
  }

  private addSourceToLinkMap(index: DocumentIndex, source: IndexedNote): void {
    for (const target of new Set(source.links.map((link) => normalizeLinkTarget(link.target)))) {
      const sources = new Set(index.linkSources[target] ?? []);
      sources.add(source.id);
      index.linkSources[target] = [...sources];
    }
  }

  private clearResolvedSource(index: DocumentIndex, sourceId: string): void {
    for (const targetId of new Set((index.resolvedLinks[sourceId] ?? []).filter(Boolean) as string[])) {
      const next = (index.backlinks[targetId] ?? []).filter((id) => id !== sourceId);
      if (next.length === 0) delete index.backlinks[targetId];
      else index.backlinks[targetId] = next;
    }
    delete index.resolvedLinks[sourceId];
    delete index.unresolved[sourceId];
  }

  private refreshResolvedSource(index: DocumentIndex, sourceId: string): void {
    this.clearResolvedSource(index, sourceId);
    const source = index.notes[sourceId];
    if (!source) return;
    const resolved = source.links.map((link) => this.resolveLinkTargetInIndex(index, link)?.id ?? null);
    index.resolvedLinks[sourceId] = resolved;
    const unresolved = source.links.filter((_, linkIndex) => resolved[linkIndex] === null);
    if (unresolved.length > 0) index.unresolved[sourceId] = unresolved;
    for (const targetId of new Set(resolved.filter(Boolean) as string[])) {
      const sources = new Set(index.backlinks[targetId] ?? []);
      if (targetId !== sourceId) sources.add(sourceId);
      index.backlinks[targetId] = [...sources];
    }
  }

  private buildDerivedIndex(notes: Record<string, IndexedNote>): DocumentIndex {
    const index: DocumentIndex = {
      version: 2,
      derived: DERIVED_LAYOUT,
      generatedAt: new Date().toISOString(),
      notes,
      backlinks: {},
      resolvedLinks: {},
      unresolved: {},
      linkSources: {},
      pathOwners: {},
      nameOwners: {},
      basenameOwners: {},
      canvases: {},
      canvasRefs: {},
      canvasAttachmentRefs: {},
      canvasPathOwners: {},
    };
    for (const note of Object.values(notes)) {
      this.addSourceToLinkMap(index, note);
      this.addOwnerLabels(index, note);
    }
    for (const id of Object.keys(notes)) this.refreshResolvedSource(index, id);
    return index;
  }

  /** Validate and stabilize one canvas write without changing live storage. */
  protected prepareCanvasPut(input: CanvasInput): PreparedCanvasPut {
    return withVaultLock(this.vaultDir, () => {
      const index = this.loadIndex();
      const canvasPath = normalizeCanvasPath(input.path);
      const pathKey = normalizeText(canvasPath);
      const existingByPathId = (index.canvasPathOwners[pathKey] ?? []).find(
        (id) => index.canvases[id] && normalizeText(index.canvases[id].path) === pathKey,
      );
      const existingByPath = existingByPathId ? index.canvases[existingByPathId] : undefined;
      const existingById = input.id ? index.canvases[input.id] : undefined;
      if (existingByPath && input.id && existingByPath.id !== input.id) {
        throw new Error(`Another canvas already uses path: ${canvasPath}`);
      }
      const existing = existingById ?? existingByPath;
      const id = existing?.id ?? input.id ?? crypto.randomUUID();
      if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid canvas ID.");
      if (!existing && (index.canvases[id] || index.notes[id])) {
        throw new Error(`Document ID already exists: ${id}`);
      }
      if (existing && input.baseRevision !== undefined && input.baseRevision !== existing.revision) {
        throw new Error(
          `Canvas revision conflict: expected revision ${input.baseRevision}, current revision ${existing.revision}.`,
        );
      }
      const archivedBase = existing ? 0 : Math.max(0, ...this.archivedCanvasRevisionNumbers(id));
      if (!existing && input.baseRevision !== undefined && input.baseRevision !== archivedBase) {
        throw new Error(
          `Canvas revision conflict: expected revision ${input.baseRevision}, archived revision ${archivedBase}.`,
        );
      }

      const existingObject = existing ? this.loadCanvasById(existing.id) : undefined;
      const nodes = normalizeCanvasNodes(input.nodes);
      const edges = normalizeCanvasEdges(input.edges, nodes);
      const now = new Date().toISOString();
      const canvas: CanvasDocument = {
        version: 1,
        id,
        path: canvasPath,
        title: normalizeCanvasTitle(input.title ?? canvasBasename(canvasPath)),
        nodes,
        edges,
        createdAt: existingObject?.createdAt ?? input.createdAt ?? now,
        updatedAt: now,
        revision: existing ? existing.revision + 1 : (input.baseRevision ?? archivedBase) + 1,
      };
      assertCanvasSize(canvas);
      return { document: structuredClone(canvas) };
    });
  }

  putCanvas(input: CanvasInput): CanvasDocument {
    return withVaultLock(this.vaultDir, () => {
      const index = this.loadIndex();
      const canvasPath = normalizeCanvasPath(input.path);
      const pathKey = normalizeText(canvasPath);
      const existingByPathId = (index.canvasPathOwners[pathKey] ?? []).find(
        (id) => index.canvases[id] && normalizeText(index.canvases[id].path) === pathKey,
      );
      const existingByPath = existingByPathId ? index.canvases[existingByPathId] : undefined;
      const existingById = input.id ? index.canvases[input.id] : undefined;
      if (existingByPath && input.id && existingByPath.id !== input.id) {
        throw new Error(`Another canvas already uses path: ${canvasPath}`);
      }
      const existing = existingById ?? existingByPath;
      const id = existing?.id ?? input.id ?? crypto.randomUUID();
      if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid canvas ID.");
      if (!existing && (index.canvases[id] || index.notes[id])) {
        throw new Error(`Document ID already exists: ${id}`);
      }
      if (existing && input.baseRevision !== undefined && input.baseRevision !== existing.revision) {
        throw new Error(
          `Canvas revision conflict: expected revision ${input.baseRevision}, current revision ${existing.revision}.`,
        );
      }
      const archivedBase = existing ? 0 : Math.max(0, ...this.archivedCanvasRevisionNumbers(id));
      if (!existing && input.baseRevision !== undefined && input.baseRevision !== archivedBase) {
        throw new Error(
          `Canvas revision conflict: expected revision ${input.baseRevision}, archived revision ${archivedBase}.`,
        );
      }

      const existingObject = existing ? this.loadCanvasById(existing.id) : undefined;
      const nodes = normalizeCanvasNodes(input.nodes);
      const edges = normalizeCanvasEdges(input.edges, nodes);
      const now = new Date().toISOString();
      const canvas: CanvasDocument = {
        version: 1,
        id,
        path: canvasPath,
        title: normalizeCanvasTitle(input.title ?? canvasBasename(canvasPath)),
        nodes,
        edges,
        createdAt: existingObject?.createdAt ?? input.createdAt ?? now,
        updatedAt: now,
        revision: existing ? existing.revision + 1 : (input.baseRevision ?? archivedBase) + 1,
      };
      assertCanvasSize(canvas);

      this.beginJournal("canvases", [id]);
      if (existingObject) this.archiveCanvasRevision(existingObject);
      fs.mkdirSync(this.objectsDir(), { recursive: true, mode: 0o700 });
      const payload = encryptDocument(JSON.stringify(canvas), this.session.key, canvasAad(id));
      writeFileAtomic(this.canvasObjectPath(id), JSON.stringify(payload), { mode: 0o600 });
      this.detachCanvas(index, existing);
      this.attachCanvas(index, this.indexCanvasEntry(index, canvas));
      this.saveIndex(index);
      this.endJournal();
      return this.materializeCanvas(canvas);
    });
  }

  getCanvas(reference: string): CanvasDocument {
    return this.materializeCanvas(this.loadCanvasById(this.resolveCanvasId(reference)));
  }

  listCanvases(): CanvasSummary[] {
    return Object.values(this.loadIndex().canvases)
      .map(canvasSummary)
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  removeCanvas(reference: string): CanvasDocument {
    return withVaultLock(this.vaultDir, () => {
      const id = this.resolveCanvasId(reference);
      const index = this.loadIndex();
      const current = this.loadCanvasById(id);
      const returned = this.materializeCanvas(current);
      this.beginJournal("canvases", [id]);
      this.archiveCanvasRevision(current);
      const filePath = this.canvasObjectPath(id);
      assertNotSymlink(filePath);
      if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      this.detachCanvas(index, index.canvases[id]);
      this.saveIndex(index);
      this.endJournal();
      return returned;
    });
  }

  renameCanvas(reference: string, newPath: string): CanvasDocument {
    const current = this.getCanvas(reference);
    return this.putCanvas({
      id: current.id,
      path: newPath,
      title: current.title,
      nodes: current.nodes,
      edges: current.edges,
      createdAt: current.createdAt,
      baseRevision: current.revision,
    });
  }

  canvasRevisions(reference: string): RevisionInfo[] {
    const id = this.resolveCanvasHistoryId(reference);
    const current = this.loadIndex().canvases[id];
    const revisions = this.archivedCanvasRevisionNumbers(id).map((revision) => {
      const canvas = this.loadCanvasRevisionById(id, revision);
      return { revision, updatedAt: canvas.updatedAt, current: false };
    });
    if (current) revisions.push({ revision: current.revision, updatedAt: current.updatedAt, current: true });
    return revisions.sort((a, b) => b.revision - a.revision);
  }

  getCanvasRevision(reference: string, revision: number): CanvasDocument {
    return this.materializeCanvas(this.loadCanvasRevisionById(this.resolveCanvasHistoryId(reference), revision));
  }

  restoreCanvas(reference: string, revision: number): CanvasDocument {
    const id = this.resolveCanvasHistoryId(reference);
    const historical = this.loadCanvasRevisionById(id, revision);
    const current = this.loadIndex().canvases[id];
    const baseRevision = current?.revision ?? Math.max(0, ...this.archivedCanvasRevisionNumbers(id));
    return this.putCanvas({
      id,
      path: historical.path,
      title: historical.title,
      nodes: historical.nodes,
      edges: historical.edges,
      createdAt: historical.createdAt,
      baseRevision,
    });
  }

  canvasesReferencing(noteReference: string): CanvasSummary[] {
    const index = this.loadIndex();
    const noteId =
      /^[a-f0-9-]{36}$/u.test(noteReference) && index.canvasRefs[noteReference]
        ? noteReference
        : this.resolveId(noteReference);
    return (index.canvasRefs[noteId] ?? [])
      .filter((id) => index.canvases[id])
      .map((id) => canvasSummary(index.canvases[id]))
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  importCanvas(canvasPath: string, jsonCanvasText: string): CanvasDocument {
    const parsed = parseJsonCanvas(jsonCanvasText);
    const index = this.loadIndex();
    const attachmentsByName = new Map<string, AttachmentInfo[]>();
    for (const info of this.listAttachments()) {
      const key = normalizeText(info.filename);
      attachmentsByName.set(key, [...(attachmentsByName.get(key) ?? []), info]);
    }
    const nodes = parsed.nodes.map((node): CanvasNode => {
      if (node.type !== "file" || node.noteId || node.attachmentId) return node;
      const noteMatches = index.pathOwners[normalizeLinkTarget(node.file)] ?? [];
      if (noteMatches.length === 1 && index.notes[noteMatches[0]]) {
        return { ...node, noteId: noteMatches[0] };
      }
      const attachmentMatches = attachmentsByName.get(normalizeText(path.posix.basename(node.file))) ?? [];
      if (attachmentMatches.length === 1) return { ...node, attachmentId: attachmentMatches[0].id };
      return node;
    });
    return this.putCanvas({ path: canvasPath, nodes, edges: parsed.edges });
  }

  exportCanvas(reference: string, assetsDir = DEFAULT_ASSETS_DIR): string {
    const safeAssetsDir = assetsDir.trim().replace(/\\/gu, "/");
    const assetParts = safeAssetsDir.split("/");
    if (
      !safeAssetsDir ||
      safeAssetsDir.startsWith("/") ||
      /^[a-z]:\//iu.test(safeAssetsDir) ||
      assetParts.some((part) => !part || part === "." || part === "..")
    ) {
      throw new Error("Canvas export assets directory must be a relative path label.");
    }
    return serializeJsonCanvas(this.getCanvas(reference), safeAssetsDir);
  }

  private loadPluginById(id: string): PluginPackage {
    this.assertUnlocked();
    const filePath = this.pluginObjectPath(id);
    if (!fs.existsSync(filePath)) throw new Error(`Plugin not found: ${id}`);
    assertNotSymlink(filePath);
    const payload = JSON.parse(fs.readFileSync(filePath, "utf8")) as DocumentPayload;
    const plugin = JSON.parse(decryptDocument(payload, this.session.key, pluginAad(id))) as PluginPackage;
    if (plugin.id !== id || plugin.version !== 1) throw new Error("Plugin identity check failed.");
    // Re-validated on the way out, not only on the way in: a manifest this
    // build cannot fully describe must not reach the runtime that enforces it.
    const manifest = parsePluginManifest(plugin.manifest);
    const signature = verifyPluginSignature(manifest, plugin.source);
    if (
      plugin.signature &&
      (!signature || plugin.signature.algorithm !== signature.algorithm || plugin.signature.keyId !== signature.keyId)
    ) {
      throw new Error("Plugin signature metadata does not match its signed package.");
    }
    const { signature: _storedSignature, ...rest } = plugin;
    return { ...rest, manifest, ...(signature ? { signature } : {}) };
  }

  private loadPluginPolicy(): PluginSecurityPolicy {
    this.assertUnlocked();
    const filePath = this.pluginPolicyPath();
    if (!fs.existsSync(filePath)) return { version: 1, restrictedMode: false, revokedSigners: [] };
    assertNotSymlink(filePath);
    const payload = JSON.parse(fs.readFileSync(filePath, "utf8")) as DocumentPayload;
    const raw = JSON.parse(
      decryptDocument(payload, this.session.key, PLUGIN_POLICY_AAD),
    ) as Partial<PluginSecurityPolicy>;
    if (raw.version !== 1 || typeof raw.restrictedMode !== "boolean" || !Array.isArray(raw.revokedSigners)) {
      throw new Error("Invalid plugin security policy.");
    }
    const revokedSigners = [...new Set(raw.revokedSigners.map((key) => String(key).toLowerCase()))];
    if (revokedSigners.length > 1_000 || revokedSigners.some((key) => !/^[a-f0-9]{64}$/u.test(key))) {
      throw new Error("Invalid plugin signer revocation list.");
    }
    return { version: 1, restrictedMode: raw.restrictedMode, revokedSigners };
  }

  private savePluginPolicy(policy: PluginSecurityPolicy): void {
    const normalized: PluginSecurityPolicy = {
      version: 1,
      restrictedMode: policy.restrictedMode,
      revokedSigners: [...new Set(policy.revokedSigners)].sort(),
    };
    const payload = encryptDocument(JSON.stringify(normalized), this.session.key, PLUGIN_POLICY_AAD);
    writeFileAtomic(this.pluginPolicyPath(), JSON.stringify(payload), { mode: 0o600 });
  }

  private pluginAllowed(plugin: PluginPackage, policy = this.loadPluginPolicy()): boolean {
    if (plugin.signature && policy.revokedSigners.includes(plugin.signature.keyId)) return false;
    return !policy.restrictedMode || Boolean(plugin.signature);
  }

  private resolvePluginId(reference: string): string {
    const plugins = this.loadIndex().plugins ?? {};
    if (plugins[reference]) return reference;
    const wanted = reference.trim().toLowerCase();
    const matches = Object.values(plugins).filter(
      (plugin) => plugin.manifestId === wanted || plugin.name.toLowerCase() === wanted,
    );
    if (matches.length === 1) return matches[0].id;
    if (matches.length > 1) throw new Error(`Ambiguous plugin reference: ${reference}`);
    throw new Error(`Plugin not found: ${reference}`);
  }

  /**
   * Installing is deliberately one call that takes both the manifest and the
   * source: a plugin whose declared reach and whose code arrived separately
   * could be approved as one thing and run as another.
   */
  installPlugin(input: { manifest: unknown; source: string; enabled?: boolean; baseRevision?: number }): PluginPackage {
    return withVaultLock(this.vaultDir, () => {
      const manifest = parsePluginManifest(input.manifest);
      const source = validatePluginSource(input.source);
      const signature = verifyPluginSignature(manifest, source);
      const policy = this.loadPluginPolicy();
      if (signature && policy.revokedSigners.includes(signature.keyId)) {
        throw new Error(`Plugin signer is revoked: ${signature.keyId}`);
      }
      if (policy.restrictedMode && !signature) {
        throw new Error("Restricted mode accepts cryptographically signed plugins only.");
      }
      const index = this.loadIndex();
      const plugins = index.plugins ?? {};
      const existing = Object.values(plugins).find((plugin) => plugin.manifestId === manifest.id);
      if (!existing && Object.keys(plugins).length >= MAX_PLUGINS) {
        throw new Error(`A vault may hold at most ${MAX_PLUGINS} plugins.`);
      }
      if (existing && input.baseRevision !== undefined && input.baseRevision !== existing.revision) {
        throw new Error(
          `Plugin revision conflict: expected revision ${input.baseRevision}, current revision ${existing.revision}.`,
        );
      }
      const id = existing?.id ?? crypto.randomUUID();
      if (!existing && (index.notes[id] || index.canvases[id])) {
        throw new Error(`Document ID already exists: ${id}`);
      }
      const previous = existing ? this.loadPluginById(id) : undefined;
      if (previous?.signature && !signature) {
        throw new Error("A signed plugin cannot be updated with an unsigned package.");
      }
      if (previous?.signature && signature && previous.signature.keyId !== signature.keyId) {
        throw new Error("Plugin signer changed. Remove the plugin and approve it as a new install.");
      }
      const now = new Date().toISOString();
      const plugin: PluginPackage = {
        version: 1,
        id,
        manifest,
        source,
        ...(signature ? { signature } : {}),
        // An update never silently re-enables a plugin the person turned off,
        // and never enables a new one without being asked to.
        enabled: input.enabled ?? previous?.enabled ?? false,
        installedAt: previous?.installedAt ?? now,
        updatedAt: now,
        revision: (existing?.revision ?? 0) + 1,
      };
      this.beginJournal("plugins", [id]);
      fs.mkdirSync(this.objectsDir(), { recursive: true, mode: 0o700 });
      const payload = encryptDocument(JSON.stringify(plugin), this.session.key, pluginAad(id));
      writeFileAtomic(this.pluginObjectPath(id), JSON.stringify(payload), { mode: 0o600 });
      index.plugins = { ...plugins, [id]: summarizePlugin(plugin, policy) };
      this.saveIndex(index);
      this.endJournal();
      return plugin;
    });
  }

  getPlugin(reference: string): PluginPackage {
    const plugin = this.loadPluginById(this.resolvePluginId(reference));
    return this.pluginAllowed(plugin) ? plugin : { ...plugin, enabled: false };
  }

  listPlugins(): PluginSummary[] {
    const policy = this.loadPluginPolicy();
    return Object.values(this.loadIndex().plugins ?? {})
      .map((summary) => {
        const revoked = Boolean(summary.signer && policy.revokedSigners.includes(summary.signer));
        const signatureStatus = revoked ? "revoked" : summary.signer ? "verified" : "unsigned";
        const allowed = !revoked && (!policy.restrictedMode || signatureStatus === "verified");
        return {
          ...summary,
          enabled: summary.enabled && allowed,
          signatureStatus,
          signed: signatureStatus === "verified",
        } as PluginSummary;
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  pluginSecurityPolicy(): PluginSecurityPolicy {
    return this.loadPluginPolicy();
  }

  setPluginRestrictedMode(restrictedMode: boolean): PluginSecurityPolicy {
    return withVaultLock(this.vaultDir, () => {
      const policy = { ...this.loadPluginPolicy(), restrictedMode };
      this.savePluginPolicy(policy);
      return policy;
    });
  }

  revokePluginSigner(reference: string): PluginSecurityPolicy {
    return withVaultLock(this.vaultDir, () => {
      const plugin = this.loadPluginById(this.resolvePluginId(reference));
      if (!plugin.signature) throw new Error("An unsigned plugin has no signer to revoke.");
      const current = this.loadPluginPolicy();
      const policy = {
        ...current,
        revokedSigners: [...new Set([...current.revokedSigners, plugin.signature.keyId])],
      };
      this.savePluginPolicy(policy);
      for (const summary of Object.values(this.loadIndex().plugins ?? {})) {
        const candidate = this.loadPluginById(summary.id);
        if (candidate.enabled && candidate.signature?.keyId === plugin.signature.keyId) {
          this.setPluginEnabled(candidate.id, false);
        }
      }
      return policy;
    });
  }

  restorePluginSigner(keyId: string): PluginSecurityPolicy {
    return withVaultLock(this.vaultDir, () => {
      const normalized = keyId.trim().toLowerCase();
      if (!/^[a-f0-9]{64}$/u.test(normalized)) throw new Error("Invalid plugin signer key ID.");
      const current = this.loadPluginPolicy();
      const policy = {
        ...current,
        revokedSigners: current.revokedSigners.filter((entry) => entry !== normalized),
      };
      this.savePluginPolicy(policy);
      return policy;
    });
  }

  setPluginEnabled(reference: string, enabled: boolean): PluginSummary {
    return withVaultLock(this.vaultDir, () => {
      const id = this.resolvePluginId(reference);
      const existing = this.loadPluginById(id);
      if (enabled && !this.pluginAllowed(existing)) {
        throw new Error("This plugin is blocked by restricted mode or signer revocation.");
      }
      const plugin = { ...existing, enabled, updatedAt: new Date().toISOString() };
      const index = this.loadIndex();
      this.beginJournal("plugins", [id]);
      const payload = encryptDocument(JSON.stringify(plugin), this.session.key, pluginAad(id));
      writeFileAtomic(this.pluginObjectPath(id), JSON.stringify(payload), { mode: 0o600 });
      const summary = summarizePlugin(plugin, this.loadPluginPolicy());
      index.plugins = { ...(index.plugins ?? {}), [id]: summary };
      this.saveIndex(index);
      this.endJournal();
      return summary;
    });
  }

  removePlugin(reference: string): PluginSummary {
    return withVaultLock(this.vaultDir, () => {
      const id = this.resolvePluginId(reference);
      const plugin = this.loadPluginById(id);
      const index = this.loadIndex();
      this.beginJournal("plugins", [id]);
      for (const filePath of [this.pluginObjectPath(id), this.pluginStorePath(id)]) {
        assertNotSymlink(filePath);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
      const plugins = { ...(index.plugins ?? {}) };
      delete plugins[id];
      index.plugins = plugins;
      this.saveIndex(index);
      this.endJournal();
      return summarizePlugin(plugin);
    });
  }

  /** A plugin's own namespace. Never the vault, never another plugin's. */
  pluginStorage(reference: string): Record<string, string> {
    const id = this.resolvePluginId(reference);
    const filePath = this.pluginStorePath(id);
    if (!fs.existsSync(filePath)) return {};
    assertNotSymlink(filePath);
    const payload = JSON.parse(fs.readFileSync(filePath, "utf8")) as DocumentPayload;
    const parsed = JSON.parse(decryptDocument(payload, this.session.key, pluginStoreAad(id))) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, string>) : {};
  }

  setPluginStorage(reference: string, data: Record<string, string>): Record<string, string> {
    const id = this.resolvePluginId(reference);
    const stored: Record<string, string> = {};
    for (const [key, value] of Object.entries(data)) {
      if (typeof key !== "string" || typeof value !== "string") {
        throw new Error("Plugin storage holds string keys and string values only.");
      }
      if (key.length > 160) throw new Error("A plugin storage key cannot exceed 160 characters.");
      stored[key] = value;
    }
    const serialized = JSON.stringify(stored);
    if (Buffer.byteLength(serialized, "utf8") > MAX_PLUGIN_STORAGE_BYTES) {
      throw new Error(`Plugin storage cannot exceed ${MAX_PLUGIN_STORAGE_BYTES / 1024} KiB.`);
    }
    fs.mkdirSync(this.objectsDir(), { recursive: true, mode: 0o700 });
    const payload = encryptDocument(serialized, this.session.key, pluginStoreAad(id));
    writeFileAtomic(this.pluginStorePath(id), JSON.stringify(payload), { mode: 0o600 });
    return stored;
  }

  put(input: NoteInput): NoteDocument {
    return withVaultLock(this.vaultDir, () => this.putIntoIndex(input, this.loadIndex(), true));
  }

  putMany(inputs: NoteInput[]): NoteDocument[] {
    if (inputs.length > 100_000) throw new Error("A single bulk operation cannot exceed 100,000 notes.");
    return withVaultLock(this.vaultDir, () => {
      const index = this.loadIndex();
      this.beginJournal("bulk", []);
      const notes = inputs.map((input) => this.putIntoIndex(input, index, false));
      this.saveIndex(index);
      this.endJournal();
      return notes;
    });
  }

  /** Validate an evolving note batch without touching objects, history or the index on disk. */
  protected prepareNotePuts(inputs: readonly NoteInput[]): PreparedNotePut[] {
    if (inputs.length > 100_000) throw new Error("A single bulk operation cannot exceed 100,000 notes.");
    return withVaultLock(this.vaultDir, () => {
      const index = structuredClone(this.loadIndex());
      return inputs.map((input) => this.prepareNotePutIntoIndex(input, index));
    });
  }

  private prepareNotePutIntoIndex(input: NoteInput, index: DocumentIndex): PreparedNotePut {
    const notePath = normalizeNotePath(input.path);
    const existingByPathId = (index.pathOwners[normalizeLinkTarget(notePath)] ?? []).find((id) => index.notes[id]);
    const existingByPath = existingByPathId ? index.notes[existingByPathId] : undefined;
    const existingById = input.id ? index.notes[input.id] : undefined;
    if (existingByPath && input.id && existingByPath.id !== input.id) {
      throw new Error(`Another note already uses path: ${notePath}`);
    }
    const existing = existingById ?? existingByPath;
    const id = existing?.id ?? input.id ?? crypto.randomUUID();
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid note ID.");
    if (!existing && (index.notes[id] || index.canvases[id])) throw new Error(`Document ID already exists: ${id}`);
    if (existing && input.baseRevision !== undefined && input.baseRevision !== existing.revision) {
      throw new Error(
        `Note revision conflict: expected revision ${input.baseRevision}, current revision ${existing.revision}.`,
      );
    }
    const archivedBase = existing ? 0 : Math.max(0, ...this.archivedRevisionNumbers(id));
    if (!existing && input.baseRevision !== undefined && input.baseRevision !== archivedBase) {
      throw new Error(
        `Note revision conflict: expected revision ${input.baseRevision}, archived revision ${archivedBase}.`,
      );
    }

    const now = new Date().toISOString();
    const title = (input.title ?? path.posix.basename(notePath, ".md")).trim();
    if (!title || title.length > 300 || /[\r\n\u0000]/u.test(title)) throw new Error("Invalid note title.");
    if (Buffer.byteLength(input.body, "utf8") > 25 * 1024 * 1024) {
      throw new Error("A note body cannot exceed 25 MiB.");
    }
    const analysis = analyzeMarkdown(input.body);
    const note: NoteDocument = {
      version: 1,
      id,
      path: notePath,
      title,
      body: input.body,
      aliases: normalizeStringList(input.aliases),
      tags: normalizeStringList([...(input.tags ?? []), ...analysis.tags]),
      properties: normalizeProperties(input.properties),
      createdAt: existing?.createdAt ?? input.createdAt ?? now,
      updatedAt: now,
      revision: existing ? existing.revision + 1 : (input.baseRevision ?? archivedBase) + 1,
    };
    const frontmatterSource = input.frontmatterSource ?? existing?.frontmatterSource;
    if (frontmatterSource) note.frontmatterSource = frontmatterSource;

    const oldLabels = existing ? this.identityLabels(existing) : [];
    const indexed: IndexedNote = { ...note, links: analysis.links, headings: analysis.headings };
    if (existing) this.removeOwnerLabels(index, existing);
    index.notes[id] = indexed;
    this.addOwnerLabels(index, indexed);
    this.removeSourceFromLinkMap(index, id, existing);
    this.addSourceToLinkMap(index, indexed);
    const affected = new Set<string>([id]);
    for (const label of [...oldLabels, ...this.identityLabels(indexed)]) {
      for (const sourceId of index.linkSources[label] ?? []) affected.add(sourceId);
    }
    for (const sourceId of affected) this.refreshResolvedSource(index, sourceId);
    this.refreshCanvasesForNoteChange(index, id, [...oldLabels, ...this.identityLabels(indexed)]);

    return { document: structuredClone(note) };
  }

  private putIntoIndex(input: NoteInput, index: DocumentIndex, persistIndex: boolean): NoteDocument {
    const notePath = normalizeNotePath(input.path);
    const existingByPathId = (index.pathOwners[normalizeLinkTarget(notePath)] ?? []).find((id) => index.notes[id]);
    const existingByPath = existingByPathId ? index.notes[existingByPathId] : undefined;
    const existingById = input.id ? index.notes[input.id] : undefined;
    if (existingByPath && input.id && existingByPath.id !== input.id) {
      throw new Error(`Another note already uses path: ${notePath}`);
    }
    const existing = existingById ?? existingByPath;
    const id = existing?.id ?? input.id ?? crypto.randomUUID();
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid note ID.");
    if (!existing && (index.notes[id] || index.canvases[id])) throw new Error(`Document ID already exists: ${id}`);
    if (existing && input.baseRevision !== undefined && input.baseRevision !== existing.revision) {
      throw new Error(
        `Note revision conflict: expected revision ${input.baseRevision}, current revision ${existing.revision}.`,
      );
    }
    const archivedBase = existing ? 0 : Math.max(0, ...this.archivedRevisionNumbers(id));
    if (!existing && input.baseRevision !== undefined && input.baseRevision !== archivedBase) {
      throw new Error(
        `Note revision conflict: expected revision ${input.baseRevision}, archived revision ${archivedBase}.`,
      );
    }

    const oldLabels = existing ? this.identityLabels(existing) : [];
    const existingObject = existing ? this.loadById(existing.id) : undefined;
    const now = new Date().toISOString();
    const title = (input.title ?? path.posix.basename(notePath, ".md")).trim();
    if (!title || title.length > 300 || /[\r\n\u0000]/u.test(title)) throw new Error("Invalid note title.");
    if (Buffer.byteLength(input.body, "utf8") > 25 * 1024 * 1024) {
      throw new Error("A note body cannot exceed 25 MiB.");
    }
    const analysis = analyzeMarkdown(input.body);
    const tags = normalizeStringList([...(input.tags ?? []), ...analysis.tags]);
    const note: NoteDocument = {
      version: 1,
      id,
      path: notePath,
      title,
      body: input.body,
      aliases: normalizeStringList(input.aliases),
      tags,
      properties: normalizeProperties(input.properties),
      createdAt: existing?.createdAt ?? input.createdAt ?? now,
      updatedAt: now,
      revision: existing ? existing.revision + 1 : (input.baseRevision ?? archivedBase) + 1,
    };
    const frontmatterSource = input.frontmatterSource ?? existing?.frontmatterSource;
    if (frontmatterSource) note.frontmatterSource = frontmatterSource;

    if (persistIndex) this.beginJournal("notes", [id]);
    if (existingObject) this.archiveRevision(existingObject);
    fs.mkdirSync(this.objectsDir(), { recursive: true, mode: 0o700 });
    const payload = encryptDocument(JSON.stringify(note), this.session.key, noteAad(id));
    writeFileAtomic(encryptedDocumentPath(this.session.rootDir, id), JSON.stringify(payload), {
      mode: 0o600,
    });
    const indexed: IndexedNote = { ...note, links: analysis.links, headings: analysis.headings };
    this.searchCache.delete(id);
    if (existing) this.removeOwnerLabels(index, existing);
    index.notes[id] = indexed;
    this.addOwnerLabels(index, indexed);
    this.removeSourceFromLinkMap(index, id, existing);
    this.addSourceToLinkMap(index, indexed);
    const affected = new Set<string>([id]);
    for (const label of [...oldLabels, ...this.identityLabels(indexed)]) {
      for (const sourceId of index.linkSources[label] ?? []) affected.add(sourceId);
    }
    for (const sourceId of affected) this.refreshResolvedSource(index, sourceId);
    this.refreshCanvasesForNoteChange(index, id, [...oldLabels, ...this.identityLabels(indexed)]);
    if (persistIndex) {
      this.saveIndex(index);
      this.endJournal();
    }
    return structuredClone(note);
  }

  get(reference: string): NoteDocument {
    return this.loadById(this.resolveId(reference));
  }

  rename(reference: string, newPath: string, newTitle?: string): NoteDocument {
    const current = this.get(reference);
    return this.put({
      id: current.id,
      path: newPath,
      title: newTitle ?? current.title,
      body: current.body,
      aliases: current.aliases,
      tags: current.tags,
      properties: current.properties,
      createdAt: current.createdAt,
    });
  }

  list(): NoteSummary[] {
    return Object.values(this.loadIndex().notes)
      .map(summary)
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  remove(reference: string): NoteSummary {
    return withVaultLock(this.vaultDir, () => this.removeLocked(reference));
  }

  private removeLocked(reference: string): NoteSummary {
    const id = this.resolveId(reference);
    const index = this.loadIndex();
    this.beginJournal("notes", [id]);
    const existing = index.notes[id];
    const affected = new Set<string>();
    for (const label of this.identityLabels(existing)) {
      for (const sourceId of index.linkSources[label] ?? []) affected.add(sourceId);
    }
    this.archiveRevision(this.loadById(id));
    const filePath = encryptedDocumentPath(this.session.rootDir, id);
    assertNotSymlink(filePath);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    this.removeSourceFromLinkMap(index, id, existing);
    this.removeOwnerLabels(index, existing);
    this.clearResolvedSource(index, id);
    delete index.notes[id];
    delete index.backlinks[id];
    affected.delete(id);
    for (const sourceId of affected) this.refreshResolvedSource(index, sourceId);
    this.refreshCanvasesForNoteChange(index, id, this.identityLabels(existing));
    this.saveIndex(index);
    this.endJournal();
    return summary(existing);
  }

  search(query: string, limit = 20): SearchHit[] {
    const chunks = query.match(/-?"[^"]+"|-?\S+/gu) ?? [];
    const tags: string[] = [];
    const paths: string[] = [];
    const required: string[] = [];
    const excluded: string[] = [];
    for (let chunk of chunks) {
      const negative = chunk.startsWith("-");
      if (negative) chunk = chunk.slice(1);
      if (chunk.startsWith('"') && chunk.endsWith('"')) chunk = chunk.slice(1, -1);
      const normalized = normalizeText(chunk);
      if (normalized.startsWith("tag:")) tags.push(normalized.slice(4).replace(/^#/u, ""));
      else if (normalized.startsWith("path:")) paths.push(normalized.slice(5));
      else if (negative) excluded.push(normalized);
      else if (normalized) required.push(normalized);
    }

    // A query whose terms appear in every note matches the whole vault, so the
    // result set is bounded as it is built: scoring keeps only the best `limit`
    // instead of materializing and sorting one entry per note. Same results,
    // same order — it just stops paying for the 99,900 it would throw away.
    const wanted = Math.max(1, Math.min(limit, 100));
    const matches: Array<{ note: IndexedNote; score: number }> = [];
    // The filter loop runs once per note in the vault, so it allocates
    // nothing: no per-note closures, and the clauses a query does not use are
    // skipped outright rather than iterated over an empty list.
    candidates: for (const note of this.indexedNotes()) {
      const fields = this.searchFieldsFor(note);
      const head = fields.head;
      const body = fields.body;
      for (const tag of tags) if (!fields.tags.includes(tag)) continue candidates;
      for (const part of paths) if (!fields.path.includes(part)) continue candidates;
      for (const term of excluded) if (head.includes(term) || body.includes(term)) continue candidates;
      for (const term of required) if (!head.includes(term) && !body.includes(term)) continue candidates;

      let score = 0;
      for (const term of required) {
        if (fields.title === term) score += 40;
        else if (fields.title.includes(term)) score += 20;
        if (fields.aliases.some((alias) => alias.includes(term))) score += 14;
        if (fields.tags.some((tag) => tag.includes(term))) score += 10;
        if (fields.path.includes(term)) score += 8;
        score += Math.min(10, countOccurrences(fields.body, term));
        if (fields.properties.includes(term)) score += 4;
      }
      if (required.length === 0) score = 1;

      if (matches.length === wanted) {
        const weakest = matches[matches.length - 1];
        if (score < weakest.score) continue;
        if (score === weakest.score && note.updatedAt <= weakest.note.updatedAt) continue;
      }
      let low = 0;
      let high = matches.length;
      while (low < high) {
        const middle = (low + high) >> 1;
        const other = matches[middle];
        const ahead = other.score > score || (other.score === score && other.note.updatedAt >= note.updatedAt);
        if (ahead) low = middle + 1;
        else high = middle;
      }
      matches.splice(low, 0, { note, score });
      if (matches.length > wanted) matches.pop();
    }

    const terms = required.join(" ");
    return matches.map(({ note, score }) => ({
      ...summary(note),
      score,
      excerpt: makeExcerpt(note.body, terms),
    }));
  }

  /**
   * Optional semantic recall. Calling this method is the opt-in switch: normal
   * search never loads a model or exposes note text outside this process. The
   * adapter is expected to enforce its own on-device boundary.
   */
  async semanticSearch(
    query: string,
    adapter: EmbeddingAdapter,
    options: SemanticSearchOptions = {},
  ): Promise<SemanticSearchHit[]> {
    this.assertUnlocked();
    const generation = this.sessionGeneration;
    let semanticIndex = this.semanticIndexes.get(adapter);
    if (!semanticIndex) {
      semanticIndex = new SemanticNoteIndex();
      this.semanticIndexes.set(adapter, semanticIndex);
    }
    try {
      const hits = await semanticIndex.search(this.indexedNotes(), query, adapter, options);
      if (this.locked || generation !== this.sessionGeneration) {
        semanticIndex.clear();
        this.semanticIndexes.delete(adapter);
        throw new Error("This vault session was locked while semantic search was running.");
      }
      return hits;
    } catch (error) {
      if (this.locked || generation !== this.sessionGeneration) {
        semanticIndex.clear();
        this.semanticIndexes.delete(adapter);
        throw new Error("This vault session was locked while semantic search was running.", { cause: error });
      }
      throw error;
    }
  }

  outgoing(reference: string): OutgoingLink[] {
    const id = this.resolveId(reference);
    const index = this.loadIndex();
    return index.notes[id].links.map((link, linkIndex) => {
      const resolvedId = index.resolvedLinks[id]?.[linkIndex] ?? undefined;
      const resolved = resolvedId ? index.notes[resolvedId] : undefined;
      return {
        ...link,
        resolvedId: resolved?.id,
        resolvedPath: resolved?.path,
      };
    });
  }

  backlinks(reference: string): NoteSummary[] {
    const targetId = this.resolveId(reference);
    const index = this.loadIndex();
    return (index.backlinks[targetId] ?? [])
      .map((sourceId) => summary(index.notes[sourceId]))
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  unresolvedLinks(): Array<{ source: NoteSummary; links: WikiLink[] }> {
    const index = this.loadIndex();
    return Object.entries(index.unresolved)
      .filter(([sourceId]) => Boolean(index.notes[sourceId]))
      .map(([sourceId, links]) => ({ source: summary(index.notes[sourceId]), links }))
      .sort((a, b) => a.source.path.localeCompare(b.source.path));
  }

  rebuildIndex(): DocumentIndex {
    const notes: Record<string, IndexedNote> = {};
    const objectsDir = this.objectsDir();
    if (fs.existsSync(objectsDir)) {
      for (const filename of fs.readdirSync(objectsDir).filter((name) => name.endsWith(".note.enc"))) {
        const id = filename.slice(0, -9);
        const note = this.loadById(id);
        const analysis = analyzeMarkdown(note.body);
        notes[id] = { ...note, links: analysis.links, headings: analysis.headings };
      }
    }
    const index = this.buildDerivedIndex(notes);
    // A second pass over the same directory, filtered on the canvas suffix.
    // Canvases are indexed after the notes because a text node's wikilinks
    // resolve against the finished note index, exactly as a note body's would.
    if (fs.existsSync(objectsDir)) {
      for (const filename of fs.readdirSync(objectsDir).filter((name) => name.endsWith(".canvas.enc"))) {
        const canvas = this.loadCanvasById(filename.slice(0, -".canvas.enc".length));
        this.attachCanvas(index, this.indexCanvasEntry(index, canvas));
      }
    }
    // Plugins carry nothing derived, so this pass only restores the listing an
    // index rebuild would otherwise drop while the objects sat safely on disk.
    if (fs.existsSync(objectsDir)) {
      index.plugins = {};
      for (const filename of fs.readdirSync(objectsDir).filter((name) => name.endsWith(".plugin.enc"))) {
        const plugin = this.loadPluginById(filename.slice(0, -".plugin.enc".length));
        index.plugins[plugin.id] = summarizePlugin(plugin);
      }
    }
    this.saveIndex(index);
    this.endJournal();
    return index;
  }

  revisions(reference: string): RevisionInfo[] {
    const id = this.resolveHistoryId(reference);
    const current = this.loadIndex().notes[id];
    const revisions: RevisionInfo[] = [];
    for (const revision of this.archivedRevisionNumbers(id)) {
      const note = this.loadRevisionById(id, revision);
      revisions.push({ revision, updatedAt: note.updatedAt, current: false });
    }
    if (current) {
      revisions.push({ revision: current.revision, updatedAt: current.updatedAt, current: true });
    }
    return revisions.sort((a, b) => b.revision - a.revision);
  }

  getRevision(reference: string, revision: number): NoteDocument {
    return this.loadRevisionById(this.resolveHistoryId(reference), revision);
  }

  restore(reference: string, revision: number): NoteDocument {
    const id = this.resolveHistoryId(reference);
    const historical = this.loadRevisionById(id, revision);
    const current = this.loadIndex().notes[id];
    const baseRevision = current?.revision ?? Math.max(0, ...this.archivedRevisionNumbers(id));
    return this.put({
      id,
      path: historical.path,
      title: historical.title,
      body: historical.body,
      aliases: historical.aliases,
      tags: historical.tags,
      properties: historical.properties,
      createdAt: historical.createdAt,
      baseRevision,
    });
  }

  /** Validate attachment metadata and freeze its keyed content ID without writing chunks. */
  protected prepareAttachmentPut(
    data: Buffer,
    filename: string,
    mime = "application/octet-stream",
  ): PreparedAttachmentPut {
    this.assertUnlocked();
    if (data.length === 0 || data.length > MAX_ATTACHMENT_SIZE) {
      throw new Error("Attachments must be between 1 byte and 250 MiB.");
    }
    const safeFilename = filename.trim();
    if (!safeFilename || safeFilename.length > 255 || /[\r\n\u0000]/u.test(safeFilename)) {
      throw new Error("Invalid attachment filename.");
    }
    const safeMime = mime.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/u.test(safeMime)) {
      throw new Error("Invalid attachment MIME type.");
    }
    const id = crypto
      .createHmac("sha256", this.session.key)
      .update("secondbrain-vault:attachment-id:v1\0", "utf8")
      .update(data)
      .digest("hex");
    const existed = fs.existsSync(this.attachmentManifestPath(id));
    const info = existed
      ? this.readAttachmentManifest(id)
      : {
          id,
          filename: safeFilename,
          mime: safeMime,
          size: data.length,
          chunks: Math.ceil(data.length / ATTACHMENT_CHUNK_SIZE),
          createdAt: new Date().toISOString(),
        };
    return { data: Buffer.from(data), info: structuredClone(info), existed };
  }

  putAttachment(data: Buffer, filename: string, mime = "application/octet-stream"): AttachmentInfo {
    this.assertUnlocked();
    return withVaultLock(this.vaultDir, () => this.putAttachmentLocked(data, filename, mime));
  }

  private putAttachmentLocked(data: Buffer, filename: string, mime: string): AttachmentInfo {
    if (data.length === 0 || data.length > MAX_ATTACHMENT_SIZE) {
      throw new Error("Attachments must be between 1 byte and 250 MiB.");
    }
    const safeFilename = filename.trim();
    if (!safeFilename || safeFilename.length > 255 || /[\r\n\u0000]/u.test(safeFilename)) {
      throw new Error("Invalid attachment filename.");
    }
    const safeMime = mime.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/u.test(safeMime)) {
      throw new Error("Invalid attachment MIME type.");
    }
    const id = crypto
      .createHmac("sha256", this.session.key)
      .update("secondbrain-vault:attachment-id:v1\0", "utf8")
      .update(data)
      .digest("hex");
    if (fs.existsSync(this.attachmentManifestPath(id))) return this.readAttachmentManifest(id);

    const attachmentDir = this.attachmentDir(id);
    fs.mkdirSync(attachmentDir, { recursive: true, mode: 0o700 });
    const chunks = Math.ceil(data.length / ATTACHMENT_CHUNK_SIZE);
    for (let index = 0; index < chunks; index += 1) {
      const chunk = data.subarray(index * ATTACHMENT_CHUNK_SIZE, (index + 1) * ATTACHMENT_CHUNK_SIZE);
      const payload = encryptDocumentBytes(chunk, this.session.key, attachmentChunkAad(id, index));
      writeFileAtomic(resolveInside(attachmentDir, `${index}.chunk.enc`), JSON.stringify(payload), {
        mode: 0o600,
      });
    }
    const info: AttachmentInfo = {
      id,
      filename: safeFilename,
      mime: safeMime,
      size: data.length,
      chunks,
      createdAt: new Date().toISOString(),
    };
    const manifest = encryptDocument(JSON.stringify(info), this.session.key, attachmentManifestAad(id));
    writeFileAtomic(this.attachmentManifestPath(id), JSON.stringify(manifest), { mode: 0o600 });
    return info;
  }

  getAttachment(id: string): { info: AttachmentInfo; data: Buffer } {
    const info = this.readAttachmentManifest(id);
    const parts: Buffer[] = [];
    for (let index = 0; index < info.chunks; index += 1) {
      const chunkPath = resolveInside(this.attachmentDir(id), `${index}.chunk.enc`);
      if (!fs.existsSync(chunkPath)) throw new Error(`Missing attachment chunk ${index}.`);
      assertNotSymlink(chunkPath);
      const payload = JSON.parse(fs.readFileSync(chunkPath, "utf8")) as DocumentPayload;
      parts.push(decryptDocumentBytes(payload, this.session.key, attachmentChunkAad(id, index)));
    }
    const data = Buffer.concat(parts);
    const actualId = crypto
      .createHmac("sha256", this.session.key)
      .update("secondbrain-vault:attachment-id:v1\0", "utf8")
      .update(data)
      .digest("hex");
    if (data.length !== info.size || actualId !== id) throw new Error("Attachment integrity check failed.");
    return { info, data };
  }

  listAttachments(): AttachmentInfo[] {
    const root = resolveInside(this.session.rootDir, "attachments");
    if (!fs.existsSync(root)) return [];
    return fs
      .readdirSync(root)
      .filter((id) => /^[a-f0-9]{64}$/u.test(id) && fs.existsSync(this.attachmentManifestPath(id)))
      .map((id) => this.readAttachmentManifest(id))
      .sort((a, b) => a.filename.localeCompare(b.filename));
  }

  unreferencedAttachments(): AttachmentInfo[] {
    const index = this.loadIndex();
    const referenced = new Set(Object.keys(index.canvasAttachmentRefs));
    const embeddedLabels = new Set<string>();
    for (const note of Object.values(index.notes)) {
      for (const link of note.links) {
        if (!link.embed) continue;
        embeddedLabels.add(normalizeText(link.target));
        embeddedLabels.add(normalizeText(path.posix.basename(link.target)));
      }
    }
    return this.listAttachments().filter((info) => {
      if (referenced.has(info.id)) return false;
      return !embeddedLabels.has(normalizeText(info.filename)) && !embeddedLabels.has(normalizeText(info.id));
    });
  }

  removeAttachment(id: string): AttachmentInfo {
    return withVaultLock(this.vaultDir, () => {
      const info = this.readAttachmentManifest(id);
      fs.rmSync(this.attachmentDir(id), { recursive: true, force: false });
      return info;
    });
  }

  exportMarkdown(reference: string): string {
    const note = this.get(reference);
    const frontmatter: Record<string, PropertyValue> = {
      ...note.properties,
      vbrain_id: note.id,
      title: note.title,
      aliases: note.aliases,
      tags: note.tags,
      created: note.createdAt,
      modified: note.updatedAt,
    };
    return note.frontmatterSource
      ? applyFrontmatter(note.frontmatterSource, frontmatter, note.body)
      : stringifyFrontmatter(frontmatter, note.body);
  }

  importMarkdown(notePath: string, markdown: string): NoteDocument {
    return this.put(parseMarkdownNote(notePath, markdown));
  }
}
