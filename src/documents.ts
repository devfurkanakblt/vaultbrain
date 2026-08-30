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

export type PropertyValue = string | number | boolean | null | PropertyValue[] | {
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
 * The on-disk index stays at version 2, the layout the Rust desktop core also
 * reads and writes: both implementations must be able to open the same vault.
 * The lookup maps below are additive, so the desktop core simply ignores them,
 * and `derived` records that they are present — an index written by a build
 * without them is rebuilt rather than trusted.
 */
interface DocumentIndex {
  version: 2;
  derived: 4;
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
}

const DERIVED_LAYOUT = 4;

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
  scope: "notes" | "bulk";
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
const ATTACHMENT_CHUNK_SIZE = 1024 * 1024;
const MAX_ATTACHMENT_SIZE = 250 * 1024 * 1024;

function noteAad(id: string): string {
  return `secondbrain-vault:note:v1:${id}`;
}

function historyAad(id: string, revision: number): string {
  return `secondbrain-vault:note-history:v1:${id}:${revision}`;
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

function normalizeProperties(
  properties: Record<string, PropertyValue> | undefined
): Record<string, PropertyValue> {
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
  private locked = false;

  constructor(private readonly vaultDir: string, passphrase: string) {
    this.session = openDocumentKey(vaultDir, passphrase);
  }

  /**
   * Ends the session: the derived key is overwritten in place and the decrypted
   * index is dropped, so nothing readable survives in this process. Every
   * subsequent operation fails until a new DocumentVault is constructed with
   * the passphrase again — locking is a state change, not a UI gesture.
   */
  lock(): void {
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

  private readAttachmentManifest(id: string): AttachmentInfo {
    this.assertUnlocked();
    const manifestPath = this.attachmentManifestPath(id);
    if (!fs.existsSync(manifestPath)) throw new Error(`Attachment not found: ${id}`);
    assertNotSymlink(manifestPath);
    const payload = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as DocumentPayload;
    const info = JSON.parse(
      decryptDocument(payload, this.session.key, attachmentManifestAad(id))
    ) as AttachmentInfo;
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
    const parsed = JSON.parse(
      decryptDocument(payload, this.session.key, INDEX_AAD)
    ) as DocumentIndex | LegacyDocumentIndex;
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
      if (journal?.version !== 1 || (journal.scope !== "notes" && journal.scope !== "bulk")) return undefined;
      const ids = Array.isArray(journal.ids) ? journal.ids.filter((id) => /^[a-f0-9-]{36}$/u.test(id)) : [];
      return { version: 1, startedAt: String(journal.startedAt), scope: journal.scope, ids };
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

  /** Re-derive the index entries an interrupted transaction may have left stale. */
  private recoverFromJournal(index: DocumentIndex): DocumentIndex | undefined {
    const journal = this.readJournal();
    if (!journal) return undefined;
    if (journal.scope === "bulk") return this.rebuildIndex();

    const affected = new Set<string>();
    const collect = (note: IndexedNote | undefined) => {
      if (!note) return;
      for (const label of this.identityLabels(note)) {
        for (const sourceId of index.linkSources[label] ?? []) affected.add(sourceId);
      }
    };

    for (const id of journal.ids) {
      collect(index.notes[id]);
      const filePath = encryptedDocumentPath(this.session.rootDir, id);
      const stale = index.notes[id];
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
    }
    for (const sourceId of affected) {
      if (index.notes[sourceId]) this.refreshResolvedSource(index, sourceId);
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

  private archiveRevision(note: NoteDocument): void {
    const historyPath = this.historyPath(note.id, note.revision);
    if (fs.existsSync(historyPath)) return;
    fs.mkdirSync(this.historyDir(note.id), { recursive: true, mode: 0o700 });
    const payload = encryptDocument(
      JSON.stringify(note),
      this.session.key,
      historyAad(note.id, note.revision)
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
    const note = JSON.parse(
      decryptDocument(payload, this.session.key, historyAad(id, revision))
    ) as NoteDocument;
    if (note.id !== id || note.revision !== revision) throw new Error("Invalid revision object.");
    return note;
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
    const matches = [...new Set([
      ...(notePath ? index.pathOwners[normalizeLinkTarget(notePath)] ?? [] : []),
      ...(index.nameOwners[normalizedReference] ?? []),
    ])].filter((id) => index.notes[id]);
    if (matches.length === 0) throw new Error(`Note not found: ${reference}`);
    if (matches.length > 1) throw new Error(`Ambiguous note reference: ${reference}`);
    return matches[0];
  }

  private resolveLinkTargetInIndex(index: DocumentIndex, link: WikiLink): IndexedNote | undefined {
    const target = normalizeLinkTarget(link.target);
    const exactPath = (index.pathOwners[target] ?? [])[0];
    if (exactPath && index.notes[exactPath]) return index.notes[exactPath];
    const candidates = [...new Set([
      ...(index.nameOwners[target] ?? []),
      ...(index.basenameOwners[target] ?? []),
    ])].filter((id) => index.notes[id]);
    return candidates.length === 1 ? index.notes[candidates[0]] : undefined;
  }

  private identityLabels(note: IndexedNote): string[] {
    return [...new Set([
      normalizeLinkTarget(note.path),
      normalizeLinkTarget(path.posix.basename(note.path, ".md")),
      normalizeText(note.title),
      ...note.aliases.map(normalizeText),
    ])];
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
    };
    for (const note of Object.values(notes)) {
      this.addSourceToLinkMap(index, note);
      this.addOwnerLabels(index, note);
    }
    for (const id of Object.keys(notes)) this.refreshResolvedSource(index, id);
    return index;
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

  private putIntoIndex(input: NoteInput, index: DocumentIndex, persistIndex: boolean): NoteDocument {
    const notePath = normalizeNotePath(input.path);
    const existingByPathId = (index.pathOwners[normalizeLinkTarget(notePath)] ?? [])
      .find((id) => index.notes[id]);
    const existingByPath = existingByPathId ? index.notes[existingByPathId] : undefined;
    const existingById = input.id ? index.notes[input.id] : undefined;
    if (existingByPath && existingById && existingByPath.id !== existingById.id) {
      throw new Error(`Another note already uses path: ${notePath}`);
    }
    const existing = existingById ?? existingByPath;
    const id = existing?.id ?? input.id ?? crypto.randomUUID();
    if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid note ID.");
    if (!existing && index.notes[id]) throw new Error(`Note ID already exists: ${id}`);

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
      revision: existing ? existing.revision + 1 : (input.baseRevision ?? 0) + 1,
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
    candidates:
    for (const note of this.indexedNotes()) {
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
    return matches
      .map(({ note, score }) => ({
        ...summary(note),
        score,
        excerpt: makeExcerpt(note.body, terms),
      }));
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
      const payload = encryptDocumentBytes(
        chunk,
        this.session.key,
        attachmentChunkAad(id, index)
      );
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
    const manifest = encryptDocument(
      JSON.stringify(info),
      this.session.key,
      attachmentManifestAad(id)
    );
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
      sbrain_id: note.id,
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
    const parsed = parseFrontmatter(markdown);
    const metadata = { ...parsed.attributes };
    const legacyProperties =
      metadata.properties && typeof metadata.properties === "object" && !Array.isArray(metadata.properties)
        ? (metadata.properties as Record<string, PropertyValue>)
        : {};
    const reserved = new Set([
      "id", "sbrain_id", "title", "aliases", "tags", "created", "createdAt",
      "modified", "updatedAt", "properties",
    ]);
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
    return this.put({
      path: notePath,
      title: typeof metadata.title === "string" ? metadata.title : undefined,
      body: parsed.body,
      aliases: stringList(metadata.aliases, false),
      tags: stringList(metadata.tags, true).map((tag) => tag.replace(/^#/u, "")),
      properties,
      frontmatterSource: parsed.hasFrontmatter ? parsed.source : undefined,
      id:
        typeof metadata.sbrain_id === "string"
          ? metadata.sbrain_id
          : typeof metadata.id === "string"
            ? metadata.id
            : undefined,
      createdAt:
        typeof metadata.created === "string"
          ? metadata.created
          : typeof metadata.createdAt === "string"
            ? metadata.createdAt
            : undefined,
    });
  }
}
