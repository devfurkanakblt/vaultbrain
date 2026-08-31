import type { AttachmentInfo, CanvasDocument, NoteDocument } from "../documents.js";
import { MAX_CHANGE_BYTES, assertSyncJson, canonicalSyncJson, type SyncJson } from "./protocol.js";

export interface NoteSyncSnapshot {
  path: string;
  title: string;
  body: string;
  aliases: string[];
  tags: string[];
  properties: NoteDocument["properties"];
  createdAt: string;
  frontmatterSource?: string;
}

export interface CanvasSyncSnapshot {
  path: string;
  title: string;
  nodes: CanvasDocument["nodes"];
  edges: CanvasDocument["edges"];
  createdAt: string;
}

export interface AttachmentSyncSnapshot {
  filename: string;
  mime: string;
  data: string;
}

export function asSyncJson(value: unknown): SyncJson {
  assertSyncJson(value);
  return structuredClone(value) as SyncJson;
}

export function assertSyncSnapshotSize(value: unknown, label: string): void {
  const jsonCompatible = JSON.parse(JSON.stringify(value)) as SyncJson;
  const bytes = Buffer.byteLength(canonicalSyncJson(jsonCompatible), "utf8");
  // Leave room for device metadata and the maximum causal-parent list.
  if (bytes > MAX_CHANGE_BYTES - 64 * 1024) throw new Error(`${label} is too large for an 8 MiB sync change.`);
}

export function noteSnapshot(note: NoteDocument): NoteSyncSnapshot {
  const snapshot: NoteSyncSnapshot = {
    path: note.path,
    title: note.title,
    body: note.body,
    aliases: note.aliases,
    tags: note.tags,
    properties: note.properties,
    createdAt: note.createdAt,
  };
  if (note.frontmatterSource !== undefined) snapshot.frontmatterSource = note.frontmatterSource;
  return structuredClone(snapshot);
}

export function canvasSnapshot(canvas: CanvasDocument): CanvasSyncSnapshot {
  return structuredClone({ path: canvas.path, title: canvas.title, nodes: canvas.nodes, edges: canvas.edges, createdAt: canvas.createdAt });
}

export function attachmentSnapshot(data: Buffer, info: AttachmentInfo): AttachmentSyncSnapshot {
  return { filename: info.filename, mime: info.mime, data: data.toString("base64") };
}

function recordValue(value: SyncJson, label: string): Record<string, SyncJson> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} sync snapshot must be an object.`);
  return value;
}

function requiredString(value: SyncJson | undefined, label: string): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  return value;
}

export function parseNoteSnapshot(value: SyncJson): NoteSyncSnapshot {
  const raw = recordValue(value, "Note");
  const aliases = raw.aliases;
  const tags = raw.tags;
  const properties = raw.properties;
  if (!Array.isArray(aliases) || aliases.some((item) => typeof item !== "string")) throw new Error("Note sync aliases must be strings.");
  if (!Array.isArray(tags) || tags.some((item) => typeof item !== "string")) throw new Error("Note sync tags must be strings.");
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) throw new Error("Note sync properties must be an object.");
  const createdAt = requiredString(raw.createdAt, "Note sync createdAt");
  if (!Number.isFinite(Date.parse(createdAt))) throw new Error("Note sync createdAt must be an ISO timestamp.");
  const snapshot: NoteSyncSnapshot = {
    path: requiredString(raw.path, "Note sync path"),
    title: requiredString(raw.title, "Note sync title"),
    body: requiredString(raw.body, "Note sync body"),
    aliases: aliases as string[],
    tags: tags as string[],
    properties: properties as NoteDocument["properties"],
    createdAt,
  };
  if (raw.frontmatterSource !== undefined) snapshot.frontmatterSource = requiredString(raw.frontmatterSource, "Note sync frontmatterSource");
  return structuredClone(snapshot);
}

export function parseCanvasSnapshot(value: SyncJson): CanvasSyncSnapshot {
  const raw = recordValue(value, "Canvas");
  if (!Array.isArray(raw.nodes) || !Array.isArray(raw.edges)) throw new Error("Canvas sync snapshot needs node and edge arrays.");
  const createdAt = requiredString(raw.createdAt, "Canvas sync createdAt");
  if (!Number.isFinite(Date.parse(createdAt))) throw new Error("Canvas sync createdAt must be an ISO timestamp.");
  return structuredClone({
    path: requiredString(raw.path, "Canvas sync path"),
    title: requiredString(raw.title, "Canvas sync title"),
    nodes: raw.nodes as unknown as CanvasDocument["nodes"],
    edges: raw.edges as unknown as CanvasDocument["edges"],
    createdAt,
  });
}

export function parseAttachmentSnapshot(value: SyncJson): AttachmentSyncSnapshot {
  const raw = recordValue(value, "Attachment");
  const data = requiredString(raw.data, "Attachment sync data");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(data)) throw new Error("Attachment sync data must be canonical base64.");
  if (Buffer.from(data, "base64").toString("base64") !== data) throw new Error("Attachment sync data must be canonical base64.");
  return { filename: requiredString(raw.filename, "Attachment sync filename"), mime: requiredString(raw.mime, "Attachment sync MIME type"), data };
}
