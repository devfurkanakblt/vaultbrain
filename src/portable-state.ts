import fs from "node:fs";
import { decryptDocument, encryptDocument, type DocumentKeySession, type DocumentPayload } from "./document-crypto.js";
import { assertNoSymlinkComponents, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { AAD } from "./format-version.js";
import { assertSyncJson, type SyncJson } from "./sync/protocol.js";

export type PortableStateId = "workspace" | "saved-views";
export function isPortableStateId(id: string): id is PortableStateId {
  return id === "workspace" || id === "saved-views";
}
const fields = {
  bookmarks: ["id", "label", "createdAt"],
  layouts: ["id", "name", "tabs", "active", "secondary", "view", "createdAt", "updatedAt"],
  views: ["id", "name", "filter", "tags", "sort", "direction", "columns", "createdAt", "updatedAt"],
} as const;

/** Only the native portable schema crosses devices; unknown fields fail closed. */
export function parsePortableState(id: PortableStateId, value: unknown): SyncJson {
  assertSyncJson(value);
  if (!value || Array.isArray(value) || typeof value !== "object" || value.version !== 1) throw new Error("Unsupported portable state version.");
  const groups = id === "workspace" ? ["bookmarks", "layouts"] as const : ["views"] as const;
  if (Object.keys(value).some(key => key !== "version" && !groups.some(group => group === key))) throw new Error("Unknown portable state field.");
  for (const group of groups) {
    const entries = value[group];
    const limit = group === "bookmarks" ? 500 : group === "layouts" ? 100 : 200;
    if (!Array.isArray(entries) || entries.length > limit) throw new Error("Invalid portable state collection.");
    const ids = new Set<string>();
    for (const entry of entries) {
      if (!entry || Array.isArray(entry) || typeof entry !== "object") throw new Error("Invalid portable state entry.");
      if (Object.keys(entry).some(key => !(fields[group] as readonly string[]).includes(key))) throw new Error("Unknown portable entry field.");
      if (typeof entry.id !== "string" || !entry.id.trim() || entry.id.length > 64 || ids.has(entry.id)) throw new Error("Invalid portable entry identity.");
      if (group !== "bookmarks" && (typeof entry.name !== "string" || !entry.name.trim() || entry.name.length > 120)) throw new Error("Invalid portable entry name.");
      ids.add(entry.id);
      for (const [key, field] of Object.entries(entry)) {
        if (["tabs", "tags", "columns"].includes(key)) {
          if (!Array.isArray(field) || field.length > 1000 || field.some(item => typeof item !== "string" || item.length > 4096)) throw new Error("Invalid portable string collection.");
        } else if (field === null ? !["active", "secondary"].includes(key) : typeof field !== "string" || field.length > 16384) throw new Error("Invalid portable string field.");
      }
      if (group === "layouts") {
        if (Array.isArray(entry.tabs) && (entry.tabs.length > 64 || entry.tabs.some(tab => typeof tab !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u.test(tab)))) throw new Error("Invalid portable tab identity.");
      }
    }
  }
  return structuredClone(value);
}

export function readPortableState(session: DocumentKeySession, id: PortableStateId): SyncJson {
  const file = resolveInside(session.rootDir, id === "workspace" ? "workspace.enc" : "views.enc");
  assertNoSymlinkComponents(session.rootDir, file);
  if (!fs.existsSync(file)) return id === "workspace" ? { version: 1, bookmarks: [], layouts: [] } : { version: 1, views: [] };
  const payload = JSON.parse(readTextFileLimited(file, 16 * 1024 * 1024, "Portable state")) as DocumentPayload;
  return parsePortableState(id, JSON.parse(decryptDocument(payload, session.key, id === "workspace" ? AAD.workspace : AAD.savedViews)));
}

export function writePortableState(session: DocumentKeySession, id: PortableStateId, value: unknown): void {
  const validated = parsePortableState(id, value);
  const file = resolveInside(session.rootDir, id === "workspace" ? "workspace.enc" : "views.enc");
  assertNoSymlinkComponents(session.rootDir, file);
  const payload = encryptDocument(JSON.stringify(validated), session.key, id === "workspace" ? AAD.workspace : AAD.savedViews);
  writeFileAtomic(file, JSON.stringify(payload));
}
