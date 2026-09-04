import fs from "node:fs";
import path from "node:path";

import {
  INDEX_AAD,
  PLUGIN_POLICY_AAD,
  attachmentChunkAad,
  attachmentManifestAad,
  canvasAad,
  canvasHistoryAad,
  historyAad,
  noteAad,
  pluginAad,
  pluginStoreAad,
} from "./documents.js";
import { resolveInside } from "./safety.js";
import { APPLIED_AAD } from "./sync/protocol.js";
import { APPLY_RECEIPT_AAD, LOCAL_TRANSACTION_AAD } from "./sync/transaction.js";

export const STAGING_DIRNAME = ".rekey";

export type RekeyItemKind = "document" | "kv" | "sync-change";

export interface RekeyItem {
  /** Path relative to the vault directory, POSIX separators. */
  path: string;
  kind: RekeyItemKind;
  /**
   * What the envelope authenticates, and therefore what must survive the
   * re-key byte for byte. For `document` it is the GCM AAD; for `kv` the
   * logical file identity `encryptWithKey` binds; for `sync-change` the
   * change ID, from which both the body subkey and the AAD derive.
   */
  identity: string;
}

/** Plaintext bookkeeping under `documents/`. Neither is encrypted. */
const DOCUMENT_PLAINTEXT = new Set(["manifest.json", "journal.json"]);

/** Plaintext or separately-managed files at the vault root. */
const ROOT_PLAINTEXT = new Set([
  "keyring.json",
  "audit.log",
  "audit.meta.json",
  "schema.json",
  ".sbrain.lock",
]);

const OBJECT_FILE = /^([a-f0-9-]{36})\.(note|canvas|plugin|pluginstore)\.enc$/u;
// `(0|[1-9]\d*)` rather than `\d+` so acceptance matches round-trip: a
// leading-zero filename like `007.note.enc` would classify but could never be
// produced again by the writer that names files with `String(revision)`.
const HISTORY_FILE = /^(0|[1-9]\d*)\.(note|canvas)\.enc$/u;
const CHUNK_FILE = /^(0|[1-9]\d*)\.chunk\.enc$/u;
const CHANGE_FILE = /^([a-f0-9]{64})\.change\.enc$/u;
const DOCUMENT_ID = /^[a-f0-9-]{36}$/u;
const CONTENT_ID = /^[a-f0-9]{64}$/u;

/**
 * `writeFileAtomic` (src/fs-safe.ts) and `SyncChangeLog.storeEnvelope`
 * (src/sync/change-log.ts) both stage writes as a dot-prefixed sibling named
 * `.<final-name>.<pid>.<uuid>.tmp` and remove it once the write lands. A hard
 * crash between the write and the cleanup can leave one behind. Every reader
 * in this codebase already ignores these — they filter directory listings by
 * the suffix they care about, so a `.tmp` sibling is never opened as data —
 * and the walk should agree: it is a known crash leftover no reader consults,
 * not an artifact anything needs re-encrypted. This is different from an
 * unrecognized `.enc` file, which fails closed below, because an unrecognized
 * `.enc` may be live data the vault still depends on and must not be left
 * behind under a key the re-key is about to discard.
 */
const WRITER_TEMP_FILE = /^\..+\.tmp$/u;

const SYNC_STATE_AAD: Record<string, string> = {
  "applied.enc": APPLIED_AAD,
  "pending-local.enc": LOCAL_TRANSACTION_AAD,
  "apply-receipt.enc": APPLY_RECEIPT_AAD,
};

/**
 * Every AAD is a pure function of the file's own path, which is what makes a
 * re-key possible at all: the identity an envelope authenticates can be
 * recovered without opening it. Anything this cannot classify throws, so a
 * file the walk does not know about aborts the run instead of surviving under
 * a key nothing keeps.
 */
function classifyDocument(relative: string): RekeyItem | null {
  const segments = relative.split("/");
  const item = (kind: RekeyItemKind, identity: string): RekeyItem => ({
    path: `documents/${relative}`,
    kind,
    identity,
  });

  if (WRITER_TEMP_FILE.test(segments[segments.length - 1])) return null;

  if (segments.length === 1) {
    if (DOCUMENT_PLAINTEXT.has(segments[0])) return null;
    if (segments[0] === "index.enc") return item("document", INDEX_AAD);
    if (segments[0] === "plugin-policy.enc") return item("document", PLUGIN_POLICY_AAD);
  }

  if (segments.length === 2 && segments[0] === "objects") {
    const match = OBJECT_FILE.exec(segments[1]);
    if (match) {
      const [, id, type] = match;
      if (type === "note") return item("document", noteAad(id));
      if (type === "canvas") return item("document", canvasAad(id));
      if (type === "plugin") return item("document", pluginAad(id));
      return item("document", pluginStoreAad(id));
    }
  }

  if (segments.length === 3 && segments[0] === "history" && DOCUMENT_ID.test(segments[1])) {
    const match = HISTORY_FILE.exec(segments[2]);
    if (match) {
      const revision = Number(match[1]);
      return item(
        "document",
        match[2] === "note" ? historyAad(segments[1], revision) : canvasHistoryAad(segments[1], revision),
      );
    }
  }

  if (segments.length === 3 && segments[0] === "attachments" && CONTENT_ID.test(segments[1])) {
    if (segments[2] === "manifest.enc") return item("document", attachmentManifestAad(segments[1]));
    const match = CHUNK_FILE.exec(segments[2]);
    if (match) return item("document", attachmentChunkAad(segments[1], Number(match[1])));
  }

  if (segments.length === 2 && segments[0] === "sync") {
    const aad = SYNC_STATE_AAD[segments[1]];
    if (aad) return item("document", aad);
  }

  if (segments.length === 3 && segments[0] === "sync" && segments[1] === "changes") {
    const match = CHANGE_FILE.exec(segments[2]);
    if (match) return item("sync-change", match[1]);
  }

  throw new Error(`Refusing to re-key: cannot classify documents/${relative}.`);
}

function walkDocuments(current: string, prefix: string, items: RekeyItem[]): void {
  for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    const full = path.join(current, entry.name);
    if (entry.isDirectory()) {
      walkDocuments(full, relative, items);
      continue;
    }
    if (!entry.isFile()) continue;
    const item = classifyDocument(relative);
    if (item) items.push(item);
  }
}

/**
 * Every artifact a re-key must rewrite, in a deterministic order. The vault
 * root is scanned shallowly — only the vault's own encrypted files live there
 * — and `documents/` is walked in full.
 */
export function planRekey(vaultDir: string): RekeyItem[] {
  const items: RekeyItem[] = [];

  for (const entry of fs.readdirSync(vaultDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.isDirectory()) continue;
    if (!entry.isFile()) continue;
    if (ROOT_PLAINTEXT.has(entry.name)) continue;
    if (WRITER_TEMP_FILE.test(entry.name)) continue;
    if (entry.name.endsWith(".kv.enc")) {
      const base = entry.name.slice(0, -".kv.enc".length);
      // `base` is the filename `saveVaultFile` (src/store.ts) chose, and it
      // already ran the user's input through `normalizeVaultName` before
      // using the result as the filename — so the base IS the normalized
      // identity. Re-normalizing here would strip a trailing ".kv" a second
      // time: a file whose real identity is "backup.kv" (stored as
      // "backup.kv.kv.enc") would be reported as "backup", and re-encrypting
      // under that wrong identity produces a file `loadVaultFile` can never
      // authenticate again.
      items.push({ path: entry.name, kind: "kv", identity: base });
      continue;
    }
    if (entry.name === "grants.enc") {
      items.push({ path: entry.name, kind: "kv", identity: "grants" });
      continue;
    }
    if (entry.name.endsWith(".enc")) {
      throw new Error(`Refusing to re-key: cannot classify ${entry.name}.`);
    }
  }

  const documentsDir = resolveInside(vaultDir, "documents");
  if (fs.existsSync(documentsDir)) walkDocuments(documentsDir, "", items);

  return items;
}
