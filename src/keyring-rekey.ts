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
import { decryptWithKey, encryptWithKey, type KeyedEncryptedPayload } from "./crypto.js";
import {
  decryptDocument,
  decryptDocumentBytes,
  encryptDocument,
  encryptDocumentBytes,
  type DocumentPayload,
} from "./document-crypto.js";
import { writeFileAtomic } from "./fs-safe.js";
import { readKeyring, writeKeyring, type KeyringFile, type KeySet } from "./keyring.js";
import { resolveInside } from "./safety.js";
import {
  APPLIED_AAD,
  CHANGE_AAD_PREFIX,
  changeEncryptionKey,
  validateEncryptedSyncChange,
} from "./sync/protocol.js";
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

/**
 * The bytes an artifact protects, whatever envelope it wears. The `kv`
 * envelope is UTF-8 text and the other two are byte payloads, so everything
 * is normalized to a Buffer: the staging phase compares plaintexts to prove a
 * re-encryption preserved content, and that comparison must not care which
 * envelope produced it.
 */
export function decryptItem(item: RekeyItem, keys: KeySet, raw: Buffer): Buffer {
  const parsed = JSON.parse(raw.toString("utf8")) as unknown;

  if (item.kind === "document") {
    return decryptDocumentBytes(parsed as DocumentPayload, keys.documents, item.identity);
  }

  if (item.kind === "kv") {
    return Buffer.from(decryptWithKey(parsed as KeyedEncryptedPayload, keys.kv, item.identity), "utf8");
  }

  const envelope = validateEncryptedSyncChange(parsed);
  if (envelope.id !== item.identity) throw new Error(`Sync change filename does not match its envelope: ${item.identity}`);
  const envelopeKey = changeEncryptionKey(keys.syncEnvelope, envelope.id);
  try {
    return Buffer.from(
      decryptDocument(envelope.payload, envelopeKey, `${CHANGE_AAD_PREFIX}${envelope.id}`),
      "utf8",
    );
  } finally {
    envelopeKey.fill(0);
  }
}

/**
 * The inverse, serialized exactly the way the module that owns each artifact
 * writes it: two-space JSON for the key-value envelopes `saveVaultFile` and
 * `saveGrants` produce, compact JSON for everything else. A re-key must not
 * be visible as a formatting change.
 */
export function encryptItem(item: RekeyItem, keys: KeySet, plaintext: Buffer): Buffer {
  if (item.kind === "document") {
    const payload = encryptDocumentBytes(plaintext, keys.documents, item.identity);
    return Buffer.from(JSON.stringify(payload), "utf8");
  }

  if (item.kind === "kv") {
    const payload = encryptWithKey(plaintext.toString("utf8"), keys.kv, item.identity);
    return Buffer.from(JSON.stringify(payload, null, 2), "utf8");
  }

  const envelopeKey = changeEncryptionKey(keys.syncEnvelope, item.identity);
  try {
    const payload = encryptDocument(
      plaintext.toString("utf8"),
      envelopeKey,
      `${CHANGE_AAD_PREFIX}${item.identity}`,
    );
    return Buffer.from(JSON.stringify({ version: 1, id: item.identity, payload }), "utf8");
  } finally {
    envelopeKey.fill(0);
  }
}

/**
 * `<vault>/.rekey`, holding the shadow tree (and, from Task 4 on, the journal
 * that commits it). A directory here is invisible to `planRekey`: its
 * vault-root scan only classifies files, so `.rekey` is skipped exactly like
 * any other subdirectory, and the staged tree is never itself walked as
 * `documents/` only resolves under the vault root, not under `.rekey`.
 */
export function stagingRoot(vaultDir: string): string {
  return resolveInside(vaultDir, STAGING_DIRNAME);
}

/** `<vault>/.rekey/new`, mirroring the vault's own layout. */
export function stagedTree(vaultDir: string): string {
  return resolveInside(stagingRoot(vaultDir), "new");
}

/**
 * Re-encrypts every item into the shadow tree and proves each staged file
 * opens under the new keyset to the same plaintext the live file holds under
 * the old one. Nothing live is touched, so any failure here — a wrong
 * passphrase, a damaged object, a full disk — leaves the vault byte-identical.
 *
 * Any prior staging attempt is discarded before this one starts, and that
 * removal is the entire basis for the anti-resume property: nothing on disk
 * distinguishes a complete, verified `.rekey/new` from one a process left
 * behind when it was killed mid-loop, so a leftover tree is never resumed or
 * trusted — it is destroyed and rebuilt from scratch. Do not add a code path
 * that reuses an existing staging tree.
 *
 * The one thing that removal must not destroy is a live journal. A journal
 * under the staging root means a commit passed — or is passing — the point of
 * no return, and the staged remainder beside it is the only copy of files the
 * vault now depends on. Staging refuses outright in that case: recovery runs
 * first, and only once it has cleared the journal can a fresh re-key start.
 */
export function stageRekey(vaultDir: string, oldKeys: KeySet, newKeys: KeySet, items: RekeyItem[]): void {
  const tree = stagedTree(vaultDir);
  if (fs.existsSync(journalPath(vaultDir))) {
    throw new Error(
      "An interrupted re-key is still journaled; run recovery before staging a new one.",
    );
  }
  fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
  fs.mkdirSync(tree, { recursive: true, mode: 0o700 });

  for (const item of items) {
    const live = resolveInside(vaultDir, item.path);
    const staged = resolveInside(tree, item.path);
    let plaintext: Buffer | undefined;
    let verified: Buffer | undefined;
    try {
      plaintext = decryptItem(item, oldKeys, fs.readFileSync(live));
      const rewritten = encryptItem(item, newKeys, plaintext);
      fs.mkdirSync(path.dirname(staged), { recursive: true, mode: 0o700 });
      writeFileAtomic(staged, rewritten, { mode: 0o600 });

      // Read back from disk rather than trusting the buffer in hand: this is
      // what catches a truncated or partially flushed write before the
      // commit, and it is what proves the staged file — not just the
      // in-memory value that produced it — opens under the new keyset.
      verified = decryptItem(item, newKeys, fs.readFileSync(staged));
      if (!verified.equals(plaintext)) {
        throw new Error(`The re-keyed copy of ${item.path} does not carry its plaintext.`);
      }
    } catch (error) {
      // Fail closed: any failure anywhere in the loop discards the whole
      // shadow tree rather than leaving a partially staged (and therefore
      // partially unverified) directory behind. The cleanup is itself
      // guarded: a locked or read-only staging tree must not replace the
      // diagnostic the operator needs — a wrong passphrase, a damaged
      // object, a full disk — with an EBUSY from the removal. A surviving
      // tree is harmless because the next run clears it on entry.
      try {
        fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
      } catch {
        // Intentionally ignored: the original failure is the one to report.
      }
      throw error;
    } finally {
      plaintext?.fill(0);
      verified?.fill(0);
    }
  }
}

export interface RekeyJournal {
  version: 1;
  /** The ID of the slot the new keyring carries. */
  slotId: string;
  /** Vault-relative POSIX paths still to install. */
  files: string[];
}

export function journalPath(vaultDir: string): string {
  return resolveInside(stagingRoot(vaultDir), "journal.json");
}

function readJournal(vaultDir: string): RekeyJournal | null {
  const filePath = journalPath(vaultDir);
  if (!fs.existsSync(filePath)) return null;
  let parsed: RekeyJournal;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as RekeyJournal;
  } catch {
    // A truncated journal is an ordinary crash artifact. It must take the same
    // path as a structurally invalid one, so the operator sees the refusal
    // rather than a raw SyntaxError from the parser.
    throw new Error("The re-key journal is malformed; refusing to touch the vault.");
  }
  if (
    parsed?.version !== 1 ||
    typeof parsed.slotId !== "string" ||
    !/^[0-9a-f-]{36}$/u.test(parsed.slotId) ||
    !Array.isArray(parsed.files) ||
    parsed.files.some((entry) => typeof entry !== "string")
  ) {
    throw new Error("The re-key journal is malformed; refusing to touch the vault.");
  }
  return { version: 1, slotId: parsed.slotId, files: parsed.files };
}

/**
 * Moves the staged tree over the live vault. Every rename is atomic and a
 * file already installed is simply absent from the staging tree, so replaying
 * this from the top of the list is safe — which is what makes recovery after
 * a crash mid-install a plain re-run.
 */
export function installStaged(vaultDir: string, journal: RekeyJournal): void {
  const tree = stagedTree(vaultDir);
  for (const relative of journal.files) {
    const staged = resolveInside(tree, relative);
    if (!fs.existsSync(staged)) continue;
    const live = resolveInside(vaultDir, relative);
    fs.mkdirSync(path.dirname(live), { recursive: true, mode: 0o700 });
    fs.renameSync(staged, live);
  }
}

/**
 * The commit, in the only order that is recoverable in both directions:
 * journal, then the keyring, then the installs. Writing `keyring.json` is a
 * single-file replace and therefore the point of no return; the journal
 * written before it is what lets a later run tell which side of that point a
 * crash landed on.
 *
 * Every file the journal names must be present in the staged tree before that
 * point is crossed. `installStaged` skips a file it cannot find — which is
 * what makes a replay after a partial install a no-op — so an incomplete
 * staged tree would otherwise commit silently and leave the vault holding the
 * new keyring over an object still sealed under the old keyset: readable by
 * neither, and invisible to recovery.
 */
export function commitRekey(vaultDir: string, journal: RekeyJournal, keyring: KeyringFile): void {
  const tree = stagedTree(vaultDir);
  for (const relative of journal.files) {
    if (!fs.existsSync(resolveInside(tree, relative))) {
      throw new Error(`Refusing to commit the re-key: ${relative} is missing from the staged tree.`);
    }
  }

  fs.mkdirSync(stagingRoot(vaultDir), { recursive: true, mode: 0o700 });
  writeFileAtomic(journalPath(vaultDir), `${JSON.stringify(journal)}\n`, { mode: 0o600 });
  writeKeyring(vaultDir, keyring);
  installStaged(vaultDir, journal);
  fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
}

/**
 * Finishes or discards an interrupted re-key. The journal names the slot the
 * new keyring carries, so its presence in `keyring.json` is what says whether
 * the commit point was passed.
 */
export function recoverRekey(vaultDir: string): "none" | "rolled-back" | "finished" {
  const journal = readJournal(vaultDir);
  if (!journal) {
    // A staging tree with no journal is an abandoned stage: nothing live was
    // ever touched, so it is safe to drop.
    fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
    return "none";
  }

  const committed = readKeyring(vaultDir)?.slots.some((slot) => slot.id === journal.slotId) ?? false;
  if (!committed) {
    fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
    return "rolled-back";
  }

  installStaged(vaultDir, journal);
  fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
  return "finished";
}
