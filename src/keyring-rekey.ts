import fs from "node:fs";
import path from "node:path";

import {
  AAD,
  attachmentChunkAad,
  attachmentManifestAad,
  canvasAad,
  canvasHistoryAad,
  noteHistoryAad,
  noteAad,
  pluginAad,
  pluginStoreAad,
  syncAgreementKeyAad,
  syncDeviceKeyAad,
  syncEpochKeyAad,
} from "./format-version.js";
import { decryptWithKey, encryptWithKey, type KeyedEncryptedPayload } from "./crypto.js";
import {
  decryptDocumentBytes,
  encryptDocument,
  encryptDocumentBytes,
  type DocumentPayload,
} from "./document-crypto.js";
import { writeFileAtomic } from "./fs-safe.js";
import {
  DEFAULT_SCRYPT_N,
  KEYRING_VERSION,
  ROTATABLE_KEY_NAMES,
  detectVaultFormat,
  forgetVaultKeys,
  randomKeySet,
  readKeyring,
  unwrapKeyring,
  unwrapSlot,
  wrapKeySet,
  writeKeyring,
  zeroKeySet,
  zeroRetiringKeys,
  type KeyName,
  type KeyringFile,
  type KeyringSlot,
  type KeySet,
  type RetiringKeys,
} from "./keyring.js";
import { MIN_PASSPHRASE_LENGTH } from "./keyring-passphrase.js";
import { appendKeyringAuditWithKey, newKeyringAuditKey } from "./keyring-audit.js";
import {
  prepareRecoveryForRekey,
  rewriteRecoveryKitForRekey,
  type PreparedRecoveryRekey,
  type RekeyRecoveryInput,
} from "./keyring-recovery.js";
import { resolveInside } from "./safety.js";
import { canonicalSyncJson, openSyncChange, type SyncChangeKeys, type SyncJson } from "./sync.js";
import { CHANGE_AAD_PREFIX, changeEncryptionKey } from "./sync/protocol.js";
import { APPLY_RECEIPT_AAD, LOCAL_TRANSACTION_AAD } from "./sync/transaction.js";
import { withVaultLock } from "./vault-lock.js";

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
  "applied.enc": AAD.syncApplied,
  "pending-local.enc": LOCAL_TRANSACTION_AAD,
  "apply-receipt.enc": APPLY_RECEIPT_AAD,
  "devices.enc": AAD.syncDeviceRegistry,
  "checkpoint.enc": AAD.syncFreshnessCheckpoint,
};

// `sync/identity/*` filenames, mirroring the loose 36-character convention
// `DOCUMENT_ID` already uses for note/canvas/attachment ids: these are device
// ids, never re-validated as a strict UUID here because the walk only has to
// reproduce the AAD a device id feeds into, not police the id's shape.
const SYNC_DEVICE_KEY_FILE = /^([a-f0-9-]{36})\.key\.enc$/u;
const SYNC_AGREEMENT_KEY_FILE = /^([a-f0-9-]{36})\.x25519\.key\.enc$/u;
// `sync/identity/epochs/*`: the epoch number, same round-trip-safe shape as
// `HISTORY_FILE`'s revision.
const SYNC_EPOCH_KEY_FILE = /^(0|[1-9]\d*)\.key\.enc$/u;

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
    if (segments[0] === "index.enc") return item("document", AAD.documentIndex);
    if (segments[0] === "plugin-policy.enc") return item("document", AAD.pluginPolicy);
    if (segments[0] === "retention.enc") return item("document", AAD.retentionPolicy);
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
        match[2] === "note" ? noteHistoryAad(segments[1], revision) : canvasHistoryAad(segments[1], revision),
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

  // `sync/blobs/<64hex>`: sealed by `deriveBlobKey(syncChangeKey)`
  // (src/sync-blobs.ts), a key derived from the PINNED `syncChange` key. A
  // blob's id is the SHA-256 of its own sealed bytes, and that id is baked
  // into every manifest and change body that references it — re-encrypting
  // one under a fresh IV would rename it out from under everything pointing
  // at it. There is nothing to rotate here, so the walk enumerates it and
  // then leaves it alone rather than throwing on it as unclassifiable.
  if (segments.length === 3 && segments[0] === "sync" && segments[1] === "blobs" && CONTENT_ID.test(segments[2])) {
    return null;
  }

  if (segments.length === 3 && segments[0] === "sync" && segments[1] === "identity") {
    if (segments[2] === "authority.key.enc") return item("document", AAD.syncAuthorityKey);
    const agreementMatch = SYNC_AGREEMENT_KEY_FILE.exec(segments[2]);
    if (agreementMatch) return item("document", syncAgreementKeyAad(agreementMatch[1]));
    const deviceMatch = SYNC_DEVICE_KEY_FILE.exec(segments[2]);
    if (deviceMatch) return item("document", syncDeviceKeyAad(deviceMatch[1]));
  }

  if (segments.length === 4 && segments[0] === "sync" && segments[1] === "identity" && segments[2] === "epochs") {
    const match = SYNC_EPOCH_KEY_FILE.exec(segments[3]);
    if (match) return item("document", syncEpochKeyAad(Number(match[1])));
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
    // Fail closed like every other unclassifiable entry: a symlink to an
    // `.enc` file would otherwise be skipped silently and survive under the
    // keyset this run discards, unreadable and un-re-keyable afterwards.
    if (!entry.isFile()) {
      throw new Error(`Refusing to re-key: documents/${relative} is not a regular file.`);
    }
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
/** The two keys `openSyncChange` (src/sync.ts) needs to open a version 1 change. */
function syncChangeMaterial(keys: KeySet): SyncChangeKeys {
  return { syncChangeKey: keys.syncChange, syncEnvelopeKey: keys.syncEnvelope };
}

/**
 * `sync/devices.enc` and `sync/checkpoint.enc` (`encryptedRegistry` /
 * `encryptedCheckpoint` in src/sync.ts) each wrap their `DocumentPayload` one
 * level deeper than every other `document`-kind artifact on disk: the file is
 * `{version: 1, payload: {version, iv, authTag, ciphertext}}`, not the
 * `DocumentPayload` itself at the top level. Every other document-kind file
 * IS its `DocumentPayload` directly, so this is the one place the walk has to
 * know the on-disk shape as well as the AAD.
 */
const WRAPPED_DOCUMENT_AAD = new Set<string>([AAD.syncDeviceRegistry, AAD.syncFreshnessCheckpoint]);

export function decryptItem(item: RekeyItem, keys: KeySet, raw: Buffer): Buffer {
  const parsed = JSON.parse(raw.toString("utf8")) as unknown;

  if (item.kind === "document") {
    if (WRAPPED_DOCUMENT_AAD.has(item.identity)) {
      const outer = parsed as { version?: unknown; payload?: DocumentPayload };
      if (outer.version !== 1 || !outer.payload) {
        throw new Error(`${item.path} is not a supported encrypted sync control artifact.`);
      }
      return decryptDocumentBytes(outer.payload, keys.documents, item.identity);
    }
    return decryptDocumentBytes(parsed as DocumentPayload, keys.documents, item.identity);
  }

  if (item.kind === "kv") {
    return Buffer.from(decryptWithKey(parsed as KeyedEncryptedPayload, keys.kv, item.identity), "utf8");
  }

  // sync-change: delegated to `openSyncChange` (src/sync.ts), the format's
  // real, epoch-aware implementation — not the partially-extracted duplicate
  // in src/sync/protocol.ts, which hard-rejects any envelope but version 1
  // and, worse, would derive the body key with the epoch-1 formula against
  // whatever version it was handed if that rejection were ever loosened.
  // `resealSyncChange` (src/sync.ts) is what a re-key applies to the change
  // log, and it refuses epoch 2 and above by design: their bodies are sealed
  // under an epoch key a re-key never rotates — only the file holding that
  // key is rewritten (classified above as `sync/identity/epochs/<n>.key.enc`)
  // — so there is nothing for a re-key to re-seal here. This mirrors that
  // same refusal, in its own words, before spending a decrypt attempt on a
  // key formula that could not have matched a later epoch anyway.
  const envelope = parsed as { version?: unknown };
  if (envelope.version !== 1) {
    throw new Error("Only an epoch 1 sync change is re-sealed; later epochs keep their epoch key.");
  }
  const { id, ...body } = openSyncChange(envelope, syncChangeMaterial(keys));
  if (id !== item.identity) {
    throw new Error(`Sync change filename does not match its envelope: ${item.identity}`);
  }
  return Buffer.from(canonicalSyncJson(body as unknown as SyncJson), "utf8");
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
    if (WRAPPED_DOCUMENT_AAD.has(item.identity)) {
      return Buffer.from(JSON.stringify({ version: 1, payload }), "utf8");
    }
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
 * A cipher failure carries no context of its own — `Unsupported state or
 * unable to authenticate data` is all AES-GCM says — so an operator reading
 * a refused re-key cannot tell which of thousands of objects is damaged.
 * Every crypto call the staging loop makes runs through here so the refusal
 * names the file. Only the crypto: the reads and writes around it raise
 * system errors that already carry a path and a `code`, and those must reach
 * the caller exactly as they were thrown.
 */
function withItemPath<T>(item: RekeyItem, run: () => T): T {
  try {
    return run();
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Refusing to re-key: ${item.path} could not be processed: ${detail}`, { cause: error });
  }
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
      const liveBytes = fs.readFileSync(live);
      plaintext = withItemPath(item, () => decryptItem(item, oldKeys, liveBytes));
      const rewritten = encryptItem(item, newKeys, plaintext);
      fs.mkdirSync(path.dirname(staged), { recursive: true, mode: 0o700 });
      writeFileAtomic(staged, rewritten, { mode: 0o600 });

      // Read back from disk rather than trusting the buffer in hand: this is
      // what catches a staged file that does not decrypt to the plaintext it
      // was built from, and it is what proves the staged file — not just the
      // in-memory value that produced it — opens under the new keyset.
      const stagedBytes = fs.readFileSync(staged);
      verified = withItemPath(item, () => decryptItem(item, newKeys, stagedBytes));
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

/**
 * Thrown by `readJournal` (via `recoverRekey`) and by `stageRekey` when the
 * on-disk journal cannot be trusted. Exported so the CLI's `catch` can match
 * on this constant instead of re-typing the literal — the two would
 * otherwise drift silently if this wording ever changed.
 */
export const MALFORMED_JOURNAL_MESSAGE = "The re-key journal is malformed; refusing to touch the vault.";

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
    throw new Error(MALFORMED_JOURNAL_MESSAGE);
  }
  if (
    parsed?.version !== 1 ||
    typeof parsed.slotId !== "string" ||
    !/^[0-9a-f-]{36}$/u.test(parsed.slotId) ||
    !Array.isArray(parsed.files) ||
    parsed.files.some((entry) => typeof entry !== "string")
  ) {
    throw new Error(MALFORMED_JOURNAL_MESSAGE);
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
 * The staged set has to match the enumerated set exactly, in both directions.
 * `planRekey` runs once, before the re-encryption, and `commitRekey` checks
 * only that every journaled path was staged. Nothing else would notice a file
 * a racing writer added — or one the first walk missed — between the two: it
 * is not in the journal, so it is never installed, and after the commit it is
 * the one object left sealed under a keyset `keyring.json` no longer names.
 * That is not merely an unreadable file; every later `rekeyVault` aborts on it
 * during staging, so the vault can never be re-keyed again.
 *
 * Re-walking costs one directory scan next to the re-encryption that just ran,
 * and refusing here is free: nothing live has been touched yet, and the next
 * run stages from scratch.
 */
export function assertPlanUnchanged(vaultDir: string, items: RekeyItem[]): void {
  const planned = new Set(items.map((item) => item.path));
  const present = new Set(planRekey(vaultDir).map((item) => item.path));
  const appeared = [...present].filter((relative) => !planned.has(relative)).sort();
  const vanished = [...planned].filter((relative) => !present.has(relative)).sort();
  if (appeared.length === 0 && vanished.length === 0) return;

  const detail = [
    appeared.length > 0 ? `appeared after it was planned: ${appeared.join(", ")}` : "",
    vanished.length > 0 ? `disappeared after it was planned: ${vanished.join(", ")}` : "",
  ].filter(Boolean).join("; ");
  throw new Error(
    `Refusing to commit the re-key: the vault changed while it was being staged — ${detail}.`,
  );
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

/**
 * How long a re-key's lock stays fresh. `withVaultLock`'s 30-second default
 * suits the short writes every other caller performs; a re-key re-encrypts
 * every object in the vault and derives scrypt at the current cost on top of
 * that, so on a large vault it passes 30 seconds routinely. Under the default
 * another process would reclaim the lock as stale mid-run and could write a
 * note under the keyset this commit is about to orphan. The window is recorded
 * in the lock file, so every other process honours it too.
 *
 * Fifteen minutes covers a re-key of a very large vault with room to spare
 * while keeping the cost of a crash small: the window is also how long a
 * killed re-key wedges the vault, and there is no command to break the lock
 * deliberately — recovery is deleting `.sbrain.lock` by hand, as
 * `VaultBusyError` says.
 */
const REKEY_STALE_MS = 15 * 60 * 1_000;

/**
 * The three keys that protect content, and therefore rotate. The list itself
 * lives in `keyring.ts` beside the keyset format it describes: the split is
 * load-bearing for readers too, which fall back to the retiring copy of
 * exactly these keys while a re-key is in flight.
 */
export const ROTATED_KEYS: KeyName[] = [...ROTATABLE_KEY_NAMES];

/**
 * The three keys carried across unchanged, with the reason each one is not a
 * rotation but a migration. `vbrain rekey` prints these, because a user whose
 * passphrase leaked deserves to know exactly what a re-key did not do.
 */
export const PINNED_KEYS: { name: KeyName; reason: string }[] = [
  {
    name: "attachmentId",
    reason: "attachment content addresses name directories, AADs, canvas nodes and sync objects",
  },
  { name: "syncChange", reason: "change IDs are referenced as parents by every descendant change" },
  { name: "audit", reason: "the audit chain carries no key epoch, so rotating it invalidates it" },
];

export interface DroppedSlot {
  id: string;
  label: string;
  createdAt: string;
}

/**
 * What happened to the offline recovery kit, when the caller supplied one.
 * `kitPath` and `slotId` are the same kit and slot `prepareRecoveryForRekey`
 * validated up front — the id never changes across a re-key — so the caller
 * can tell the operator the kit they already have on hand is the one that was
 * advanced, not a new one they need to go generate.
 */
export interface RekeyRecoveryReport {
  slotId: string;
  kitPath: string;
}

export interface RekeyReport {
  rotated: KeyName[];
  pinned: { name: KeyName; reason: string }[];
  reencrypted: { documents: number; kv: number; syncChanges: number; total: number };
  droppedSlots: DroppedSlot[];
  passphraseChanged: boolean;
  resumed: boolean;
  /**
   * False only when the re-key itself succeeded — every object installed
   * under the new keyset, past the commit point `commitRekey` crosses — but
   * the best-effort cleanup write that drops the outgoing keys from
   * `keyring.json` afterward failed (a full disk, most plausibly). The vault
   * is fully readable and writable under the new passphrase either way; an
   * unsettled keyring just still carries the retiring keys, harmlessly, until
   * the next re-key or passphrase change clears them.
   */
  settled: boolean;
  /**
   * Null when this vault carries no recovery slot (or the caller passed no
   * recovery input for one that does not exist — `prepareRecoveryForRekey`
   * already refused that combination before anything ran). Present whenever
   * the recovery slot survived the re-key: the offline kit was rewritten
   * under the new keyset and the matching slot was installed alongside the
   * new primary slot, so the recovery code still opens this vault.
   */
  recovery: RekeyRecoveryReport | null;
}

function emptyReport(overrides: Partial<RekeyReport>): RekeyReport {
  return {
    rotated: [...ROTATED_KEYS],
    pinned: PINNED_KEYS.map((entry) => ({ ...entry })),
    reencrypted: { documents: 0, kv: 0, syncChanges: 0, total: 0 },
    droppedSlots: [],
    passphraseChanged: false,
    resumed: false,
    settled: true,
    recovery: null,
    ...overrides,
  };
}

/**
 * A new keyset and every object re-encrypted under it. Unlike
 * `changeVaultPassphrase`, which re-wraps the same keyset and touches no
 * content, this is the answer to a leaked passphrase: afterwards no byte on
 * disk opens under the old passphrase or the old keys.
 *
 * `attachmentId`, `syncChange` and `audit` are pinned. They derive identities
 * and signatures rather than protecting content, and rotating any of them is
 * an identity migration that cascades into canvas objects, index references,
 * the causal DAG and every peer device.
 */
export function rekeyVault(
  vaultDir: string,
  currentPassphrase: string,
  newPassphrase: string,
  options: {
    keepPassphrase?: boolean;
    allowSamePassphrase?: boolean;
    /** The offline kit and code for the recovery slot this vault carries, if any. */
    recovery?: RekeyRecoveryInput;
  } = {},
): RekeyReport {
  if (!currentPassphrase) throw new Error("A non-empty vault passphrase is required.");
  const keepPassphrase = Boolean(options.keepPassphrase);
  if (!keepPassphrase && newPassphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`The new passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
  // Reporting `passphraseChanged: true` while the passphrase the user is
  // re-keying away from still opens the vault would contradict the one
  // property this command exists for.
  if (!keepPassphrase && newPassphrase === currentPassphrase && !options.allowSamePassphrase) {
    throw new Error(
      "The new passphrase is the same as the current one, so a leaked passphrase would still open the vault. Pass --keep-passphrase to rotate the keyset without changing it.",
    );
  }
  const wrapPassphrase = keepPassphrase ? currentPassphrase : newPassphrase;

  return withVaultLock(
    vaultDir,
    () => {
      // An interrupted earlier run is finished or discarded before anything
      // else looks at the vault, so the rest of this function only ever sees a
      // consistent one. Recovery appends nothing to the audit chain: it runs
      // without a passphrase by design, so no audit key is available to sign
      // an entry. The interrupted run's journal remains its recovery record.
      if (recoverRekey(vaultDir) === "finished") {
        // The install just replaced live objects under a keyset this process
        // may still be caching from before the interruption.
        forgetVaultKeys(vaultDir);
        return emptyReport({ resumed: true, passphraseChanged: false });
      }

      if (detectVaultFormat(vaultDir) !== "keyring") {
        throw new Error("This vault is not in the keyring format yet. Run 'vbrain migrate' first.");
      }
      const file = readKeyring(vaultDir);
      if (!file) throw new Error("This vault has no keyring to re-key.");
      // This is retained solely to distinguish a proven-original keyring from
      // the uncertain interval after commitRekey starts. Its byte identity is
      // stronger evidence than a journal path, which commitRekey removes on a
      // completed install before later read-back and audit work can fail.
      const originalKeyringBytes = fs.readFileSync(path.join(vaultDir, "keyring.json"));

      let oldKeys: KeySet | undefined;
      let newKeys: KeySet | undefined;
      const droppedSlots: DroppedSlot[] = [];
      // Set once the offline kit's rewrite has actually landed on disk. From
      // that point until `commitRekey` finishes, the kit and this vault's
      // (still unrekeyed) keyring disagree — see the catch block below.
      let recoveryKitRewritten = false;
      // Audit terminal outcomes are only knowable before commit is attempted.
      // `commitRekey` may have replaced keyring.json even if its journal is no
      // longer present when a later read-back or audit append fails.
      let commitAttempted = false;
      let auditOperation: string | undefined;
      let auditPendingWritten = false;

      try {
        for (const slot of file.slots) {
          let opened: KeySet;
          try {
            opened = unwrapSlot(slot, currentPassphrase);
          } catch {
            // Wrapped around the keyset this run supersedes, so it is dropped
            // rather than preserved — the deliberate opposite of a passphrase
            // change, which keeps a recovery slot alive.
            droppedSlots.push({ id: slot.id, label: slot.label, createdAt: slot.createdAt });
            continue;
          }
          if (oldKeys) zeroKeySet(opened);
          else oldKeys = opened;
        }
        if (!oldKeys) {
          throw new Error("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.");
        }

        // Validated before anything below writes a single byte: a vault that
        // carries a recovery slot but was given no matching kit and code
        // refuses right here, with nothing on disk touched yet — the same
        // guarantee every other refusal in this function gives.
        const preparedRecovery: PreparedRecoveryRekey | null = prepareRecoveryForRekey(
          file,
          oldKeys,
          options.recovery,
        );
        // The recovery slot is wrapped under the recovery code, not
        // `currentPassphrase`, so the loop above could not open it and
        // recorded it above as dropped, same as any stranger slot. It is
        // about to be reinstalled (rewritten, but not discarded), so that
        // false "dropped" entry is removed here rather than reported to the
        // caller as something this re-key destroyed.
        if (preparedRecovery) {
          const droppedIndex = droppedSlots.findIndex((entry) => entry.id === preparedRecovery.slot.id);
          if (droppedIndex !== -1) droppedSlots.splice(droppedIndex, 1);
        }

        // Credentials and any recovery kit are now validated, but no vault
        // mutation has started. The audit key is pinned across a re-key, so
        // this pending entry and its eventual allowed entry verify in one
        // chain under either keyset. audit.log is ROOT_PLAINTEXT and therefore
        // intentionally outside assertPlanUnchanged's re-key plan.
        auditOperation = newKeyringAuditKey("rekey");
        appendKeyringAuditWithKey(vaultDir, oldKeys.audit, auditOperation, "pending");
        auditPendingWritten = true;

        newKeys = randomKeySet();
        for (const { name } of PINNED_KEYS) {
          newKeys[name].fill(0);
          newKeys[name] = Buffer.from(oldKeys[name]);
        }

        const items = planRekey(vaultDir);
        stageRekey(vaultDir, oldKeys, newKeys, items);
        assertPlanUnchanged(vaultDir, items);

        // The keyring published at the commit point carries the outgoing
        // rotatable keys. `keyring.json` is replaced before the staged files
        // are renamed into place, so for the length of that install a reader
        // meets objects still sealed under the old keys; every read path tries
        // the key in force and falls back to the retiring one, which is what
        // keeps the vault readable through the window instead of opaque.
        const retiring: RetiringKeys = {
          documents: Buffer.from(oldKeys.documents),
          kv: Buffer.from(oldKeys.kv),
          syncEnvelope: Buffer.from(oldKeys.syncEnvelope),
        };
        // This and the settle-time wrap below each pay `DEFAULT_SCRYPT_N`
        // (2**17) once. They cannot share a single derivation: `wrapKeySet`
        // generates a fresh random salt per call, and reusing one across the
        // committed slot and the settled slot would mean two ciphertexts
        // published to disk under one salt — the very thing a fresh salt per
        // wrap exists to avoid. `wrapKeySetSlot` (src/keyring.ts) has no entry
        // point that takes an already-derived key and a caller-chosen salt, so
        // avoiding the second scrypt run would mean widening that surface
        // rather than fixing this call site; left as is.
        let slot: KeyringSlot;
        try {
          slot = wrapKeySet(newKeys, wrapPassphrase, DEFAULT_SCRYPT_N, retiring, oldKeys.documents);
        } finally {
          zeroRetiringKeys(retiring);
        }

        // The offline kit is rewritten before the vault commits, because
        // `commitRekey` needs the exact slot this returns to build the
        // keyring it publishes — there is no way to install "the slot that
        // matches the kit" without first knowing what that slot is. This is
        // also the ordering hazard: the kit write below is atomic on its own,
        // but the vault's own commit is a separate step that follows it, so a
        // crash in between leaves a kit already advanced to the new keyset
        // while the vault (nothing committed yet) still opens only under the
        // OLD passphrase and OLD keys. The catch block below detects exactly
        // that window and tells the operator how to recover: the current
        // passphrase still works, so a fresh kit can always be created after
        // the fact — it is the one thing that must be said out loud, because
        // a kit that disagrees with its vault opens nothing.
        let recoverySlot: KeyringSlot | undefined;
        if (preparedRecovery) {
          recoverySlot = rewriteRecoveryKitForRekey(preparedRecovery, options.recovery!.code, newKeys);
          recoveryKitRewritten = true;
        }

        const committedSlots = recoverySlot ? [slot, recoverySlot] : [slot];
        // From this point on, even a missing journal is not proof that this is
        // safe to clean up or deny: commitRekey may already have crossed its
        // keyring replacement point and then removed the journal on success.
        commitAttempted = true;
        commitRekey(
          vaultDir,
          { version: 1, slotId: slot.id, files: items.map((item) => item.path) },
          { version: KEYRING_VERSION, slots: committedSlots },
        );

        // Every staged file is installed, so nothing on disk is sealed under
        // the outgoing keys any more: settle the keyring so no reader carries
        // them further. `legacyChangeIdentity` stays — it is what recomputes
        // the ids of sync changes an older build derived from the documents
        // key, and it outlives the re-key by design. A crash between the two
        // writes leaves the retiring copy in place, which is readable and is
        // cleared by the next run.
        //
        // This write is past `commitRekey`'s point of no return: the re-key
        // itself already succeeded, so a failure here (a full disk, most
        // plausibly) must not be reported as one. It is best-effort cleanup,
        // not part of what makes the re-key atomic — that is `commitRekey`'s
        // job alone — so it gets its own try/catch instead of falling into
        // the outer one below, which exists to decide whether the *staging*
        // half of a refused run may still be cleared.
        // The recovery slot never carries retiring keys — `rewriteRecoveryKitForRekey`
        // wraps the new keyset directly, with nothing left to settle — so it is
        // carried across unchanged rather than re-wrapped a second time.
        let settled = true;
        try {
          const settledSlot = wrapKeySet(newKeys, wrapPassphrase, DEFAULT_SCRYPT_N, null, oldKeys.documents);
          writeKeyring(vaultDir, {
            version: KEYRING_VERSION,
            slots: recoverySlot ? [settledSlot, recoverySlot] : [settledSlot],
          });
        } catch {
          settled = false;
        }
        // The keyset just committed is what every reader must use from here
        // on, whether or not settling landed: a process cache still holding
        // the outgoing keys would otherwise keep serving them after this
        // function returns success.
        forgetVaultKeys(vaultDir);

        // Prove the vault on disk opens under the passphrase the user was just
        // given before reporting success. `unwrapKeyring` rather than
        // `openVaultKeys`, because the latter would leave the brand-new keyset
        // resident and un-zeroized in the process key cache — the very cache
        // the `forgetVaultKeys` above just cleared. This still passes when
        // settling failed: `commitRekey`'s slot and the settled slot are both
        // wrapped under `wrapPassphrase`, so whichever one is on disk opens.
        const written = readKeyring(vaultDir);
        if (!written) throw new Error("The re-keyed vault could not be reopened.");
        zeroKeySet(unwrapKeyring(written, wrapPassphrase));

        // This is deliberately after the read-back verification. If the
        // append itself fails, propagate that error rather than returning a
        // success report without the terminal audit outcome.
        appendKeyringAuditWithKey(vaultDir, oldKeys.audit, auditOperation, "allowed");

        return {
          rotated: [...ROTATED_KEYS],
          pinned: PINNED_KEYS.map((entry) => ({ ...entry })),
          reencrypted: {
            documents: items.filter((item) => item.kind === "document").length,
            kv: items.filter((item) => item.kind === "kv").length,
            syncChanges: items.filter((item) => item.kind === "sync-change").length,
            total: items.length,
          },
          droppedSlots,
          passphraseChanged: !keepPassphrase,
          resumed: false,
          settled,
          recovery: recoverySlot
            ? { slotId: recoverySlot.id, kitPath: preparedRecovery!.kitPath }
            : null,
        };
      } catch (error) {
        // `commitAttempted`, rather than journal existence, is the decisive
        // boundary: a successful commit removes its journal before read-back
        // and audit settlement. Only before it starts are staged files known
        // to be disposable and a denied outcome known to be truthful.
        const safePrecommitFailure = !commitAttempted;
        if (safePrecommitFailure) {
          fs.rmSync(stagingRoot(vaultDir), { recursive: true, force: true });
        }
        // A rewritten kit already disagrees with an uncommitted vault, so its
        // failure is not a clean denial even though the vault staging tree can
        // be removed. Post-commit and uncertain failures likewise leave the
        // operation pending for recovery rather than inventing an outcome.
        if (
          auditOperation &&
          auditPendingWritten &&
          oldKeys &&
          safePrecommitFailure &&
          !recoveryKitRewritten
        ) {
          appendKeyringAuditWithKey(vaultDir, oldKeys.audit, auditOperation, "denied");
        }
        // A failed commit attempt can occur before it publishes keyring.json.
        // Preserve the recovery-kit warning in that provable case, but do not
        // infer it merely from a missing journal after commit was attempted.
        let keyringStillOriginal = false;
        try {
          keyringStillOriginal = fs.readFileSync(path.join(vaultDir, "keyring.json")).equals(originalKeyringBytes);
        } catch {
          // A missing or unreadable keyring is not evidence that the original
          // one survived, so leave recovery to the journal/state on disk.
        }
        // The ordering hazard: this vault still has the original keyring, but
        // the offline kit was already rewritten to the new keyset before this
        // failure landed. The kit and this vault now disagree, and a kit that
        // disagrees opens nothing — so the operator has to be told explicitly.
        if (keyringStillOriginal && recoveryKitRewritten) {
          const detail = error instanceof Error ? error.message : String(error);
          throw new Error(
            `${detail} The offline recovery kit was already rewritten under the new keyset before this failure, ` +
              "but the vault itself was not re-keyed and still opens only under the CURRENT passphrase. That kit " +
              "no longer matches this vault and will not open it. The current passphrase still works: once the " +
              "problem that caused this failure is fixed, remove the recovery slot ('vbrain keyring recovery " +
              "remove --slot <id>') and create a fresh kit ('vbrain keyring recovery create --out <file>') before " +
              "retrying 'vbrain rekey'.",
            { cause: error },
          );
        }
        throw error;
      } finally {
        if (oldKeys) zeroKeySet(oldKeys);
        if (newKeys) zeroKeySet(newKeys);
      }
    },
    { staleMs: REKEY_STALE_MS },
  );
}

/**
 * Recovery on its own: finish an interrupted install or roll it back, and
 * rotate nothing. `rekeyVault` runs `recoverRekey` itself as its safety net,
 * but it needs a passphrase to reach it and the passphrase that ends a
 * recovery is never the one the caller supplied — a finished install is
 * sealed under whatever the crashed run chose, and a roll-back leaves the
 * original in force. So the command reaches for this first, before it asks
 * for anything it would only discard.
 *
 * Appends nothing to the audit chain, for the same reason it asks for no
 * passphrase: there is no audit key to sign an entry with. The run that left
 * the journal behind is the one the chain records.
 *
 * Under the same lock and the same window a full re-key takes, because the
 * install half of a recovery moves live files exactly as a commit does.
 */
export function resumeRekey(vaultDir: string): "none" | "rolled-back" | "finished" {
  return withVaultLock(
    vaultDir,
    () => {
      const outcome = recoverRekey(vaultDir);
      // The install just replaced live objects under a keyset this process
      // may still be caching from before the interruption.
      if (outcome === "finished") forgetVaultKeys(vaultDir);
      return outcome;
    },
    { staleMs: REKEY_STALE_MS },
  );
}
