import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  decrypt,
  decryptWithKey,
  encrypt,
  encryptWithKey,
  ENVELOPE_VERSION,
  envelopeVersion,
  KEYED_ENVELOPE_VERSION,
  type AnyEncryptedPayload,
  type KeyedEncryptedPayload,
} from "./crypto.js";
import { openOrCreateVaultKey, openVaultKey, openVaultReadKeys } from "./keyring.js";
import { parseKV, serializeKV, type KVEntry } from "./format.js";
import { assertNotSymlink, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import {
  assertValueSize,
  normalizeDescription,
  normalizeEntryKey,
  normalizeVaultName,
  resolveInside,
} from "./safety.js";
import { withVaultLock } from "./vault-lock.js";

export const DEFAULT_VAULT_DIR = path.resolve(process.cwd(), "vault");

/**
 * Resolves the keyring before a write takes the vault lock.
 *
 * Unwrapping a slot runs scrypt at the configured cost, which dominates the
 * cost of the write itself. Doing it inside the lock would make every waiting
 * writer queue behind another process's key derivation; doing it here puts the
 * result in this process's keyset cache so the locked section is file I/O and
 * one AEAD seal. `openOrCreateVaultKey` takes the lock itself when it has to
 * create a keyring, and `withVaultLock` is reentrant, so this is safe to call
 * from inside a transaction a caller has already opened.
 */
function warmKeyring(vaultDir: string, passphrase: string): void {
  kvKeyForWrite(vaultDir, passphrase)?.fill(0);
}

export function vaultFilePath(vaultDir: string, name: string): string {
  const base = normalizeVaultName(name);
  return resolveInside(vaultDir, `${base}.kv.enc`);
}

export function listVaultFiles(vaultDir: string): string[] {
  if (!fs.existsSync(vaultDir)) return [];
  return fs
    .readdirSync(vaultDir)
    .filter((f) => f.endsWith(".kv.enc"))
    .map((f) => f.replace(/\.kv\.enc$/, ""));
}

/** The keyed key-value key when this vault has a keyring, otherwise null. */
function kvKey(vaultDir: string, passphrase: string): Buffer | null {
  return openVaultKey(vaultDir, passphrase, "kv");
}

/**
 * The key-value key for a write. A vault with neither a keyring nor legacy
 * material becomes keyring-native here: the first write to a fresh vault is
 * what creates the keyring. A legacy vault still gets `null` and keeps writing
 * its per-file envelope exactly as before.
 */
function kvKeyForWrite(vaultDir: string, passphrase: string): Buffer | null {
  return openOrCreateVaultKey(vaultDir, passphrase, "kv");
}

export function loadVaultFile(
  vaultDir: string,
  name: string,
  passphrase: string
): KVEntry[] {
  const filePath = vaultFilePath(vaultDir, name);
  if (!fs.existsSync(filePath)) return [];
  assertNotSymlink(filePath);
  const payload: AnyEncryptedPayload = JSON.parse(readTextFileLimited(filePath, 64 * 1024 * 1024, "Vault file"));
  const plaintext = envelopeVersion(payload) === KEYED_ENVELOPE_VERSION
    ? decryptWithKey(payload as KeyedEncryptedPayload, requireKvReadKeys(vaultDir, passphrase), normalizeVaultName(name))
    : decrypt(payload, passphrase);
  return parseKV(plaintext);
}

/**
 * The keys a read may try: the `kv` key in force, and behind it the retiring
 * one while a re-key has not yet rewritten every file.
 */
function requireKvReadKeys(vaultDir: string, passphrase: string): Buffer[] {
  const keys = openVaultReadKeys(vaultDir, passphrase, "kv");
  if (!keys) throw new Error("This file is keyring-encrypted but the vault has no readable keyring.");
  return keys;
}

export interface MigrationReport {
  name: string;
  from: number;
  to: number;
  migrated: boolean;
}

/** Envelope version of a stored file, or undefined when there is no such file. */
export function vaultFileEnvelopeVersion(vaultDir: string, name: string): number | undefined {
  const filePath = vaultFilePath(vaultDir, name);
  if (!fs.existsSync(filePath)) return undefined;
  assertNotSymlink(filePath);
  return envelopeVersion(JSON.parse(readTextFileLimited(filePath, 64 * 1024 * 1024, "Vault file")) as AnyEncryptedPayload);
}

/**
 * Rewrites one vault file in the current envelope format. Decrypting first
 * proves the passphrase and the authentication tag before anything is
 * replaced, and the write is atomic, so a failed migration leaves the original
 * file untouched rather than half-converted.
 */
export function migrateVaultFile(
  vaultDir: string,
  name: string,
  passphrase: string
): MigrationReport {
  warmKeyring(vaultDir, passphrase);
  return withVaultLock(
    vaultDir,
    () => {
      const from = vaultFileEnvelopeVersion(vaultDir, name);
      if (from === undefined) throw new Error(`No such vault file: ${name}`);
      const to = kvKey(vaultDir, passphrase) ? KEYED_ENVELOPE_VERSION : ENVELOPE_VERSION;
      if (from === to) return { name, from, to, migrated: false };
      const entries = loadVaultFile(vaultDir, name, passphrase);
      saveVaultFile(vaultDir, name, entries, passphrase);
      return { name, from, to, migrated: true };
    },
  );
}

/** Migrates every key-value file in a vault directory. */
export function migrateVault(vaultDir: string, passphrase: string): MigrationReport[] {
  return listVaultFiles(vaultDir).map((name) => migrateVaultFile(vaultDir, name, passphrase));
}

/**
 * Replaces one key-value file wholesale.
 *
 * This is the write primitive, not a transaction: it does not take the vault
 * lock, because a caller that read the file first has to hold that lock across
 * both halves or its decision is already stale. `upsertEntry` is the
 * read-modify-write entry point and does exactly that; a caller assembling
 * entries some other way must wrap this in `withVaultLock` itself.
 */
export function saveVaultFile(
  vaultDir: string,
  name: string,
  entries: KVEntry[],
  passphrase: string
): void {
  if (!fs.existsSync(vaultDir)) fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  const filePath = vaultFilePath(vaultDir, name);
  const plaintext = serializeKV(entries);
  const key = kvKeyForWrite(vaultDir, passphrase);
  const payload = key
    ? encryptWithKey(plaintext, key, normalizeVaultName(name))
    : encrypt(plaintext, passphrase);
  writeFileAtomic(filePath, JSON.stringify(payload, null, 2), { mode: 0o600 });
}

export function upsertEntry(
  vaultDir: string,
  name: string,
  key: string,
  value: string,
  desc: string,
  passphrase: string
): void {
  const safeKey = normalizeEntryKey(key);
  const safeDesc = normalizeDescription(desc);
  assertValueSize(value);
  warmKeyring(vaultDir, passphrase);
  // The whole read-modify-write runs under the vault lock. Atomically
  // replacing the file is not enough on its own: two processes that each read
  // the same starting file and then each replace it atomically still lose one
  // of the two writes, and both report success.
  withVaultLock(
    vaultDir,
    () => {
      const entries = loadVaultFile(vaultDir, name, passphrase);
      const idx = entries.findIndex((e) => e.key === safeKey);
      if (idx >= 0) {
        entries[idx] = { key: safeKey, value, desc: safeDesc || entries[idx].desc };
      } else {
        entries.push({ key: safeKey, value, desc: safeDesc });
      }
      saveVaultFile(vaultDir, name, entries, passphrase);
    },
  );
}

export interface KVUpsert {
  key: string;
  value: string;
  desc: string;
}

export interface BulkUpsertResult {
  added: number;
  replaced: number;
}

/**
 * The most entries one bulk write may carry.
 *
 * A bound rather than a guess: the whole batch is held in memory, encrypted
 * as one plaintext and written as one file, so an unbounded batch is an
 * unbounded allocation. Ten thousand keys in one category is already far past
 * anything this format is meant to hold.
 */
export const MAX_BULK_ENTRIES = 10_000;

/**
 * Writes many entries into one category as a single transaction.
 *
 * `upsertEntry` costs about 620 ms from the command line, of which roughly
 * 610 is fixed: process start, the module graph, and the scrypt keyring
 * unwrap. The entry itself costs about 4 ms. Entering 250 keys one command at
 * a time therefore took 158 seconds, of which about one was the work. This
 * pays those fixed costs once.
 *
 * All or nothing, deliberately. Every entry is validated before the lock is
 * taken, so a batch with one bad key writes nothing rather than leaving the
 * category half-updated — a partial bulk import is the worst outcome here,
 * because the caller cannot tell from the outside where it stopped.
 *
 * A duplicate key inside one batch is refused rather than resolved by order.
 * "Last one wins" is a reasonable rule that the caller did not necessarily
 * intend, and silently dropping one of two values in a file the user wrote by
 * hand is the kind of loss this vault exists to prevent.
 */
export function upsertEntries(
  vaultDir: string,
  name: string,
  updates: readonly KVUpsert[],
  passphrase: string,
): BulkUpsertResult {
  if (!updates.length) return { added: 0, replaced: 0 };
  if (updates.length > MAX_BULK_ENTRIES) {
    throw new Error(`A single bulk write cannot exceed ${MAX_BULK_ENTRIES} entries.`);
  }

  // Validate everything first. Nothing below this point may reject a value.
  const prepared: KVUpsert[] = [];
  const seen = new Map<string, number>();
  updates.forEach((update, index) => {
    let safeKey: string;
    let safeDesc: string;
    try {
      safeKey = normalizeEntryKey(update.key);
      safeDesc = normalizeDescription(update.desc);
      assertValueSize(update.value);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      // Which entry, by position and by key: a batch is rejected whole, so the
      // message has to say what to fix without the caller bisecting the file.
      throw new Error(`Entry ${index + 1} (${update.key}): ${reason}`, { cause: error });
    }
    const duplicate = seen.get(safeKey);
    if (duplicate !== undefined) {
      throw new Error(
        `Entry ${index + 1} repeats the key ${safeKey}, already given as entry ${duplicate + 1}. Remove one; this write will not choose for you.`,
      );
    }
    seen.set(safeKey, index);
    prepared.push({ key: safeKey, value: update.value, desc: safeDesc });
  });

  warmKeyring(vaultDir, passphrase);
  return withVaultLock(
    vaultDir,
    () => {
      const entries = loadVaultFile(vaultDir, name, passphrase);
      const positions = new Map(entries.map((entry, index) => [entry.key, index]));
      let added = 0;
      let replaced = 0;
      for (const update of prepared) {
        const at = positions.get(update.key);
        if (at === undefined) {
          positions.set(update.key, entries.length);
          entries.push(update);
          added += 1;
        } else {
          entries[at] = { key: update.key, value: update.value, desc: update.desc || entries[at].desc };
          replaced += 1;
        }
      }
      // One read, one encrypt, one atomic replace for the whole batch.
      saveVaultFile(vaultDir, name, entries, passphrase);
      return { added, replaced };
    },
  );
}

/**
 * Auto-generated keys for freeform journal-style notes encode their own
 * timestamp: NOTE_YYYYMMDD_HHMMSS_xxxx. This lets date-range browsing work
 * directly off the encrypted discovery catalog (key names + descriptions) —
 * the same "fast, safe index" the fact-lookup path already relies on.
 */
export function generateAutoKey(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(
    now.getUTCDate()
  )}_${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
  const rand = crypto.randomBytes(6).toString("hex");
  return `NOTE_${stamp}_${rand}`;
}

/**
 * Stores either a fact (explicit key, e.g. IBAN) or a freeform journal note
 * (key omitted -> auto-generated, timestamp-prefixed). Both are just KV
 * entries under the hood — same encryption, same schema, same audit path.
 * Returns the key actually used, since callers may not have supplied one.
 */
export function storeNote(
  vaultDir: string,
  category: string,
  value: string,
  desc: string,
  passphrase: string,
  key?: string
): string {
  const finalKey = key && key.trim() ? key.trim() : generateAutoKey();
  upsertEntry(vaultDir, category, finalKey, value, desc, passphrase);
  return finalKey;
}
