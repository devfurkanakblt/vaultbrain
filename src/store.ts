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

export const DEFAULT_VAULT_DIR = path.resolve(process.cwd(), "vault");

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
  const from = vaultFileEnvelopeVersion(vaultDir, name);
  if (from === undefined) throw new Error(`No such vault file: ${name}`);
  const to = kvKey(vaultDir, passphrase) ? KEYED_ENVELOPE_VERSION : ENVELOPE_VERSION;
  if (from === to) return { name, from, to, migrated: false };
  const entries = loadVaultFile(vaultDir, name, passphrase);
  saveVaultFile(vaultDir, name, entries, passphrase);
  return { name, from, to, migrated: true };
}

/** Migrates every key-value file in a vault directory. */
export function migrateVault(vaultDir: string, passphrase: string): MigrationReport[] {
  return listVaultFiles(vaultDir).map((name) => migrateVaultFile(vaultDir, name, passphrase));
}

export function saveVaultFile(
  vaultDir: string,
  name: string,
  entries: KVEntry[],
  passphrase: string
): void {
  if (!fs.existsSync(vaultDir)) fs.mkdirSync(vaultDir, { recursive: true });
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
  const entries = loadVaultFile(vaultDir, name, passphrase);
  const idx = entries.findIndex((e) => e.key === safeKey);
  if (idx >= 0) {
    entries[idx] = { key: safeKey, value, desc: safeDesc || entries[idx].desc };
  } else {
    entries.push({ key: safeKey, value, desc: safeDesc });
  }
  saveVaultFile(vaultDir, name, entries, passphrase);
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
