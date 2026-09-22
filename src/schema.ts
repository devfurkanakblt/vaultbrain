import fs from "node:fs";
import { listVaultFiles, loadVaultFile } from "./store.js";
import { assertNotSymlink, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import { removeFile } from "./fs-tree.js";
import { resolveInside } from "./safety.js";
import {
  decrypt,
  decryptWithKey,
  encrypt,
  encryptWithKey,
  envelopeVersion,
  KEYED_ENVELOPE_VERSION,
  type AnyEncryptedPayload,
  type KeyedEncryptedPayload,
} from "./crypto.js";
import { openOrCreateVaultKey, openVaultReadKeys } from "./keyring.js";
import { withVaultLock } from "./vault-lock.js";

export interface SchemaEntry {
  key: string;
  desc: string;
}

export interface Schema {
  generatedAt: string;
  files: Record<string, SchemaEntry[]>;
}

export const SCHEMA_FILENAME = "schema.enc";
const LEGACY_SCHEMA_FILENAME = "schema.json";

/**
 * The catalog's AEAD domain, and the reason it is not simply `"schema"`: a
 * key-value file may legitimately be called `schema`, and it would then be
 * stored as `schema.kv.enc` under that same identity. `normalizeVaultName`
 * rejects `:`, so no vault file can ever collide with this string.
 */
export const SCHEMA_CATALOG_IDENTITY = "schema:catalog";

/**
 * The catalog is sealed with the keyring's `kv` key, the same key the entries
 * it describes are sealed with — not with a key derived from the passphrase.
 *
 * Deriving it from the passphrase made the catalog the one artifact a
 * passphrase change could not carry: changing the passphrase re-wraps the
 * keyring, which is all a keyring-sealed artifact needs, but it cannot rewrite
 * something bound to the old passphrase directly. A vault in that state
 * resolved single keys with the new passphrase and failed every `list`,
 * `search` and MCP discovery call with an authentication error.
 */
function catalogKeyForWrite(vaultDir: string, passphrase: string): Buffer | null {
  return openOrCreateVaultKey(vaultDir, passphrase, "kv");
}

/**
 * Rebuilds the encrypted discovery catalog: key names + descriptions only,
 * values stripped. MCP decrypts it in-process and applies live grants.
 */
export function buildSchema(vaultDir: string, passphrase: string): Schema {
  // Resolved before the lock: see `warmKeyring` in store.ts.
  catalogKeyForWrite(vaultDir, passphrase)?.fill(0);
  // Under the lock for the whole scan, not just the write: a catalog built
  // from files a concurrent writer was replacing halfway through would list a
  // set of keys that never existed together.
  return withVaultLock(
    vaultDir,
    () => {
      const files = listVaultFiles(vaultDir);
      const schema: Schema = { generatedAt: new Date().toISOString(), files: {} };

      for (const name of files) {
        const entries = loadVaultFile(vaultDir, name, passphrase);
        schema.files[name] = entries.map((e) => ({ key: e.key, desc: e.desc }));
      }

      const key = catalogKeyForWrite(vaultDir, passphrase);
      const payload = key
        ? encryptWithKey(JSON.stringify(schema), key, SCHEMA_CATALOG_IDENTITY)
        : encrypt(JSON.stringify(schema), passphrase);
      writeFileAtomic(resolveInside(vaultDir, SCHEMA_FILENAME), JSON.stringify(payload, null, 2), {
        mode: 0o600,
      });

      // Earlier releases generated a plaintext catalog. Remove it only after the
      // encrypted replacement has been committed successfully.
      const legacyPath = resolveInside(vaultDir, LEGACY_SCHEMA_FILENAME);
      if (fs.existsSync(legacyPath)) {
        assertNotSymlink(legacyPath);
        removeFile(legacyPath);
      }
      return schema;
    },
  );
}

/**
 * True when a catalog exists but is still sealed under the pre-keyring,
 * passphrase-derived envelope. `vbrain passphrase change` uses this to rewrite
 * it while both passphrases are known, which is the only moment it can.
 */
export function schemaNeedsKeyringMigration(vaultDir: string): boolean {
  const p = resolveInside(vaultDir, SCHEMA_FILENAME);
  if (!fs.existsSync(p)) return false;
  assertNotSymlink(p);
  const payload = JSON.parse(readTextFileLimited(p, 64 * 1024 * 1024, "Schema")) as AnyEncryptedPayload;
  return envelopeVersion(payload) !== KEYED_ENVELOPE_VERSION;
}

export function readSchema(vaultDir: string, passphrase: string): Schema | null {
  const p = resolveInside(vaultDir, SCHEMA_FILENAME);
  if (!fs.existsSync(p)) return null;
  assertNotSymlink(p);
  const payload = JSON.parse(readTextFileLimited(p, 64 * 1024 * 1024, "Schema")) as AnyEncryptedPayload;
  if (envelopeVersion(payload) === KEYED_ENVELOPE_VERSION) {
    const keys = openVaultReadKeys(vaultDir, passphrase, "kv");
    if (!keys) throw new Error("The catalog is keyring-encrypted but the vault has no readable keyring.");
    return JSON.parse(
      decryptWithKey(payload as KeyedEncryptedPayload, keys, SCHEMA_CATALOG_IDENTITY),
    ) as Schema;
  }
  // A catalog an earlier release sealed directly with the passphrase. It stays
  // readable here, and the next `vbrain index` or `passphrase change` rewrites
  // it under the keyring.
  try {
    return JSON.parse(decrypt(payload, passphrase)) as Schema;
  } catch (error) {
    throw new Error(
      "This vault's catalog was written by an earlier release and cannot be opened with the current " +
        "passphrase. Run 'vbrain index' to rebuild it.",
      { cause: error },
    );
  }
}

/** Very simple fuzzy match over key names + descriptions for MVP "fast find". */
export function searchSchema(schema: Schema, query: string): Array<{ file: string } & SchemaEntry> {
  const q = query.toLowerCase();
  const hits: Array<{ file: string } & SchemaEntry> = [];
  for (const [file, entries] of Object.entries(schema.files)) {
    for (const e of entries) {
      const hay = `${e.key} ${e.desc}`.toLowerCase();
      if (hay.includes(q) || q.split(/\s+/).every((tok) => hay.includes(tok))) {
        hits.push({ file, ...e });
      }
    }
  }
  return hits;
}

const NOTE_KEY_RE = /^NOTE_(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_/;

function dateFromNoteKey(key: string): Date | null {
  const m = key.match(NOTE_KEY_RE);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  const parsed = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)));
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function parseBoundary(value: string | undefined, endOfDay: boolean): Date | null {
  if (!value) return null;
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(value);
  const parsed = new Date(dateOnly ? `${value}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}Z` : value);
  if (Number.isNaN(parsed.getTime())) throw new Error(`Invalid ISO date: ${value}`);
  return parsed;
}

/**
 * Auto-generated note keys carry their own timestamp, so after the encrypted
 * schema catalog is unlocked, date-range filtering does not decrypt note
 * values. This is the "daily notes" equivalent — recall by when, not by what.
 */
export function filterNotesByDate(
  schema: Schema,
  opts: { file?: string; from?: string; to?: string }
): Array<{ file: string; createdAt: string } & SchemaEntry> {
  const from = parseBoundary(opts.from, false);
  const to = parseBoundary(opts.to, true);
  if (from && to && from > to) throw new Error("The 'from' date must not be after 'to'.");
  const hits: Array<{ file: string; createdAt: string } & SchemaEntry> = [];

  for (const [file, entries] of Object.entries(schema.files)) {
    if (opts.file && file !== opts.file) continue;
    for (const e of entries) {
      const d = dateFromNoteKey(e.key);
      if (!d) continue;
      if (from && d < from) continue;
      if (to && d > to) continue;
      hits.push({ file, createdAt: d.toISOString(), ...e });
    }
  }

  return hits.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}
