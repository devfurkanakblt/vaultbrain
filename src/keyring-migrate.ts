import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { loadGrants, saveGrants } from "./grants.js";
import {
  detectVaultFormat,
  forgetVaultKeys,
  manifestTombstone,
  openVaultKeys,
  randomKeySet,
  wrapKeySet,
  writeKeyring,
  type KeyName,
  type KeySet,
} from "./keyring.js";
import { resolveInside } from "./safety.js";
import { listVaultFiles, loadVaultFile, saveVaultFile, vaultFileEnvelopeVersion } from "./store.js";
import { withVaultLock } from "./vault-lock.js";

const LEGACY_SCRYPT_N = 2 ** 15;
const LEGACY_KEY_LENGTH = 32;
const LEGACY_KEY_CHECK_CONTEXT = "secondbrain-vault:document-key:v1";

export interface KeyringMigrationReport {
  /** True when this run wrote the keyring; false when it resumed or did nothing. */
  created: boolean;
  adopted: KeyName[];
  generated: KeyName[];
  kvFilesRewritten: string[];
  grantsRewritten: boolean;
  manifestTombstoned: boolean;
}

function legacyDerive(passphrase: string, salt: Buffer, N: number): Buffer {
  return crypto.scryptSync(passphrase, salt, LEGACY_KEY_LENGTH, { N, maxmem: 256 * 1024 * 1024 });
}

/**
 * The legacy document key, or null when this vault never used the document
 * engine. Reading is enough: this never creates a manifest, because creating
 * one during a migration would invent material to adopt.
 */
function legacyDocumentKey(vaultDir: string, passphrase: string): Buffer | null {
  const manifestPath = resolveInside(vaultDir, path.join("documents", "manifest.json"));
  if (!fs.existsSync(manifestPath)) return null;
  assertNotSymlink(manifestPath);
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as {
    version?: number;
    kdf?: { name?: string; N?: number; salt?: string };
    verifier?: string;
  };
  if (manifest.version === 2) {
    // Reachable only when detectVaultFormat(vaultDir) !== "keyring", i.e. a
    // version-2 manifest with no keyring.json: the keyring was lost. Returning
    // null here would make the caller generate fresh document/attachmentId/
    // syncChange keys, silently orphaning every existing note behind an opaque
    // GCM error instead of this diagnostic.
    throw new Error("This vault was upgraded to a keyring, but keyring.json is missing or unreadable.");
  }
  if (
    manifest.version !== 1 ||
    manifest.kdf?.name !== "scrypt" ||
    manifest.kdf.N !== LEGACY_SCRYPT_N ||
    !manifest.kdf.salt ||
    typeof manifest.verifier !== "string" ||
    !/^[a-f0-9]{64}$/u.test(manifest.verifier)
  ) {
    throw new Error("Unsupported or invalid document vault manifest.");
  }
  const key = legacyDerive(passphrase, Buffer.from(manifest.kdf.salt, "base64"), manifest.kdf.N);
  const actual = crypto.createHmac("sha256", key).update(LEGACY_KEY_CHECK_CONTEXT).digest();
  const expected = Buffer.from(manifest.verifier, "hex");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    key.fill(0);
    throw new Error("Unable to unlock document vault: wrong passphrase or damaged manifest.");
  }
  return key;
}

/**
 * The legacy audit chain key, or null when this vault has no audit metadata.
 * Read here rather than imported from `audit.ts` so that `keyring.ts` and its
 * migration stay free of a cycle back through the modules that consume them.
 */
function legacyAuditKey(vaultDir: string, passphrase: string): Buffer | null {
  const metaPath = resolveInside(vaultDir, "audit.meta.json");
  if (!fs.existsSync(metaPath)) return null;
  assertNotSymlink(metaPath);
  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8")) as { version?: number; salt?: string };
  if (meta.version !== 1 || !meta.salt) throw new Error("Invalid audit metadata.");
  return legacyDerive(passphrase, Buffer.from(meta.salt, "base64"), LEGACY_SCRYPT_N);
}

function tombstoneManifest(vaultDir: string): boolean {
  const manifestPath = resolveInside(vaultDir, path.join("documents", "manifest.json"));
  if (!fs.existsSync(manifestPath)) return false;
  assertNotSymlink(manifestPath);
  const current = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as { version?: number };
  if (current.version === 2) return false;
  writeFileAtomic(manifestPath, manifestTombstone(), { mode: 0o600 });
  return true;
}

/**
 * Upgrades a vault to the keyring format. Existing keys are adopted verbatim,
 * so attachment content IDs, sync change IDs and the audit chain all keep
 * verifying and not one encrypted object is rewritten.
 *
 * Resumable: a run interrupted after the keyring was written finishes the
 * remaining key-value rewrites and the manifest tombstone on the next call.
 */
export function migrateToKeyring(vaultDir: string, passphrase: string): KeyringMigrationReport {
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  return withVaultLock(vaultDir, () => {
    const adopted: KeyName[] = [];
    const generated: KeyName[] = [];

    if (detectVaultFormat(vaultDir) !== "keyring") {
      const documentKey = legacyDocumentKey(vaultDir, passphrase);
      const auditKey = legacyAuditKey(vaultDir, passphrase);
      const keys: KeySet = randomKeySet();

      if (documentKey) {
        // Legacy code used K directly for content, attachment identity and
        // sync change identity/encryption alike; adopting it into all four
        // keeps every existing attachment ID, sync change ID and sync change
        // body decrypting unchanged. syncEnvelope is rotatable going forward
        // (unlike syncChange), so this is only where the two keys start out equal.
        for (const name of ["documents", "attachmentId", "syncChange", "syncEnvelope"] as const) {
          keys[name] = Buffer.from(documentKey);
          adopted.push(name);
        }
        documentKey.fill(0);
      } else {
        generated.push("documents", "attachmentId", "syncChange", "syncEnvelope");
      }

      if (auditKey) {
        keys.audit = auditKey;
        adopted.push("audit");
      } else {
        generated.push("audit");
      }
      generated.push("kv");

      // Prove every key-value file opens before committing the keyring, so a
      // wrong passphrase cannot leave a vault half-converted.
      const pending = new Map(listVaultFiles(vaultDir).map((name) => [name, loadVaultFile(vaultDir, name, passphrase)]));
      const grants = loadGrants(vaultDir, passphrase);

      writeKeyring(vaultDir, { version: 2, slots: [wrapKeySet(keys, passphrase)] });
      forgetVaultKeys(vaultDir);

      for (const [name, entries] of pending) saveVaultFile(vaultDir, name, entries, passphrase);
      if (grants) saveGrants(vaultDir, grants, passphrase);

      return {
        created: true,
        adopted,
        generated,
        kvFilesRewritten: [...pending.keys()],
        grantsRewritten: grants !== null,
        manifestTombstoned: tombstoneManifest(vaultDir),
      };
    }

    // Resume: the keyring exists, so finish anything an earlier run left behind.
    // Prove the keyring opens before touching anything: the tombstone below
    // destroys the legacy salt, and a corrupt or wrong-passphrase keyring would
    // otherwise leave the vault with no way to derive its document key at all.
    if (!openVaultKeys(vaultDir, passphrase)) {
      throw new Error("This vault has a keyring but it could not be read; refusing to modify the vault.");
    }
    const kvFilesRewritten: string[] = [];
    for (const name of listVaultFiles(vaultDir)) {
      if (vaultFileEnvelopeVersion(vaultDir, name) === 2) continue;
      saveVaultFile(vaultDir, name, loadVaultFile(vaultDir, name, passphrase), passphrase);
      kvFilesRewritten.push(name);
    }
    let grantsRewritten = false;
    const grants = loadGrants(vaultDir, passphrase);
    if (grants) {
      const grantsPath = resolveInside(vaultDir, "grants.enc");
      const payload = JSON.parse(fs.readFileSync(grantsPath, "utf8")) as { version?: number };
      if (payload.version !== 2) {
        saveGrants(vaultDir, grants, passphrase);
        grantsRewritten = true;
      }
    }
    return {
      created: false,
      adopted,
      generated,
      kvFilesRewritten,
      grantsRewritten,
      manifestTombstoned: tombstoneManifest(vaultDir),
    };
  });
}
