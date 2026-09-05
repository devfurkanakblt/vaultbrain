import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertNoSymlinkComponents, assertNotSymlink, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { assertStrongPassphrase } from "./passphrase-policy.js";
import { AAD } from "./format-version.js";
import { openOrCreateVaultKeySet } from "./keyring.js";

const SCRYPT_N = 2 ** 16;
const SUPPORTED_SCRYPT_N = new Set([2 ** 15, SCRYPT_N]);
const KEY_LENGTH = 32;

export interface DocumentManifest {
  version: 1;
  kdf: { name: "scrypt"; N: number; salt: string };
  verifier: string;
}

export interface DocumentPayload {
  version: 1;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface DocumentKeySession {
  rootDir: string;
  /** Encrypts every object under `documents/`. Writers use this one. */
  key: Buffer;
  /**
   * What readers under `documents/` try, in order: `key`, and behind it the
   * retiring key of a re-key that has not finished rewriting every object.
   * Its first entry is `key` itself, not a copy.
   */
  readKeys: readonly Buffer[];
  /** Keys the content address of an attachment. Never rotated. */
  attachmentIdKey: Buffer;
  /** Keys sync change IDs. Never rotated: the causal DAG references them. */
  syncChangeKey: Buffer;
  /** Keys sync change body encryption (the envelope subkey). Rotatable. */
  syncEnvelopeKey: Buffer;
  /** `readKeys` for the sync envelope key. Its first entry is `syncEnvelopeKey`. */
  syncEnvelopeReadKeys: readonly Buffer[];
  /**
   * The documents key a completed re-key replaced. Recomputes the ids of sync
   * changes an older build derived from it, and nothing else. Null on a vault
   * that has never been re-keyed, and on every legacy vault.
   */
  legacyChangeIdentityKey: Buffer | null;
  /** The legacy manifest, or null when the keys came from the vault keyring. */
  manifest: DocumentManifest | null;
}

function derive(passphrase: string, salt: Buffer, N: number): Buffer {
  return crypto.scryptSync(passphrase, salt, KEY_LENGTH, {
    N,
    maxmem: 128 * 1024 * 1024,
  });
}

function verifier(key: Buffer): string {
  return crypto.createHmac("sha256", key).update(AAD.documentKeyCheck).digest("hex");
}

export function openDocumentKey(vaultDir: string, passphrase: string): DocumentKeySession {
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  const rootDir = resolveInside(vaultDir, "documents");
  const manifestPath = resolveInside(rootDir, "manifest.json");
  assertNoSymlinkComponents(vaultDir, rootDir);
  fs.mkdirSync(rootDir, { recursive: true, mode: 0o700 });

  const vaultKeys = openOrCreateVaultKeySet(vaultDir, passphrase);
  if (vaultKeys) {
    const { keys, retiring, legacyChangeIdentity } = vaultKeys;
    return {
      rootDir,
      key: keys.documents,
      readKeys: retiring ? [keys.documents, retiring.documents] : [keys.documents],
      attachmentIdKey: keys.attachmentId,
      syncChangeKey: keys.syncChange,
      syncEnvelopeKey: keys.syncEnvelope,
      syncEnvelopeReadKeys: retiring
        ? [keys.syncEnvelope, retiring.syncEnvelope]
        : [keys.syncEnvelope],
      legacyChangeIdentityKey: legacyChangeIdentity,
      manifest: null,
    };
  }

  let manifest: DocumentManifest;
  if (fs.existsSync(manifestPath)) {
    assertNotSymlink(manifestPath);
    manifest = JSON.parse(readTextFileLimited(manifestPath, 64 * 1024, "Document manifest")) as DocumentManifest;
    if ((manifest as unknown as { version?: number; keyring?: boolean }).version === 2) {
      throw new Error("This vault was upgraded to a keyring, but keyring.json is missing or unreadable.");
    }
    if (
      manifest.version !== 1 ||
      manifest.kdf?.name !== "scrypt" ||
      !SUPPORTED_SCRYPT_N.has(manifest.kdf.N) ||
      !manifest.kdf.salt ||
      !/^[a-f0-9]{64}$/u.test(manifest.verifier)
    ) {
      throw new Error("Unsupported or invalid document vault manifest.");
    }
    const key = derive(passphrase, Buffer.from(manifest.kdf.salt, "base64"), manifest.kdf.N);
    const actual = Buffer.from(verifier(key), "hex");
    const expected = Buffer.from(manifest.verifier, "hex");
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
      key.fill(0);
      throw new Error("Unable to unlock document vault: wrong passphrase or damaged manifest.");
    }
    const syncEnvelopeKey = Buffer.from(key);
    return {
      rootDir,
      key,
      readKeys: [key],
      attachmentIdKey: Buffer.from(key),
      syncChangeKey: Buffer.from(key),
      syncEnvelopeKey,
      syncEnvelopeReadKeys: [syncEnvelopeKey],
      legacyChangeIdentityKey: null,
      manifest,
    };
  } else {
    assertStrongPassphrase(passphrase);
    const salt = crypto.randomBytes(16);
    const key = derive(passphrase, salt, SCRYPT_N);
    manifest = {
      version: 1,
      kdf: { name: "scrypt", N: SCRYPT_N, salt: salt.toString("base64") },
      verifier: verifier(key),
    };
  }

  const key = derive(passphrase, Buffer.from(manifest.kdf.salt, "base64"), manifest.kdf.N);
  writeFileAtomic(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  const syncEnvelopeKey = Buffer.from(key);
  return {
    rootDir,
    key,
    readKeys: [key],
    attachmentIdKey: Buffer.from(key),
    syncChangeKey: Buffer.from(key),
    syncEnvelopeKey,
    syncEnvelopeReadKeys: [syncEnvelopeKey],
    legacyChangeIdentityKey: null,
    manifest,
  };
}

export function encryptDocument(plaintext: string, key: Buffer, aad: string): DocumentPayload {
  return encryptDocumentBytes(Buffer.from(plaintext, "utf8"), key, aad);
}

export function encryptDocumentBytes(data: Buffer, key: Buffer, aad: string): DocumentPayload {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
  return {
    version: 1,
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

/**
 * A key to read with, or the ordered list to try. A list is how an object
 * written before an unfinished re-key is still read: the key in force comes
 * first and the retiring one after it. Trying a second key is safe because
 * the AAD already binds the object's identity, so a fallback cannot succeed
 * against the wrong object — only against the right object under the older
 * key. Writers always take a single key.
 */
export type DocumentReadKey = Buffer | readonly Buffer[];

export function decryptDocument(payload: DocumentPayload, key: DocumentReadKey, aad: string): string {
  return decryptDocumentBytes(payload, key, aad).toString("utf8");
}

export function decryptDocumentBytes(payload: DocumentPayload, key: DocumentReadKey, aad: string): Buffer {
  if (payload.version !== 1) throw new Error("Unsupported encrypted document version.");
  const candidates = Buffer.isBuffer(key) ? [key] : key;
  if (candidates.length === 0) throw new Error("No key was offered to decrypt this object.");
  let failure: unknown;
  for (const candidate of candidates) {
    try {
      return decryptDocumentUnder(payload, candidate, aad);
    } catch (error) {
      failure = error;
    }
  }
  throw failure;
}

function decryptDocumentUnder(payload: DocumentPayload, key: Buffer, aad: string): Buffer {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "base64")
  );
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(payload.authTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]);
}

export function encryptedDocumentPath(rootDir: string, id: string): string {
  if (!/^[a-f0-9-]{36}$/u.test(id)) throw new Error("Invalid note ID.");
  return resolveInside(path.join(rootDir, "objects"), `${id}.note.enc`);
}
