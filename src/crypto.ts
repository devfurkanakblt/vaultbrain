import crypto from "node:crypto";
import { assertStrongPassphrase } from "./passphrase-policy.js";

const ALGO = "aes-256-gcm";
const KEY_LEN = 32; // 256-bit
const SCRYPT_N = 2 ** 16;
const LEGACY_SCRYPT_N = 2 ** 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const MAX_MEM = 128 * 1024 * 1024;

/** Envelope format written by this version. Bump only with a migration path. */
export const ENVELOPE_VERSION = 1;

export interface ScryptParameters {
  name: "scrypt";
  N: number;
  r: number;
  p: number;
  salt: string;
}

export interface EncryptedPayload {
  version: number;
  cipher: "aes-256-gcm";
  kdf: ScryptParameters;
  iv: string;
  authTag: string;
  ciphertext: string;
}

/**
 * The pre-versioning envelope: no version, no recorded KDF parameters, and no
 * additional authenticated data. Its parameters were compiled into the binary,
 * which is exactly why the format is versioned now.
 */
export interface LegacyEncryptedPayload {
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

/** Envelope version written when the vault has a keyring: no KDF, the key comes from the keyset. */
export const KEYED_ENVELOPE_VERSION = 2;

export interface KeyedEncryptedPayload {
  version: 2;
  cipher: "aes-256-gcm";
  keyId: "kv";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export type AnyEncryptedPayload = EncryptedPayload | LegacyEncryptedPayload | KeyedEncryptedPayload;

const LEGACY_PARAMETERS: Omit<ScryptParameters, "salt"> = {
  name: "scrypt",
  N: LEGACY_SCRYPT_N,
  r: SCRYPT_R,
  p: SCRYPT_P,
};

export function envelopeVersion(payload: AnyEncryptedPayload): number {
  const version = (payload as EncryptedPayload).version;
  return typeof version === "number" ? version : 0;
}

export function isLegacyEnvelope(payload: AnyEncryptedPayload): payload is LegacyEncryptedPayload {
  return envelopeVersion(payload) === 0;
}

function base64Bytes(value: unknown, min: number, max: number, label: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    throw new Error(`Encrypted envelope has a malformed ${label}.`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length < min || bytes.length > max) {
    throw new Error(`Encrypted envelope has an out-of-range ${label}.`);
  }
  return bytes;
}

/**
 * Reject parameters a file could otherwise dictate to us: a hostile envelope
 * must not be able to demand a multi-gigabyte scrypt run, nor silently
 * downgrade the work factor below what this build considers acceptable.
 */
function validateParameters(kdf: unknown): ScryptParameters {
  const candidate = kdf as ScryptParameters | undefined;
  if (!candidate || candidate.name !== "scrypt") {
    throw new Error("Unsupported key-derivation function in encrypted envelope.");
  }
  const { N, r, p } = candidate;
  if (!Number.isSafeInteger(N) || N < 2 ** 14 || N > 2 ** 20 || (N & (N - 1)) !== 0) {
    throw new Error("Encrypted envelope declares an unacceptable scrypt cost.");
  }
  if (!Number.isSafeInteger(r) || r < 1 || r > 32)
    throw new Error("Encrypted envelope declares an unacceptable scrypt block size.");
  if (!Number.isSafeInteger(p) || p < 1 || p > 16)
    throw new Error("Encrypted envelope declares an unacceptable scrypt parallelism.");
  base64Bytes(candidate.salt, 16, 64, "salt");
  return { name: "scrypt", N, r, p, salt: candidate.salt };
}

function deriveKey(passphrase: string, salt: Buffer, parameters: Omit<ScryptParameters, "salt">): Buffer {
  // scrypt's default maxmem (32MB) is too tight for N=2^15; raise it explicitly.
  return crypto.scryptSync(passphrase, salt, KEY_LEN, {
    N: parameters.N,
    r: parameters.r,
    p: parameters.p,
    maxmem: MAX_MEM,
  });
}

/**
 * The version, cipher and KDF parameters are authenticated alongside the
 * ciphertext, so an attacker cannot rewrite the header to weaken the next
 * derivation without the tag check failing.
 */
function headerAad(version: number, kdf: ScryptParameters): Buffer {
  return Buffer.from(
    JSON.stringify({ version, cipher: ALGO, kdf: { name: kdf.name, N: kdf.N, r: kdf.r, p: kdf.p, salt: kdf.salt } }),
    "utf8",
  );
}

/**
 * Encrypts plaintext with a fresh salt + iv every call (never reuse either).
 * The passphrase itself is never written to disk anywhere.
 */
export function encrypt(plaintext: string, passphrase: string): EncryptedPayload {
  assertStrongPassphrase(passphrase);
  const salt = crypto.randomBytes(16);
  const kdf: ScryptParameters = { ...LEGACY_PARAMETERS, N: SCRYPT_N, salt: salt.toString("base64") };
  const key = deriveKey(passphrase, salt, kdf);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  cipher.setAAD(headerAad(ENVELOPE_VERSION, kdf));
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  key.fill(0);
  return {
    version: ENVELOPE_VERSION,
    cipher: ALGO,
    kdf,
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: enc.toString("base64"),
  };
}

/**
 * Decrypts a payload written by this version or by the pre-versioning format.
 * Throws if the passphrase is wrong or the ciphertext was tampered with (GCM
 * auth tag check fails closed, not open).
 */
export function decrypt(payload: AnyEncryptedPayload, passphrase: string): string {
  const version = envelopeVersion(payload);
  if (version === KEYED_ENVELOPE_VERSION) {
    throw new Error("This file is encrypted with the vault keyring; open it with the vault's keyset, not a passphrase.");
  }
  if (version > ENVELOPE_VERSION) {
    throw new Error(
      `This vault file uses envelope version ${version}; this build understands up to ${ENVELOPE_VERSION}. Upgrade Vault Brain to open it.`,
    );
  }
  if (version !== 0 && version !== 1) throw new Error(`Unsupported encrypted envelope version: ${version}`);

  const legacy = version === 0;
  const kdf = legacy
    ? { ...LEGACY_PARAMETERS, salt: (payload as LegacyEncryptedPayload).salt }
    : validateParameters((payload as EncryptedPayload).kdf);
  if (!legacy && (payload as EncryptedPayload).cipher !== ALGO) {
    throw new Error("Unsupported cipher in encrypted envelope.");
  }

  const salt = base64Bytes(kdf.salt, 16, 64, "salt");
  const iv = base64Bytes(payload.iv, 12, 12, "iv");
  const authTag = base64Bytes(payload.authTag, 16, 16, "authentication tag");
  const key = deriveKey(passphrase, salt, kdf);
  try {
    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    if (!legacy) decipher.setAAD(headerAad(version, kdf));
    decipher.setAuthTag(authTag);
    const dec = Buffer.concat([decipher.update(Buffer.from(payload.ciphertext, "base64")), decipher.final()]);
    return dec.toString("utf8");
  } finally {
    key.fill(0);
  }
}

const KEYED_AAD_CONTEXT = "secondbrain-vault:kv:v2";

/**
 * The logical file name is authenticated, so an attacker with write access
 * cannot swap one encrypted category for another and have it open as that
 * category. The v1 envelope could not do this: it bound only its own header.
 */
function keyedAad(name: string): Buffer {
  if (!name || name.length > 128) throw new Error("Invalid encrypted file identity.");
  return Buffer.from(
    JSON.stringify({ context: KEYED_AAD_CONTEXT, version: KEYED_ENVELOPE_VERSION, cipher: ALGO, keyId: "kv", name }),
    "utf8",
  );
}

export function encryptWithKey(plaintext: string, key: Buffer, name: string): KeyedEncryptedPayload {
  if (key.length !== KEY_LEN) throw new Error("A 256-bit key is required.");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  cipher.setAAD(keyedAad(name));
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    version: KEYED_ENVELOPE_VERSION,
    cipher: ALGO,
    keyId: "kv",
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: enc.toString("base64"),
  };
}

/** The `kv` key to read with, or the ordered list to try. See `DocumentReadKey`. */
export type KeyedReadKey = Buffer | readonly Buffer[];

export function decryptWithKey(payload: KeyedEncryptedPayload, key: KeyedReadKey, name: string): string {
  if (payload.version !== KEYED_ENVELOPE_VERSION) {
    throw new Error(`Unsupported keyed envelope version: ${String(payload.version)}`);
  }
  if (payload.cipher !== ALGO) throw new Error("Unsupported cipher in encrypted envelope.");
  if (payload.keyId !== "kv") throw new Error(`Unsupported key ID in encrypted envelope: ${String(payload.keyId)}`);
  const candidates = Buffer.isBuffer(key) ? [key] : key;
  if (candidates.length === 0) throw new Error("No key was offered to decrypt this envelope.");
  let failure: unknown;
  for (const candidate of candidates) {
    try {
      return decryptUnderKey(payload, candidate, name);
    } catch (error) {
      failure = error;
    }
  }
  throw failure;
}

function decryptUnderKey(payload: KeyedEncryptedPayload, key: Buffer, name: string): string {
  if (key.length !== KEY_LEN) throw new Error("A 256-bit key is required.");
  const decipher = crypto.createDecipheriv(ALGO, key, base64Bytes(payload.iv, 12, 12, "iv"));
  decipher.setAAD(keyedAad(name));
  decipher.setAuthTag(base64Bytes(payload.authTag, 16, 16, "authentication tag"));
  return Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
}
