import crypto from "node:crypto";
import fs from "node:fs";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";

export const KEYRING_VERSION = 2;
export const KEYSET_VERSION = 1;
export const KEYRING_FILENAME = "keyring.json";
export const DEFAULT_SCRYPT_N = 2 ** 17;

const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 32;
const SLOT_AAD_CONTEXT = "secondbrain-vault:keyring-slot:v1";

/** The order is part of the format: it is what `serializeKeySet` writes. */
export const KEY_NAMES = ["documents", "kv", "attachmentId", "syncChange", "audit"] as const;
export type KeyName = (typeof KEY_NAMES)[number];
export type KeySet = { [K in KeyName]: Buffer };

export interface SlotKdf {
  name: "scrypt";
  N: number;
  r: number;
  p: number;
  salt: string;
}

export interface KeyringSlot {
  id: string;
  type: "passphrase";
  label: string;
  kdf: SlotKdf;
  createdAt: string;
  wrapped: { iv: string; authTag: string; ciphertext: string };
}

export interface KeyringFile {
  version: number;
  slots: KeyringSlot[];
}

function base64Bytes(value: unknown, min: number, max: number, label: string): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    throw new Error(`Vault keyring has a malformed ${label}.`);
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length < min || bytes.length > max) {
    throw new Error(`Vault keyring has an out-of-range ${label}.`);
  }
  return bytes;
}

/**
 * Reject parameters the file could otherwise dictate to us: a hostile keyring
 * must not be able to demand a multi-gigabyte scrypt run, nor silently
 * downgrade the work factor below what this build considers acceptable. Same
 * bounds as the key-value envelope in `crypto.ts`.
 */
function validateKdf(kdf: unknown): SlotKdf {
  const candidate = kdf as SlotKdf | undefined;
  if (!candidate || candidate.name !== "scrypt") {
    throw new Error("Unsupported key-derivation function in vault keyring.");
  }
  const { N, r, p } = candidate;
  if (!Number.isSafeInteger(N) || N < 2 ** 14 || N > 2 ** 20 || (N & (N - 1)) !== 0) {
    throw new Error("Vault keyring declares an unacceptable scrypt cost.");
  }
  if (!Number.isSafeInteger(r) || r < 1 || r > 32) {
    throw new Error("Vault keyring declares an unacceptable scrypt block size.");
  }
  if (!Number.isSafeInteger(p) || p < 1 || p > 16) {
    throw new Error("Vault keyring declares an unacceptable scrypt parallelism.");
  }
  base64Bytes(candidate.salt, 16, 64, "salt");
  return { name: "scrypt", N, r, p, salt: candidate.salt };
}

export function validateSlot(value: unknown): KeyringSlot {
  const slot = value as KeyringSlot | undefined;
  if (!slot || typeof slot !== "object") throw new Error("Vault keyring has a malformed slot.");
  if (typeof slot.id !== "string" || !/^[0-9a-f-]{36}$/u.test(slot.id)) {
    throw new Error("Vault keyring has a malformed slot ID.");
  }
  if (slot.type !== "passphrase") throw new Error(`Unsupported vault keyring slot type: ${String(slot.type)}`);
  if (typeof slot.label !== "string" || slot.label.length > 64) {
    throw new Error("Vault keyring has a malformed slot label.");
  }
  if (typeof slot.createdAt !== "string" || Number.isNaN(Date.parse(slot.createdAt))) {
    throw new Error("Vault keyring has a malformed slot timestamp.");
  }
  const kdf = validateKdf(slot.kdf);
  const wrapped = slot.wrapped;
  if (!wrapped || typeof wrapped !== "object") throw new Error("Vault keyring has a malformed wrapped keyset.");
  base64Bytes(wrapped.iv, 12, 12, "iv");
  base64Bytes(wrapped.authTag, 16, 16, "authentication tag");
  base64Bytes(wrapped.ciphertext, 16, 4096, "wrapped keyset");
  return { id: slot.id, type: "passphrase", label: slot.label, kdf, createdAt: slot.createdAt, wrapped };
}

function scryptMaxmem(kdf: SlotKdf): number {
  return Math.max(256 * 1024 * 1024, 256 * kdf.N * kdf.r);
}

function deriveSlotKey(passphrase: string, kdf: SlotKdf): Buffer {
  return crypto.scryptSync(passphrase, Buffer.from(kdf.salt, "base64"), KEY_LENGTH, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: scryptMaxmem(kdf),
  });
}

/**
 * The slot's identity and its declared cost are authenticated alongside the
 * wrapped keyset, so nobody can weaken the header or move one slot's
 * ciphertext under another slot's identity without the tag check failing.
 */
function slotAad(slot: Omit<KeyringSlot, "wrapped">): Buffer {
  return Buffer.from(
    JSON.stringify({
      context: SLOT_AAD_CONTEXT,
      version: KEYRING_VERSION,
      id: slot.id,
      type: slot.type,
      kdf: { name: slot.kdf.name, N: slot.kdf.N, r: slot.kdf.r, p: slot.kdf.p, salt: slot.kdf.salt },
    }),
    "utf8",
  );
}

function serializeKeySet(keys: KeySet): string {
  const encoded: Record<string, string> = {};
  for (const name of KEY_NAMES) encoded[name] = keys[name].toString("base64");
  return JSON.stringify({ version: KEYSET_VERSION, keys: encoded });
}

function parseKeySet(plaintext: string): KeySet {
  const parsed = JSON.parse(plaintext) as { version?: number; keys?: Record<string, unknown> };
  if (parsed?.version !== KEYSET_VERSION) {
    throw new Error(`Unsupported vault keyset version: ${String(parsed?.version)}`);
  }
  const keys = {} as KeySet;
  for (const name of KEY_NAMES) {
    keys[name] = base64Bytes(parsed.keys?.[name], KEY_LENGTH, KEY_LENGTH, `${name} key`);
  }
  return keys;
}

export function randomKeySet(): KeySet {
  const keys = {} as KeySet;
  for (const name of KEY_NAMES) keys[name] = crypto.randomBytes(KEY_LENGTH);
  return keys;
}

export function copyKeySet(keys: KeySet): KeySet {
  const copy = {} as KeySet;
  for (const name of KEY_NAMES) copy[name] = Buffer.from(keys[name]);
  return copy;
}

export function zeroKeySet(keys: KeySet): void {
  for (const name of KEY_NAMES) keys[name].fill(0);
}

export function wrapKeySet(keys: KeySet, passphrase: string, N: number = DEFAULT_SCRYPT_N): KeyringSlot {
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  const header = {
    id: crypto.randomUUID(),
    type: "passphrase" as const,
    label: "primary",
    kdf: validateKdf({ name: "scrypt", N, r: SCRYPT_R, p: SCRYPT_P, salt: crypto.randomBytes(16).toString("base64") }),
    createdAt: new Date().toISOString(),
  };
  const derived = deriveSlotKey(passphrase, header.kdf);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", derived, iv);
    cipher.setAAD(slotAad(header));
    const ciphertext = Buffer.concat([cipher.update(serializeKeySet(keys), "utf8"), cipher.final()]);
    return {
      ...header,
      wrapped: {
        iv: iv.toString("base64"),
        authTag: cipher.getAuthTag().toString("base64"),
        ciphertext: ciphertext.toString("base64"),
      },
    };
  } finally {
    derived.fill(0);
  }
}

/**
 * A wrong passphrase fails as an authentication error. There is deliberately
 * no verifier field: publishing one hands an offline attacker a free
 * passphrase-guessing oracle.
 */
export function unwrapSlot(slot: KeyringSlot, passphrase: string): KeySet {
  const validated = validateSlot(slot);
  const derived = deriveSlotKey(passphrase, validated.kdf);
  let plaintext: Buffer | undefined;
  try {
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      derived,
      base64Bytes(validated.wrapped.iv, 12, 12, "iv"),
    );
    decipher.setAAD(slotAad(validated));
    decipher.setAuthTag(base64Bytes(validated.wrapped.authTag, 16, 16, "authentication tag"));
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(validated.wrapped.ciphertext, "base64")),
      decipher.final(),
    ]);
    return parseKeySet(plaintext.toString("utf8"));
  } finally {
    derived.fill(0);
    plaintext?.fill(0);
  }
}

export function keyringPath(vaultDir: string): string {
  return resolveInside(vaultDir, KEYRING_FILENAME);
}

export function readKeyring(vaultDir: string): KeyringFile | null {
  const filePath = keyringPath(vaultDir);
  if (!fs.existsSync(filePath)) return null;
  assertNotSymlink(filePath);
  const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as KeyringFile;
  if (parsed?.version !== KEYRING_VERSION) {
    throw new Error(
      `This vault keyring uses version ${String(parsed?.version)}; this build understands ${KEYRING_VERSION}. Upgrade Vault Brain to open it.`,
    );
  }
  if (!Array.isArray(parsed.slots) || parsed.slots.length === 0 || parsed.slots.length > 16) {
    throw new Error("Vault keyring has no usable slots.");
  }
  return { version: KEYRING_VERSION, slots: parsed.slots.map(validateSlot) };
}

export function writeKeyring(vaultDir: string, file: KeyringFile): void {
  fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  writeFileAtomic(keyringPath(vaultDir), `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
}

export function unwrapKeyring(file: KeyringFile, passphrase: string): KeySet {
  for (const slot of file.slots) {
    try {
      return unwrapSlot(slot, passphrase);
    } catch {
      // Try the next slot: a keyring may hold several, and only one has to open.
    }
  }
  throw new Error("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.");
}
