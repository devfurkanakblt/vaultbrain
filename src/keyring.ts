import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AAD } from "./format-version.js";
import { assertNotSymlink, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { withVaultLock } from "./vault-lock.js";

export const KEYRING_VERSION = 2;
export const KEYSET_VERSION = 1;
/**
 * The version a keyset carries while a re-key is in flight, when it holds the
 * outgoing rotatable keys alongside the new ones. Any build that does not
 * understand the field rejects the whole keyset, which is the point: a vault
 * caught mid-re-key must fail closed rather than be opened by a reader that
 * would silently fail to decrypt the objects still holding old ciphertext.
 */
export const RETIRING_KEYSET_VERSION = 2;
export const KEYRING_FILENAME = "keyring.json";
export const DEFAULT_SCRYPT_N = 2 ** 17;

const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LENGTH = 32;
/** Declared in the frozen inventory with every other domain-separation string. */
const SLOT_AAD_CONTEXT = AAD.keyringSlot;

/** The order is part of the format: it is what `serializeKeySet` writes. */
export const KEY_NAMES = ["documents", "kv", "attachmentId", "syncChange", "syncEnvelope", "audit"] as const;
export type KeyName = (typeof KEY_NAMES)[number];
export type KeySet = { [K in KeyName]: Buffer };

/**
 * The keys `vbrain rekey` replaces. The three left out are permanent by
 * design: `attachmentId` keys content addresses, `syncChange` keys change IDs
 * the causal DAG references, and `audit` keys a chain already signed. Rotating
 * any of them would invalidate every reference already in the vault.
 */
export const ROTATABLE_KEY_NAMES = ["documents", "kv", "syncEnvelope"] as const;
export type RotatableKeyName = (typeof ROTATABLE_KEY_NAMES)[number];
export type RetiringKeys = { [K in RotatableKeyName]: Buffer };

/**
 * A keyset as it sits inside a slot: the keys in force, plus the outgoing
 * rotatable keys while a re-key has not yet finished rewriting every object
 * under the new ones. `retiring` is null in a settled vault.
 */
export interface VaultKeySet {
  keys: KeySet;
  retiring: RetiringKeys | null;
}

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

/**
 * Deliberately fixed, not derived from `kdf`: `validateKdf` accepts N and r
 * values that are each individually in range but whose product still implies
 * a multi-gigabyte scrypt allocation (e.g. N = 2**20, r = 32). Scaling the
 * ceiling with parameters the keyring file itself declares would let a
 * tampered file dictate its own memory budget; a fixed ceiling instead makes
 * an out-of-policy cost fail fast with "memory limit exceeded", the same
 * policy `crypto.ts`'s MAX_MEM enforces for the key-value envelope.
 */
function scryptMaxmem(_kdf: SlotKdf): number {
  return 256 * 1024 * 1024;
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

function serializeKeySet(keys: KeySet, retiring: RetiringKeys | null): string {
  const encoded: Record<string, string> = {};
  for (const name of KEY_NAMES) encoded[name] = keys[name].toString("base64");
  if (!retiring) return JSON.stringify({ version: KEYSET_VERSION, keys: encoded });
  const outgoing: Record<string, string> = {};
  for (const name of ROTATABLE_KEY_NAMES) outgoing[name] = retiring[name].toString("base64");
  return JSON.stringify({ version: RETIRING_KEYSET_VERSION, keys: encoded, retiring: outgoing });
}

function parseKeySet(plaintext: string): VaultKeySet {
  const parsed = JSON.parse(plaintext) as {
    version?: number;
    keys?: Record<string, unknown>;
    retiring?: Record<string, unknown>;
  };
  const version = parsed?.version;
  if (version !== KEYSET_VERSION && version !== RETIRING_KEYSET_VERSION) {
    throw new Error(`Unsupported vault keyset version: ${String(version)}`);
  }
  const keys = {} as KeySet;
  for (const name of KEY_NAMES) {
    keys[name] = base64Bytes(parsed.keys?.[name], KEY_LENGTH, KEY_LENGTH, `${name} key`);
  }
  if (version === KEYSET_VERSION) {
    // Refused rather than ignored: a reader that silently dropped retiring
    // keys it was not expecting would report success and then fail to open
    // every object the interrupted re-key had not reached yet.
    if (parsed.retiring !== undefined) {
      zeroKeySet(keys);
      throw new Error("A version 1 vault keyset must not carry retiring keys.");
    }
    return { keys, retiring: null };
  }
  const retiring = {} as RetiringKeys;
  for (const name of ROTATABLE_KEY_NAMES) {
    retiring[name] = base64Bytes(parsed.retiring?.[name], KEY_LENGTH, KEY_LENGTH, `retiring ${name} key`);
  }
  return { keys, retiring };
}

export function copyRetiringKeys(retiring: RetiringKeys): RetiringKeys {
  const copy = {} as RetiringKeys;
  for (const name of ROTATABLE_KEY_NAMES) copy[name] = Buffer.from(retiring[name]);
  return copy;
}

export function zeroRetiringKeys(retiring: RetiringKeys): void {
  for (const name of ROTATABLE_KEY_NAMES) retiring[name].fill(0);
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

export function wrapKeySet(
  keys: KeySet,
  passphrase: string,
  N: number = DEFAULT_SCRYPT_N,
  retiring: RetiringKeys | null = null,
): KeyringSlot {
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
    const ciphertext = Buffer.concat([
      cipher.update(serializeKeySet(keys, retiring), "utf8"),
      cipher.final(),
    ]);
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
  const opened = unwrapSlotKeySet(slot, passphrase);
  if (opened.retiring) zeroRetiringKeys(opened.retiring);
  return opened.keys;
}

/**
 * `unwrapSlot`, but surfacing the retiring keys of a vault caught mid-re-key.
 * Callers that only need the keys in force should use `unwrapSlot`, which
 * zeroizes what it drops.
 */
export function unwrapSlotKeySet(slot: KeyringSlot, passphrase: string): VaultKeySet {
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
  const opened = unwrapKeyringKeySet(file, passphrase);
  if (opened.retiring) zeroRetiringKeys(opened.retiring);
  return opened.keys;
}

/** `unwrapKeyring`, surfacing the retiring keys of a vault caught mid-re-key. */
export function unwrapKeyringKeySet(file: KeyringFile, passphrase: string): VaultKeySet {
  for (const slot of file.slots) {
    try {
      return unwrapSlotKeySet(slot, passphrase);
    } catch {
      // Try the next slot: a keyring may hold several, and only one has to open.
    }
  }
  throw new Error("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.");
}

export type VaultFormat = "keyring" | "legacy" | "empty";

const LEGACY_MARKERS = [
  path.join("documents", "manifest.json"),
  "audit.meta.json",
  "grants.enc",
  "schema.json",
];

/**
 * A vault is legacy when it holds material an earlier release wrote. Detection
 * never writes anything: creating a keyring is `vbrain migrate`'s job, not a
 * side effect of opening a vault.
 */
export function detectVaultFormat(vaultDir: string): VaultFormat {
  if (fs.existsSync(keyringPath(vaultDir))) return "keyring";
  if (!fs.existsSync(vaultDir)) return "empty";
  for (const marker of LEGACY_MARKERS) {
    if (fs.existsSync(resolveInside(vaultDir, marker))) return "legacy";
  }
  if (fs.readdirSync(vaultDir).some((entry) => entry.endsWith(".kv.enc"))) return "legacy";
  return "empty";
}

/**
 * One resolved keyset per vault per passphrase, so unlocking does not pay the
 * KDF again on every operation. The fingerprint identifies an already-unlocked
 * in-process session; neither it nor the keyset is ever written to disk. This
 * is the pattern `audit.ts` already uses for its chain key.
 */
const keySetCache = new Map<string, KeySet>();

function cacheId(vaultDir: string, passphrase: string, file: KeyringFile): string {
  const fingerprint = crypto
    .createHash("sha256")
    .update(file.slots[0].kdf.salt, "utf8")
    .update("\0", "utf8")
    .update(passphrase, "utf8")
    .digest("hex");
  return `${resolveInside(vaultDir, ".")}\0${fingerprint}`;
}

/**
 * Returns the vault's keyset, or `null` when this vault has no keyring — which
 * means the caller must use the legacy derivation it already has. Callers
 * receive their own buffers: several of them zeroize what they are handed when
 * they lock, and that must not blind the next caller.
 */
export function openVaultKeys(vaultDir: string, passphrase: string): KeySet | null {
  const file = readKeyring(vaultDir);
  if (!file) return null;
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");

  const id = cacheId(vaultDir, passphrase, file);
  const cached = keySetCache.get(id);
  if (cached) return copyKeySet(cached);

  const opened = unwrapKeyringKeySet(file, passphrase);
  if (opened.retiring) {
    // Nothing here can read an object still holding old ciphertext, so say so
    // rather than hand back keys that will fail halfway through the vault.
    zeroRetiringKeys(opened.retiring);
    zeroKeySet(opened.keys);
    throw new Error(
      "This vault has an unfinished re-key. Run 'vbrain rekey --resume' to complete it before opening the vault.",
    );
  }
  keySetCache.set(id, opened.keys);
  return copyKeySet(opened.keys);
}

/**
 * Returns a copy of a single named key from the vault's keyset, or `null`
 * when this vault has no keyring — exactly like `openVaultKeys`, but for
 * callers that only ever need one key. `openVaultKeys(...)?.kv`-style call
 * sites were each allocating and then silently dropping four other 32-byte
 * key copies (including the permanent `attachmentId` and `syncChange` keys)
 * with no `.fill(0)`, scattering unused key material across the heap on
 * every call over a long-lived process. This zeroizes the other four before
 * returning so only the wanted key survives past this call.
 */
export function openVaultKey(vaultDir: string, passphrase: string, name: KeyName): Buffer | null {
  const keys = openVaultKeys(vaultDir, passphrase);
  if (!keys) return null;
  const wanted = keys[name];
  for (const other of KEY_NAMES) {
    if (other !== name) keys[other].fill(0);
  }
  return wanted;
}

/** Drops cached key material, for one vault or for all of them. */
export function forgetVaultKeys(vaultDir?: string): void {
  if (vaultDir === undefined) {
    for (const keys of keySetCache.values()) zeroKeySet(keys);
    keySetCache.clear();
    return;
  }
  const prefix = `${resolveInside(vaultDir, ".")}\0`;
  for (const [id, keys] of keySetCache) {
    if (!id.startsWith(prefix)) continue;
    zeroKeySet(keys);
    keySetCache.delete(id);
  }
}

/**
 * The single definition of the manifest tombstone bytes. Both the keyring
 * creation path and `vbrain migrate` must write exactly these bytes so a
 * vault created from scratch and a vault upgraded by migration are
 * indistinguishable on disk.
 */
export function manifestTombstone(): string {
  return `${JSON.stringify({ version: 2, keyring: true }, null, 2)}\n`;
}

/**
 * The document manifest a keyring-native vault carries, byte-identical to the
 * tombstone `vbrain migrate` leaves behind. Builds from before the keyring
 * refuse any manifest whose version is not 1, so writing this is what makes an
 * older build fail closed instead of mistaking a keyring vault for an empty
 * legacy one and writing notes under a key of its own.
 */
function writeManifestTombstone(vaultDir: string): void {
  const manifestPath = resolveInside(vaultDir, path.join("documents", "manifest.json"));
  if (fs.existsSync(manifestPath)) {
    assertNotSymlink(manifestPath);
    return;
  }
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
  writeFileAtomic(manifestPath, manifestTombstone(), {
    mode: 0o600,
  });
}

/**
 * Returns the vault's keyset, creating one when the vault is brand new.
 *
 * `openVaultKeys` deliberately never writes — reading a vault must not bring
 * one into existence — so this is its write-path counterpart, and the only
 * place outside `vbrain migrate` that a keyring is created. A vault holding
 * legacy material still returns `null`: a fresh keyring written beside an
 * existing `audit.meta.json` would put a random audit key in front of a chain
 * signed with the key derived from that file, and `vbrain audit verify` would
 * stop validating a chain that is in fact intact. Adopting legacy keys so that
 * cannot happen is migration's job, not this function's.
 */
export function openOrCreateVaultKeys(vaultDir: string, passphrase: string): KeySet | null {
  const existing = openVaultKeys(vaultDir, passphrase);
  if (existing) return existing;
  if (!passphrase) throw new Error("A non-empty vault passphrase is required.");
  if (detectVaultFormat(vaultDir) === "legacy") return null;

  fs.mkdirSync(vaultDir, { recursive: true, mode: 0o700 });
  return withVaultLock(vaultDir, () => {
    // Re-checked under the lock: two processes racing on the same fresh vault
    // must not each write a keyset of their own, or whichever lost the race
    // would have encrypted its first write under keys nobody keeps.
    const raced = openVaultKeys(vaultDir, passphrase);
    if (raced) return raced;
    if (detectVaultFormat(vaultDir) === "legacy") return null;

    const keys = randomKeySet();
    try {
      writeKeyring(vaultDir, { version: KEYRING_VERSION, slots: [wrapKeySet(keys, passphrase)] });
    } finally {
      zeroKeySet(keys);
    }
    writeManifestTombstone(vaultDir);

    // Read back rather than returning what we just generated: this proves the
    // keyring on disk really unwraps before one byte is encrypted under it,
    // and it populates the process cache every other caller expects.
    const created = openVaultKeys(vaultDir, passphrase);
    if (!created) throw new Error("Failed to create a vault keyring.");
    return created;
  });
}

/**
 * `openOrCreateVaultKeys` for a caller that needs one key, zeroizing the five
 * it did not ask for — the same contract as `openVaultKey`.
 */
export function openOrCreateVaultKey(
  vaultDir: string,
  passphrase: string,
  name: KeyName,
): Buffer | null {
  const keys = openOrCreateVaultKeys(vaultDir, passphrase);
  if (!keys) return null;
  const wanted = keys[name];
  for (const other of KEY_NAMES) {
    if (other !== name) keys[other].fill(0);
  }
  return wanted;
}
