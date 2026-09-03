import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { decryptDocument, encryptDocument, type DocumentPayload } from "./document-crypto.js";
import { assertNotSymlink, readTextFileLimited, writeFileAtomic } from "./fs-safe.js";
import { resolveInside } from "./safety.js";
import { AAD, canonicalBase64, syncEpochKeyAad } from "./format-version.js";

/** AES-256 content key for one sync epoch. */
export const EPOCH_KEY_BYTES = 32;

const DEVICE_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;

/**
 * One epoch content key sealed to one enrolled device. These live inside the
 * owner-signed device registry, so the authority signature covers them.
 */
export interface EpochKeyWrap {
  deviceId: string;
  /** base64 X25519 SPKI DER, fresh for every wrap. */
  ephemeralPublicKey: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export function generateAgreementKeyPair(): crypto.KeyPairKeyObjectResult {
  return crypto.generateKeyPairSync("x25519");
}

export function exportAgreementPublicKey(key: crypto.KeyObject): string {
  return key.export({ format: "der", type: "spki" }).toString("base64");
}

export function agreementPublicKeyFromBase64(value: unknown, label: string): crypto.KeyObject {
  const encoded = canonicalBase64(value, 44, label);
  let key: crypto.KeyObject;
  try {
    key = crypto.createPublicKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "spki" });
  } catch {
    throw new Error(`${label} is not a valid X25519 public key.`);
  }
  // Ed25519 SPKI DER is also 44 bytes, so the length check alone is not enough.
  if (key.asymmetricKeyType !== "x25519") throw new Error(`${label} must be an X25519 public key.`);
  return key;
}

export function agreementPrivateKeyFromBase64(value: string, label: string): crypto.KeyObject {
  const encoded = canonicalBase64(value, 48, label);
  let key: crypto.KeyObject;
  try {
    key = crypto.createPrivateKey({ key: Buffer.from(encoded, "base64"), format: "der", type: "pkcs8" });
  } catch {
    throw new Error(`${label} is not a valid X25519 private key.`);
  }
  if (key.asymmetricKeyType !== "x25519") throw new Error(`${label} must be an X25519 private key.`);
  return key;
}

/**
 * The epoch number and device ID are bound into both the HKDF info and the
 * AEAD associated data, so a wrap cannot be replayed onto another device or
 * presented as belonging to a different epoch.
 */
function wrapContext(epoch: number, deviceId: string): Buffer {
  return Buffer.from(`${AAD.syncEpochWrap}:${epoch}:${deviceId}`, "utf8");
}

function wrapKey(shared: Buffer, epoch: number, deviceId: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync("sha256", shared, Buffer.alloc(0), wrapContext(epoch, deviceId), 32),
  );
}

export function wrapEpochKey(
  epochKey: Buffer,
  epoch: number,
  deviceId: string,
  devicePublicKey: crypto.KeyObject,
): EpochKeyWrap {
  if (epochKey.length !== EPOCH_KEY_BYTES) throw new Error("An epoch content key must be 32 bytes.");
  if (!Number.isSafeInteger(epoch) || epoch < 2) throw new Error("Only epoch 2 and above carry wrapped keys.");
  if (!DEVICE_ID.test(deviceId)) throw new Error("Sync device ID must be a lowercase UUID.");

  const ephemeral = generateAgreementKeyPair();
  const shared = crypto.diffieHellman({ privateKey: ephemeral.privateKey, publicKey: devicePublicKey });
  const key = wrapKey(shared, epoch, deviceId);
  shared.fill(0);
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(wrapContext(epoch, deviceId));
    const ciphertext = Buffer.concat([cipher.update(epochKey), cipher.final()]);
    return {
      deviceId,
      ephemeralPublicKey: exportAgreementPublicKey(ephemeral.publicKey),
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
  } finally {
    key.fill(0);
  }
}

export function unwrapEpochKey(
  wrap: EpochKeyWrap,
  epoch: number,
  deviceId: string,
  devicePrivateKey: crypto.KeyObject,
): Buffer {
  if (!Number.isSafeInteger(epoch) || epoch < 2) throw new Error("Only epoch 2 and above carry wrapped keys.");
  const normalized = validateEpochKeyWrap(wrap);
  if (normalized.deviceId !== deviceId) throw new Error("Epoch key wrap is addressed to a different device.");
  const ephemeral = agreementPublicKeyFromBase64(normalized.ephemeralPublicKey, "Epoch wrap ephemeral key");
  const shared = crypto.diffieHellman({ privateKey: devicePrivateKey, publicKey: ephemeral });
  const key = wrapKey(shared, epoch, deviceId);
  shared.fill(0);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(normalized.iv, "base64"));
    decipher.setAAD(wrapContext(epoch, deviceId));
    decipher.setAuthTag(Buffer.from(normalized.authTag, "base64"));
    const epochKey = Buffer.concat([
      decipher.update(Buffer.from(normalized.ciphertext, "base64")),
      decipher.final(),
    ]);
    if (epochKey.length !== EPOCH_KEY_BYTES) throw new Error("Unwrapped epoch key has the wrong length.");
    return epochKey;
  } finally {
    key.fill(0);
  }
}

export function validateEpochKeyWrap(value: unknown): EpochKeyWrap {
  const wrap = value as EpochKeyWrap | undefined;
  if (!wrap || typeof wrap !== "object" || Array.isArray(wrap)) {
    throw new Error("An epoch key wrap must be an object.");
  }
  if (typeof wrap.deviceId !== "string" || !DEVICE_ID.test(wrap.deviceId)) {
    throw new Error("Epoch key wrap device ID must be a lowercase UUID.");
  }
  return {
    deviceId: wrap.deviceId,
    ephemeralPublicKey: canonicalBase64(wrap.ephemeralPublicKey, 44, "epoch wrap ephemeral key"),
    iv: canonicalBase64(wrap.iv, 12, "nonce"),
    authTag: canonicalBase64(wrap.authTag, 16, "authentication tag"),
    ciphertext: canonicalBase64(wrap.ciphertext, EPOCH_KEY_BYTES, "epoch key ciphertext"),
  };
}

export function epochKeyDir(rootDir: string): string {
  return resolveInside(rootDir, path.join("sync", "identity", "epochs"));
}

function assertStorableEpoch(epoch: number): number {
  if (!Number.isSafeInteger(epoch) || epoch < 2) {
    throw new Error("Only epoch 2 and above have a stored content key; epoch 1 uses the vault key.");
  }
  return epoch;
}

function epochKeyPath(rootDir: string, epoch: number): string {
  return resolveInside(epochKeyDir(rootDir), `${assertStorableEpoch(epoch)}.key.enc`);
}

export function readEpochKey(rootDir: string, vaultKey: Buffer, epoch: number): Buffer | undefined {
  const filePath = epochKeyPath(rootDir, epoch);
  if (!fs.existsSync(filePath)) return undefined;
  assertNotSymlink(filePath);
  const payload = JSON.parse(
    readTextFileLimited(filePath, 64 * 1024, `Sync epoch ${epoch} key`),
  ) as DocumentPayload;
  const key = Buffer.from(decryptDocument(payload, vaultKey, syncEpochKeyAad(epoch)), "base64");
  if (key.length !== EPOCH_KEY_BYTES) throw new Error(`Stored sync epoch ${epoch} key is malformed.`);
  return key;
}

export function saveEpochKey(rootDir: string, vaultKey: Buffer, epoch: number, epochKey: Buffer): void {
  if (epochKey.length !== EPOCH_KEY_BYTES) throw new Error("An epoch content key must be 32 bytes.");
  const filePath = epochKeyPath(rootDir, epoch);
  fs.mkdirSync(epochKeyDir(rootDir), { recursive: true, mode: 0o700 });
  writeFileAtomic(
    filePath,
    JSON.stringify(encryptDocument(epochKey.toString("base64"), vaultKey, syncEpochKeyAad(epoch))),
    { mode: 0o600 },
  );
}
