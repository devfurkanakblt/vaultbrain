import crypto from "node:crypto";
import type { PluginManifest, PluginSignatureInfo } from "./plugins.js";

const SIGNATURE_PREFIX = "vault-brain-plugin-signature-v1\n";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const RAW_PUBLIC_KEY_BYTES = 32;
const RAW_PRIVATE_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

function frame(value: string): Buffer {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([Buffer.from(`${bytes.length}:`, "ascii"), bytes]);
}

/**
 * A language-neutral byte format shared with the Rust desktop core. Fields are
 * length-prefixed, and capabilities are sorted because their order carries no
 * authority. The signature itself is deliberately absent from the payload.
 */
export function pluginSignaturePayload(
  manifest: Omit<PluginManifest, "signature"> | PluginManifest,
  source: string
): Buffer {
  const capabilities = [...manifest.capabilities].sort();
  return Buffer.concat([
    Buffer.from(SIGNATURE_PREFIX, "utf8"),
    ...[
      String(manifest.manifestVersion),
      manifest.id,
      manifest.name,
      manifest.version,
      manifest.description,
      manifest.author,
      String(capabilities.length),
      ...capabilities,
      source,
    ].map(frame),
  ]);
}

function rawPublicKey(key: crypto.KeyObject): Buffer {
  const der = key.export({ format: "der", type: "spki" });
  if (
    der.length !== ED25519_SPKI_PREFIX.length + RAW_PUBLIC_KEY_BYTES ||
    !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error("Plugin signing key must be Ed25519.");
  }
  return der.subarray(ED25519_SPKI_PREFIX.length);
}

function publicKeyFromRaw(raw: Buffer): crypto.KeyObject {
  if (raw.length !== RAW_PUBLIC_KEY_BYTES) {
    throw new Error("Plugin signature public key must be 32 bytes.");
  }
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function decodeBase64Url(value: string, label: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error(`Invalid plugin ${label} encoding.`);
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new Error(`Invalid plugin ${label} encoding.`);
  return decoded;
}

export function pluginSignerKeyId(raw: Uint8Array): string {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

export function verifyPluginSignature(
  manifest: PluginManifest,
  source: string
): PluginSignatureInfo | undefined {
  if (!manifest.signature) return undefined;
  const parts = manifest.signature.split(":");
  if (parts.length !== 3 || parts[0] !== "ed25519") {
    throw new Error("Plugin signature must use ed25519:<public-key>:<signature>.");
  }
  const raw = decodeBase64Url(parts[1], "public key");
  const signature = decodeBase64Url(parts[2], "signature");
  if (signature.length !== SIGNATURE_BYTES) {
    throw new Error("Plugin Ed25519 signature must be 64 bytes.");
  }
  if (!crypto.verify(null, pluginSignaturePayload(manifest, source), publicKeyFromRaw(raw), signature)) {
    throw new Error("Plugin signature verification failed; the manifest or source was changed.");
  }
  return { algorithm: "ed25519", keyId: pluginSignerKeyId(raw) };
}

export function signPluginPackage(
  manifest: Omit<PluginManifest, "signature"> | PluginManifest,
  source: string,
  privateKey: string | Buffer | crypto.KeyObject
): string {
  const key = privateKey instanceof crypto.KeyObject
    ? privateKey
    : crypto.createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Plugin signing key must be Ed25519.");
  const publicRaw = rawPublicKey(crypto.createPublicKey(key));
  const signature = crypto.sign(null, pluginSignaturePayload(manifest, source), key);
  return `ed25519:${publicRaw.toString("base64url")}:${signature.toString("base64url")}`;
}

export function generatePluginSigningKey(): {
  privateKeyPem: string;
  publicKey: string;
  keyId: string;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const raw = rawPublicKey(publicKey);
  return {
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
    publicKey: raw.toString("base64url"),
    keyId: pluginSignerKeyId(raw),
  };
}

/** Accept a raw 32-byte seed for deterministic fixture/tooling use. */
export function privatePluginKeyFromSeed(seed: Uint8Array): crypto.KeyObject {
  if (seed.length !== RAW_PRIVATE_KEY_BYTES) throw new Error("Ed25519 private seed must be 32 bytes.");
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}
