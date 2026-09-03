/**
 * Writes the deterministic cross-core keyring vector. Run once, deliberately:
 *
 *   npm run build && node scripts/make-keyring-vector.mjs
 *
 * The output is a frozen fixture. Regenerating it destroys the evidence that
 * both cores agree on the bytes, so only ever regenerate it alongside a
 * deliberate format version bump, and add a new file instead when you can.
 *
 * Everything here is fixed: a vector with random inputs proves nothing twice.
 * N is the lowest accepted cost (2**14) so a debug-profile Rust test stays fast.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PASSPHRASE = "vector-only-passphrase";
const SALT = Buffer.alloc(16, 0x11);
const IV = Buffer.alloc(12, 0x22);
const KDF = { name: "scrypt", N: 2 ** 14, r: 8, p: 1, salt: SALT.toString("base64") };
const HEADER = {
  id: "00000000-0000-4000-8000-000000000001",
  type: "passphrase",
  label: "primary",
  kdf: KDF,
  createdAt: "2026-09-03T00:00:00.000Z",
};
const KEY_BYTES = {
  documents: 0x01,
  kv: 0x02,
  attachmentId: 0x03,
  syncChange: 0x04,
  syncEnvelope: 0x05,
  audit: 0x06,
};

const keys = {};
for (const [name, byte] of Object.entries(KEY_BYTES)) keys[name] = Buffer.alloc(32, byte);

// Mirrors slotAad in src/keyring.ts. The test below proves the mirror is exact:
// unwrapSlot only succeeds when the production builder produces these bytes.
const aad = JSON.stringify({
  context: "secondbrain-vault:keyring-slot:v1",
  version: 2,
  id: HEADER.id,
  type: HEADER.type,
  kdf: { name: KDF.name, N: KDF.N, r: KDF.r, p: KDF.p, salt: KDF.salt },
});

const keysetPlaintext = JSON.stringify({
  version: 1,
  keys: Object.fromEntries(Object.keys(KEY_BYTES).map((name) => [name, keys[name].toString("base64")])),
});

const kek = crypto.scryptSync(PASSPHRASE, SALT, 32, {
  N: KDF.N,
  r: KDF.r,
  p: KDF.p,
  maxmem: 256 * 1024 * 1024,
});
const cipher = crypto.createCipheriv("aes-256-gcm", kek, IV);
cipher.setAAD(Buffer.from(aad, "utf8"));
const ciphertext = Buffer.concat([cipher.update(keysetPlaintext, "utf8"), cipher.final()]);

const vector = {
  note: "Deterministic cross-core keyring vector. Both cores must unwrap this slot to these keys and must serialize this keyset to keysetPlaintext byte-for-byte. Dummy key material; never a real vault.",
  passphrase: PASSPHRASE,
  aad,
  keysetPlaintext,
  keys: Object.fromEntries(Object.keys(KEY_BYTES).map((name) => [name, keys[name].toString("base64")])),
  slot: {
    ...HEADER,
    wrapped: {
      iv: IV.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    },
  },
};

const target = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "test",
  "fixtures",
  "keyring-vector.json",
);
if (fs.existsSync(target) && !process.argv.includes("--force")) {
  console.error(`Refusing to overwrite ${target}. Pass --force only for a deliberate format bump.`);
  process.exit(1);
}
fs.writeFileSync(target, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`Cross-core keyring vector written to ${target}`);
