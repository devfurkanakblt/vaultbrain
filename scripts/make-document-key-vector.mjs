/**
 * Writes the deterministic cross-core document key vector. Run once, deliberately:
 *
 *   node scripts/make-document-key-vector.mjs
 *
 * It pins three constructions both cores implement on their own: the legacy
 * version 1 manifest key derivation (scrypt, N = 32768, r = 8, p = 1, 32 bytes),
 * the manifest `verifier` (HMAC-SHA-256 of the document key-check context) and
 * the content-addressed attachment ID (HMAC-SHA-256 of the attachment-ID
 * context, NUL-terminated, followed by the attachment bytes).
 *
 * The output is a frozen fixture. Regenerating it destroys the evidence that
 * both cores agree on the bytes, so add a new file instead of overwriting it.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PASSPHRASE = "vector-only-passphrase";
const SALT = Buffer.alloc(16, 0x33);
const N = 32768;
const KEY_CHECK_CONTEXT = "secondbrain-vault:document-key:v1";
const ATTACHMENT_ID_CONTEXT = "secondbrain-vault:attachment-id:v1\0";

const ATTACHMENTS = [
  Buffer.from("vector-only attachment\n", "utf8"),
  Buffer.from([0x00]),
  Buffer.from(Array.from({ length: 256 }, (_, index) => index)),
];

const key = crypto.scryptSync(PASSPHRASE, SALT, 32, { N, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });

const vector = {
  note: "Deterministic cross-core document key vector: the legacy manifest scrypt key, its verifier, and attachment IDs under that key. Dummy key material; never a real vault.",
  passphrase: PASSPHRASE,
  kdf: { name: "scrypt", N, r: 8, p: 1, salt: SALT.toString("base64") },
  key: key.toString("base64"),
  verifier: crypto.createHmac("sha256", key).update(KEY_CHECK_CONTEXT, "utf8").digest("hex"),
  attachments: ATTACHMENTS.map((data) => ({
    data: data.toString("base64"),
    id: crypto.createHmac("sha256", key).update(ATTACHMENT_ID_CONTEXT, "utf8").update(data).digest("hex"),
  })),
};

const target = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "test",
  "fixtures",
  "document-key-vector.json",
);
if (fs.existsSync(target) && !process.argv.includes("--force")) {
  throw new Error(`${target} already exists; pass --force only alongside a deliberate format change.`);
}
fs.writeFileSync(target, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`wrote ${target}`);
