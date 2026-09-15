import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { DocumentVault } from "../dist/documents.js";
import { removeTree } from "../dist/fs-tree.js";

const VECTOR = JSON.parse(
  fs.readFileSync(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "document-key-vector.json"),
    "utf8",
  ),
);

/**
 * Writes a legacy version 1 vault holding only the vector's manifest. Its
 * document key is the scrypt output, and it doubles as the attachment-ID key,
 * so unlocking and attaching run the production `verifier` and attachment-ID
 * code rather than a copy of them.
 */
function legacyVault(verifier) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-document-key-vector-"));
  fs.mkdirSync(path.join(dir, "documents"), { recursive: true });
  const { name, N, salt } = VECTOR.kdf;
  fs.writeFileSync(
    path.join(dir, "documents", "manifest.json"),
    JSON.stringify({ version: 1, kdf: { name, N, salt }, verifier }, null, 2),
  );
  return dir;
}

/**
 * Both cores derive the legacy document key, its verifier and attachment IDs
 * independently. This is the TypeScript half; the Rust half is
 * `the_document_key_vector_matches_the_typescript_core` in `src-tauri/src/lib.rs`.
 */
test("the legacy manifest verifier and attachment IDs match the committed cross-core vector", () => {
  const dir = legacyVault(VECTOR.verifier);
  try {
    const vault = new DocumentVault(dir, VECTOR.passphrase);
    assert.equal(VECTOR.attachments.length, 3);
    for (const [index, expected] of VECTOR.attachments.entries()) {
      const info = vault.putAttachment(Buffer.from(expected.data, "base64"), `vector-${index}.bin`);
      assert.equal(info.id, expected.id, `attachment ${index}`);
    }
    vault.lock();
  } finally {
    removeTree(dir);
  }
});

test("a manifest whose verifier differs from the vector does not unlock", () => {
  const flipped = `${VECTOR.verifier.slice(0, -1)}${VECTOR.verifier.endsWith("0") ? "1" : "0"}`;
  const dir = legacyVault(flipped);
  try {
    assert.throws(() => new DocumentVault(dir, VECTOR.passphrase), /wrong passphrase or damaged manifest/u);
  } finally {
    removeTree(dir);
  }
});
