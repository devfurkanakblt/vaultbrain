import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { SyncBlobStore, sealAttachmentBlobs } from "../dist/sync-blobs.js";
import { decryptDocumentBytes } from "../dist/document-crypto.js";
import { attachmentChunkAad } from "../dist/format-version.js";

const KEY = crypto.randomBytes(32);
const ATTACHMENT_ID = "c".repeat(64);

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "vault-brain-blobs-"));
}

test("sealed blobs are chunk-bound, hash-named and decrypt back to the original bytes", () => {
  const data = crypto.randomBytes(2 * 1024 * 1024 + 7);
  const { blobs, payloads } = sealAttachmentBlobs(data, ATTACHMENT_ID, KEY);

  assert.equal(blobs.length, 3);
  assert.equal(payloads.length, 3);
  for (const [index, payload] of payloads.entries()) {
    assert.equal(crypto.createHash("sha256").update(payload).digest("hex"), blobs[index]);
  }

  const parts = payloads.map((payload, index) =>
    decryptDocumentBytes(JSON.parse(payload.toString("utf8")), KEY, attachmentChunkAad(ATTACHMENT_ID, index)),
  );
  assert.deepEqual(Buffer.concat(parts), data);

  // The AAD binds the chunk to its index: reading chunk 1 as chunk 0 fails.
  assert.throws(() =>
    decryptDocumentBytes(JSON.parse(payloads[1].toString("utf8")), KEY, attachmentChunkAad(ATTACHMENT_ID, 0)),
  );
});

test("the blob store refuses a body that does not hash to its id", () => {
  const dir = tempDir();
  const store = new SyncBlobStore(dir);
  const body = Buffer.from("hello");
  const id = crypto.createHash("sha256").update(body).digest("hex");

  assert.equal(store.has(id), false);
  assert.throws(() => store.put("d".repeat(64), body), /does not match/i);

  store.put(id, body);
  assert.equal(store.has(id), true);
  assert.deepEqual(store.read(id), body);
  store.put(id, body); // idempotent
  assert.deepEqual(store.missing([id, "e".repeat(64)]), ["e".repeat(64)]);

  store.remove(id);
  assert.equal(store.has(id), false);
});

test("the blob store rejects an oversize body and a malformed id", () => {
  const store = new SyncBlobStore(tempDir());
  const big = Buffer.alloc(2 * 1024 * 1024 + 1);
  const id = crypto.createHash("sha256").update(big).digest("hex");
  assert.throws(() => store.put(id, big), /2 MiB/i);
  assert.throws(() => store.read("../escape"), /blob id/i);
});
