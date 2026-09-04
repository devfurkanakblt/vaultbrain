import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import { planRekey } from "../dist/keyring-rekey.js";
import { upsertEntry } from "../dist/store.js";
import { saveGrants, emptyGrantFile } from "../dist/grants.js";

const PASSPHRASE = "phase-74-current-passphrase";

function tempDir(label = "rekey") {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-${label}-`));
}

/**
 * A keyring-native vault holding a note with history, a canvas, an
 * attachment, a key-value file, a grant file and an audit chain — one of
 * every artifact class the walk has to classify.
 */
function seedVault(passphrase = PASSPHRASE) {
  const dir = tempDir();
  const vault = new DocumentVault(dir, passphrase);
  const note = vault.put({ path: "Atlas/First.md", title: "First", body: "# First\n\nbody" });
  vault.put({ id: note.id, path: "Atlas/First.md", title: "First", body: "# First\n\nsecond revision" });
  const canvas = vault.putCanvas({ path: "Atlas/Board.canvas", title: "Board", nodes: [], edges: [] });
  const attachment = vault.putAttachment(Buffer.from("phase 7.4 attachment"), "note.bin");
  vault.lock();
  upsertEntry(dir, "health", "BLOOD_TYPE", "0 Rh+", "blood group", passphrase);
  saveGrants(dir, emptyGrantFile(), passphrase);
  appendAudit(dir, { actor: "cli-direct-write", file: "health", key: "BLOOD_TYPE" }, passphrase);
  return { dir, noteId: note.id, canvasId: canvas.id, attachmentId: attachment.id };
}

test("the walk classifies every encrypted artifact with the AAD that wrote it", () => {
  const { dir, noteId, canvasId, attachmentId } = seedVault();

  const items = planRekey(dir);
  const byPath = new Map(items.map((item) => [item.path, item]));

  assert.deepEqual(byPath.get("health.kv.enc"), {
    path: "health.kv.enc",
    kind: "kv",
    identity: "health",
  });
  assert.deepEqual(byPath.get("grants.enc"), {
    path: "grants.enc",
    kind: "kv",
    identity: "grants",
  });
  assert.deepEqual(byPath.get("documents/index.enc"), {
    path: "documents/index.enc",
    kind: "document",
    identity: "secondbrain-vault:document-index:v1",
  });
  assert.deepEqual(byPath.get(`documents/objects/${noteId}.note.enc`), {
    path: `documents/objects/${noteId}.note.enc`,
    kind: "document",
    identity: `secondbrain-vault:note:v1:${noteId}`,
  });
  assert.deepEqual(byPath.get(`documents/objects/${canvasId}.canvas.enc`), {
    path: `documents/objects/${canvasId}.canvas.enc`,
    kind: "document",
    identity: `secondbrain-vault:canvas:v1:${canvasId}`,
  });
  assert.deepEqual(byPath.get(`documents/history/${noteId}/1.note.enc`), {
    path: `documents/history/${noteId}/1.note.enc`,
    kind: "document",
    identity: `secondbrain-vault:note-history:v1:${noteId}:1`,
  });
  assert.deepEqual(byPath.get(`documents/attachments/${attachmentId}/manifest.enc`), {
    path: `documents/attachments/${attachmentId}/manifest.enc`,
    kind: "document",
    identity: `secondbrain-vault:attachment-manifest:v1:${attachmentId}`,
  });
  assert.deepEqual(byPath.get(`documents/attachments/${attachmentId}/0.chunk.enc`), {
    path: `documents/attachments/${attachmentId}/0.chunk.enc`,
    kind: "document",
    identity: `secondbrain-vault:attachment-chunk:v1:${attachmentId}:0`,
  });

  fs.rmSync(dir, { recursive: true, force: true });
});

test("plaintext bookkeeping files are not scheduled for re-encryption", () => {
  const { dir } = seedVault();
  const scheduled = new Set(planRekey(dir).map((item) => item.path));

  for (const untouched of ["keyring.json", "audit.log", "documents/manifest.json"]) {
    assert.equal(scheduled.has(untouched), false, `${untouched} must not be re-encrypted`);
  }

  fs.rmSync(dir, { recursive: true, force: true });
});

test("an unrecognized file under documents/ fails the walk closed", () => {
  const { dir } = seedVault();
  fs.writeFileSync(path.join(dir, "documents", "objects", "surprise.enc"), "{}");

  assert.throws(() => planRekey(dir), /cannot classify/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("an unrecognized encrypted file at the vault root fails the walk closed", () => {
  const { dir } = seedVault();
  fs.writeFileSync(path.join(dir, "mystery.enc"), "{}");

  assert.throws(() => planRekey(dir), /cannot classify/iu);

  fs.rmSync(dir, { recursive: true, force: true });
});
