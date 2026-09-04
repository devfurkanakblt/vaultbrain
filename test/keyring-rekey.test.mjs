import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { appendAudit } from "../dist/audit.js";
import { DocumentVault } from "../dist/documents.js";
import { planRekey } from "../dist/keyring-rekey.js";
import { upsertEntry } from "../dist/store.js";
import { saveGrants, emptyGrantFile } from "../dist/grants.js";
import { SyncChangeLog } from "../dist/sync.js";

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

// Finding 1 (critical): normalizeVaultName must not run a second time on a
// filename base that saveVaultFile already normalized. A key-value file
// whose real identity ends in ".kv" is the case that exposes a double strip.
test("a kv identity that itself ends in .kv is not stripped twice", () => {
  const dir = tempDir();
  upsertEntry(dir, "backup.kv.kv", "SOME_KEY", "some value", "a note", PASSPHRASE);

  const items = planRekey(dir);
  const backup = items.find((item) => item.path === "backup.kv.kv.enc");

  assert.ok(backup, "backup.kv.kv.enc should have been scheduled");
  assert.equal(backup.kind, "kv");
  assert.equal(backup.identity, "backup.kv", "the identity is the normalized filename base, stripped once");

  fs.rmSync(dir, { recursive: true, force: true });
});

// Finding 3 (important): a leftover atomic-write temp file must be treated
// like every other reader in this codebase treats it — as a crash artifact
// no one consults, not as data to classify.
test("a leftover atomic-write temp file under documents/ is skipped, not scheduled", () => {
  const { dir } = seedVault();
  const changesDir = path.join(dir, "documents", "sync", "changes");
  fs.mkdirSync(changesDir, { recursive: true });
  const leftover = path.join(changesDir, ".something.123.11111111-1111-4111-8111-111111111111.tmp");
  fs.writeFileSync(leftover, "partial write");

  const items = planRekey(dir);

  assert.equal(
    items.some((item) => item.path.endsWith(".tmp")),
    false,
    "a .tmp leftover must never be scheduled for re-encryption",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test("a leftover atomic-write temp file at the vault root is skipped, not scheduled", () => {
  const { dir } = seedVault();
  fs.writeFileSync(path.join(dir, ".health.kv.enc.999.22222222-2222-4222-8222-222222222222.tmp"), "partial write");

  const items = planRekey(dir);

  assert.equal(
    items.some((item) => item.path.endsWith(".tmp")),
    false,
    "a .tmp leftover at the vault root must never be scheduled for re-encryption",
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

// Finding 4 (important): every classifier branch, exercised by the real
// writer that produces it where practical. The sync-change branch matters
// most — it is the only place `kind: "sync-change"` is reachable at all, and
// its identity feeds a key derivation in a later task.
test("plugin, plugin storage, plugin policy and canvas history all classify with the AAD that wrote them", () => {
  const dir = tempDir();
  const vault = new DocumentVault(dir, PASSPHRASE);

  const plugin = vault.installPlugin({
    manifest: {
      manifestVersion: 1,
      id: "word-count",
      name: "Word count",
      version: "1.0.0",
      description: "Counts words in the open note",
      author: "someone",
      capabilities: ["notes:read"],
    },
    source: "vbrain.ui.panel('Words', '12');",
  });
  vault.setPluginStorage(plugin.id, { lastCount: "12" });
  vault.setPluginRestrictedMode(true);

  const canvas = vault.putCanvas({ path: "Atlas/Board.canvas", title: "Board", nodes: [], edges: [] });
  vault.putCanvas({
    id: canvas.id,
    path: "Atlas/Board.canvas",
    title: "Board",
    nodes: [{ id: "n1", type: "text", x: 0, y: 0, width: 100, height: 50, text: "note" }],
    edges: [],
  });

  vault.lock();

  const items = planRekey(dir);
  const byPath = new Map(items.map((item) => [item.path, item]));

  assert.deepEqual(byPath.get(`documents/objects/${plugin.id}.plugin.enc`), {
    path: `documents/objects/${plugin.id}.plugin.enc`,
    kind: "document",
    identity: `secondbrain-vault:plugin:v1:${plugin.id}`,
  });
  assert.deepEqual(byPath.get(`documents/objects/${plugin.id}.pluginstore.enc`), {
    path: `documents/objects/${plugin.id}.pluginstore.enc`,
    kind: "document",
    identity: `secondbrain-vault:plugin-store:v1:${plugin.id}`,
  });
  assert.deepEqual(byPath.get("documents/plugin-policy.enc"), {
    path: "documents/plugin-policy.enc",
    kind: "document",
    identity: "secondbrain-vault:plugin-policy:v1",
  });
  assert.deepEqual(byPath.get(`documents/history/${canvas.id}/1.canvas.enc`), {
    path: `documents/history/${canvas.id}/1.canvas.enc`,
    kind: "document",
    identity: `secondbrain-vault:canvas-history:v1:${canvas.id}:1`,
  });

  fs.rmSync(dir, { recursive: true, force: true });
});

test("sync state files and a sync change all classify with the AAD or ID that wrote them", () => {
  const dir = tempDir();
  const log = new SyncChangeLog(dir, PASSPHRASE);
  const deviceId = "33333333-3333-4333-8333-333333333333";
  const change = log.append(deviceId, {
    objectType: "note",
    objectId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    operation: "put",
    baseRevision: null,
    revision: 1,
    value: { title: "Plan", body: "private body" },
  });
  log.markApplied(change);
  log.close();

  // pending-local.enc and apply-receipt.enc are written by
  // SyncLocalTransaction / SyncApplyReceiptStore, whose multi-phase APIs are
  // impractical to drive here — planted directly per the brief's fallback.
  fs.writeFileSync(path.join(dir, "documents", "sync", "pending-local.enc"), "{}");
  fs.writeFileSync(path.join(dir, "documents", "sync", "apply-receipt.enc"), "{}");

  const items = planRekey(dir);
  const byPath = new Map(items.map((item) => [item.path, item]));

  assert.deepEqual(byPath.get(`documents/sync/changes/${change.id}.change.enc`), {
    path: `documents/sync/changes/${change.id}.change.enc`,
    kind: "sync-change",
    identity: change.id,
  });
  assert.deepEqual(byPath.get("documents/sync/applied.enc"), {
    path: "documents/sync/applied.enc",
    kind: "document",
    identity: "secondbrain-vault:sync-applied:v1",
  });
  assert.deepEqual(byPath.get("documents/sync/pending-local.enc"), {
    path: "documents/sync/pending-local.enc",
    kind: "document",
    identity: "secondbrain-vault:sync-local-transaction:v1",
  });
  assert.deepEqual(byPath.get("documents/sync/apply-receipt.enc"), {
    path: "documents/sync/apply-receipt.enc",
    kind: "document",
    identity: "secondbrain-vault:sync-apply-receipt:v1",
  });

  fs.rmSync(dir, { recursive: true, force: true });
});
