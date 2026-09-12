import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { SyncedDocumentVault } from "../dist/sync.js";
import { DocumentVault } from "../dist/documents.js";
import { decryptDocument } from "../dist/document-crypto.js";
import { parsePortableState } from "../dist/portable-state.js";
import { runPortableRecoveryDrill } from "../scripts/portable-recovery-drill.mjs";
import { rekeyVault } from "../dist/keyring-rekey.js";

test("encrypted backup plus relay catch-up restores every portable live object", async () => {
  assert.equal((await runPortableRecoveryDrill()).ok, true);
});

test("portable state remains readable after an ordinary content re-key", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "portable-rekey-"));
  let vault;
  try {
    vault = new SyncedDocumentVault(root, "portable-before-passphrase", "11111111-1111-4111-8111-111111111111");
    const state = { version: 1, bookmarks: [{ id: "note", label: "Keep me", createdAt: "2026-09-11T00:00:00.000Z" }], layouts: [] };
    vault.setPortableState("workspace", state);
    vault.setPortableState("saved-views", { version: 1, views: [] });
    vault.lock();
    rekeyVault(root, "portable-before-passphrase", "portable-after-passphrase");
    vault = new SyncedDocumentVault(root, "portable-after-passphrase");
    assert.deepEqual(vault.getPortableState("workspace"), state);
    assert.deepEqual(vault.getPortableState("saved-views"), { version: 1, views: [] });
  } finally { vault?.lock(); fs.rmSync(root, { recursive: true, force: true }); }
});

test("the shared native workspace vector fixes the ciphertext contract", () => {
  const vector = JSON.parse(fs.readFileSync(new URL("./fixtures/portable-workspace-vector.json", import.meta.url), "utf8"));
  assert.deepEqual(JSON.parse(decryptDocument(vector.payload, Buffer.from(vector.key, "base64"), "secondbrain-vault:workspace:v1")), vector.value);
  assert.throws(() => decryptDocument(vector.payload, Buffer.from(vector.key, "base64"), "secondbrain-vault:saved-views:v1"));
  assert.throws(() => parsePortableState("workspace", { ...vector.value, localPath: "C:/private" }), /Unknown/);
  assert.throws(() => parsePortableState("saved-views", { version: 2, views: [] }), /version/);
});

test("native disk edits are captured once without creating new storage revisions", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "desktop-capture-"));
  let native, synced;
  try {
    native = new DocumentVault(root, "portable-test-passphrase");
    const note = native.put({ path: "Native.md", body: "written outside sync" });
    native.lock();
    synced = new SyncedDocumentVault(root, "portable-test-passphrase", "11111111-1111-4111-8111-111111111111");
    assert.ok(synced.captureDesktopChanges().captured > 0);
    const count = synced.changeLog.changes().length;
    assert.equal(synced.get(note.id).revision, note.revision);
    assert.equal(synced.captureDesktopChanges().captured, 0);
    assert.equal(synced.changeLog.changes().length, count);
    synced.lock();
    native = new DocumentVault(root, "portable-test-passphrase");
    native.remove(note.id);
    native.lock();
    synced = new SyncedDocumentVault(root, "portable-test-passphrase", "11111111-1111-4111-8111-111111111111");
    assert.equal(synced.captureDesktopChanges().captured, 1);
    assert.equal(synced.changeLog.resolve("note", note.id).winner.mutation.operation, "delete");
  } finally {
    native?.lock(); synced?.lock();
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("portable workspace travels to another vault without losing bookmarks", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "portable-sync-"));
  let source, target;
  try {
    const from = path.join(root, "from");
    const to = path.join(root, "to");
    source = new SyncedDocumentVault(from, "portable-test-passphrase", "11111111-1111-4111-8111-111111111111");
    source.lock();
    fs.cpSync(from, to, { recursive: true });
    source = new SyncedDocumentVault(from, "portable-test-passphrase", "11111111-1111-4111-8111-111111111111");
    const state = { version: 1, bookmarks: [{ id: "note-id", label: "Pinned", createdAt: "2026-09-09T00:00:00Z" }], layouts: [] };
    source.setPortableState("workspace", state);
    target = new SyncedDocumentVault(to, "portable-test-passphrase");
    target.changeLog.import(source.changeLog.envelopes());
    assert.equal(target.applyResolved("vault", "workspace").conflict, undefined);
    assert.deepEqual(target.getPortableState("workspace"), state);
    assert.equal(target.applyResolved("vault", "workspace").alreadyApplied, true);
    assert.ok(!fs.readFileSync(path.join(to, "documents", "workspace.enc"), "utf8").includes("Pinned"));
  } finally {
    source?.lock(); target?.lock();
    fs.rmSync(root, { recursive: true, force: true });
  }
});
