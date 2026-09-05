import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { SyncedDocumentVault } from "../dist/sync.js";

const PASSPHRASE = "sync-apply-test-passphrase";
const DEVICE_A = "11111111-1111-4111-8111-111111111111";
const DEVICE_B = "22222222-2222-4222-8222-222222222222";

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-sync-apply-${label}-`));
}

function closeAndRemove(vault, vaultDir) {
  vault?.lock();
  fs.rmSync(vaultDir, { recursive: true, force: true });
}

// A device receives sealed attachment chunks out of band, the way `sync relay
// pull` will deliver them; without them an attachment change cannot be applied.
function stageBlobs(fromDir, toDir) {
  const from = path.join(fromDir, "documents", "sync", "blobs");
  if (!fs.existsSync(from)) return;
  fs.cpSync(from, path.join(toDir, "documents", "sync", "blobs"), { recursive: true });
}

function copyVault(from, label) {
  const to = tempVault(label);
  fs.rmSync(to, { recursive: true, force: true });
  fs.cpSync(from, to, { recursive: true });
  return to;
}

test("an asymmetric clean merge applies its required off-cursor ancestor before the winner", () => {
  const baseDir = tempVault("asymmetric-base");
  let base = new SyncedDocumentVault(baseDir, PASSPHRASE, DEVICE_A);
  const note = base.put({ path: "Shared/Plan.md", body: "base" });
  base.lock();

  const sourceDir = copyVault(baseDir, "asymmetric-source");
  const branchDir = copyVault(baseDir, "asymmetric-branch");
  const targetDir = copyVault(baseDir, "asymmetric-target");

  let source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  source.put({ id: note.id, path: note.path, body: "from A", baseRevision: 1 });
  source.lock();
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.cpSync(sourceDir, targetDir, { recursive: true });

  const branch = new SyncedDocumentVault(branchDir, PASSPHRASE, DEVICE_B);
  branch.put({ id: note.id, path: note.path, body: "from B", baseRevision: 1 });
  branch.lock();

  source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  const branchForImport = new SyncedDocumentVault(branchDir, PASSPHRASE);
  source.changeLog.import(branchForImport.changeLog.envelopes());
  const merged = source.put({ id: note.id, path: note.path, body: "merged", baseRevision: 2 });

  const target = new SyncedDocumentVault(targetDir, PASSPHRASE);
  target.changeLog.import(source.changeLog.envelopes());
  const result = target.applyResolved("note", note.id);
  assert.deepEqual(
    [
      result.applied,
      target.getRevision(note.id, 3).body,
      target.get(note.id).body,
      target.revisions(note.id).map((item) => item.revision),
    ],
    [2, "from B", "merged", [4, 3, 2, 1]],
  );
  assert.equal(result.changeId, source.changeLog.resolve("note", note.id).winner.id);
  assert.equal(result.revision, 3);
  assert.equal(merged.revision, 3);

  closeAndRemove(base, baseDir);
  closeAndRemove(source, sourceDir);
  closeAndRemove(branchForImport, branchDir);
  closeAndRemove(target, targetDir);
});

test("an unresolved remote conflict returns its heads without writing live state or cursor", () => {
  const firstDir = tempVault("conflict-first");
  let first = new SyncedDocumentVault(firstDir, PASSPHRASE, DEVICE_A);
  const note = first.put({ path: "Conflict.md", body: "base" });
  first.lock();

  const secondDir = copyVault(firstDir, "conflict-second");
  first = new SyncedDocumentVault(firstDir, PASSPHRASE, DEVICE_A);
  const second = new SyncedDocumentVault(secondDir, PASSPHRASE, DEVICE_B);
  first.put({ id: note.id, path: note.path, body: "from A", baseRevision: 1 });
  second.put({ id: note.id, path: note.path, body: "from B", baseRevision: 1 });
  first.changeLog.import(second.changeLog.envelopes());
  const heads = first.changeLog
    .changes()
    .filter((change) => change.mutation.objectId === note.id && change.mutation.revision === 2)
    .map((change) => change.id)
    .sort();
  const firstHead = first.changeLog
    .changes()
    .find(
      (change) =>
        change.deviceId === DEVICE_A && change.mutation.objectId === note.id && change.mutation.revision === 2,
    );

  const result = first.applyResolved("note", note.id);

  assert.deepEqual(result, {
    objectType: "note",
    objectId: note.id,
    changeId: heads.at(-1),
    revision: 2,
    applied: 0,
    alreadyApplied: false,
    conflict: true,
    heads,
  });
  assert.equal(first.get(note.id).body, "from A");
  assert.deepEqual(
    first.revisions(note.id).map((item) => item.revision),
    [2, 1],
  );
  assert.equal(first.changeLog.applied("note", note.id).changeId, firstHead.id);

  closeAndRemove(first, firstDir);
  closeAndRemove(second, secondDir);
});

function applyFaultAtStorage() {
  return ({ phase, timing }) => {
    if (phase === "storage-written" && timing === "after-effect") {
      throw new Error("Injected remote storage-written after-effect fault.");
    }
  };
}

function setupRemoteScenario(label) {
  const sourceDir = tempVault(`remote-${label}-source`);
  let source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  switch (label) {
    case "note-put": {
      const note = source.put({ path: "Note.md", body: "base" });
      source.lock();
      const targetDir = copyVault(sourceDir, `remote-${label}-target`);
      source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
      source.put({ id: note.id, path: note.path, body: "remote", baseRevision: 1 });
      return {
        source,
        sourceDir,
        targetDir,
        objectType: "note",
        objectId: note.id,
        expectedRevision: 2,
        verify(vault) {
          assert.deepEqual(
            vault.revisions(note.id).map((item) => item.revision),
            [2, 1],
          );
          assert.equal(vault.get(note.id).body, "remote");
        },
      };
    }
    case "note-delete": {
      const note = source.put({ path: "Note.md", body: "base" });
      source.lock();
      const targetDir = copyVault(sourceDir, `remote-${label}-target`);
      source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
      source.remove(note.id);
      return {
        source,
        sourceDir,
        targetDir,
        objectType: "note",
        objectId: note.id,
        expectedRevision: 2,
        verify(vault) {
          assert.deepEqual(
            vault.revisions(note.id).map((item) => item.revision),
            [1],
          );
          assert.throws(() => vault.get(note.id), /not found/iu);
        },
      };
    }
    case "canvas-put": {
      const canvas = source.putCanvas({ path: "Board.canvas", nodes: [], edges: [] });
      source.lock();
      const targetDir = copyVault(sourceDir, `remote-${label}-target`);
      source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
      source.putCanvas({
        id: canvas.id,
        path: canvas.path,
        nodes: [{ id: "remote", type: "text", x: 0, y: 0, width: 1, height: 1, text: "remote" }],
        edges: [],
        baseRevision: 1,
      });
      return {
        source,
        sourceDir,
        targetDir,
        objectType: "canvas",
        objectId: canvas.id,
        expectedRevision: 2,
        verify(vault) {
          assert.deepEqual(
            vault.canvasRevisions(canvas.id).map((item) => item.revision),
            [2, 1],
          );
          assert.equal(vault.getCanvas(canvas.id).nodes[0].text, "remote");
        },
      };
    }
    case "canvas-delete": {
      const canvas = source.putCanvas({ path: "Board.canvas", nodes: [], edges: [] });
      source.lock();
      const targetDir = copyVault(sourceDir, `remote-${label}-target`);
      source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
      source.removeCanvas(canvas.id);
      return {
        source,
        sourceDir,
        targetDir,
        objectType: "canvas",
        objectId: canvas.id,
        expectedRevision: 2,
        verify(vault) {
          assert.deepEqual(
            vault.canvasRevisions(canvas.id).map((item) => item.revision),
            [1],
          );
          assert.throws(() => vault.getCanvas(canvas.id), /not found/iu);
        },
      };
    }
    case "attachment-put": {
      const attachment = source.putAttachment(Buffer.from("base attachment"), "base.txt", "text/plain");
      source.lock();
      const targetDir = copyVault(sourceDir, `remote-${label}-target`);
      source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
      const remote = source.putAttachment(Buffer.from("remote attachment"), "remote.txt", "text/plain");
      return {
        source,
        sourceDir,
        targetDir,
        objectType: "attachment",
        objectId: remote.id,
        expectedRevision: 1,
        verify(vault) {
          assert.equal(vault.listAttachments().length, 2);
          assert.equal(vault.getAttachment(remote.id).data.toString(), "remote attachment");
          assert.equal(vault.getAttachment(attachment.id).data.toString(), "base attachment");
        },
      };
    }
    case "attachment-delete": {
      const attachment = source.putAttachment(Buffer.from("base attachment"), "base.txt", "text/plain");
      source.lock();
      const targetDir = copyVault(sourceDir, `remote-${label}-target`);
      source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
      source.removeAttachment(attachment.id);
      return {
        source,
        sourceDir,
        targetDir,
        objectType: "attachment",
        objectId: attachment.id,
        expectedRevision: 2,
        verify(vault) {
          assert.equal(vault.listAttachments().length, 0);
        },
      };
    }
    default:
      throw new Error(`Unknown remote scenario: ${label}`);
  }
}

for (const scenarioName of [
  "note-put",
  "note-delete",
  "canvas-put",
  "canvas-delete",
  "attachment-put",
  "attachment-delete",
]) {
  test(`${scenarioName} recovery never repeats a remote mutation after storage succeeds`, () => {
    const scenario = setupRemoteScenario(scenarioName);
    let target = new SyncedDocumentVault(scenario.targetDir, PASSPHRASE, undefined, {
      applyFaultInjector: applyFaultAtStorage(),
    });
    target.changeLog.import(scenario.source.changeLog.envelopes());
    stageBlobs(scenario.sourceDir, scenario.targetDir);
    assert.throws(
      () => target.applyResolved(scenario.objectType, scenario.objectId),
      /remote storage-written after-effect/iu,
    );
    target.lock();
    target = new SyncedDocumentVault(scenario.targetDir, PASSPHRASE);
    scenario.verify(target);
    assert.equal(target.changeLog.applied(scenario.objectType, scenario.objectId).revision, scenario.expectedRevision);

    closeAndRemove(scenario.source, scenario.sourceDir);
    closeAndRemove(target, scenario.targetDir);
  });
}

test("applying an attachment change fails closed while its blobs are missing", async () => {
  const { parseAttachmentSnapshot } = await import("../dist/sync.js");
  const { SyncBlobStore } = await import("../dist/sync-blobs.js");

  const sourceDir = tempVault("blob-apply-source");
  let source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  source.lock();
  const targetDir = copyVault(sourceDir, "blob-apply-target");

  source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  const data = crypto.randomBytes(3 * 1024 * 1024 + 11);
  const info = source.putAttachment(data, "clip.bin", "application/octet-stream");

  // The target device receives the envelopes but not yet the blobs.
  let target = new SyncedDocumentVault(targetDir, PASSPHRASE);
  target.changeLog.import(source.changeLog.envelopes());
  assert.throws(() => target.applyResolved("attachment", info.id), /of 4 attachment chunks are missing/iu);
  assert.equal(target.listAttachments().length, 0);
  const snapshot = parseAttachmentSnapshot(target.changeLog.resolve("attachment", info.id).winner.mutation.value);
  assert.equal(snapshot.blobs.length, 4);
  // The refusal left no receipt behind: the vault reopens cleanly and still
  // holds nothing partial.
  target.lock();
  target = new SyncedDocumentVault(targetDir, PASSPHRASE);
  assert.equal(target.listAttachments().length, 0);

  // Once every blob is staged, the same apply succeeds and the bytes verify.
  const from = new SyncBlobStore(sourceDir);
  const to = new SyncBlobStore(targetDir);
  for (const id of snapshot.blobs) to.put(id, from.read(id));

  target.applyResolved("attachment", info.id);
  assert.deepEqual(target.getAttachment(info.id).data, data);

  closeAndRemove(source, sourceDir);
  closeAndRemove(target, targetDir);
});
