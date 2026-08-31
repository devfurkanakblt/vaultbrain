import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { openDocumentKey } from "../dist/document-crypto.js";
import {
  SyncChangeLog,
  SyncedDocumentVault,
  canonicalSyncJson,
  openSyncChange,
  sealSyncChange,
} from "../dist/sync.js";

const PASSPHRASE = "sync-test-passphrase";
const DEVICE_A = "11111111-1111-4111-8111-111111111111";
const DEVICE_B = "22222222-2222-4222-8222-222222222222";

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `secondbrain-sync-${label}-`));
}

function noteMutation(baseRevision, revision, body) {
  return {
    objectType: "note",
    objectId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    operation: "put",
    baseRevision,
    revision,
    value: { title: "Plan", body },
  };
}

test("canonical sync JSON and keyed change IDs are stable without leaking content", () => {
  assert.equal(
    canonicalSyncJson({ z: 1, nested: { b: true, a: "x" }, list: [3, null] }),
    '{"list":[3,null],"nested":{"a":"x","b":true},"z":1}',
  );
  const vaultDir = tempVault("canonical");
  const session = openDocumentKey(vaultDir, PASSPHRASE);
  const body = {
    version: 1,
    deviceId: DEVICE_A,
    sequence: 1,
    previousDeviceChange: null,
    parents: [],
    createdAt: "2026-08-31T08:30:00.000Z",
    mutation: noteMutation(null, 1, "private body"),
  };
  const first = sealSyncChange(body, session.key);
  const second = sealSyncChange(
    { ...body, mutation: { ...body.mutation, value: { body: "private body", title: "Plan" } } },
    session.key,
  );
  assert.equal(first.id, second.id, "object key order must not change identity");
  assert.notEqual(first.payload.iv, second.payload.iv, "every envelope gets a fresh nonce");
  assert.deepEqual(openSyncChange(first, session.key).mutation.value, { body: "private body", title: "Plan" });
  assert.doesNotMatch(JSON.stringify(first), /private body/u);

  const renamed = { ...first, id: `${first.id.slice(0, -1)}${first.id.endsWith("0") ? "1" : "0"}` };
  assert.throws(() => openSyncChange(renamed, session.key));
  assert.throws(
    () => openSyncChange({ ...first, payload: { ...first.payload, iv: "not-base64" } }, session.key),
    /malformed nonce/iu,
  );
  session.key.fill(0);
  fs.rmSync(vaultDir, { recursive: true, force: true });
});

test("the local log appends an immutable encrypted device chain", () => {
  const vaultDir = tempVault("append");
  const log = new SyncChangeLog(vaultDir, PASSPHRASE);
  const created = log.append(DEVICE_A, noteMutation(null, 1, "first private version"), "2026-08-31T09:00:00.000Z");
  const updated = log.append(DEVICE_A, noteMutation(1, 2, "second private version"), "2026-08-31T09:01:00.000Z");
  assert.equal(updated.sequence, 2);
  assert.equal(updated.previousDeviceChange, created.id);
  assert.ok(updated.parents.includes(created.id));
  assert.deepEqual(log.verify(), { changes: 2, devices: 1, heads: [updated.id] });

  const changeDir = path.join(vaultDir, "documents", "sync", "changes");
  const encrypted = fs
    .readdirSync(changeDir)
    .map((name) => fs.readFileSync(path.join(changeDir, name), "utf8"))
    .join("\n");
  assert.doesNotMatch(encrypted, /first private version|second private version/u);
  assert.equal(fs.readdirSync(changeDir).length, 2);
  log.close();
  assert.throws(() => log.changes(), /closed/iu);
  fs.rmSync(vaultDir, { recursive: true, force: true });
});

test("concurrent device edits remain visible and a causal merge resolves them", () => {
  const vaultA = tempVault("device-a");
  const firstLog = new SyncChangeLog(vaultA, PASSPHRASE);
  const base = firstLog.append(DEVICE_A, noteMutation(null, 1, "base"), "2026-08-31T10:00:00.000Z");
  firstLog.close();

  const vaultB = tempVault("device-b");
  fs.rmSync(vaultB, { recursive: true, force: true });
  fs.cpSync(vaultA, vaultB, { recursive: true });
  const logA = new SyncChangeLog(vaultA, PASSPHRASE);
  const logB = new SyncChangeLog(vaultB, PASSPHRASE);
  const branchA = logA.append(DEVICE_A, noteMutation(1, 2, "edit from A"), "2026-08-31T10:01:00.000Z");
  const branchB = logB.append(DEVICE_B, noteMutation(1, 2, "edit from B"), "2026-08-31T10:02:00.000Z");
  assert.equal(branchA.parents[0], base.id);
  assert.equal(branchB.parents[0], base.id);

  assert.deepEqual(logA.import(logB.envelopes()), { imported: 1, existing: 1 });
  assert.deepEqual(logB.import(logA.envelopes()), { imported: 1, existing: 2 });
  const resolutionA = logA.resolve("note", base.mutation.objectId);
  const resolutionB = logB.resolve("note", base.mutation.objectId);
  assert.equal(resolutionA.status, "conflict");
  assert.equal(resolutionA.winner.id, resolutionB.winner.id);
  assert.deepEqual(new Set(resolutionA.heads), new Set([branchA.id, branchB.id]));
  assert.equal(resolutionA.conflicts.length, 1, "the losing branch stays available");

  const merged = logB.append(DEVICE_B, noteMutation(2, 3, "merged A + B"), "2026-08-31T10:03:00.000Z");
  assert.ok(merged.parents.includes(branchA.id));
  assert.ok(merged.parents.includes(branchB.id));
  assert.equal(logB.resolve("note", base.mutation.objectId).status, "clean");
  logA.import(logB.envelopes());
  assert.equal(logA.resolve("note", base.mutation.objectId).winner.id, merged.id);

  logA.close();
  logB.close();
  fs.rmSync(vaultA, { recursive: true, force: true });
  fs.rmSync(vaultB, { recursive: true, force: true });
});

test("imports fail closed on device forks without writing a partial batch", () => {
  const vaultDir = tempVault("fork");
  const log = new SyncChangeLog(vaultDir, PASSPHRASE);
  const base = log.append(DEVICE_A, noteMutation(null, 1, "base"), "2026-08-31T11:00:00.000Z");
  const session = openDocumentKey(vaultDir, PASSPHRASE);
  const fork = sealSyncChange(
    {
      version: 1,
      deviceId: DEVICE_A,
      sequence: 2,
      previousDeviceChange: base.id,
      parents: [base.id],
      createdAt: "2026-08-31T11:01:00.000Z",
      mutation: noteMutation(1, 2, "forked edit"),
    },
    session.key,
  );
  log.append(DEVICE_A, noteMutation(1, 2, "real edit"), "2026-08-31T11:02:00.000Z");
  const before = log.envelopes().length;
  assert.throws(() => log.import([fork]), /fork/iu);
  assert.equal(log.envelopes().length, before);
  session.key.fill(0);
  log.close();
  fs.rmSync(vaultDir, { recursive: true, force: true });
});

test("an out-of-order batch is installed parent-first and remains valid after interruption boundaries", () => {
  const sourceDir = tempVault("ordered-source");
  const source = new SyncChangeLog(sourceDir, PASSPHRASE);
  source.append(DEVICE_A, noteMutation(null, 1, "base"), "2026-08-31T12:00:00.000Z");
  source.append(DEVICE_A, noteMutation(1, 2, "child"), "2026-08-31T12:01:00.000Z");

  const targetDir = tempVault("ordered-target");
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.cpSync(sourceDir, targetDir, { recursive: true });
  const targetChanges = path.join(targetDir, "documents", "sync", "changes");
  fs.rmSync(targetChanges, { recursive: true, force: true });
  fs.mkdirSync(targetChanges, { recursive: true });
  const target = new SyncChangeLog(targetDir, PASSPHRASE);
  const reversed = source.envelopes().reverse();
  assert.deepEqual(target.import(reversed), { imported: 2, existing: 0 });
  assert.equal(target.verify().changes, 2);

  source.close();
  target.close();
  fs.rmSync(sourceDir, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

test("synced document operations automatically emit note, canvas and attachment changes", () => {
  const vaultDir = tempVault("automatic-capture");
  const vault = new SyncedDocumentVault(vaultDir, PASSPHRASE, DEVICE_A);

  const note = vault.put({ path: "Plans/Launch.md", body: "first" });
  vault.put({ id: note.id, path: note.path, title: note.title, body: "second", baseRevision: note.revision });
  const canvas = vault.putCanvas({ path: "Boards/Launch.canvas", nodes: [], edges: [] });
  vault.removeCanvas(canvas.id);
  const attachment = vault.putAttachment(Buffer.from("private attachment"), "brief.txt", "text/plain");
  vault.removeAttachment(attachment.id);

  const changes = vault.changeLog.changes();
  assert.deepEqual(
    changes.map((change) => [change.mutation.objectType, change.mutation.operation, change.mutation.revision]),
    [
      ["note", "put", 1],
      ["note", "put", 2],
      ["canvas", "put", 1],
      ["canvas", "delete", 2],
      ["attachment", "put", 1],
      ["attachment", "delete", 2],
    ],
  );
  assert.equal(vault.changeLog.applied("note", note.id).revision, 2);
  assert.equal(vault.changeLog.applied("canvas", canvas.id).operation, "delete");
  assert.equal(vault.changeLog.applied("attachment", attachment.id).operation, "delete");
  const disk = fs.readFileSync(path.join(vaultDir, "documents", "sync", "applied.enc"), "utf8");
  assert.doesNotMatch(disk, /Launch|brief|attachment/u);

  vault.lock();
  fs.rmSync(vaultDir, { recursive: true, force: true });
});

test("clean remote changes apply idempotently to the real vault storage", () => {
  const sourceDir = tempVault("apply-source");
  let source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  const note = source.put({ path: "Shared/Plan.md", body: "base" });
  const canvas = source.putCanvas({
    path: "Shared/Board.canvas",
    nodes: [{ id: "text", type: "text", x: 0, y: 0, width: 200, height: 100, text: "base" }],
    edges: [],
  });
  const attachment = source.putAttachment(Buffer.from("shared bytes"), "shared.txt", "text/plain");
  source.lock();

  const targetDir = tempVault("apply-target");
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.cpSync(sourceDir, targetDir, { recursive: true });

  source = new SyncedDocumentVault(sourceDir, PASSPHRASE, DEVICE_A);
  source.put({ id: note.id, path: note.path, title: note.title, body: "remote edit", baseRevision: 1 });
  source.putCanvas({
    id: canvas.id,
    path: canvas.path,
    title: canvas.title,
    baseRevision: 1,
    nodes: [{ id: "text", type: "text", x: 0, y: 0, width: 200, height: 100, text: "remote edit" }],
    edges: [],
  });
  source.removeAttachment(attachment.id);

  const target = new SyncedDocumentVault(targetDir, PASSPHRASE);
  target.changeLog.import(source.changeLog.envelopes());
  assert.equal(target.applyResolved("note", note.id).applied, 1);
  assert.equal(target.applyResolved("canvas", canvas.id).applied, 1);
  assert.equal(target.applyResolved("attachment", attachment.id).applied, 1);
  assert.equal(target.get(note.id).body, "remote edit");
  assert.equal(target.getCanvas(canvas.id).nodes[0].text, "remote edit");
  assert.equal(target.listAttachments().some((item) => item.id === attachment.id), false);
  assert.deepEqual(target.applyResolved("note", note.id), {
    objectType: "note",
    objectId: note.id,
    changeId: source.changeLog.resolve("note", note.id).winner.id,
    revision: 2,
    applied: 0,
    alreadyApplied: true,
  });

  source.lock();
  target.lock();
  fs.rmSync(sourceDir, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

test("unresolved remote conflicts never mutate live vault storage", () => {
  const firstDir = tempVault("apply-conflict-a");
  let first = new SyncedDocumentVault(firstDir, PASSPHRASE, DEVICE_A);
  const note = first.put({ path: "Conflict.md", body: "base" });
  first.lock();

  const secondDir = tempVault("apply-conflict-b");
  fs.rmSync(secondDir, { recursive: true, force: true });
  fs.cpSync(firstDir, secondDir, { recursive: true });
  first = new SyncedDocumentVault(firstDir, PASSPHRASE, DEVICE_A);
  const second = new SyncedDocumentVault(secondDir, PASSPHRASE, DEVICE_B);
  first.put({ id: note.id, path: note.path, body: "from A", baseRevision: 1 });
  second.put({ id: note.id, path: note.path, body: "from B", baseRevision: 1 });
  first.changeLog.import(second.changeLog.envelopes());

  assert.equal(first.changeLog.resolve("note", note.id).status, "conflict");
  assert.throws(() => first.applyResolved("note", note.id), /unresolved sync heads/iu);
  assert.equal(first.get(note.id).body, "from A");

  first.lock();
  second.lock();
  fs.rmSync(firstDir, { recursive: true, force: true });
  fs.rmSync(secondDir, { recursive: true, force: true });
});
