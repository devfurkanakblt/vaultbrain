import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault, validateRetentionPolicy } from "../dist/documents.js";

const PASSPHRASE = "vault-retention-test-passphrase";

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-retention-${label}-`));
}

function historyNames(vaultDir, id) {
  const dir = path.join(vaultDir, "documents", "history", id);
  return fs.existsSync(dir) ? fs.readdirSync(dir).sort() : [];
}

/** Writes `count` revisions of one note and returns it. */
function editRepeatedly(vault, count) {
  const note = vault.put({ path: "Journal.md", title: "Journal", body: "revision 1" });
  for (let revision = 2; revision <= count; revision += 1) {
    vault.put({
      id: note.id,
      path: note.path,
      title: "Journal",
      body: `revision ${revision}`,
      baseRevision: revision - 1,
    });
  }
  return note;
}

test("a vault keeps every revision until it is asked not to", () => {
  const dir = tempVault("default");
  const vault = new DocumentVault(dir, PASSPHRASE);

  assert.deepEqual(vault.getRetentionPolicy(), {
    version: 1,
    keepRevisions: null,
    keepDays: null,
  });

  const note = editRepeatedly(vault, 6);
  assert.equal(historyNames(dir, note.id).length, 5, "five archived plus the live one");
  assert.equal(vault.revisions(note.id).length, 6);
});

test("a revision count policy bounds history as it is written", () => {
  const dir = tempVault("count");
  const vault = new DocumentVault(dir, PASSPHRASE);
  vault.setRetentionPolicy({ version: 1, keepRevisions: 2, keepDays: null });

  const note = editRepeatedly(vault, 6);

  // Two archived revisions, plus the live one that is not archived at all.
  assert.deepEqual(historyNames(dir, note.id), ["4.note.enc", "5.note.enc"]);
  assert.deepEqual(
    vault.revisions(note.id).map((entry) => entry.revision),
    [6, 5, 4],
  );
  // The ones it kept still open.
  assert.equal(vault.getRevision(note.id, 4).body, "revision 4");
  assert.throws(() => vault.getRevision(note.id, 1), /not found/iu);
});

test("setting a policy applies it to the history that already exists", () => {
  const dir = tempVault("retroactive");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const note = editRepeatedly(vault, 8);
  const canvasBoard = (overrides = {}) => ({
    path: "Board.canvas",
    title: "Board",
    nodes: [{ id: "n1", type: "text", text: "x", x: 0, y: 0, width: 10, height: 10 }],
    edges: [],
    ...overrides,
  });
  const canvas = vault.putCanvas(canvasBoard());
  vault.putCanvas(canvasBoard({ id: canvas.id, title: "Board 2", baseRevision: 1 }));
  vault.putCanvas(canvasBoard({ id: canvas.id, title: "Board 3", baseRevision: 2 }));

  assert.equal(historyNames(dir, note.id).length, 7);
  assert.equal(historyNames(dir, canvas.id).length, 2);

  const report = vault.setRetentionPolicy({ version: 1, keepRevisions: 1, keepDays: null });

  assert.equal(report.policy.keepRevisions, 1);
  assert.equal(report.objectsExamined, 2);
  assert.equal(report.objectsPruned, 2);
  assert.equal(report.revisionsRemoved, 6 + 1);
  assert.deepEqual(historyNames(dir, note.id), ["7.note.enc"]);
  assert.deepEqual(historyNames(dir, canvas.id), ["2.canvas.enc"]);

  // A second sweep with nothing left to do reports honestly.
  const again = vault.sweepRetention();
  assert.equal(again.revisionsRemoved, 0);
  assert.equal(again.objectsPruned, 0);
  assert.equal(again.objectsExamined, 2);
});

test("an age policy drops revisions by their own timestamp", () => {
  const dir = tempVault("age");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const note = editRepeatedly(vault, 3);
  assert.equal(historyNames(dir, note.id).length, 2);

  // Nothing is old yet, so a 30-day bound removes nothing.
  const fresh = vault.setRetentionPolicy({ version: 1, keepRevisions: null, keepDays: 30 });
  assert.equal(fresh.revisionsRemoved, 0);
  assert.equal(historyNames(dir, note.id).length, 2);

  // Swept against an instant 40 days on, both archived revisions are past the
  // bound. The live one is untouched: it was never archived, and a retention
  // policy prunes history, not the note.
  const later = Date.now() + 40 * 24 * 60 * 60 * 1000;
  const report = vault.sweepRetention(later);

  assert.equal(report.revisionsRemoved, 2);
  assert.deepEqual(historyNames(dir, note.id), []);
  assert.equal(vault.get(note.id).body, "revision 3");
  assert.equal(vault.revisions(note.id).length, 1);
});

test("a policy survives a lock, and is stored encrypted", () => {
  const dir = tempVault("persist");
  const vault = new DocumentVault(dir, PASSPHRASE);
  vault.setRetentionPolicy({ version: 1, keepRevisions: 3, keepDays: 90 });
  vault.lock();

  const reopened = new DocumentVault(dir, PASSPHRASE);
  assert.deepEqual(reopened.getRetentionPolicy(), {
    version: 1,
    keepRevisions: 3,
    keepDays: 90,
  });

  const stored = fs.readFileSync(path.join(dir, "documents", "retention.enc"), "utf8");
  assert.equal(stored.includes("keepRevisions"), false);
  assert.equal(JSON.parse(stored).version, 1);
});

test("a policy the vault cannot honour is refused rather than rounded", () => {
  assert.deepEqual(validateRetentionPolicy({ version: 1 }), {
    version: 1,
    keepRevisions: null,
    keepDays: null,
  });
  assert.throws(() => validateRetentionPolicy({ version: 2 }), /Unsupported retention policy/u);
  assert.throws(() => validateRetentionPolicy({ version: 1, keepRevisions: 0 }), /between 1 and/u);
  assert.throws(() => validateRetentionPolicy({ version: 1, keepRevisions: -1 }), /between 1 and/u);
  assert.throws(() => validateRetentionPolicy({ version: 1, keepDays: 1.5 }), /between 1 and/u);
  assert.throws(() => validateRetentionPolicy({ version: 1, keepDays: 40000 }), /between 1 and/u);
});
