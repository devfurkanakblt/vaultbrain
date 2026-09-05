import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DocumentVault } from "../dist/documents.js";
import { SyncedDocumentVault } from "../dist/sync.js";

const PASSPHRASE = "vault-purge-test-passphrase";
const DEVICE_A = "11111111-1111-4111-8111-111111111111";

function tempVault(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vault-brain-purge-${label}-`));
}

function historyDir(vaultDir, id) {
  return path.join(vaultDir, "documents", "history", id);
}

function objectPath(vaultDir, id, suffix) {
  return path.join(vaultDir, "documents", "objects", `${id}${suffix}`);
}

/** A note with three revisions, so there is real history to remove. */
function noteWithHistory(vault) {
  const first = vault.put({ path: "Health/Results.md", title: "Results", body: "one" });
  vault.put({ id: first.id, path: first.path, title: "Results", body: "two", baseRevision: 1 });
  vault.put({ id: first.id, path: first.path, title: "Results", body: "three", baseRevision: 2 });
  return first;
}

test("remove keeps the content, purge does not", () => {
  const dir = tempVault("note");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const note = noteWithHistory(vault);
  const keeper = vault.put({ path: "Keep.md", title: "Keep", body: "untouched" });
  vault.put({ id: keeper.id, path: keeper.path, title: "Keep", body: "still here", baseRevision: 1 });

  // remove archives the outgoing revision: the content is still in the vault.
  vault.remove(note.id);
  assert.equal(vault.revisions(note.id).length, 3);
  assert.equal(fs.existsSync(historyDir(dir, note.id)), true);
  assert.equal(vault.getRevision(note.id, 3).body, "three");

  const report = vault.purgeNote(note.id);

  assert.equal(report.kind, "note");
  assert.equal(report.id, note.id);
  assert.equal(report.liveRemoved, false, "it had already been removed");
  assert.equal(report.revisionsRemoved, 3);
  assert.equal(report.syncChangesPresent, 0);

  assert.equal(fs.existsSync(historyDir(dir, note.id)), false);
  // The id is not a thing the vault knows about any more. A removed note still
  // resolves through its history; a purged one has none to resolve through.
  assert.throws(() => vault.revisions(note.id), /not found/iu);
  assert.throws(() => vault.getRevision(note.id, 3), /not found/iu);

  // Nothing else lost its history.
  assert.equal(vault.revisions(keeper.id).length, 2);
  assert.equal(vault.get(keeper.id).body, "still here");
});

test("purging a live note takes the object and its history in one step", () => {
  const dir = tempVault("live");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const note = noteWithHistory(vault);

  const report = vault.purgeNote("Health/Results.md");

  assert.equal(report.liveRemoved, true);
  assert.equal(report.path, "Health/Results.md");
  // Two archived revisions plus the live one, which is never archived on the
  // way out: purging must not write the copy it is removing.
  assert.equal(report.revisionsRemoved, 2);
  assert.equal(fs.existsSync(objectPath(dir, note.id, ".note.enc")), false);
  assert.equal(fs.existsSync(historyDir(dir, note.id)), false);
  assert.equal(vault.list().length, 0);
  assert.throws(() => vault.get(note.id), /not found/iu);

  // The index no longer resolves the path either, so the name is reusable.
  const replacement = vault.put({ path: "Health/Results.md", title: "Results", body: "fresh" });
  assert.notEqual(replacement.id, note.id);
  assert.equal(replacement.revision, 1);
});

test("a purged note leaves no readable ciphertext behind for its own body", () => {
  const dir = tempVault("bytes");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const note = vault.put({ path: "Secret.md", title: "Secret", body: "a sentence to erase" });
  vault.put({ id: note.id, path: note.path, title: "Secret", body: "edited", baseRevision: 1 });

  vault.purgeNote(note.id);

  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else files.push(absolute);
    }
  };
  walk(path.join(dir, "documents"));
  assert.equal(files.some((file) => file.includes(note.id)), false, files.join(", "));
});

test("purging a canvas removes the board and its revisions", () => {
  const dir = tempVault("canvas");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const board = (overrides = {}) => ({
    path: "Boards/Plan.canvas",
    title: "Plan",
    nodes: [{ id: "n1", type: "text", text: "one", x: 0, y: 0, width: 100, height: 100 }],
    edges: [],
    ...overrides,
  });
  const canvas = vault.putCanvas(board());
  vault.putCanvas(board({ id: canvas.id, title: "Plan v2", baseRevision: 1 }));

  assert.equal(vault.canvasRevisions(canvas.id).length, 2);

  const report = vault.purgeCanvas(canvas.id);

  assert.equal(report.kind, "canvas");
  assert.equal(report.liveRemoved, true);
  assert.equal(report.path, "Boards/Plan.canvas");
  assert.equal(report.revisionsRemoved, 1);
  assert.equal(fs.existsSync(historyDir(dir, canvas.id)), false);
  assert.equal(vault.listCanvases().length, 0);
  assert.throws(() => vault.getCanvas(canvas.id), /not found/iu);
});

test("purging an attachment reports what removeAttachment already did", () => {
  const dir = tempVault("attachment");
  const vault = new DocumentVault(dir, PASSPHRASE);
  const attachment = vault.putAttachment(Buffer.from("bytes"), "scan.pdf", "application/pdf");

  const report = vault.purgeAttachment(attachment.id);

  assert.equal(report.kind, "attachment");
  assert.equal(report.path, "scan.pdf");
  assert.equal(report.liveRemoved, true);
  assert.equal(report.revisionsRemoved, 0);
  assert.equal(fs.existsSync(path.join(dir, "documents", "attachments", attachment.id)), false);
  assert.equal(vault.listAttachments().length, 0);
  assert.throws(() => vault.purgeAttachment(attachment.id), /not found/iu);
});

test("a purge on a synchronized vault says what it did not reach", () => {
  const dir = tempVault("synced");
  const vault = new SyncedDocumentVault(dir, PASSPHRASE, DEVICE_A);
  const note = vault.put({ path: "Health/Results.md", title: "Results", body: "one" });
  vault.put({ id: note.id, path: note.path, title: "Results", body: "two", baseRevision: 1 });

  const report = vault.purgeNote(note.id);

  assert.equal(report.liveRemoved, true);
  assert.equal(report.revisionsRemoved, 1);
  // The change log still holds both writes. A purge does not rewrite it, and
  // the report is the only thing standing between the user and believing it did.
  assert.ok(report.syncChangesPresent >= 2, `expected the change log to be counted, got ${report.syncChangesPresent}`);
  vault.lock();
});
