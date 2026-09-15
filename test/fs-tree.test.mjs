import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { copyTree, removeFile, removeTree, surviving } from "../scripts/fs-tree.mjs";

// Deliberately not an ASCII name. Node's own recursive helpers fail here on
// Windows — fs.rmSync silently removes nothing, fs.cpSync aborts the process
// with 0xC0000409 — so a build script that reaches for them again fails this
// file rather than shipping a build over stale output.
const AWKWARD = "fs-tree-ü-é-";

function temporaryRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), AWKWARD));
}

function writeTree(root, entries) {
  for (const [relative, contents] of Object.entries(entries)) {
    const file = path.join(root, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
  return root;
}

test("copyTree reproduces a nested tree under a non-ASCII path", () => {
  const root = temporaryRoot();
  const source = writeTree(path.join(root, "source"), {
    "cli.js": "entry point",
    "sync/protocol.js": "nested",
    "sync/blobs/store.js": "deeply nested",
  });
  const destination = path.join(root, "copy");

  copyTree(source, destination);

  assert.equal(fs.readFileSync(path.join(destination, "cli.js"), "utf8"), "entry point");
  assert.equal(fs.readFileSync(path.join(destination, "sync/protocol.js"), "utf8"), "nested");
  assert.equal(fs.readFileSync(path.join(destination, "sync/blobs/store.js"), "utf8"), "deeply nested");

  removeTree(root);
});

test("copyTree copies a single file when handed one", () => {
  const root = temporaryRoot();
  const source = path.join(root, "one.js");
  fs.writeFileSync(source, "alone");

  copyTree(source, path.join(root, "two.js"));

  assert.equal(fs.readFileSync(path.join(root, "two.js"), "utf8"), "alone");

  removeTree(root);
});

test("removeTree empties a nested tree under a non-ASCII path", () => {
  const root = temporaryRoot();
  const tree = writeTree(path.join(root, "dist"), { "cli.js": "x", "sync/blobs/store.js": "y" });

  removeTree(tree);

  assert.equal(fs.existsSync(tree), false);

  removeTree(root);
});

test("removeTree removes a link without touching what it points at", () => {
  const root = temporaryRoot();
  const real = writeTree(path.join(root, "elsewhere"), { "keep.js": "not ours to delete" });
  const link = path.join(root, "linked");
  fs.symlinkSync(real, link, "junction");

  removeTree(link);

  assert.equal(fs.existsSync(link), false);
  assert.equal(fs.readFileSync(path.join(real, "keep.js"), "utf8"), "not ours to delete");

  removeTree(root);
});

test("removeFile removes a single file under a non-ASCII path", () => {
  const root = temporaryRoot();
  const file = path.join(root, "note.js");
  fs.writeFileSync(file, "content");

  removeFile(file);

  assert.equal(fs.existsSync(file), false);

  removeTree(root);
});

test("removeFile on a missing path returns without throwing", () => {
  const root = temporaryRoot();
  const missing = path.join(root, "does-not-exist.js");

  assert.doesNotThrow(() => removeFile(missing));

  removeTree(root);
});

test("removeFile handed a directory throws and leaves it (and its contents) in place", () => {
  const root = temporaryRoot();
  const dir = writeTree(path.join(root, "a-directory"), { "note.js": "inside" });

  assert.throws(() => removeFile(dir));
  assert.equal(fs.existsSync(dir), true);
  assert.equal(fs.readFileSync(path.join(dir, "note.js"), "utf8"), "inside");

  removeTree(root);
});

test("surviving reports every remaining path, deepest first", () => {
  const root = temporaryRoot();
  const tree = writeTree(path.join(root, "dist"), { "sync/blobs/store.js": "y" });

  const left = surviving(tree);

  assert.equal(left.at(0), path.join(tree, "sync", "blobs", "store.js"));
  assert.equal(left.at(-1), tree);
  assert.equal(surviving(path.join(root, "absent")).length, 0);

  removeTree(root);
});
