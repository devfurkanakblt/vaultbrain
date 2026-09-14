import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { removeFile, removeTree } from "../dist/fs-tree.js";

// Deliberately not an ASCII name. Node's own fs.rmSync fails here on Windows —
// it silently removes nothing and returns as if it had succeeded — so this
// module (and every test that exercises it) is exercised under a path that
// reproduces the defect rather than one that happens to avoid it.
const AWKWARD = "fs-removal-ü-é-";

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

test("removeTree removes a nested tree and the root is gone afterwards", () => {
  const root = temporaryRoot();
  const tree = writeTree(path.join(root, "vault"), {
    "note.md": "top level",
    "a/note.md": "one level deep",
    "a/b/note.md": "two levels deep",
  });

  removeTree(tree);

  assert.equal(fs.existsSync(tree), false);

  removeTree(root);
});

test("removeTree on a missing path returns without throwing", () => {
  const root = temporaryRoot();
  const missing = path.join(root, "does-not-exist");

  assert.doesNotThrow(() => removeTree(missing));

  removeTree(root);
});

test("removeTree on a directory junction/symlink removes the link and leaves the target's contents intact", () => {
  const root = temporaryRoot();
  const real = writeTree(path.join(root, "elsewhere"), { "keep.md": "not ours to delete" });
  const link = path.join(root, "linked");
  fs.symlinkSync(real, link, "junction");

  removeTree(link);

  assert.equal(fs.existsSync(link), false);
  assert.equal(fs.readFileSync(path.join(real, "keep.md"), "utf8"), "not ours to delete");

  removeTree(root);
});

test("removeFile removes a single file", () => {
  const root = temporaryRoot();
  const file = path.join(root, "note.md");
  fs.writeFileSync(file, "content");

  removeFile(file);

  assert.equal(fs.existsSync(file), false);

  removeTree(root);
});

test("removeFile on a missing path returns without throwing", () => {
  const root = temporaryRoot();
  const missing = path.join(root, "does-not-exist.md");

  assert.doesNotThrow(() => removeFile(missing));

  removeTree(root);
});

test("removeFile handed a directory throws rather than removing it", () => {
  const root = temporaryRoot();
  const dir = writeTree(path.join(root, "a-directory"), { "note.md": "inside" });

  assert.throws(() => removeFile(dir));
  assert.equal(fs.existsSync(dir), true);

  removeTree(root);
});

// Node's fs.rmSync/fs.cpSync (and their promises and non-fs-qualified
// equivalents) are the defect this module exists to route around. This scan
// fails on any host — including Linux CI, which cannot reproduce the
// underlying Windows defect — if a source file under src/ still calls one of
// them, so a new call site cannot slip back in silently. src/fs-tree.ts gets
// no exemption: it must not use them either, even to explain the defect it
// works around, so its own comments avoid spelling the banned names.
const BANNED_CALL = /\brmSync\b|\bcpSync\b|\bfs\.rm\(|\bfs\.cp\(|promises\.rm\b|promises\.cp\b/;

function listTsFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listTsFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
}

test("no source file under src/ calls Node's non-ASCII-unsafe recursive removal helpers", () => {
  const srcDir = path.join(import.meta.dirname, "..", "src");
  const offenses = [];

  for (const file of listTsFiles(srcDir)) {
    const lines = fs.readFileSync(file, "utf8").split("\n");
    lines.forEach((line, index) => {
      if (BANNED_CALL.test(line)) offenses.push(`${path.relative(srcDir, file)}:${index + 1}: ${line.trim()}`);
    });
  }

  assert.deepEqual(offenses, []);
});
