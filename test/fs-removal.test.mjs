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

test("removeTree on a tree containing a nested junction removes the tree and leaves the junction's target intact", () => {
  const root = temporaryRoot();
  const real = writeTree(path.join(root, "elsewhere"), { "keep.md": "not ours to delete" });
  const tree = writeTree(path.join(root, "vault"), { "note.md": "top level" });
  const link = path.join(tree, "linked");
  fs.symlinkSync(real, link, "junction");

  removeTree(tree);

  assert.equal(fs.existsSync(tree), false);
  assert.equal(fs.existsSync(real), true, "the junction's target directory must survive");
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

// Node's rm/cp family (Sync, promises-based, callback-based, imported by
// name, or reached through "node:fs/promises") are the defect this module
// exists to route around. This scan fails on any host — including Linux CI,
// which cannot reproduce the underlying Windows defect — if a source file
// under src/ still calls one of them, so a new call site cannot slip back in
// silently. src/fs-tree.ts gets no exemption: it must not use them either,
// even to explain the defect it works around, so its own comments avoid
// spelling the banned names.
//
// A plain regex over the raw source missed real equivalents: `rmdirSync`
// called with a `recursive` option shares the defect (measured on this host:
// it emits DEP0147, returns normally, and leaves the directory), and neither
// a "node:fs/promises" import nor a named `{ rm }`/`{ cp }` import from "fs"
// is caught by matching only qualified calls like "fs.rm(". findBannedCalls
// below is exported for a probe test to pin against, and is the same
// function the source scan runs.
function findBannedCalls(text) {
  const offenses = [];

  function lineAt(index) {
    return text.slice(0, index).split("\n").length;
  }

  function record(index) {
    const start = text.lastIndexOf("\n", index) + 1;
    const nextNewline = text.indexOf("\n", index);
    const end = nextNewline === -1 ? text.length : nextNewline;
    offenses.push({ line: lineAt(index), text: text.slice(start, end).trim() });
  }

  // rmSync / cpSync, however they were imported or namespaced.
  for (const m of text.matchAll(/\b(?:rm|cp)Sync\b/g)) record(m.index);

  // fs.rm( / fs.cp(, with or without whitespace before the parenthesis.
  for (const m of text.matchAll(/\bfs\.(?:rm|cp)\s*\(/g)) record(m.index);

  // promises.rm(...) / promises.cp(...), including fs.promises.rm(...),
  // whether promises came from a namespace import or a destructured one.
  for (const m of text.matchAll(/\bpromises\.(?:rm|cp)\b/g)) record(m.index);

  // Any import (or require) of the promises-flavored fs module: every export
  // it offers, rm/cp included, is unsafe to bring in for this reason alone.
  for (const m of text.matchAll(/(?:from\s+|require\(\s*)["'](?:node:)?fs\/promises["']/g)) record(m.index);

  // Named imports of rm/rmSync/cp/cpSync straight off "fs" or "node:fs",
  // e.g. `import { rmSync } from "node:fs"`, which a call-site regex like
  // "fs.rm(" cannot see because the call site reads only "rmSync(...)".
  for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*["'](?:node:)?fs["']/gs)) {
    if (/\b(?:rm|rmSync|cp|cpSync)\b/.test(m[1])) record(m.index);
  }

  // rmdirSync(...)/rmdir(...) called with a recursive option: on this host it
  // shares the exact defect (silently removes nothing) that the rest of this
  // scan exists to catch. Non-recursive rmdirSync stays legal — it is how
  // this very module empties a directory it has already walked. The call's
  // argument list can wrap onto later lines, so this walks matched
  // parentheses instead of matching within one line.
  for (const m of text.matchAll(/\brmdir(?:Sync)?\s*\(/g)) {
    const openParen = m.index + m[0].length - 1;
    let depth = 0;
    let closeParen = -1;
    for (let i = openParen; i < text.length; i += 1) {
      if (text[i] === "(") depth += 1;
      else if (text[i] === ")") {
        depth -= 1;
        if (depth === 0) {
          closeParen = i;
          break;
        }
      }
    }
    if (closeParen === -1) continue;
    if (/\brecursive\b/.test(text.slice(openParen + 1, closeParen))) record(m.index);
  }

  return offenses;
}

const MUST_MATCH = [
  'fs.rmSync(dir, { recursive: true, force: true });',
  'rmSync(dir);',
  'fs.cpSync(a, b, { recursive: true });',
  'cpSync(a, b);',
  "fs.rm(x, () => {});",
  "fs.rm (x, cb);",
  "fs.cp (a, b);",
  "fs.cp(a, b, cb);",
  "promises.rm(dir);",
  "fs.promises.rm(dir);",
  "fs.promises.cp(a, b);",
  'import { rm } from "node:fs/promises";',
  'import { cp } from "fs/promises";',
  'const fsp = require("node:fs/promises");',
  'const fsp = require("fs/promises");',
  'import { rm, mkdirSync } from "node:fs";',
  'import { rmSync } from "fs";',
  'import { cp } from "node:fs";',
  'import { cpSync } from "fs";',
  "fs.rmdirSync(dir, { recursive: true });",
  "fs.rmdir(dir, { recursive: true }, callback);",
  "rmdirSync(dir, {\n  recursive: true,\n});",
];

const MUST_NOT_MATCH = [
  "fs.mkdirSync(dir, { recursive: true });",
  "fs.rmdirSync(dir);",
  "fs.rmdirSync(historyDir);",
  "if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);",
  "const confirmed = true;",
  "function performCleanup() { term(); }",
  'import { readdirSync } from "node:fs";',
  'import fs from "node:fs";',
  "fs.unlinkSync(file);",
  "// this comment merely reforms a sentence, it removes nothing",
  "const cpuCount = 4;",
  "compare(a, b);",
];

test("findBannedCalls matches every probe that names a banned removal, and none of the others", () => {
  for (const probe of MUST_MATCH) {
    assert.ok(findBannedCalls(probe).length > 0, `expected a match: ${probe}`);
  }
  for (const probe of MUST_NOT_MATCH) {
    assert.deepEqual(findBannedCalls(probe), [], `expected no match: ${probe}`);
  }
});

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
    const text = fs.readFileSync(file, "utf8");
    for (const offense of findBannedCalls(text)) {
      offenses.push(`${path.relative(srcDir, file)}:${offense.line}: ${offense.text}`);
    }
  }

  assert.deepEqual(offenses, []);
});
