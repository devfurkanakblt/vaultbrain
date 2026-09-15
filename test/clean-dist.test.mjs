import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { cleanDist } from "../scripts/clean-dist.mjs";

function temporaryRoot(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `clean-dist-${label}-`));
}

function writeOutput(root, entries) {
  const output = path.join(root, "dist");
  for (const [relative, contents] of Object.entries(entries)) {
    const file = path.join(output, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
  return output;
}

test("cleaning removes the whole output directory", () => {
  const root = temporaryRoot("removes");
  const output = writeOutput(root, { "cli.js": "current", "sync/change-log.js": "retired" });

  cleanDist(output);

  assert.equal(fs.existsSync(output), false);
});

test("cleaning an output directory that was never built is not an error", () => {
  const root = temporaryRoot("absent");

  cleanDist(path.join(root, "dist"));
});

test("a removal that silently leaves files behind fails and names them", () => {
  const root = temporaryRoot("silent");
  const output = writeOutput(root, { "cli.js": "current", "sync/change-log.js": "retired" });

  // The observed defect: Node's recursive removal helper, called with force,
  // returned without removing the tree and without reporting anything, so the
  // build carried on over stale output.
  assert.throws(() => cleanDist(output, { remove: () => {} }), (error) => {
    assert.match(error.message, /could not be removed/u);
    assert.match(error.message, /change-log\.js/u);
    assert.match(error.message, /cli\.js/u);
    return true;
  });

  assert.equal(fs.existsSync(path.join(output, "sync/change-log.js")), true);
});

test("an empty output directory that survives removal still fails the build", () => {
  const root = temporaryRoot("empty");
  const output = path.join(root, "dist");
  fs.mkdirSync(output);

  assert.throws(() => cleanDist(output, { remove: () => {} }), (error) => {
    assert.match(error.message, /could not be removed/u);
    assert.ok(error.message.includes(output), error.message);
    return true;
  });
});

test("a removal that throws is reported with the output path and the cause", () => {
  const root = temporaryRoot("throws");
  const output = writeOutput(root, { "cli.js": "current" });

  assert.throws(() => cleanDist(output, { remove: () => { throw new Error("EBUSY: resource busy or locked"); } }), (error) => {
    assert.ok(error.message.includes(output), error.message);
    assert.match(error.message, /EBUSY/u);
    return true;
  });
});

test("a linked output directory is refused instead of followed", () => {
  const root = temporaryRoot("linked");
  const real = path.join(root, "elsewhere");
  fs.mkdirSync(real);
  fs.writeFileSync(path.join(real, "keep.js"), "not ours to delete");
  const output = path.join(root, "dist");
  fs.symlinkSync(real, output, "junction");

  assert.throws(() => cleanDist(output), /Refusing to clean a linked dist directory/u);

  assert.equal(fs.existsSync(path.join(real, "keep.js")), true);
});
