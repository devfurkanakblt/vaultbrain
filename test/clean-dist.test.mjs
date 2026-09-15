import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { cleanDist } from "../scripts/clean-dist.mjs";
import { removeTree } from "../scripts/fs-tree.mjs";

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

// Deliberately not an ASCII name: on Windows, Node's recursive removal helper
// silently removes nothing under such a path, and so does Vite's emptyOutDir,
// which calls it. These tests run the real command from a copy of scripts/
// under this root, so they exercise the path that reproduces the defect.
const AWKWARD = "clean-dist-ü-é-";
const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));

function awkwardCheckout() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), AWKWARD));
  fs.mkdirSync(path.join(root, "scripts"));
  for (const script of ["clean-dist.mjs", "fs-tree.mjs"]) {
    fs.copyFileSync(path.join(repositoryRoot, "scripts", script), path.join(root, "scripts", script));
  }
  return root;
}

function runClean(root, ...args) {
  return spawnSync(process.execPath, [path.join(root, "scripts", "clean-dist.mjs"), ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

test("the clean command removes stale desktop-dist output under a non-ASCII path and leaves dist alone", () => {
  const root = awkwardCheckout();
  const desktopDist = path.join(root, "desktop-dist");
  for (const [relative, contents] of Object.entries({
    "index.html": "previous build",
    "stale.txt": "left by an earlier build",
    "stale-dir/x.txt": "left by an earlier build",
    "assets/index-old.js": "retired bundle",
  })) {
    const file = path.join(desktopDist, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
  const dist = writeOutput(root, { "cli.js": "not this command's output" });

  const result = runClean(root, "desktop-dist");

  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(desktopDist), false, "desktop-dist must be gone, stale files included");
  assert.equal(fs.readFileSync(path.join(dist, "cli.js"), "utf8"), "not this command's output");

  removeTree(root);
});

test("the clean command still cleans dist when given no output name", () => {
  const root = awkwardCheckout();
  const dist = writeOutput(root, { "cli.js": "current", "sync/change-log.js": "retired" });

  const result = runClean(root);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(dist), false);

  removeTree(root);
});

test("the clean command refuses a directory that is not a build output", () => {
  const root = awkwardCheckout();
  const source = path.join(root, "src");
  fs.mkdirSync(source);
  fs.writeFileSync(path.join(source, "cli.ts"), "source, not output");

  for (const args of [["src"], [".."], ["desktop-dist", "dist"]]) {
    const result = runClean(root, ...args);
    assert.notEqual(result.status, 0, `expected a refusal for ${args.join(" ")}`);
    assert.match(result.stderr, /Refusing to clean/u);
  }
  assert.equal(fs.readFileSync(path.join(source, "cli.ts"), "utf8"), "source, not output");

  removeTree(root);
});

test("the clean command fails loudly instead of building over desktop-dist it did not clean", () => {
  const root = awkwardCheckout();
  const real = path.join(root, "elsewhere");
  fs.mkdirSync(real);
  fs.writeFileSync(path.join(real, "keep.js"), "not ours to delete");
  fs.symlinkSync(real, path.join(root, "desktop-dist"), "junction");

  const result = runClean(root, "desktop-dist");

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Refusing to clean a linked desktop-dist directory/u);
  assert.equal(fs.existsSync(path.join(real, "keep.js")), true);

  removeTree(root);
});

test("a desktop-dist removal that silently leaves files behind under a non-ASCII path fails and names them", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), AWKWARD));
  const output = path.join(root, "desktop-dist");
  fs.mkdirSync(path.join(output, "stale-dir"), { recursive: true });
  fs.writeFileSync(path.join(output, "stale.txt"), "left by an earlier build");
  fs.writeFileSync(path.join(output, "stale-dir", "x.txt"), "left by an earlier build");

  // What Vite's emptyOutDir does on this host: return normally, remove nothing.
  assert.throws(() => cleanDist(output, { remove: () => {} }), (error) => {
    assert.match(error.message, /could not be removed/u);
    assert.match(error.message, /stale\.txt/u);
    assert.match(error.message, /x\.txt/u);
    return true;
  });

  removeTree(root);
});

// Every path that produces desktop-dist must go through the verified clean
// first: CI runs `npm run desktop:build`, and `tauri build` (local, CI, and the
// release workflow through `npm run tauri:build`) runs it as beforeBuildCommand.
test("every desktop-dist build cleans through the verified command and Vite does not empty it", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "package.json"), "utf8"));
  const clean = "node scripts/clean-dist.mjs desktop-dist && ";

  assert.ok(manifest.scripts["desktop:build"].startsWith(clean), manifest.scripts["desktop:build"]);
  for (const [name, command] of Object.entries(manifest.scripts)) {
    if (/\bvite\s+build\b/u.test(command)) {
      assert.ok(command.startsWith(clean), `${name} runs vite build without cleaning desktop-dist first`);
    }
  }
  assert.match(manifest.scripts["tauri:build"], /\btauri build\b/u);

  const tauri = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "src-tauri", "tauri.conf.json"), "utf8"));
  assert.equal(tauri.build.beforeBuildCommand, "npm run desktop:build");
  assert.equal(tauri.build.frontendDist, "../desktop-dist");
  for (const overlay of fs.readdirSync(path.join(repositoryRoot, "src-tauri"))) {
    if (!/^tauri\..+\.conf\.json$/u.test(overlay)) continue;
    const config = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "src-tauri", overlay), "utf8"));
    assert.equal(config.build?.beforeBuildCommand, undefined, `${overlay} must not replace beforeBuildCommand`);
  }

  const workflows = path.join(repositoryRoot, ".github", "workflows");
  for (const workflow of fs.readdirSync(workflows)) {
    const text = fs.readFileSync(path.join(workflows, workflow), "utf8");
    assert.doesNotMatch(text, /\bvite\s+build\b|\btauri\s+build\b/u, `${workflow} must build through the npm scripts`);
  }

  const vite = fs.readFileSync(path.join(repositoryRoot, "desktop", "vite.config.ts"), "utf8");
  assert.match(vite, /outDir:\s*path\.resolve\(import\.meta\.dirname,\s*"\.\.\/desktop-dist"\)/u);
  assert.match(vite, /emptyOutDir:\s*false/u);
});
