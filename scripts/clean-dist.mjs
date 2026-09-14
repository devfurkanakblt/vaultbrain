import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPORTED_SURVIVORS = 20;

function linkStat(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
}

// Everything still under target after a removal, deepest entries first, so the
// report names the files a reader can act on rather than only the root.
function surviving(target, collected = []) {
  const stat = linkStat(target);
  if (!stat) return collected;
  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(target)) surviving(path.join(target, entry), collected);
  }
  collected.push(target);
  return collected;
}

// Node's own recursive removal is not dependable here: under a path containing a
// non-ASCII component — this checkout lives under "Masaüstü" — fs.rmSync returns
// normally and deletes nothing, while fs.unlinkSync on the same entries works.
// It is the same family as the fs.cpSync crash the project already works around,
// so the build scripts walk the tree themselves and let every error surface.
function removeTree(target) {
  const stat = linkStat(target);
  if (!stat) return;
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    for (const entry of fs.readdirSync(target)) removeTree(path.join(target, entry));
    fs.rmdirSync(target);
    return;
  }
  fs.unlinkSync(target);
}

// tsc does not remove output for deleted source files. Build only owns dist.
export function cleanDist(output, { remove = removeTree } = {}) {
  const before = linkStat(output);
  if (before?.isSymbolicLink()) {
    throw new Error("Refusing to clean a linked dist directory.");
  }
  if (!before) return;

  try {
    remove(output);
  } catch (cause) {
    throw new Error(`Could not remove the build output at ${output}: ${cause.message}`, { cause });
  }

  // The removal is never trusted on its report alone. A build that continues over
  // a surviving tree compiles on top of a previous build's output, including
  // implementations a phase has retired — which is how dist/sync/change-log.js
  // outlived Phase 14.3 by five days without any command saying so.
  const left = surviving(output);
  if (left.length === 0) return;

  const named = left.slice(0, REPORTED_SURVIVORS).join("\n  ");
  const more = left.length > REPORTED_SURVIVORS ? `\n  ...and ${left.length - REPORTED_SURVIVORS} more` : "";
  throw new Error(
    `The build output at ${output} could not be removed. ${left.length} path(s) survived:\n  ${named}${more}\n` +
      "Either something holds these files, or the removal itself is not working on this host. " +
      "Do not build over them: remove the directory by hand, confirm it is gone, then build again.",
  );
}

const entryPoint = process.argv[1] ? path.resolve(process.argv[1]) : undefined;
if (entryPoint === fileURLToPath(import.meta.url)) {
  const root = path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  try {
    cleanDist(path.join(root, "dist"));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
