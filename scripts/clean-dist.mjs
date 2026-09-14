import path from "node:path";
import { fileURLToPath } from "node:url";

import { linkStat, removeTree, surviving } from "./fs-tree.mjs";

const REPORTED_SURVIVORS = 20;

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
