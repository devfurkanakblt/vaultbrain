import fs from "node:fs";
import path from "node:path";

// Some of Node's filesystem calls are not dependable on every host. Measured on
// Windows 11 with Node v24.11.1: when any component of a path is non-ASCII,
// the single-call recursive-removal helper in "node:fs" removes nothing and
// returns normally — file or directory, with or without recursive, with or
// without force, never even ENOENT — and the single-call recursive copy
// helper aborts the whole process with 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN).
// Under an all-ASCII path both behave, and the same removal from PowerShell
// succeeds, so the defect is Node's and not the filesystem's.
// unlink, rmdir, readdir, rename, mkdir and copyFile are unaffected, so this
// module walks trees with those and lets every error surface.
//
// This is not a workaround for a slow disk or a held handle. A removal that
// does not remove must be reported, never retried into silence.
//
// This is a TypeScript copy of scripts/fs-tree.mjs's removeTree and
// removeFile: build and packaging scripts run before `tsc` has produced
// anything under dist/, so they cannot import compiled product code, and
// product code cannot import a .mjs script. The two copies exist so both
// sides of that boundary get the same fix; keep them in sync.
//
// Accepted TOCTOU: between the lstat below and the readdir it precedes, a
// same-user process with write access inside the tree being removed could
// swap a directory entry for a junction, redirecting the recursion outside
// the tree. This is accepted because it requires write access inside the
// vault while a removal is running — a process already in that position has
// no need of this window — and Node's own removal helper carries the same
// gap between its own stat and its own recursion.

function linkStat(target: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return undefined;
    throw error;
  }
}

export function removeTree(target: string): void {
  const stat = linkStat(target);
  if (!stat) return;
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    for (const entry of fs.readdirSync(target)) removeTree(path.join(target, entry));
    fs.rmdirSync(target);
    return;
  }
  fs.unlinkSync(target);
}

export function removeFile(target: string): void {
  const stat = linkStat(target);
  if (!stat) return;
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    throw new Error(`Refusing to remove a directory as a file: ${target}`);
  }
  fs.unlinkSync(target);
}
