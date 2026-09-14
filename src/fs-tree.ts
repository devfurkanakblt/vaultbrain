import fs from "node:fs";
import path from "node:path";

// Some of Node's filesystem calls are not dependable on every host. Measured on
// Windows 11 with Node v24.11.1: when any component of a path is non-ASCII,
// every fs.rmSync call removes nothing and returns normally — file or
// directory, with or without recursive, with or without force, never even
// ENOENT. Under an all-ASCII path it behaves, and the same removal from
// PowerShell succeeds, so the defect is Node's and not the filesystem's.
// unlink, rmdir, readdir and lstat are unaffected, so this module walks trees
// with those and lets every error surface.
//
// This is not a workaround for a slow disk or a held handle. A removal that
// does not remove must be reported, never retried into silence.
//
// This is a TypeScript copy of scripts/fs-tree.mjs's removeTree: build and
// packaging scripts run before `tsc` has produced anything under dist/, so
// they cannot import compiled product code, and product code cannot import a
// .mjs script. The two copies exist so both sides of that boundary get the
// same fix; keep them in sync.

export function removeTree(target: string): void {
  let stat: fs.Stats | undefined;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    for (const entry of fs.readdirSync(target)) removeTree(path.join(target, entry));
    fs.rmdirSync(target);
    return;
  }
  fs.unlinkSync(target);
}

export function removeFile(target: string): void {
  let stat: fs.Stats | undefined;
  try {
    stat = fs.lstatSync(target);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    throw new Error(`Refusing to remove a directory as a file: ${target}`);
  }
  fs.unlinkSync(target);
}
