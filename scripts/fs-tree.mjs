import fs from "node:fs";
import path from "node:path";

// Some of Node's filesystem calls are not dependable on every host. Measured on
// Windows 11 with Node v24.11.1: when any component of a path is non-ASCII,
// every fs.rmSync call removes nothing and returns normally — file or
// directory, with or without recursive, with or without force, never even
// ENOENT — and fs.cpSync({ recursive: true }) kills the process with 0xC0000409
// (STATUS_STACK_BUFFER_OVERRUN). Under an all-ASCII path both behave, and the
// same removal from PowerShell succeeds, so the defect is Node's and not the
// filesystem's. unlink, rmdir, readdir, rename, mkdir and copyFile are
// unaffected, so this module walks trees with those and lets every error
// surface.
//
// This is not a workaround for a slow disk or a held handle. A removal that does
// not remove must be reported, never retried into silence.

export function linkStat(target) {
  try {
    return fs.lstatSync(target);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
}

export function removeTree(target) {
  const stat = linkStat(target);
  if (!stat) return;
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    for (const entry of fs.readdirSync(target)) removeTree(path.join(target, entry));
    fs.rmdirSync(target);
    return;
  }
  fs.unlinkSync(target);
}

export function copyTree(source, destination) {
  const stat = fs.lstatSync(source);
  if (stat.isSymbolicLink()) {
    fs.symlinkSync(fs.readlinkSync(source), destination);
    return;
  }
  if (!stat.isDirectory()) {
    fs.copyFileSync(source, destination);
    fs.chmodSync(destination, stat.mode & 0o777);
    return;
  }
  fs.mkdirSync(destination, { recursive: true, mode: stat.mode & 0o777 });
  for (const entry of fs.readdirSync(source)) copyTree(path.join(source, entry), path.join(destination, entry));
}

// Everything still under target, deepest entries first, so a report names the
// files a reader can act on rather than only the root.
export function surviving(target, collected = []) {
  const stat = linkStat(target);
  if (!stat) return collected;
  if (stat.isDirectory() && !stat.isSymbolicLink()) {
    for (const entry of fs.readdirSync(target)) surviving(path.join(target, entry), collected);
  }
  collected.push(target);
  return collected;
}
