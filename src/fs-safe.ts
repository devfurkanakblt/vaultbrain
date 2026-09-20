import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export function assertNotSymlink(filePath: string): void {
  if (fs.existsSync(filePath) && fs.lstatSync(filePath).isSymbolicLink()) {
    throw new Error(`Refusing to follow a symbolic link: ${path.basename(filePath)}`);
  }
}

/** Reject any existing symbolic-link component below a trusted selected root. */
export function assertNoSymlinkComponents(rootDir: string, targetPath: string): void {
  const root = path.resolve(rootDir);
  const target = path.resolve(targetPath);
  const relative = path.relative(root, target);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("Refusing to inspect a path outside the trusted root.");
  }
  let current = root;
  if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
    throw new Error(`Refusing symbolic-link directory: ${path.basename(current)}`);
  }
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
      throw new Error(`Refusing symbolic-link path component: ${part}`);
    }
  }
}

/**
 * The physical path `target` names, with every symbolic link and Windows
 * junction in its existing ancestors resolved.
 *
 * `path.resolve` answers a lexical question: it normalizes `.` and `..` and
 * nothing else. That is not enough to decide whether a directory lies inside
 * another, because a junction or symlink anywhere above the target can point
 * the whole subtree somewhere else while the two strings still look unrelated.
 * A containment check built on the lexical answer therefore passes for a path
 * that physically resolves inside the very directory it was meant to stay out
 * of.
 *
 * The target itself usually does not exist yet — it is about to be created —
 * so the deepest ancestor that does exist is resolved and the remaining
 * segments are appended to it. Those segments cannot themselves be links,
 * because nothing is there.
 */
export function resolvePhysicalPath(target: string): string {
  const resolved = path.resolve(target);
  const tail: string[] = [];
  let current = resolved;
  for (;;) {
    try {
      return path.join(fs.realpathSync.native(current), ...tail);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = path.dirname(current);
      // A root that does not resolve leaves nothing further to walk; the
      // lexical answer is then the only one there is.
      if (parent === current) return resolved;
      tail.unshift(path.basename(current));
      current = parent;
    }
  }
}

export function readTextFileLimited(filePath: string, maxBytes: number, label: string): string {
  assertNotSymlink(filePath);
  const size = fs.statSync(filePath).size;
  if (size > maxBytes) throw new Error(`${label} exceeds the ${maxBytes}-byte safety limit.`);
  return fs.readFileSync(filePath, "utf8");
}

export function readBufferFileLimited(filePath: string, maxBytes: number, label: string): Buffer {
  assertNotSymlink(filePath);
  const size = fs.statSync(filePath).size;
  if (size > maxBytes) throw new Error(`${label} exceeds the ${maxBytes}-byte safety limit.`);
  return fs.readFileSync(filePath);
}

const WINDOWS_REPLACE_RETRY_CODES = new Set(["EACCES", "EBUSY", "EPERM"]);

/**
 * Antivirus and indexers can briefly hold a just-written file on Windows.
 * Retry only those transient sharing violations; every other rename failure
 * remains immediate, and the successful operation is still one atomic rename.
 */
export function replaceFileAtomic(source: string, destination: string): void {
  for (let attempt = 0; ; attempt += 1) {
    try {
      fs.renameSync(source, destination);
      return;
    } catch (error) {
      const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
      if (process.platform !== "win32" || !WINDOWS_REPLACE_RETRY_CODES.has(code) || attempt >= 7) throw error;
      const delayMs = 10 * 2 ** attempt;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
    }
  }
}

/**
 * Write and fsync a sibling temporary file before replacing the destination.
 * A crash can therefore leave either the old complete file or the new complete
 * file, never a half-written encrypted payload.
 */
export function writeFileAtomic(
  filePath: string,
  data: string | Buffer,
  options: { mode?: number } = {}
): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertNotSymlink(filePath);

  const tempPath = path.join(
    dir,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`
  );
  let fd: number | undefined;
  try {
    fd = fs.openSync(tempPath, "wx", options.mode ?? 0o600);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    replaceFileAtomic(tempPath, filePath);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
  }
}
