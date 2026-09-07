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
