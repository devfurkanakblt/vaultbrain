import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readTextFileLimited } from "./fs-safe.js";

const LOCK_FILENAME = ".sbrain.lock";
const DEFAULT_STALE_MS = 30_000;
const DEFAULT_WAIT_MS = 2_000;
const POLL_MS = 40;

export interface LockRecord {
  token: string;
  pid: number;
  host: string;
  acquiredAt: string;
  /**
   * How long the holder intends this lock to stay fresh. Written so that
   * other processes judge the record by the holder's window rather than their
   * own: a long operation (a re-key) must not be reclaimed out from under
   * itself by a short one. Absent on records written by older builds, which
   * are therefore judged by the acquirer's window alone, exactly as before.
   */
  staleMs?: number;
}

export class VaultBusyError extends Error {
  constructor(
    readonly holder: LockRecord | undefined,
    lockPath: string,
  ) {
    super(
      holder
        ? `Vault is being written by process ${holder.pid} on ${holder.host} since ${holder.acquiredAt}. Close that session, or remove ${lockPath} if it crashed.`
        : `Vault is locked by another process. Remove ${lockPath} if no session is running.`,
    );
    this.name = "VaultBusyError";
  }
}

/** Per-process reentrancy: a locked operation may call another locked one. */
const held = new Map<string, number>();
const sleeper = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms: number): void {
  Atomics.wait(sleeper, 0, 0, ms);
}

function readRecord(lockPath: string): LockRecord | undefined {
  try {
    const record = JSON.parse(readTextFileLimited(lockPath, 64 * 1024, "Vault lock")) as LockRecord;
    return typeof record?.token === "string" && typeof record.acquiredAt === "string" ? record : undefined;
  } catch {
    return undefined;
  }
}

function processIsAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // EPERM means the process exists but cannot be signalled. Unknown errors
    // also fail closed: a stuck lock is safer than overlapping writers.
    return code !== "ESRCH";
  }
}

function isReclaimable(record: LockRecord | undefined, staleMs: number): boolean {
  // Corrupt and remote-host locks are never deleted automatically. They need
  // an explicit owner recovery action because their liveness is unknowable.
  if (!record || record.host.toLocaleLowerCase() !== os.hostname().toLocaleLowerCase()) return false;
  const age = Date.now() - Date.parse(record.acquiredAt);
  // The holder's own window wins outright, longer or shorter: it is the only
  // party that knows how long its operation runs. Reclaiming it early is what
  // corrupts the vault; holding to an acquirer's longer window instead only
  // wedges the vault, so a 15-minute re-key would wait out a crashed
  // 30-second writer for a quarter of an hour. A record from an older build
  // carries no window and falls back to ours.
  const declared =
    typeof record.staleMs === "number" && Number.isFinite(record.staleMs) && record.staleMs > 0
      ? record.staleMs
      : 0;
  const window = declared || staleMs;
  return Number.isFinite(age) && age > window && !processIsAlive(record.pid);
}

/**
 * Runs `operation` while holding an exclusive on-disk lock for the vault, so
 * two processes cannot interleave a note write with an index write. The lock
 * is advisory between Vault Brain processes — it protects against a
 * second CLI/MCP/desktop session, not against someone editing files by hand.
 *
 * A same-host lock left behind by a process proven dead is reclaimed after the
 * grace period. A live PID, remote host, or malformed lock always fails closed.
 */
export function withVaultLock<T>(
  vaultDir: string,
  operation: () => T,
  options: { staleMs?: number; waitMs?: number } = {},
): T {
  const staleMs = options.staleMs ?? DEFAULT_STALE_MS;
  const waitMs = options.waitMs ?? DEFAULT_WAIT_MS;
  const lockPath = path.join(path.resolve(vaultDir), LOCK_FILENAME);

  const depth = held.get(lockPath) ?? 0;
  if (depth > 0) {
    held.set(lockPath, depth + 1);
    try {
      return operation();
    } finally {
      held.set(lockPath, (held.get(lockPath) ?? 1) - 1);
    }
  }

  fs.mkdirSync(path.dirname(lockPath), { recursive: true, mode: 0o700 });
  const token = crypto.randomUUID();
  const record: LockRecord = {
    token,
    pid: process.pid,
    host: os.hostname(),
    acquiredAt: new Date().toISOString(),
    staleMs,
  };
  const deadline = Date.now() + waitMs;

  for (;;) {
    try {
      const fd = fs.openSync(lockPath, "wx", 0o600);
      fs.writeFileSync(fd, JSON.stringify(record));
      fs.closeSync(fd);
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const holder = readRecord(lockPath);
      if (isReclaimable(holder, staleMs)) {
        try {
          fs.unlinkSync(lockPath);
        } catch {
          /* another process reclaimed it first; fall through and retry */
        }
        continue;
      }
      if (Date.now() >= deadline) throw new VaultBusyError(holder, lockPath);
      sleepSync(POLL_MS);
    }
  }

  held.set(lockPath, 1);
  try {
    return operation();
  } finally {
    held.set(lockPath, 0);
    held.delete(lockPath);
    // Only drop the lock if it is still ours: a stale-reclaim may have handed
    // it to someone else while we were working.
    if (readRecord(lockPath)?.token === token) {
      try {
        fs.unlinkSync(lockPath);
      } catch {
        /* already gone */
      }
    }
  }
}

/** Test/diagnostic helper: who holds the lock right now, if anyone. */
export function lockHolder(vaultDir: string): LockRecord | undefined {
  return readRecord(path.join(path.resolve(vaultDir), LOCK_FILENAME));
}
