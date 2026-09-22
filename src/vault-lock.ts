import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readTextFileLimited } from "./fs-safe.js";

const LOCK_FILENAME = ".sbrain.lock";
// Every implementation that touches .sbrain.lock (CLI or desktop) takes this
// short-lived gate first. It prevents a releaser or recovery command from
// unlinking a lock which a different process has just replaced (the ABA race).
const TRANSITION_FILENAME = ".sbrain.lock.transition";
const DEFAULT_STALE_MS = 30_000;
/**
 * How long one unchanged holder may block a waiter.
 *
 * This budget is spent per holder, not per wait: every time the lock changes
 * hands the waiter starts it again, because a lock that is moving is a queue
 * draining rather than a vault that is busy. A fan-out of writers -- eight
 * `vbrain add` calls, a script, a CLI beside the MCP server -- is a legitimate
 * use of this vault, and the budget that used to cover the whole queue made
 * the writers at the back fail with "vault is being written by ..." while
 * nothing was wrong. Sizing that budget for the longest queue anyone might
 * form would just be a larger guess; what a waiter can actually tell is
 * whether the holder in front of it is moving.
 *
 * A holder that does not move is still reported here, and within this budget
 * rather than at the ceiling below.
 */
const DEFAULT_WAIT_MS = 2_000;
/**
 * The end of the waiter's patience, however well the queue is moving.
 *
 * Resetting the budget on every hand-off means a busy enough vault could hold
 * a waiter indefinitely, and a command that never returns is worse than one
 * that says the vault is busy. Two minutes is far past any queue this vault's
 * writers form -- each holder replaces one file -- so reaching it means
 * something other than a queue.
 */
const DEFAULT_MAX_WAIT_MS = 120_000;
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

export type VaultLockState = "unlocked" | "live" | "dead" | "remote" | "malformed";

export interface VaultLockInspection {
  state: VaultLockState;
  holder?: LockRecord;
}

export class VaultLockRecoveryError extends Error {
  constructor(readonly inspection: VaultLockInspection, lockPath: string) {
    const message =
      inspection.state === "live"
        ? "Vault lock is still held by a live local process."
        : inspection.state === "remote"
          ? "Vault lock belongs to a process that is not on this host."
          : inspection.state === "malformed"
            ? "Vault lock is malformed and cannot be safely recovered automatically."
            : `Vault lock is not recoverable: ${lockPath}`;
    super(message);
    this.name = "VaultLockRecoveryError";
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

function validRecord(record: LockRecord | undefined): record is LockRecord {
  return Boolean(
    record &&
      typeof record.token === "string" &&
      record.token.length > 0 &&
      Number.isSafeInteger(record.pid) &&
      record.pid > 0 &&
      typeof record.host === "string" &&
      record.host.length > 0 &&
      typeof record.acquiredAt === "string" &&
      Number.isFinite(Date.parse(record.acquiredAt)),
  );
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
  if (!validRecord(record) || record.host.toLocaleLowerCase() !== os.hostname().toLocaleLowerCase()) return false;
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

function inspectLockPath(lockPath: string): VaultLockInspection {
  if (!fs.existsSync(lockPath)) return { state: "unlocked" };
  const holder = readRecord(lockPath);
  if (!validRecord(holder)) return { state: "malformed" };
  if (holder.host.toLocaleLowerCase() !== os.hostname().toLocaleLowerCase()) return { state: "remote", holder };
  return { state: processIsAlive(holder.pid) ? "live" : "dead", holder };
}

/**
 * Errnos that mean "someone else is touching this file right now", not
 * "you may not have this file".
 *
 * Creating a lock file with `wx` reports an existing file as `EEXIST`
 * everywhere, and for a long time that was the only code these loops treated
 * as contention: everything else aborted the command. On Windows that is not
 * enough. A file another process is creating, closing or deleting at the same
 * moment can surface as `EPERM` or `EBUSY` instead, and the same is true of
 * the unlink that releases it — a virus scanner or search indexer holding a
 * brief handle is enough. The result was a `vbrain add` that failed outright
 * under concurrency, which is precisely what holding the lock is supposed to
 * prevent.
 *
 * These codes are retried rather than trusted. A genuine permission problem
 * does not go away, so it still surfaces once the caller's deadline expires —
 * see `throwAfterDeadline`, which reports the real error rather than claiming
 * the vault is busy.
 */
const CONTENTION_CODES = new Set(["EEXIST", "EPERM", "EBUSY", "EACCES"]);

function isContention(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code !== undefined && CONTENTION_CODES.has(code);
}

/**
 * Ends a contended acquisition.
 *
 * `EEXIST` means the file was there, so the vault really is held by someone
 * and `VaultBusyError` names the holder. The other codes are ambiguous: they
 * are usually a transient collision, but a directory that is genuinely
 * read-only produces them forever. Reporting "vault is busy" for that would
 * send the reader looking for a process that does not exist, so the original
 * error is raised instead.
 */
function throwAfterDeadline(lastError: unknown, lockPath: string): never {
  const code = (lastError as NodeJS.ErrnoException | undefined)?.code;
  if (code && code !== "EEXIST") throw lastError;
  throw new VaultBusyError(readRecord(lockPath), lockPath);
}

/**
 * Serializes short lock-file transitions. A transition left by a crashed
 * process is reclaimable only when its same-host PID is proven dead; live,
 * remote, and malformed records fail closed. The owner token makes release
 * conditional and keeps recovery from deleting a replacement transition.
 */
function withTransition<T>(lockPath: string, operation: () => T): T {
  const transitionPath = path.join(path.dirname(lockPath), TRANSITION_FILENAME);
  const token = crypto.randomUUID();
  const deadline = Date.now() + DEFAULT_WAIT_MS;
  for (;;) {
    try {
      const fd = fs.openSync(transitionPath, "wx", 0o600);
      fs.writeFileSync(
        fd,
        JSON.stringify({ token, pid: process.pid, host: os.hostname(), acquiredAt: new Date().toISOString() }),
      );
      fs.closeSync(fd);
      break;
    } catch (error) {
      if (!isContention(error)) throw error;
      const transition = readRecord(transitionPath);
      if (isReclaimable(transition, 0) && readRecord(transitionPath)?.token === transition?.token) {
        try {
          fs.unlinkSync(transitionPath);
        } catch {
          /* another process changed it; retry the inspection */
        }
        continue;
      }
      if (Date.now() >= deadline) throwAfterDeadline(error, lockPath);
      sleepSync(POLL_MS);
    }
  }
  try {
    return operation();
  } finally {
    const transition = readRecord(transitionPath);
    if (transition?.token === token) {
      try {
        fs.unlinkSync(transitionPath);
      } catch {
        /* filesystem cleanup failure must not hide the completed operation */
      }
    }
  }
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
  options: { staleMs?: number; waitMs?: number; maxWaitMs?: number } = {},
): T {
  const staleMs = options.staleMs ?? DEFAULT_STALE_MS;
  const waitMs = options.waitMs ?? DEFAULT_WAIT_MS;
  const maxWaitMs = Math.max(options.maxWaitMs ?? DEFAULT_MAX_WAIT_MS, waitMs);
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
  const ceiling = Date.now() + maxWaitMs;
  // Restarted every time the lock changes hands: see `DEFAULT_WAIT_MS`.
  let deadline = Date.now() + waitMs;
  // The holder this waiter is currently waiting on. A record that cannot be
  // read is deliberately not treated as a change -- a waiter that reset its
  // budget on every unreadable read would never give up on anything.
  let blockingToken: string | undefined;

  let lastError: unknown;
  for (;;) {
    const acquired = withTransition(lockPath, () => {
      try {
        const fd = fs.openSync(lockPath, "wx", 0o600);
        fs.writeFileSync(fd, JSON.stringify(record));
        fs.closeSync(fd);
        return true;
      } catch (error) {
        if (!isContention(error)) throw error;
        lastError = error;
        const holder = readRecord(lockPath);
        if (holder?.token !== undefined && holder.token !== blockingToken) {
          blockingToken = holder.token;
          deadline = Date.now() + waitMs;
        }
        if (isReclaimable(holder, staleMs) && holder?.token === readRecord(lockPath)?.token) {
          try {
            fs.unlinkSync(lockPath);
          } catch {
            /* another process reclaimed or replaced it; the next pass re-reads */
          }
        }
        return false;
      }
    });
    if (acquired) break;
    if (Date.now() >= deadline || Date.now() >= ceiling) throwAfterDeadline(lastError, lockPath);
    sleepSync(POLL_MS);
  }

  held.set(lockPath, 1);
  try {
    return operation();
  } finally {
    held.set(lockPath, 0);
    held.delete(lockPath);
    // Only drop the lock if it is still ours: a stale-reclaim may have handed
    // it to someone else while we were working.
    withTransition(lockPath, () => {
      if (readRecord(lockPath)?.token === token) {
        try {
          fs.unlinkSync(lockPath);
        } catch {
          /* already gone */
        }
      }
    });
  }
}

/** Test/diagnostic helper: who holds the lock right now, if anyone. */
export function lockHolder(vaultDir: string): LockRecord | undefined {
  return readRecord(path.join(path.resolve(vaultDir), LOCK_FILENAME));
}

/** Inspect without opening or decrypting any vault content. */
export function inspectVaultLock(vaultDir: string): VaultLockInspection {
  return inspectLockPath(path.join(path.resolve(vaultDir), LOCK_FILENAME));
}

/**
 * Remove only a lock whose same-host owner PID is proven absent. This command
 * does not inspect, move, or repair re-key journals and staging directories.
 */
export function recoverVaultLock(vaultDir: string): { recovered: boolean; state: VaultLockState } {
  const lockPath = path.join(path.resolve(vaultDir), LOCK_FILENAME);
  return withTransition(lockPath, () => {
    const inspection = inspectLockPath(lockPath);
    if (inspection.state === "unlocked") return { recovered: false, state: "unlocked" };
    if (inspection.state !== "dead") throw new VaultLockRecoveryError(inspection, lockPath);
    // All lock lifecycle transitions take the same gate, so the checked token
    // cannot be replaced between inspection and removal.
    if (readRecord(lockPath)?.token !== inspection.holder?.token) {
      throw new VaultLockRecoveryError(inspectLockPath(lockPath), lockPath);
    }
    fs.unlinkSync(lockPath);
    return { recovered: true, state: "dead" };
  });
}
