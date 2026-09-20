/**
 * The encrypted index change log.
 *
 * Both cores used to rewrite the whole document index on every save, so the
 * cost of saving one note grew with the size of the vault: at 100,000 notes
 * that is a ~120 MiB serialise, encrypt, write and fsync for a one-line edit.
 * This log replaces that. A save appends one sealed record describing what
 * changed; the snapshot in `index.enc` is refreshed only when the log grows
 * past a threshold.
 *
 * The format is shared with the Rust desktop core (`src-tauri/src/index_log.rs`).
 * Both cores write `index.enc`, so a log only one of them understood would
 * leave the other reading a snapshot that omits the first one's recent saves —
 * a correctness bug, not a missed optimisation. Anything changed here changes
 * there.
 *
 * On disk: one JSON object per line, each an independently sealed
 * `DocumentPayload`.
 *
 *   line 0        the header, binding the log to one snapshot generation
 *   line 1..n     records, in the order they were applied
 *
 * The AAD of every line carries the generation and the line number, so a
 * record cannot be reordered, duplicated, dropped from the middle, or replayed
 * against a different snapshot without failing authentication.
 */
import fs from "node:fs";
import path from "node:path";
import { AAD } from "./format-version.js";
import {
  decryptDocument,
  encryptDocument,
  type DocumentPayload,
  type DocumentReadKey,
} from "./document-crypto.js";
import { assertNotSymlink } from "./fs-safe.js";

export const INDEX_LOG_FILENAME = "index-log.enc";

/** Bumped only with the on-disk shape; both cores refuse what they do not know. */
export const INDEX_LOG_VERSION = 1;

/**
 * When a log is compacted back into a snapshot.
 *
 * Every record is a note or canvas entry, so the log grows at roughly the size
 * of the notes edited into it. The count bounds unlock work — a cold open
 * replays at most this many records — and the byte ceiling bounds it for
 * vaults whose notes are large. Both are deliberately well under the point
 * where replaying the log approaches the cost of the snapshot it defers.
 */
export const COMPACT_AFTER_RECORDS = 512;
export const COMPACT_AFTER_BYTES = 8 * 1024 * 1024;

/**
 * The mutations a save can describe. Mirrored exactly in the Rust core.
 *
 * Deliberately only notes. Canvas and plugin writes commit a full snapshot
 * instead, which is always correct and is not on the path the incremental-save
 * budget measures. Keeping the log to one record type is what lets both cores
 * replay it with one small, auditable code path each; a record kind only one
 * core understood would be the cross-implementation bug this format exists to
 * avoid.
 */
export type IndexLogRecord =
  | { kind: "note"; note: unknown }
  | { kind: "note-removed"; id: string };

interface IndexLogHeader {
  version: number;
  /**
   * The snapshot this log extends. A log left behind by a crash between
   * writing a new snapshot and deleting the old log carries the previous
   * generation, and is discarded rather than replayed onto a snapshot that
   * already contains it.
   */
  generation: number;
}

export function indexLogPath(rootDir: string): string {
  return path.join(rootDir, INDEX_LOG_FILENAME);
}

function headerAad(generation: number): string {
  return `${AAD.indexLogPrefix}${generation}:header`;
}

function recordAad(generation: number, line: number): string {
  return `${AAD.indexLogPrefix}${generation}:${line}`;
}

function sealedLine(payload: DocumentPayload): string {
  return `${JSON.stringify(payload)}\n`;
}

/**
 * Splits a log into whole lines, dropping a trailing partial one.
 *
 * A record is appended with one write and then fsynced, but a crash can still
 * leave a torn final line. That line is not a corruption to refuse — it is a
 * save that was never acknowledged — so it is discarded, exactly as an
 * unfinished atomic write is.
 */
function completeLines(text: string): string[] {
  const lines = text.split("\n");
  if (lines[lines.length - 1] !== "") lines.pop();
  return lines.filter((line) => line.length > 0);
}

export class IndexLogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IndexLogError";
  }
}

export interface IndexLogRead {
  /** Records to apply to the snapshot, in order. */
  records: IndexLogRecord[];
  /** Lines already on disk, so an appending session knows where it is. */
  lines: number;
  /** Bytes on disk, for the compaction threshold. */
  bytes: number;
}

const EMPTY: IndexLogRead = { records: [], lines: 0, bytes: 0 };

/**
 * Reads the records a snapshot of `generation` should have applied to it.
 *
 * A log belonging to another generation is stale and reads as empty: that is
 * the crash window between writing a new snapshot and removing the log it
 * replaced. A log that fails to authenticate anywhere but its last line is
 * refused, because that is tampering or damage rather than an interrupted
 * append, and silently continuing would hand back an index missing whatever
 * the unreadable records held.
 */
export function readIndexLog(
  rootDir: string,
  key: DocumentReadKey,
  generation: number,
  fromLine = 0,
): IndexLogRead {
  const logPath = indexLogPath(rootDir);
  if (!fs.existsSync(logPath)) return EMPTY;
  assertNotSymlink(logPath);
  const raw = fs.readFileSync(logPath, "utf8");
  const lines = completeLines(raw);
  if (lines.length === 0) return EMPTY;

  let header: IndexLogHeader;
  try {
    header = JSON.parse(
      decryptDocument(JSON.parse(lines[0]) as DocumentPayload, key, headerAad(generation)),
    ) as IndexLogHeader;
  } catch {
    // Either a log for a different generation, or one this key cannot open.
    // Both mean "do not apply it"; a stale log is the expected case.
    return EMPTY;
  }
  if (header.version !== INDEX_LOG_VERSION || header.generation !== generation) return EMPTY;

  const records: IndexLogRecord[] = [];
  for (let line = Math.max(1, fromLine); line < lines.length; line += 1) {
    let record: IndexLogRecord;
    try {
      record = JSON.parse(
        decryptDocument(JSON.parse(lines[line]) as DocumentPayload, key, recordAad(generation, line)),
      ) as IndexLogRecord;
    } catch {
      if (line === lines.length - 1) break; // A torn final append.
      throw new IndexLogError(
        `The index change log is damaged at record ${line}; rebuild the index to recover.`,
      );
    }
    records.push(record);
  }
  return { records, lines: lines.length, bytes: Buffer.byteLength(raw, "utf8") };
}

/**
 * Starts a log for `generation`, replacing whatever was there.
 *
 * Called right after a snapshot is written, so the log always begins life
 * bound to the snapshot it extends.
 */
export function startIndexLog(
  rootDir: string,
  key: Buffer,
  generation: number,
): { lines: number; bytes: number } {
  const logPath = indexLogPath(rootDir);
  if (fs.existsSync(logPath)) assertNotSymlink(logPath);
  const header: IndexLogHeader = { version: INDEX_LOG_VERSION, generation };
  const line = sealedLine(encryptDocument(JSON.stringify(header), key, headerAad(generation)));
  const handle = fs.openSync(logPath, "w", 0o600);
  try {
    fs.writeFileSync(handle, line);
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
  return { lines: 1, bytes: Buffer.byteLength(line, "utf8") };
}

/**
 * Appends one record and makes it durable.
 *
 * The append is a single write followed by fsync, so the record a save
 * acknowledges is on disk before the save returns. Nothing here is deferred to
 * make the number look smaller.
 */
export function appendIndexLog(
  rootDir: string,
  key: Buffer,
  generation: number,
  line: number,
  record: IndexLogRecord,
): number {
  const logPath = indexLogPath(rootDir);
  assertNotSymlink(logPath);
  const sealed = sealedLine(
    encryptDocument(JSON.stringify(record), key, recordAad(generation, line)),
  );
  const handle = fs.openSync(logPath, "a", 0o600);
  try {
    fs.writeFileSync(handle, sealed);
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
  // Returned so a caller tracks the log's size without a stat per save.
  return Buffer.byteLength(sealed, "utf8");
}

export function removeIndexLog(rootDir: string): void {
  const logPath = indexLogPath(rootDir);
  if (!fs.existsSync(logPath)) return;
  assertNotSymlink(logPath);
  fs.unlinkSync(logPath);
}

/** Whether the log has grown past the point where a fresh snapshot is cheaper. */
export function shouldCompact(lines: number, bytes: number): boolean {
  return lines - 1 >= COMPACT_AFTER_RECORDS || bytes >= COMPACT_AFTER_BYTES;
}
