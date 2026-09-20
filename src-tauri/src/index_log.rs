//! The encrypted index change log.
//!
//! Both cores used to rewrite the whole document index on every save, so the
//! cost of saving one note grew with the size of the vault. This log replaces
//! that on the save path: a save appends one sealed record describing what
//! changed, and the snapshot in `index.enc` is refreshed only when the log
//! grows past a threshold or the session closes.
//!
//! The format is shared with the TypeScript core (`src/index-log.ts`). Both
//! cores write `index.enc`, so a log only one of them understood would leave
//! the other reading a snapshot that omits the first one's recent saves — a
//! correctness bug, not a missed optimisation. Anything changed here changes
//! there.
//!
//! On disk: one JSON object per line, each an independently sealed
//! `EncryptedPayload`.
//!
//!   line 0        the header, binding the log to one snapshot generation
//!   line 1..n     records, in the order they were applied
//!
//! The AAD of every line carries the generation and the line number, so a
//! record cannot be reordered, duplicated, dropped from the middle, or
//! replayed against a different snapshot without failing authentication.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{decrypt, encrypt, reject_symlink, EncryptedPayload, IndexedNote};

pub(crate) const INDEX_LOG_FILENAME: &str = "index-log.enc";
/// Bumped only with the on-disk shape; both cores refuse what they do not know.
pub(crate) const INDEX_LOG_VERSION: u8 = 1;
/// `AAD.indexLogPrefix` in `src/format-version.ts`.
const INDEX_LOG_AAD_PREFIX: &str = "secondbrain-vault:index-log:v1:";

/// When a log is compacted back into a snapshot. Mirrors `src/index-log.ts`.
pub(crate) const COMPACT_AFTER_RECORDS: usize = 512;
pub(crate) const COMPACT_AFTER_BYTES: u64 = 8 * 1024 * 1024;

/// The mutations a save can describe.
///
/// Deliberately only notes. Canvas and plugin writes commit a full snapshot
/// instead, which is always correct and is not on the path the incremental
/// save budget measures. One record type is what lets both cores replay the
/// log with one small, auditable code path each.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum IndexLogRecord {
    Note { note: Box<IndexedNote> },
    NoteRemoved { id: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexLogHeader {
    version: u8,
    /// The snapshot this log extends. A log left behind by a crash between
    /// writing a new snapshot and removing the old log carries the previous
    /// generation, and is discarded rather than replayed onto a snapshot that
    /// already contains it.
    generation: u64,
}

pub(crate) fn index_log_path(root_dir: &Path) -> PathBuf {
    root_dir.join(INDEX_LOG_FILENAME)
}

fn header_aad(generation: u64) -> String {
    format!("{INDEX_LOG_AAD_PREFIX}{generation}:header")
}

fn record_aad(generation: u64, line: usize) -> String {
    format!("{INDEX_LOG_AAD_PREFIX}{generation}:{line}")
}

fn sealed_line(payload: &EncryptedPayload) -> Result<String, String> {
    let json = serde_json::to_string(payload).map_err(|error| error.to_string())?;
    Ok(format!("{json}\n"))
}

/// What a log read produced.
pub(crate) struct IndexLogRead {
    pub records: Vec<IndexLogRecord>,
    /// Lines already on disk, so an appending session knows where it is.
    pub lines: usize,
    /// Bytes on disk, for the compaction threshold.
    pub bytes: u64,
}

impl IndexLogRead {
    fn empty() -> Self {
        Self {
            records: Vec::new(),
            lines: 0,
            bytes: 0,
        }
    }
}

/// Splits a log into whole lines, dropping a trailing partial one.
///
/// A record is appended with one write and then fsynced, but a crash can still
/// leave a torn final line. That line is not a corruption to refuse — it is a
/// save that was never acknowledged — so it is discarded, exactly as an
/// unfinished atomic write is.
fn complete_lines(text: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last().is_some_and(|last| !last.is_empty()) {
        lines.pop();
    }
    lines.into_iter().filter(|line| !line.is_empty()).collect()
}

/// Reads the records a snapshot of `generation` should have applied to it.
///
/// A log belonging to another generation is stale and reads as empty: that is
/// the crash window between writing a new snapshot and removing the log it
/// replaced. A log that fails to authenticate anywhere but its last line is
/// refused, because that is tampering or damage rather than an interrupted
/// append, and silently continuing would hand back an index missing whatever
/// the unreadable records held.
/// `from_line` is the first record this caller has not already applied.
/// Earlier lines are counted but never decrypted: a session that tails its own
/// log would otherwise re-open every record it has already seen on each save,
/// which is O(log length) work per write and defeats the point of the log.
pub(crate) fn read_index_log(
    root_dir: &Path,
    key: &[u8],
    generation: u64,
    from_line: usize,
) -> Result<IndexLogRead, String> {
    let log_path = index_log_path(root_dir);
    if !log_path.exists() {
        return Ok(IndexLogRead::empty());
    }
    reject_symlink(&log_path)?;
    let raw = fs::read_to_string(&log_path).map_err(|error| error.to_string())?;
    let lines = complete_lines(&raw);
    if lines.is_empty() {
        return Ok(IndexLogRead::empty());
    }

    let header: IndexLogHeader = match serde_json::from_str::<EncryptedPayload>(lines[0])
        .map_err(|error| error.to_string())
        .and_then(|payload| decrypt(&payload, key, &header_aad(generation)))
        .and_then(|plain| serde_json::from_slice(&plain).map_err(|error| error.to_string()))
    {
        Ok(header) => header,
        // Either a log for a different generation, or one this key cannot
        // open. Both mean "do not apply it"; a stale log is the expected case.
        Err(_) => return Ok(IndexLogRead::empty()),
    };
    if header.version != INDEX_LOG_VERSION || header.generation != generation {
        return Ok(IndexLogRead::empty());
    }

    let mut records = Vec::new();
    for (line, text) in lines.iter().enumerate().skip(from_line.max(1)) {
        let decoded = serde_json::from_str::<EncryptedPayload>(text)
            .map_err(|error| error.to_string())
            .and_then(|payload| decrypt(&payload, key, &record_aad(generation, line)))
            .and_then(|plain| {
                serde_json::from_slice::<IndexLogRecord>(&plain).map_err(|error| error.to_string())
            });
        match decoded {
            Ok(record) => records.push(record),
            Err(_) if line == lines.len() - 1 => break, // A torn final append.
            Err(_) => {
                return Err(format!(
                    "the index change log is damaged at record {line}; rebuild the index to recover"
                ))
            }
        }
    }
    Ok(IndexLogRead {
        records,
        lines: lines.len(),
        bytes: raw.len() as u64,
    })
}

/// Starts a log for `generation`, replacing whatever was there.
pub(crate) fn start_index_log(
    root_dir: &Path,
    key: &[u8],
    generation: u64,
) -> Result<(usize, u64), String> {
    let log_path = index_log_path(root_dir);
    if log_path.exists() {
        reject_symlink(&log_path)?;
    }
    let header = IndexLogHeader {
        version: INDEX_LOG_VERSION,
        generation,
    };
    let payload = encrypt(
        &serde_json::to_vec(&header).map_err(|error| error.to_string())?,
        key,
        &header_aad(generation),
    )?;
    let line = sealed_line(&payload)?;
    let mut handle = fs::File::create(&log_path).map_err(|error| error.to_string())?;
    handle
        .write_all(line.as_bytes())
        .map_err(|error| error.to_string())?;
    handle.sync_all().map_err(|error| error.to_string())?;
    Ok((1, line.len() as u64))
}

/// Appends one record and makes it durable.
///
/// A single write followed by fsync, so the record a save acknowledges is on
/// disk before the save returns. Nothing here is deferred to make the number
/// look smaller.
pub(crate) fn append_index_log(
    root_dir: &Path,
    key: &[u8],
    generation: u64,
    line: usize,
    record: &IndexLogRecord,
) -> Result<u64, String> {
    let log_path = index_log_path(root_dir);
    reject_symlink(&log_path)?;
    let payload = encrypt(
        &serde_json::to_vec(record).map_err(|error| error.to_string())?,
        key,
        &record_aad(generation, line),
    )?;
    let sealed = sealed_line(&payload)?;
    let mut handle = OpenOptions::new()
        .append(true)
        .open(&log_path)
        .map_err(|error| error.to_string())?;
    handle
        .write_all(sealed.as_bytes())
        .map_err(|error| error.to_string())?;
    handle.sync_all().map_err(|error| error.to_string())?;
    Ok(sealed.len() as u64)
}

pub(crate) fn remove_index_log(root_dir: &Path) -> Result<(), String> {
    let log_path = index_log_path(root_dir);
    if !log_path.exists() {
        return Ok(());
    }
    reject_symlink(&log_path)?;
    fs::remove_file(&log_path).map_err(|error| error.to_string())
}

/// Whether the log has grown past the point where a fresh snapshot is cheaper.
pub(crate) fn should_compact(lines: usize, bytes: u64) -> bool {
    lines.saturating_sub(1) >= COMPACT_AFTER_RECORDS || bytes >= COMPACT_AFTER_BYTES
}
