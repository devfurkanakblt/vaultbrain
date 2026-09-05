//! The passphrase-authenticated audit chain, as `src/audit.ts` writes it.
//!
//! Until now this file had no Rust counterpart, which meant every note, canvas,
//! attachment and plugin change made in the desktop application was absent from
//! the chain entirely: `audit.log` was written only by the command-line tool.
//! An audit chain with a hole that size does not answer the question it exists
//! to answer.
//!
//! Two constructions have to match the TypeScript core exactly, and neither
//! fails loudly when it drifts — a mismatch simply makes one core's entries
//! stop verifying under the other. `test/fixtures/audit-vector.json` pins both,
//! and is read by `test/audit-vector.test.mjs` on the other side.
//!
//! - An entry's `hash` is `HMAC-SHA256(auditKey, payload)` where `payload` is
//!   JSON with the field order below and every absent optional field omitted
//!   rather than serialized as null. Omission is what keeps a log written
//!   before the grant fields existed verifying unchanged.
//! - The head's `mac` is `HMAC-SHA256(auditKey, {"version","signedEntries",
//!   "lastHash"})`, again in that order.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{read_limited, reject_symlink, write_atomic};

pub(crate) const GENESIS_HASH: &str = "GENESIS";
const AUDIT_FILENAME: &str = "audit.log";
const AUDIT_HEAD_FILENAME: &str = "audit.head.json";
/// The same 16 MiB ceiling `src/audit.ts` enforces before it parses a log.
const MAX_AUDIT_BYTES: u64 = 16 * 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

/// One line of `audit.log`. `prev_hash` and `hash` are absent on entries a
/// build older than the signed chain wrote, and those stay readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AuditEntry {
    pub(crate) timestamp: String,
    pub(crate) actor: String,
    pub(crate) file: String,
    pub(crate) key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) redaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) outcome: Option<String>,
    #[serde(rename = "prevHash", default, skip_serializing_if = "Option::is_none")]
    pub(crate) prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) hash: Option<String>,
}

/// What an audit call supplies. The timestamp, chaining and hash are this
/// module's to decide, so a caller cannot accidentally forge either.
pub(crate) struct AuditRecord {
    pub(crate) actor: &'static str,
    pub(crate) file: String,
    pub(crate) key: String,
    pub(crate) outcome: Option<&'static str>,
}

/// The signed payload. This field order is part of the format.
#[derive(Serialize)]
struct SignedPayload<'a> {
    timestamp: &'a str,
    actor: &'a str,
    file: &'a str,
    key: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redaction: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<&'a str>,
    #[serde(rename = "prevHash")]
    prev_hash: &'a str,
}

#[derive(Serialize)]
struct UnsignedHead {
    version: u8,
    #[serde(rename = "signedEntries")]
    signed_entries: usize,
    #[serde(rename = "lastHash")]
    last_hash: String,
}

#[derive(Serialize)]
struct SignedHead {
    version: u8,
    #[serde(rename = "signedEntries")]
    signed_entries: usize,
    #[serde(rename = "lastHash")]
    last_hash: String,
    mac: String,
}

fn hmac_hex(key: &[u8], message: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|error| error.to_string())?;
    mac.update(message);
    Ok(hex(&mac.finalize().into_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn audit_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(AUDIT_FILENAME)
}

fn head_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(AUDIT_HEAD_FILENAME)
}

/// The hash an entry carries, given the hash of the previous signed entry.
pub(crate) fn entry_hash(
    entry: &AuditEntry,
    prev_hash: &str,
    key: &[u8],
) -> Result<String, String> {
    let payload = SignedPayload {
        timestamp: &entry.timestamp,
        actor: &entry.actor,
        file: &entry.file,
        key: &entry.key,
        agent: entry.agent.as_deref(),
        grant: entry.grant.as_deref(),
        redaction: entry.redaction.as_deref(),
        outcome: entry.outcome.as_deref(),
        prev_hash,
    };
    let encoded = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
    hmac_hex(key, &encoded)
}

/// The mac the head file carries for a chain of `signed_entries` ending at
/// `last_hash`.
pub(crate) fn head_mac(
    signed_entries: usize,
    last_hash: &str,
    key: &[u8],
) -> Result<String, String> {
    let head = UnsignedHead {
        version: 1,
        signed_entries,
        last_hash: last_hash.to_string(),
    };
    let encoded = serde_json::to_vec(&head).map_err(|error| error.to_string())?;
    hmac_hex(key, &encoded)
}

/// Every entry in the log, in the order it was written. A malformed line is an
/// error rather than a skip: silently dropping one would renumber the chain.
pub(crate) fn read(vault_dir: &Path) -> Result<Vec<AuditEntry>, String> {
    let path = audit_path(vault_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    reject_symlink(&path)?;
    let raw = read_limited(&path, MAX_AUDIT_BYTES, "Audit log")?;
    let text = String::from_utf8(raw).map_err(|_| "Audit log is not valid UTF-8.".to_string())?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        entries.push(
            serde_json::from_str::<AuditEntry>(line)
                .map_err(|error| format!("Malformed audit entry: {error}"))?,
        );
    }
    Ok(entries)
}

/// Append one signed entry and advance the head.
///
/// The caller must already hold the vault write lock. This does not take it
/// itself: every desktop write path is already inside one, and re-entering it
/// would block until the wait expired against a lock this very process holds.
pub(crate) fn append_locked(
    vault_dir: &Path,
    record: AuditRecord,
    key: &[u8],
    timestamp: String,
) -> Result<(), String> {
    let existing = read(vault_dir)?;
    let signed_entries = existing.iter().filter(|entry| entry.hash.is_some()).count();
    let prev_hash = existing
        .iter()
        .rev()
        .find_map(|entry| entry.hash.clone())
        .unwrap_or_else(|| GENESIS_HASH.to_string());

    let mut entry = AuditEntry {
        timestamp,
        actor: record.actor.to_string(),
        file: record.file,
        key: record.key,
        agent: None,
        grant: None,
        redaction: None,
        outcome: record.outcome.map(str::to_string),
        prev_hash: Some(prev_hash.clone()),
        hash: None,
    };
    let hash = entry_hash(&entry, &prev_hash, key)?;
    entry.hash = Some(hash.clone());

    let path = audit_path(vault_dir);
    reject_symlink(&path)?;
    let mut line = serde_json::to_vec(&entry).map_err(|error| error.to_string())?;
    line.push(b'\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| error.to_string())?;
    file.write_all(&line).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;

    // The head is advanced only after the entry is durable. A head that ran
    // ahead of the log would report a chain longer than the one on disk.
    let signed_entries = signed_entries + 1;
    let head = SignedHead {
        version: 1,
        signed_entries,
        last_hash: hash.clone(),
        mac: head_mac(signed_entries, &hash, key)?,
    };
    let encoded = serde_json::to_vec(&head).map_err(|error| error.to_string())?;
    write_atomic(&head_path(vault_dir), &encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use serde::Deserialize;
    use std::fs;

    #[derive(Deserialize)]
    struct VectorHead {
        #[serde(rename = "signedEntries")]
        signed_entries: usize,
        #[serde(rename = "lastHash")]
        last_hash: String,
        mac: String,
    }

    #[derive(Deserialize)]
    struct Vector {
        key: String,
        #[serde(rename = "genesisHash")]
        genesis_hash: String,
        entries: Vec<AuditEntry>,
        head: VectorHead,
    }

    fn vector() -> Vector {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("test")
            .join("fixtures")
            .join("audit-vector.json");
        serde_json::from_slice(&fs::read(path).expect("read the audit vector"))
            .expect("parse the audit vector")
    }

    /// The other half of this assertion lives in `test/audit-vector.test.mjs`.
    /// Both cores append to one chain, so a disagreement here would not fail
    /// loudly — it would make one core's entries stop verifying under the
    /// other, which is the failure the chain exists to detect.
    #[test]
    fn audit_entry_hashes_match_the_committed_cross_core_vector() {
        let vector = vector();
        let key = BASE64.decode(&vector.key).expect("vector key");
        let mut previous = vector.genesis_hash.clone();
        for (index, entry) in vector.entries.iter().enumerate() {
            assert_eq!(
                entry.prev_hash.as_deref(),
                Some(previous.as_str()),
                "entry {} must chain to the previous hash",
                index + 1
            );
            let computed = entry_hash(entry, &previous, &key).unwrap();
            assert_eq!(
                Some(computed.as_str()),
                entry.hash.as_deref(),
                "entry {} hash",
                index + 1
            );
            previous = entry.hash.clone().expect("a signed entry");
        }
    }

    #[test]
    fn the_audit_head_mac_matches_the_committed_cross_core_vector() {
        let vector = vector();
        let key = BASE64.decode(&vector.key).expect("vector key");
        assert_eq!(
            head_mac(vector.head.signed_entries, &vector.head.last_hash, &key).unwrap(),
            vector.head.mac
        );
        assert_eq!(vector.head.signed_entries, vector.entries.len());
    }

    /// An absent optional field must contribute nothing to the hash, which is
    /// what keeps a log written before the grant fields existed verifying.
    #[test]
    fn an_absent_optional_field_is_omitted_from_the_signature() {
        let key = [7u8; 32];
        let bare = AuditEntry {
            timestamp: "2026-09-05T09:00:00.000Z".into(),
            actor: "cli-direct".into(),
            file: "f".into(),
            key: "k".into(),
            agent: None,
            grant: None,
            redaction: None,
            outcome: None,
            prev_hash: Some(GENESIS_HASH.into()),
            hash: None,
        };
        let with_agent = AuditEntry {
            agent: Some("someone".into()),
            ..bare.clone()
        };
        assert_ne!(
            entry_hash(&bare, GENESIS_HASH, &key).unwrap(),
            entry_hash(&with_agent, GENESIS_HASH, &key).unwrap()
        );
    }
}
