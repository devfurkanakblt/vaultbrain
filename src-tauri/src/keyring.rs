//! The vault keyring: the passphrase-wrapped keyset that holds every data key.
//!
//! The format is defined by `docs/superpowers/specs/2026-09-03-vault-keyring-design.md`
//! and implemented on the other side by `src/keyring.ts`. Every constant, bound
//! and byte of associated data here has a counterpart there, and
//! `test/fixtures/keyring-vector.json` is what proves the two agree.
//!
//! This module reads a keyring and, for a brand-new vault, creates one. It
//! never migrates a legacy vault: adopting legacy keys so that attachment IDs,
//! sync change IDs and the audit chain keep verifying is `vbrain migrate`'s
//! job, and doing it here would silently orphan an audit chain.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{SecondsFormat, Utc};
use rand::{rngs::OsRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{reject_symlink, write_atomic};

pub(crate) const KEYRING_FILENAME: &str = "keyring.json";
pub(crate) const KEYRING_VERSION: u8 = 2;
pub(crate) const KEYSET_VERSION: u8 = 1;
/// The cost a vault created today is wrapped at. Read is never restricted to it.
pub(crate) const DEFAULT_SCRYPT_LOG_N: u8 = 17;

const KEY_LENGTH: usize = 32;
const SLOT_AAD_CONTEXT: &str = "secondbrain-vault:keyring-slot:v1";
const MIN_LOG_N: u8 = 14;
const MAX_LOG_N: u8 = 20;
const MAX_SLOTS: usize = 16;
/// Deliberately fixed rather than derived from the file's own parameters: `N`
/// and `r` can each be in range while their product implies a multi-gigabyte
/// allocation. A tampered keyring must not get to dictate its memory budget.
/// The same ceiling `scryptMaxmem` enforces in `src/keyring.ts`.
const MAX_SCRYPT_MEMORY: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SlotKdf {
    pub(crate) name: String,
    #[serde(rename = "N")]
    pub(crate) n: u32,
    pub(crate) r: u32,
    pub(crate) p: u32,
    pub(crate) salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WrappedKeySet {
    pub(crate) iv: String,
    pub(crate) auth_tag: String,
    pub(crate) ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyringSlot {
    pub(crate) id: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) kdf: SlotKdf,
    pub(crate) created_at: String,
    pub(crate) wrapped: WrappedKeySet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KeyringFile {
    pub(crate) version: u8,
    pub(crate) slots: Vec<KeyringSlot>,
}

/// The wrapped plaintext. Field order is the format's key order.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeySetKeys {
    documents: String,
    kv: String,
    attachment_id: String,
    sync_change: String,
    sync_envelope: String,
    audit: String,
}

/// The base64 in these fields is a directly reversible copy of all six vault
/// keys, and `String`'s ordinary drop leaves it in freed heap memory. Every
/// other key copy in this module is `Zeroizing`; this is the one serde has to
/// own, so it scrubs itself instead.
impl Drop for KeySetKeys {
    fn drop(&mut self) {
        self.documents.zeroize();
        self.kv.zeroize();
        self.attachment_id.zeroize();
        self.sync_change.zeroize();
        self.sync_envelope.zeroize();
        self.audit.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct KeySetFile {
    version: u8,
    keys: KeySetKeys,
}

/// Associated data for the wrap: the slot's identity and its declared cost.
/// Serialized in this exact field order, compactly, so it is byte-identical to
/// `JSON.stringify` over the same object in `src/keyring.ts`.
#[derive(Debug, Serialize)]
struct SlotAad<'a> {
    context: &'a str,
    version: u8,
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    kdf: &'a SlotKdf,
}

#[derive(Debug, Clone)]
pub(crate) struct KeySet {
    pub(crate) documents: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) kv: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) attachment_id: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) sync_change: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) sync_envelope: Zeroizing<[u8; KEY_LENGTH]>,
    pub(crate) audit: Zeroizing<[u8; KEY_LENGTH]>,
}

pub(crate) fn keyring_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(KEYRING_FILENAME)
}

/// The keyring, or `None` when this vault has none — which means the caller
/// must fall back to the legacy manifest derivation.
pub(crate) fn read(vault_dir: &Path) -> Result<Option<KeyringFile>, String> {
    let path = keyring_path(vault_dir);
    if !path.exists() {
        return Ok(None);
    }
    reject_symlink(&path)?;
    let raw = fs::read(&path).map_err(|error| error.to_string())?;
    let file: KeyringFile = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
    if file.version != KEYRING_VERSION {
        return Err(format!(
            "This vault keyring uses version {}; this build understands {}. Upgrade Vault Brain to open it.",
            file.version, KEYRING_VERSION
        ));
    }
    if file.slots.is_empty() || file.slots.len() > MAX_SLOTS {
        return Err("Vault keyring has no usable slots.".into());
    }
    for slot in &file.slots {
        validate_slot(slot)?;
    }
    Ok(Some(file))
}

pub(crate) fn write(vault_dir: &Path, file: &KeyringFile) -> Result<(), String> {
    let mut data = serde_json::to_vec_pretty(file).map_err(|error| error.to_string())?;
    data.push(b'\n');
    write_atomic(&keyring_path(vault_dir), &data)
}

fn decode_base64(value: &str, min: usize, max: usize, label: &str) -> Result<Vec<u8>, String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|_| format!("invalid base64 in vault keyring {label}"))?;
    if bytes.len() < min || bytes.len() > max {
        return Err(format!("vault keyring {label} has an unsupported length"));
    }
    Ok(bytes)
}

fn validate_slot(slot: &KeyringSlot) -> Result<(), String> {
    if slot.kind != "passphrase" {
        return Err(format!(
            "unsupported vault keyring slot type: {}",
            slot.kind
        ));
    }
    // The shape `src/keyring.ts` checks with /^[0-9a-f-]{36}$/, matched the way
    // `attachment_dir` matches a content address rather than by building a
    // regex on every validation.
    if slot.id.len() != 36
        || !slot
            .id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f' | b'-'))
    {
        return Err("vault keyring slot has a malformed id".into());
    }
    if slot.label.chars().count() > 64 {
        return Err("vault keyring slot label is too long".into());
    }
    // Deliberately stricter than `Date.parse` on the TypeScript side: every
    // timestamp either core writes is RFC 3339, so failing closed here on
    // anything looser cannot reject a keyring either core actually produced.
    chrono::DateTime::parse_from_rfc3339(&slot.created_at)
        .map_err(|_| "vault keyring slot has a malformed timestamp".to_string())?;
    validate_kdf(&slot.kdf)?;
    decode_base64(&slot.wrapped.iv, 12, 12, "iv")?;
    decode_base64(&slot.wrapped.auth_tag, 16, 16, "authentication tag")?;
    decode_base64(&slot.wrapped.ciphertext, 16, 4096, "ciphertext")?;
    Ok(())
}

fn validate_kdf(kdf: &SlotKdf) -> Result<u8, String> {
    if kdf.name != "scrypt" {
        return Err(format!(
            "unsupported key-derivation function in vault keyring: {}",
            kdf.name
        ));
    }
    if !kdf.n.is_power_of_two() {
        return Err("vault keyring cost N must be a power of two".into());
    }
    let log_n = kdf.n.trailing_zeros() as u8;
    if !(MIN_LOG_N..=MAX_LOG_N).contains(&log_n) {
        return Err(format!("vault keyring cost N is out of range: {}", kdf.n));
    }
    if !(1..=32).contains(&kdf.r) || !(1..=16).contains(&kdf.p) {
        return Err("vault keyring KDF parameters are out of range".into());
    }
    if 128 * u64::from(kdf.n) * u64::from(kdf.r) > MAX_SCRYPT_MEMORY {
        return Err("vault keyring KDF parameters exceed the memory limit".into());
    }
    decode_base64(&kdf.salt, 16, 64, "salt")?;
    Ok(log_n)
}

fn slot_aad(slot: &KeyringSlot) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SlotAad {
        context: SLOT_AAD_CONTEXT,
        version: KEYRING_VERSION,
        id: &slot.id,
        kind: &slot.kind,
        kdf: &slot.kdf,
    })
    .map_err(|error| error.to_string())
}

fn derive_slot_key(passphrase: &str, kdf: &SlotKdf) -> Result<Zeroizing<[u8; KEY_LENGTH]>, String> {
    let log_n = validate_kdf(kdf)?;
    let salt = decode_base64(&kdf.salt, 16, 64, "salt")?;
    let params =
        ScryptParams::new(log_n, kdf.r, kdf.p, KEY_LENGTH).map_err(|error| error.to_string())?;
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    scrypt(passphrase.as_bytes(), &salt, &params, key.as_mut())
        .map_err(|error| format!("key derivation failed: {error}"))?;
    Ok(key)
}

fn key_bytes(value: &str, label: &str) -> Result<Zeroizing<[u8; KEY_LENGTH]>, String> {
    let decoded = Zeroizing::new(decode_base64(value, KEY_LENGTH, KEY_LENGTH, label)?);
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn parse_key_set(plaintext: &[u8]) -> Result<KeySet, String> {
    let parsed: KeySetFile =
        serde_json::from_slice(plaintext).map_err(|_| "unreadable vault keyset".to_string())?;
    if parsed.version != KEYSET_VERSION {
        return Err(format!(
            "Unsupported vault keyset version: {}",
            parsed.version
        ));
    }
    Ok(KeySet {
        documents: key_bytes(&parsed.keys.documents, "documents key")?,
        kv: key_bytes(&parsed.keys.kv, "kv key")?,
        attachment_id: key_bytes(&parsed.keys.attachment_id, "attachmentId key")?,
        sync_change: key_bytes(&parsed.keys.sync_change, "syncChange key")?,
        sync_envelope: key_bytes(&parsed.keys.sync_envelope, "syncEnvelope key")?,
        audit: key_bytes(&parsed.keys.audit, "audit key")?,
    })
}

fn serialize_key_set(keys: &KeySet) -> Result<Zeroizing<String>, String> {
    let file = KeySetFile {
        version: KEYSET_VERSION,
        keys: KeySetKeys {
            documents: BASE64.encode(keys.documents.as_ref()),
            kv: BASE64.encode(keys.kv.as_ref()),
            attachment_id: BASE64.encode(keys.attachment_id.as_ref()),
            sync_change: BASE64.encode(keys.sync_change.as_ref()),
            sync_envelope: BASE64.encode(keys.sync_envelope.as_ref()),
            audit: BASE64.encode(keys.audit.as_ref()),
        },
    };
    Ok(Zeroizing::new(
        serde_json::to_string(&file).map_err(|error| error.to_string())?,
    ))
}

/// A wrong passphrase fails as an authentication error. There is deliberately
/// no verifier field: publishing one hands an offline attacker a free
/// passphrase-guessing oracle.
fn unwrap_slot(slot: &KeyringSlot, passphrase: &str) -> Result<KeySet, String> {
    validate_slot(slot)?;
    let derived = derive_slot_key(passphrase, &slot.kdf)?;
    let aad = slot_aad(slot)?;
    let iv = decode_base64(&slot.wrapped.iv, 12, 12, "iv")?;
    let tag = decode_base64(&slot.wrapped.auth_tag, 16, 16, "authentication tag")?;
    let mut buffer = Zeroizing::new(
        BASE64
            .decode(&slot.wrapped.ciphertext)
            .map_err(|_| "invalid base64 in vault keyring ciphertext")?,
    );
    let cipher =
        Aes256Gcm::new_from_slice(derived.as_ref()).map_err(|_| "invalid AES key".to_string())?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&iv),
            &aad,
            &mut buffer,
            Tag::from_slice(&tag),
        )
        .map_err(|_| "vault keyring slot did not authenticate".to_string())?;
    parse_key_set(&buffer)
}

/// Every slot wraps the same keyset, so the first one that opens wins.
pub(crate) fn unwrap_keyring(file: &KeyringFile, passphrase: &str) -> Result<KeySet, String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    for slot in &file.slots {
        if let Ok(keys) = unwrap_slot(slot, passphrase) {
            return Ok(keys);
        }
    }
    Err("Unable to unlock this vault: wrong passphrase, or the keyring is damaged.".into())
}

/// Six independent random keys. A created vault adopts nothing: adoption is
/// migration's business, and only a migrated vault needs it.
pub(crate) fn random_key_set() -> KeySet {
    let new_key = || {
        let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
        OsRng.fill_bytes(key.as_mut());
        key
    };
    KeySet {
        documents: new_key(),
        kv: new_key(),
        attachment_id: new_key(),
        sync_change: new_key(),
        sync_envelope: new_key(),
        audit: new_key(),
    }
}

pub(crate) fn wrap_key_set(
    keys: &KeySet,
    passphrase: &str,
    log_n: u8,
) -> Result<KeyringSlot, String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    if !(MIN_LOG_N..=MAX_LOG_N).contains(&log_n) {
        return Err("vault keyring cost N is out of range".into());
    }
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let mut slot = KeyringSlot {
        id: Uuid::new_v4().to_string(),
        kind: "passphrase".into(),
        label: "primary".into(),
        kdf: SlotKdf {
            name: "scrypt".into(),
            n: 1u32 << log_n,
            r: 8,
            p: 1,
            salt: BASE64.encode(salt),
        },
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        wrapped: WrappedKeySet {
            iv: BASE64.encode(iv),
            auth_tag: String::new(),
            ciphertext: String::new(),
        },
    };
    let derived = derive_slot_key(passphrase, &slot.kdf)?;
    let aad = slot_aad(&slot)?;
    let plaintext = serialize_key_set(keys)?;
    let mut buffer = Zeroizing::new(plaintext.as_bytes().to_vec());
    let cipher =
        Aes256Gcm::new_from_slice(derived.as_ref()).map_err(|_| "invalid AES key".to_string())?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut buffer)
        .map_err(|_| "wrapping the vault keyset failed".to_string())?;
    slot.wrapped.auth_tag = BASE64.encode(tag);
    slot.wrapped.ciphertext = BASE64.encode(&*buffer);
    Ok(slot)
}

/// NIST SP 800-63B's floor for a user-chosen secret, and the same floor
/// `MIN_PASSPHRASE_LENGTH` enforces in `src/keyring-passphrase.ts`. It applies
/// to the new passphrase only: an existing vault whose passphrase is shorter
/// still opens, because refusing it would lock its owner out rather than
/// protect them.
pub(crate) const MIN_PASSPHRASE_LENGTH: usize = 12;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PassphraseChangeReport {
    /// Slots re-wrapped under the new passphrase.
    pub(crate) slots_rewritten: usize,
    /// Slots the current passphrase could not open, carried across untouched.
    pub(crate) slots_preserved: usize,
    /// The cost of the first slot that opened, before the change.
    pub(crate) previous_n: u32,
    /// The cost every rewritten slot now carries.
    pub(crate) new_n: u32,
}

fn same_key_set(left: &KeySet, right: &KeySet) -> bool {
    let mut difference = 0u8;
    for (a, b) in [
        (&left.documents, &right.documents),
        (&left.kv, &right.kv),
        (&left.attachment_id, &right.attachment_id),
        (&left.sync_change, &right.sync_change),
        (&left.sync_envelope, &right.sync_envelope),
        (&left.audit, &right.audit),
    ] {
        for (x, y) in a.iter().zip(b.iter()) {
            difference |= x ^ y;
        }
    }
    difference == 0
}

/// Re-wraps the vault keyset under a new passphrase.
///
/// Nothing under `documents/`, no attachment, no sync change and no audit
/// entry is read or rewritten: only the wrapping layer changes, so attachment
/// identities, sync change ids and the audit chain all survive untouched.
/// Because every rewritten slot is written at the current default cost with a
/// fresh salt, this is also how a vault created at a lower cost raises its work
/// factor.
///
/// A slot the current passphrase cannot open — the recovery slot — is carried
/// across byte for byte rather than discarded, which is what keeps a recovery
/// kit valid across a passphrase change.
///
/// The caller must already hold the vault write lock.
pub(crate) fn change_passphrase_locked(
    vault_dir: &Path,
    current: &str,
    new: &str,
) -> Result<(PassphraseChangeReport, Zeroizing<[u8; KEY_LENGTH]>), String> {
    if current.is_empty() {
        return Err("a non-empty vault passphrase is required".into());
    }
    if new.chars().count() < MIN_PASSPHRASE_LENGTH {
        return Err(format!(
            "the new passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters"
        ));
    }
    if new == current {
        return Err("the new passphrase is the same as the current one".into());
    }

    let file = read(vault_dir)?.ok_or("this vault has no keyring to change")?;
    let mut opened: Option<KeySet> = None;
    let mut previous_n = 0u32;
    let mut preserved = 0usize;
    let mut slots: Vec<KeyringSlot> = Vec::with_capacity(file.slots.len());
    let mut rewritten_indexes: Vec<usize> = Vec::new();

    for slot in &file.slots {
        match unwrap_slot(slot, current) {
            Err(_) => {
                // Not this passphrase's slot. Preserving it is what keeps a
                // recovery slot alive across a passphrase change.
                slots.push(slot.clone());
                preserved += 1;
            }
            Ok(keys) => {
                match opened.as_ref() {
                    None => {
                        previous_n = slot.kdf.n;
                        opened = Some(keys);
                    }
                    Some(first) => {
                        if !same_key_set(&keys, first) {
                            return Err(
                                "a second slot this passphrase opens carries a different keyset; refusing to write the keyring"
                                    .into(),
                            );
                        }
                    }
                }
                let carried = opened.as_ref().expect("a keyset is open");
                rewritten_indexes.push(slots.len());
                slots.push(wrap_key_set(carried, new, DEFAULT_SCRYPT_LOG_N)?);
            }
        }
    }

    let opened = opened.ok_or("wrong passphrase, or the keyring is damaged")?;

    // Prove every freshly wrapped slot unwraps back to the same keyset under
    // the new passphrase before anything touches disk. A refusal here must
    // leave keyring.json byte-identical to what it was.
    for index in &rewritten_indexes {
        let check = unwrap_slot(&slots[*index], new)?;
        if !same_key_set(&check, &opened) {
            return Err(
                "a re-wrapped slot does not carry the vault's keyset; refusing to write the keyring"
                    .into(),
            );
        }
    }

    write(
        vault_dir,
        &KeyringFile {
            version: KEYRING_VERSION,
            slots,
        },
    )?;

    // Prove the file actually on disk opens under the passphrase the user was
    // just given, and carries the same keyset, before reporting success. This
    // catches a bad write that the pre-write check above cannot, since that
    // check never touches disk.
    let written = read(vault_dir)?.ok_or("the new keyring could not be read back")?;
    let verified = unwrap_keyring(&written, new)?;
    if !same_key_set(&verified, &opened) {
        return Err(
            "the keyring written to disk does not carry the vault's keyset; the vault may be corrupted"
                .into(),
        );
    }

    Ok((
        PassphraseChangeReport {
            slots_rewritten: rewritten_indexes.len(),
            slots_preserved: preserved,
            previous_n,
            new_n: default_scrypt_n(),
        },
        opened.audit.clone(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        passphrase: String,
        aad: String,
        keyset_plaintext: String,
        keys: std::collections::HashMap<String, String>,
        slot: KeyringSlot,
    }

    fn vector() -> Vector {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("test")
            .join("fixtures")
            .join("keyring-vector.json");
        serde_json::from_slice(&fs::read(path).expect("read the keyring vector"))
            .expect("parse the keyring vector")
    }

    /// The same shape `readKeyringStatus` returns in `src/keyring-status.ts`,
    /// so the application and `vbrain keyring status` describe one vault the
    /// same way.
    /// The property that makes a passphrase change safe to offer at all: it
    /// moves the wrapping and nothing else, so every identity derived from the
    /// keyset — attachment content addresses, sync change ids, the audit chain
    /// — is the same afterwards.
    #[test]
    fn changing_the_passphrase_keeps_the_keyset_and_preserves_a_recovery_slot() {
        let dir = std::env::temp_dir().join(format!("vbrain-passphrase-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let keys = random_key_set();
        let before = keys.documents.clone();
        let primary = wrap_key_set(&keys, "the original passphrase", 14).unwrap();
        let mut recovery = wrap_key_set(&keys, "a recovery code that is long", 14).unwrap();
        recovery.label = RECOVERY_LABEL.to_string();
        let recovery_id = recovery.id.clone();
        write(
            &dir,
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![primary, recovery],
            },
        )
        .unwrap();

        let (report, _chain) =
            change_passphrase_locked(&dir, "the original passphrase", "a replacement passphrase")
                .unwrap();
        assert_eq!(report.slots_rewritten, 1);
        assert_eq!(report.slots_preserved, 1, "the recovery slot must survive");
        assert_eq!(report.previous_n, 1 << 14);
        assert_eq!(
            report.new_n,
            1 << DEFAULT_SCRYPT_LOG_N,
            "a change raises the cost"
        );

        let file = read(&dir).unwrap().unwrap();
        let opened = unwrap_keyring(&file, "a replacement passphrase").unwrap();
        assert_eq!(
            opened.documents.as_ref(),
            before.as_ref(),
            "the keyset is the same keyset"
        );
        assert!(unwrap_keyring(&file, "the original passphrase").is_err());
        // The recovery kit still opens the vault, unchanged.
        let by_recovery = unwrap_keyring(&file, "a recovery code that is long").unwrap();
        assert_eq!(by_recovery.documents.as_ref(), before.as_ref());
        assert!(file.slots.iter().any(|slot| slot.id == recovery_id));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_passphrase_change_refuses_a_weak_or_unchanged_secret_and_a_wrong_current_one() {
        let dir = std::env::temp_dir().join(format!("vbrain-passphrase-bad-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let keys = random_key_set();
        write(
            &dir,
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![wrap_key_set(&keys, "the original passphrase", 14).unwrap()],
            },
        )
        .unwrap();
        let before = fs::read(keyring_path(&dir)).unwrap();

        for (current, next) in [
            ("the original passphrase", "short"),
            ("the original passphrase", "the original passphrase"),
            ("not the passphrase", "a replacement passphrase"),
        ] {
            assert!(change_passphrase_locked(&dir, current, next).is_err());
            // Every refusal must leave the keyring byte-identical: a failed
            // change that damaged the file would be far worse than no change.
            assert_eq!(fs::read(keyring_path(&dir)).unwrap(), before);
        }

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_reports_slot_headers_without_unwrapping_anything() {
        let dir = std::env::temp_dir().join(format!("vbrain-status-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let keys = random_key_set();
        let primary = wrap_key_set(&keys, "a status passphrase", 14).unwrap();
        let mut recovery = wrap_key_set(&keys, "a recovery code", 14).unwrap();
        // The label is display metadata and deliberately outside the slot AAD,
        // the same way `a_recovery_labeled_passphrase_slot_opens_the_same_keyset`
        // relies on.
        recovery.label = RECOVERY_LABEL.to_string();
        write(
            &dir,
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![primary, recovery],
            },
        )
        .unwrap();

        let status = status(&dir, "keyring").unwrap();
        assert_eq!(status.version, Some(KEYRING_VERSION));
        assert_eq!(status.recommended_scrypt_n, 1 << DEFAULT_SCRYPT_LOG_N);
        assert!(
            status.recovery_configured,
            "a recovery slot must be visible"
        );
        assert_eq!(status.slots.len(), 2);
        assert!(!status.slots[0].recovery);
        assert!(status.slots[1].recovery);
        // Both were written well below the current default, which is exactly
        // the condition a user cannot otherwise discover.
        for slot in &status.slots {
            assert!(matches!(slot.kdf.cost, CostStatus::BelowDefault));
        }

        // A vault with no keyring reports the format rather than failing.
        let empty = status_for_empty();
        assert_eq!(empty.version, None);
        assert!(empty.slots.is_empty());
        assert!(!empty.recovery_configured);

        fs::remove_dir_all(&dir).ok();
    }

    fn status_for_empty() -> KeyringStatus {
        status(Path::new("does-not-matter"), "empty").unwrap()
    }

    #[test]
    fn associated_data_matches_the_typescript_core_byte_for_byte() {
        let vector = vector();
        assert_eq!(
            String::from_utf8(slot_aad(&vector.slot).unwrap()).unwrap(),
            vector.aad
        );
    }

    #[test]
    fn the_cross_core_vector_unwraps_to_its_recorded_keyset() {
        let vector = vector();
        let keys = unwrap_keyring(
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![vector.slot.clone()],
            },
            &vector.passphrase,
        )
        .unwrap();
        for (name, expected) in [
            ("documents", &keys.documents),
            ("kv", &keys.kv),
            ("attachmentId", &keys.attachment_id),
            ("syncChange", &keys.sync_change),
            ("syncEnvelope", &keys.sync_envelope),
            ("audit", &keys.audit),
        ] {
            assert_eq!(
                BASE64.encode(expected.as_ref()),
                vector.keys[name],
                "key {name}"
            );
        }
    }

    #[test]
    fn the_serialized_keyset_matches_what_the_typescript_core_parses() {
        let vector = vector();
        let keys = unwrap_slot(&vector.slot, &vector.passphrase).unwrap();
        assert_eq!(*serialize_key_set(&keys).unwrap(), vector.keyset_plaintext);
    }

    #[test]
    fn a_rewritten_slot_header_fails_closed() {
        let vector = vector();
        // The vector is wrapped at 2**14, so the header is rewritten UPWARD here:
        // rewriting it to the same cost would authenticate and prove nothing.
        let mut recosted = vector.slot.clone();
        recosted.kdf.n = 1 << 15;
        let mut retyped = vector.slot.clone();
        retyped.id = "00000000-0000-4000-8000-000000000002".into();
        let mut corrupted = vector.slot.clone();
        corrupted.wrapped.ciphertext = BASE64.encode(b"not the original ciphertext");

        for slot in [recosted, retyped, corrupted] {
            assert!(
                unwrap_slot(&slot, &vector.passphrase).is_err(),
                "a tampered slot must not open"
            );
        }
    }

    #[test]
    fn out_of_policy_costs_are_refused() {
        let vector = vector();
        for (n, r, p) in [
            (1u32 << 13, 8u32, 1u32),
            (100_000, 8, 1),
            (1 << 20, 32, 1),
            (1 << 15, 0, 1),
        ] {
            let mut slot = vector.slot.clone();
            slot.kdf.n = n;
            slot.kdf.r = r;
            slot.kdf.p = p;
            assert!(
                validate_kdf(&slot.kdf).is_err(),
                "accepted N={n} r={r} p={p}"
            );
        }
    }

    #[test]
    fn a_wrapped_keyset_round_trips_and_rejects_the_wrong_passphrase() {
        let keys = random_key_set();
        let slot = wrap_key_set(&keys, "correct horse battery staple", MIN_LOG_N).unwrap();
        let file = KeyringFile {
            version: KEYRING_VERSION,
            slots: vec![slot],
        };
        // Through JSON, so a serde rename or a field-order mistake is caught here
        // rather than by a user whose other core cannot read the file.
        let round_tripped: KeyringFile =
            serde_json::from_str(&serde_json::to_string(&file).unwrap()).unwrap();
        let opened = unwrap_keyring(&round_tripped, "correct horse battery staple").unwrap();
        assert_eq!(opened.documents.as_ref(), keys.documents.as_ref());
        assert_eq!(opened.audit.as_ref(), keys.audit.as_ref());
        assert!(unwrap_keyring(&round_tripped, "wrong passphrase").is_err());
    }

    #[test]
    fn a_recovery_labeled_passphrase_slot_opens_the_same_keyset() {
        let keys = random_key_set();
        let primary = wrap_key_set(&keys, "correct horse battery staple", MIN_LOG_N).unwrap();
        let mut recovery = wrap_key_set(
            &keys,
            "vbr1_abcdefghijklmnopqrstuvwxyzABCDEFGH012345678_deadbeef",
            MIN_LOG_N,
        )
        .unwrap();
        // label is intentionally display metadata; the authenticated slot type
        // remains `passphrase`, preserving the phase 7.1 cross-core format.
        recovery.label = "recovery".into();
        let opened = unwrap_keyring(
            &KeyringFile {
                version: KEYRING_VERSION,
                slots: vec![primary, recovery],
            },
            "vbr1_abcdefghijklmnopqrstuvwxyzABCDEFGH012345678_deadbeef",
        )
        .unwrap();
        assert_eq!(*opened.documents, *keys.documents);
        assert_eq!(*opened.kv, *keys.kv);
        assert_eq!(*opened.audit, *keys.audit);
    }

    #[test]
    fn a_keyring_file_survives_a_write_and_a_read() {
        let dir = std::env::temp_dir().join(format!("vault-brain-keyring-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let keys = random_key_set();
        let file = KeyringFile {
            version: KEYRING_VERSION,
            slots: vec![wrap_key_set(&keys, "pass", MIN_LOG_N).unwrap()],
        };
        write(&dir, &file).unwrap();
        let read_back = read(&dir).unwrap().expect("a keyring was written");
        assert_eq!(
            unwrap_keyring(&read_back, "pass").unwrap().kv.as_ref(),
            keys.kv.as_ref()
        );
        assert!(read(&dir.join("missing")).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn slot_validation_matches_the_typescript_core() {
        let vector = vector();
        assert!(
            validate_slot(&vector.slot).is_ok(),
            "the vector's own slot must still validate"
        );

        let mut bad_id = vector.slot.clone();
        bad_id.id = "not-a-valid-slot-id".into();
        assert!(
            validate_slot(&bad_id).is_err(),
            "an id of the wrong shape must be rejected"
        );

        let mut long_label = vector.slot.clone();
        long_label.label = "x".repeat(65);
        assert!(
            validate_slot(&long_label).is_err(),
            "a label over 64 characters must be rejected"
        );

        let mut bad_timestamp = vector.slot.clone();
        bad_timestamp.created_at = "not a timestamp".into();
        assert!(
            validate_slot(&bad_timestamp).is_err(),
            "a created_at that is not a timestamp must be rejected"
        );

        let mut oversized_ciphertext = vector.slot.clone();
        oversized_ciphertext.wrapped.ciphertext = BASE64.encode(vec![0u8; 4097]);
        assert!(
            validate_slot(&oversized_ciphertext).is_err(),
            "a ciphertext decoding to more than 4096 bytes must be rejected"
        );
    }

    #[test]
    fn base64_key_material_is_cleared_by_the_zeroize_call_the_drop_impl_relies_on() {
        // `KeySetKeys::drop` scrubs each field with `String::zeroize()`. Once
        // the struct is actually dropped its heap allocation is freed, and
        // safe Rust has no way to read freed memory back to prove the scrub
        // happened — so this cannot assert anything about memory *after*
        // drop. What it can prove, safely, is that the exact primitive the
        // `Drop` impl calls on every field really does clear a base64 key
        // copy's contents before that string is torn down.
        let mut documents = BASE64.encode([7u8; KEY_LENGTH]);
        assert!(!documents.is_empty());
        documents.zeroize();
        assert!(
            documents.is_empty(),
            "zeroize must clear the string's content"
        );
    }
}

/// The recovery slot's label. `src/keyring-recovery.ts` writes exactly this,
/// and it is what distinguishes a recovery slot from the primary one — the
/// slot `type` stays `passphrase` for both, because the on-disk slot format
/// did not change when recovery kits arrived.
pub(crate) const RECOVERY_LABEL: &str = "recovery";

/// Whether a slot's work factor is behind, at, or ahead of what this build
/// writes for a new slot. A vault created before the default rose keeps its
/// old cost until its passphrase is changed once, and without this nobody can
/// discover that.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CostStatus {
    BelowDefault,
    Default,
    AboveDefault,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StatusKdf {
    pub(crate) name: String,
    #[serde(rename = "N")]
    pub(crate) n: u32,
    pub(crate) r: u32,
    pub(crate) p: u32,
    pub(crate) cost: CostStatus,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StatusSlot {
    pub(crate) id: String,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) created_at: String,
    pub(crate) recovery: bool,
    pub(crate) kdf: StatusKdf,
}

/// The same shape `readKeyringStatus` returns in `src/keyring-status.ts`, so
/// the application and `vbrain keyring status` describe one vault the same way.
/// Nothing here is unwrapped: this reads slot headers only and never needs the
/// passphrase.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyringStatus {
    pub(crate) format: String,
    pub(crate) version: Option<u8>,
    pub(crate) recommended_scrypt_n: u32,
    pub(crate) recovery_configured: bool,
    pub(crate) slots: Vec<StatusSlot>,
}

pub(crate) fn default_scrypt_n() -> u32 {
    1u32 << DEFAULT_SCRYPT_LOG_N
}

pub(crate) fn status(vault_dir: &Path, format: &str) -> Result<KeyringStatus, String> {
    let recommended = default_scrypt_n();
    if format != "keyring" {
        return Ok(KeyringStatus {
            format: format.to_string(),
            version: None,
            recommended_scrypt_n: recommended,
            recovery_configured: false,
            slots: Vec::new(),
        });
    }
    let file = read(vault_dir)?.ok_or("this vault has no keyring")?;
    let slots: Vec<StatusSlot> = file
        .slots
        .iter()
        .map(|slot| StatusSlot {
            id: slot.id.clone(),
            kind: slot.kind.clone(),
            label: slot.label.clone(),
            created_at: slot.created_at.clone(),
            recovery: slot.label == RECOVERY_LABEL,
            kdf: StatusKdf {
                name: slot.kdf.name.clone(),
                n: slot.kdf.n,
                r: slot.kdf.r,
                p: slot.kdf.p,
                cost: match slot.kdf.n.cmp(&recommended) {
                    std::cmp::Ordering::Less => CostStatus::BelowDefault,
                    std::cmp::Ordering::Equal => CostStatus::Default,
                    std::cmp::Ordering::Greater => CostStatus::AboveDefault,
                },
            },
        })
        .collect();
    Ok(KeyringStatus {
        format: format.to_string(),
        version: Some(file.version),
        recommended_scrypt_n: recommended,
        recovery_configured: slots.iter().any(|slot| slot.recovery),
        slots,
    })
}
