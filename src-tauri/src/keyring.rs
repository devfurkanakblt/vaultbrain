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
use regex::Regex;
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
        return Err(format!("unsupported vault keyring slot type: {}", slot.kind));
    }
    let id_pattern = Regex::new(r"^[0-9a-f-]{36}$").map_err(|error| error.to_string())?;
    if !id_pattern.is_match(&slot.id) {
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
    let params = ScryptParams::new(log_n, kdf.r, kdf.p, KEY_LENGTH)
        .map_err(|error| error.to_string())?;
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
            &mut *buffer,
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
        .encrypt_in_place_detached(Nonce::from_slice(&iv), &aad, &mut *buffer)
        .map_err(|_| "wrapping the vault keyset failed".to_string())?;
    slot.wrapped.auth_tag = BASE64.encode(tag);
    slot.wrapped.ciphertext = BASE64.encode(&*buffer);
    Ok(slot)
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
        assert!(documents.is_empty(), "zeroize must clear the string's content");
    }
}
