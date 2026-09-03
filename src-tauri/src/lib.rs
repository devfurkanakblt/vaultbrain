use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL},
    Engine,
};
use chrono::{DateTime, Local, NaiveDate, SecondsFormat, TimeZone, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
mod keyring;
const INDEX_AAD: &str = "secondbrain-vault:document-index:v1";
const DERIVED_LAYOUT: u8 = 5;
const KEY_CHECK_CONTEXT: &str = "secondbrain-vault:document-key:v1";
const MAX_NOTE_BYTES: usize = 25 * 1024 * 1024;
const SAVED_VIEWS_AAD: &str = "secondbrain-vault:saved-views:v1";
const MAX_SAVED_VIEWS: usize = 200;
const MAX_CLUSTER_ROUNDS: usize = 20;
const WORKSPACE_AAD: &str = "secondbrain-vault:workspace:v1";
const MAX_BOOKMARKS: usize = 500;
const MAX_LAYOUTS: usize = 100;
const MAX_MENTIONS: usize = 50;
const ATTACHMENT_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 250 * 1024 * 1024;
const MAX_CANVAS_BYTES: usize = 8 * 1024 * 1024;
const MAX_CANVAS_NODES: usize = 5_000;
const MAX_CANVAS_EDGES: usize = 10_000;
const MAX_PLUGIN_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PLUGIN_STORAGE_BYTES: usize = 256 * 1024;
const MAX_PLUGINS: usize = 100;
const PLUGIN_POLICY_AAD: &str = "secondbrain-vault:plugin-policy:v1";
const PLUGIN_SIGNATURE_PREFIX: &[u8] = b"secondbrain-vault-plugin-signature-v1\n";

/// The capability names this build understands.
///
/// This list has to agree with `PLUGIN_CAPABILITIES` in `src/plugins.ts`, which
/// is the table the sandbox host enforces at call time. Rust's copy exists so a
/// manifest naming a capability this build cannot describe is refused at the
/// point of installation rather than at the point of use — a person approving a
/// plugin must be shown its whole reach, and a name we cannot render is a reach
/// we cannot show. `plugin_capabilities_match_the_typescript_core` pins them
/// together.
const PLUGIN_CAPABILITIES: [&str; 11] = [
    "notes:metadata",
    "notes:read",
    "notes:write",
    "search",
    "canvas:read",
    "canvas:write",
    "attachments:read",
    "commands",
    "ui:notice",
    "ui:panel",
    "storage",
];
const VAULT_LOCK_FILENAME: &str = ".sbrain.lock";
const VAULT_LOCK_STALE_SECONDS: i64 = 30;
const VAULT_LOCK_WAIT: Duration = Duration::from_secs(2);
const VAULT_LOCK_POLL: Duration = Duration::from_millis(40);

#[derive(Default)]
struct AppState {
    session: Mutex<Option<VaultSession>>,
}

struct VaultSession {
    vault_dir: PathBuf,
    root_dir: PathBuf,
    /// The `documents` key: every object under `documents/` is encrypted with it.
    key: Zeroizing<[u8; 32]>,
    /// The `attachmentId` key: permanent, because attachment content addresses
    /// are HMACs under it and every reference already written uses them. Equal
    /// to `key` on a legacy vault, which is what the legacy format means.
    attachment_id_key: Zeroizing<[u8; 32]>,
    index: DocumentIndex,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultLockRecord {
    token: String,
    pid: u32,
    host: String,
    acquired_at: String,
}

struct VaultWriteGuard {
    path: PathBuf,
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WriteJournal {
    version: u8,
    started_at: String,
    scope: String,
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    version: u8,
    kdf: KdfManifest,
    verifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfManifest {
    name: String,
    #[serde(rename = "N")]
    n: u32,
    salt: String,
}

/// Just enough of a manifest to learn its version. A v2 manifest carries no
/// `kdf` and no `verifier`, so deserializing into `Manifest` fails on a missing
/// field and reports that instead of what actually happened to the vault.
#[derive(Debug, Deserialize)]
struct ManifestVersion {
    version: u8,
}

/// Byte-identical to what `vbrain migrate` writes, so a created vault and a
/// migrated vault are the same shape on disk.
const MANIFEST_TOMBSTONE: &str = "{\n  \"version\": 2,\n  \"keyring\": true\n}\n";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedPayload {
    version: u8,
    iv: String,
    auth_tag: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NoteDocument {
    version: u8,
    id: String,
    path: String,
    title: String,
    body: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "empty_object")]
    properties: Value,
    created_at: String,
    updated_at: String,
    revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frontmatter_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanvasDocument {
    version: u8,
    id: String,
    path: String,
    title: String,
    nodes: Vec<Value>,
    edges: Vec<Value>,
    created_at: String,
    updated_at: String,
    revision: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CanvasInput {
    #[serde(default)]
    id: Option<String>,
    path: String,
    #[serde(default)]
    title: Option<String>,
    nodes: Vec<Value>,
    edges: Vec<Value>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    base_revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginManifest {
    manifest_version: u8,
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    author: String,
    capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PluginSignatureInfo {
    algorithm: String,
    key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginSecurityPolicy {
    version: u8,
    restricted_mode: bool,
    #[serde(default)]
    revoked_signers: Vec<String>,
}

impl Default for PluginSecurityPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            restricted_mode: false,
            revoked_signers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginPackage {
    version: u8,
    id: String,
    manifest: PluginManifest,
    source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<PluginSignatureInfo>,
    enabled: bool,
    installed_at: String,
    updated_at: String,
    revision: u64,
}

/// The listing shape: identity, labels and reach — never the source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PluginSummary {
    id: String,
    manifest_id: String,
    name: String,
    version: String,
    description: String,
    author: String,
    capabilities: Vec<String>,
    enabled: bool,
    #[serde(default = "unsigned_signature_status")]
    signature_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
    signed: bool,
    source_bytes: usize,
    updated_at: String,
    revision: u64,
}

fn unsigned_signature_status() -> String {
    "unsigned".into()
}

impl From<&PluginPackage> for PluginSummary {
    fn from(plugin: &PluginPackage) -> Self {
        let verified = plugin.signature.is_some();
        Self {
            id: plugin.id.clone(),
            manifest_id: plugin.manifest.id.clone(),
            name: plugin.manifest.name.clone(),
            version: plugin.manifest.version.clone(),
            description: plugin.manifest.description.clone(),
            author: plugin.manifest.author.clone(),
            capabilities: plugin.manifest.capabilities.clone(),
            enabled: plugin.enabled,
            signature_status: if verified { "verified" } else { "unsigned" }.into(),
            signer: plugin.signature.as_ref().map(|info| info.key_id.clone()),
            signed: verified,
            source_bytes: plugin.source.len(),
            updated_at: plugin.updated_at.clone(),
            revision: plugin.revision,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexedCanvas {
    id: String,
    path: String,
    title: String,
    updated_at: String,
    revision: u64,
    node_count: usize,
    edge_count: usize,
    #[serde(default)]
    note_refs: Vec<String>,
    #[serde(default)]
    attachment_refs: Vec<String>,
    #[serde(default)]
    unresolved: Vec<WikiLink>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CanvasSummary {
    id: String,
    path: String,
    title: String,
    node_count: usize,
    edge_count: usize,
    updated_at: String,
    revision: u64,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IndexedNote {
    #[serde(flatten)]
    note: NoteDocument,
    #[serde(default)]
    links: Vec<WikiLink>,
    #[serde(default)]
    headings: Vec<Heading>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WikiLink {
    raw: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    heading: Option<String>,
    #[serde(rename = "block", skip_serializing_if = "Option::is_none")]
    block_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
    embed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Heading {
    level: usize,
    text: String,
    slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocumentIndex {
    version: u8,
    #[serde(default)]
    derived: u8,
    generated_at: String,
    #[serde(default)]
    notes: HashMap<String, IndexedNote>,
    #[serde(default)]
    backlinks: HashMap<String, Vec<String>>,
    #[serde(default)]
    resolved_links: HashMap<String, Vec<Option<String>>>,
    #[serde(default)]
    unresolved: HashMap<String, Vec<WikiLink>>,
    #[serde(default)]
    link_sources: HashMap<String, Vec<String>>,
    #[serde(default)]
    path_owners: HashMap<String, Vec<String>>,
    #[serde(default)]
    name_owners: HashMap<String, Vec<String>>,
    #[serde(default)]
    basename_owners: HashMap<String, Vec<String>>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

impl DocumentIndex {
    fn empty() -> Self {
        let mut extra = serde_json::Map::new();
        for field in [
            "canvases",
            "canvasRefs",
            "canvasAttachmentRefs",
            "canvasPathOwners",
        ] {
            extra.insert(field.into(), Value::Object(serde_json::Map::new()));
        }
        Self {
            version: 2,
            derived: DERIVED_LAYOUT,
            generated_at: now(),
            notes: HashMap::new(),
            backlinks: HashMap::new(),
            resolved_links: HashMap::new(),
            unresolved: HashMap::new(),
            link_sources: HashMap::new(),
            path_owners: HashMap::new(),
            name_owners: HashMap::new(),
            basename_owners: HashMap::new(),
            extra,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NoteSummary {
    id: String,
    path: String,
    title: String,
    aliases: Vec<String>,
    tags: Vec<String>,
    updated_at: String,
    revision: u64,
}

impl From<&NoteDocument> for NoteSummary {
    fn from(note: &NoteDocument) -> Self {
        Self {
            id: note.id.clone(),
            path: note.path.clone(),
            title: note.title.clone(),
            aliases: note.aliases.clone(),
            tags: note.tags.clone(),
            updated_at: note.updated_at.clone(),
            revision: note.revision,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchHit {
    #[serde(flatten)]
    note: NoteSummary,
    score: u32,
    excerpt: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultInfo {
    name: String,
    path: String,
    note_count: usize,
}

#[derive(Debug, Serialize)]
struct GraphNode {
    id: String,
    title: String,
    path: String,
    tags: Vec<String>,
    degree: usize,
    cluster: usize,
}

#[derive(Debug, Serialize)]
struct GraphEdge {
    source: String,
    target: String,
}

#[derive(Debug, Serialize)]
struct KnowledgeGraph {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PropertyRow {
    id: String,
    path: String,
    title: String,
    tags: Vec<String>,
    properties: Value,
    updated_at: String,
}

impl From<&NoteDocument> for PropertyRow {
    fn from(note: &NoteDocument) -> Self {
        Self {
            id: note.id.clone(),
            path: note.path.clone(),
            title: note.title.clone(),
            tags: note.tags.clone(),
            properties: note.properties.clone(),
            updated_at: note.updated_at.clone(),
        }
    }
}

/// A saved property query. It only ever names columns and filter text the user
/// typed, but that text is derived from vault content, so it is stored with the
/// same envelope as the note index rather than in unencrypted app settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedView {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    filter: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    direction: String,
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    updated_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedViewFile {
    version: u8,
    #[serde(default)]
    views: Vec<SavedView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bookmark {
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceLayout {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    tabs: Vec<String>,
    #[serde(default)]
    active: Option<String>,
    #[serde(default)]
    secondary: Option<String>,
    #[serde(default)]
    view: String,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    updated_at: String,
}

/// Bookmarks and named layouts share one small encrypted file. Which notes a
/// person pins, and what they called a layout, says as much about the vault as
/// the notes do, so none of it belongs in plaintext app settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkspaceState {
    version: u8,
    #[serde(default)]
    bookmarks: Vec<Bookmark>,
    #[serde(default)]
    layouts: Vec<WorkspaceLayout>,
}

impl WorkspaceState {
    fn empty() -> Self {
        Self {
            version: 1,
            bookmarks: vec![],
            layouts: vec![],
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UnlinkedMention {
    #[serde(flatten)]
    note: NoteSummary,
    /// Which title or alias actually appeared in the text.
    name: String,
    count: usize,
    excerpt: String,
}

/// One archived or live note revision.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RevisionInfo {
    revision: u64,
    updated_at: String,
    current: bool,
}

/// A note whose object is gone but whose encrypted history is still on disk.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeletedNote {
    id: String,
    path: String,
    title: String,
    revision: u64,
    updated_at: String,
}

/// A daily note plus whether this call is what created it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DailyNote {
    note: NoteDocument,
    created: bool,
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn lock_host() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".into())
}

fn read_lock_record(path: &Path) -> Option<VaultLockRecord> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn lock_is_stale(record: Option<&VaultLockRecord>) -> bool {
    let Some(record) = record else { return true };
    let Ok(acquired) = chrono::DateTime::parse_from_rfc3339(&record.acquired_at) else {
        return true;
    };
    Utc::now()
        .signed_duration_since(acquired.with_timezone(&Utc))
        .num_seconds()
        > VAULT_LOCK_STALE_SECONDS
}

impl VaultWriteGuard {
    fn acquire(vault_dir: &Path) -> Result<Self, String> {
        let path = vault_dir.join(VAULT_LOCK_FILENAME);
        let token = Uuid::new_v4().to_string();
        let record = VaultLockRecord {
            token: token.clone(),
            pid: std::process::id(),
            host: lock_host(),
            acquired_at: now(),
        };
        let encoded = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
        let deadline = Instant::now() + VAULT_LOCK_WAIT;

        loop {
            reject_symlink(&path)?;
            match OpenOptions::new().create_new(true).write(true).open(&path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(&encoded).and_then(|_| file.sync_all()) {
                        let _ = fs::remove_file(&path);
                        return Err(error.to_string());
                    }
                    return Ok(Self { path, token });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let holder = read_lock_record(&path);
                    if lock_is_stale(holder.as_ref()) {
                        match fs::remove_file(&path) {
                            Ok(()) => continue,
                            Err(remove_error)
                                if remove_error.kind() == std::io::ErrorKind::NotFound =>
                            {
                                continue
                            }
                            Err(_) => {}
                        }
                    }
                    if Instant::now() >= deadline {
                        return Err(match holder {
                            Some(holder) => format!(
                                "vault is being written by process {} on {} since {}",
                                holder.pid, holder.host, holder.acquired_at
                            ),
                            None => "vault is locked by another process".into(),
                        });
                    }
                    thread::sleep(VAULT_LOCK_POLL);
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }
}

impl Drop for VaultWriteGuard {
    fn drop(&mut self) {
        if read_lock_record(&self.path).is_some_and(|record| record.token == self.token) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn verifier(key: &[u8]) -> Result<String, String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| "invalid HMAC key")?;
    mac.update(KEY_CHECK_CONTEXT.as_bytes());
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = ScryptParams::new(15, 8, 1, 32).map_err(|error| error.to_string())?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt(passphrase.as_bytes(), salt, &params, key.as_mut())
        .map_err(|error| format!("key derivation failed: {error}"))?;
    Ok(key)
}

fn encrypt(plaintext: &[u8], key: &[u8], aad: &str) -> Result<EncryptedPayload, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid AES key")?;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&iv), aad.as_bytes(), &mut ciphertext)
        .map_err(|_| "encryption failed")?;
    Ok(EncryptedPayload {
        version: 1,
        iv: BASE64.encode(iv),
        auth_tag: BASE64.encode(tag),
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt(payload: &EncryptedPayload, key: &[u8], aad: &str) -> Result<Vec<u8>, String> {
    if payload.version != 1 {
        return Err("unsupported encrypted payload version".into());
    }
    let iv = BASE64
        .decode(&payload.iv)
        .map_err(|_| "invalid payload IV")?;
    let tag = BASE64
        .decode(&payload.auth_tag)
        .map_err(|_| "invalid authentication tag")?;
    let mut ciphertext = BASE64
        .decode(&payload.ciphertext)
        .map_err(|_| "invalid ciphertext")?;
    if iv.len() != 12 || tag.len() != 16 {
        return Err("invalid encrypted payload dimensions".into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "invalid AES key")?;
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&iv),
            aad.as_bytes(),
            &mut ciphertext,
            Tag::from_slice(&tag),
        )
        .map_err(|_| "wrong passphrase or authenticated data was modified")?;
    Ok(ciphertext)
}

pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("target has no parent directory")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    reject_symlink(path)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("vault"),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    let result = (|| {
        file.write_all(data).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        replace_atomic(&temp, path)?;
        Ok(())
    })();
    if temp.exists() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(not(windows))]
fn replace_atomic(source: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(source, destination).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn replace_atomic(source: &Path, destination: &Path) -> Result<(), String> {
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(crate) fn reject_symlink(path: &Path) -> Result<(), String> {
    if path.exists()
        && fs::symlink_metadata(path)
            .map_err(|error| error.to_string())?
            .file_type()
            .is_symlink()
    {
        return Err(format!("refusing symbolic link: {}", path.display()));
    }
    Ok(())
}

fn note_aad(id: &str) -> String {
    format!("secondbrain-vault:note:v1:{id}")
}

fn history_aad(id: &str, revision: u64) -> String {
    format!("secondbrain-vault:note-history:v1:{id}:{revision}")
}

fn journal_path(session: &VaultSession) -> PathBuf {
    session.root_dir.join("journal.json")
}

fn begin_note_journal(session: &VaultSession, ids: &[String]) -> Result<(), String> {
    let journal = WriteJournal {
        version: 1,
        started_at: now(),
        scope: "notes".into(),
        ids: ids.to_vec(),
    };
    write_atomic(
        &journal_path(session),
        &serde_json::to_vec(&journal).map_err(|error| error.to_string())?,
    )
}

fn end_journal(session: &VaultSession) -> Result<(), String> {
    let path = journal_path(session);
    if path.exists() {
        reject_symlink(&path)?;
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn note_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    Uuid::parse_str(id).map_err(|_| "invalid note ID")?;
    Ok(root.join("objects").join(format!("{id}.note.enc")))
}

fn validate_note_path(input: &str) -> Result<String, String> {
    let mut value = input.trim().replace('\\', "/");
    if !value.to_lowercase().ends_with(".md") {
        value.push_str(".md");
    }
    if value.len() > 512
        || value.starts_with('/')
        || value.as_bytes().get(1) == Some(&b':')
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("invalid logical Markdown path".into());
    }
    Ok(value)
}

fn load_note(session: &VaultSession, id: &str) -> Result<NoteDocument, String> {
    let path = note_path(&session.root_dir, id)?;
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let note: NoteDocument =
        serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), &note_aad(id))?)
            .map_err(|error| error.to_string())?;
    if note.id != id || note.version != 1 {
        return Err("note identity check failed".into());
    }
    Ok(note)
}

fn read_index(session: &VaultSession) -> Result<DocumentIndex, String> {
    let path = session.root_dir.join("index.enc");
    if !path.exists() {
        return Ok(DocumentIndex::empty());
    }
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let mut index: DocumentIndex =
        serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), INDEX_AAD)?)
            .map_err(|error| error.to_string())?;
    if index.version != 2 || index.derived != DERIVED_LAYOUT {
        index.version = 2;
        rebuild_derived(&mut index);
    }
    Ok(index)
}

fn recover_pending_journal(session: &mut VaultSession) -> Result<(), String> {
    let path = journal_path(session);
    if !path.exists() {
        return Ok(());
    }
    reject_symlink(&path)?;
    let journal = serde_json::from_slice::<WriteJournal>(
        &fs::read(&path).map_err(|error| error.to_string())?,
    )
    .ok();
    if journal
        .as_ref()
        .is_some_and(|entry| entry.version == 1 && entry.scope == "canvases")
    {
        recover_canvas_index(session)?;
        save_index(session)?;
        return end_journal(session);
    }
    if journal
        .as_ref()
        .is_some_and(|entry| entry.version == 1 && entry.scope == "plugins")
    {
        recover_plugin_index(session)?;
        save_index(session)?;
        return end_journal(session);
    }

    let targeted = journal
        .as_ref()
        .is_some_and(|entry| entry.version == 1 && entry.scope == "notes");
    if targeted {
        for id in journal.unwrap().ids {
            if Uuid::parse_str(&id).is_err() {
                continue;
            }
            let object = note_path(&session.root_dir, &id)?;
            if object.exists() {
                let note = load_note(session, &id)?;
                let (links, headings) = analyze_markdown(&note.body)?;
                session.index.notes.insert(
                    id,
                    IndexedNote {
                        note,
                        links,
                        headings,
                    },
                );
            } else {
                session.index.notes.remove(&id);
            }
        }
    } else {
        session.index.notes.clear();
        let objects = session.root_dir.join("objects");
        if objects.exists() {
            reject_symlink(&objects)?;
            for entry in fs::read_dir(objects).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let Some(id) = name.strip_suffix(".note.enc") else {
                    continue;
                };
                if Uuid::parse_str(id).is_err() {
                    continue;
                }
                let note = load_note(session, id)?;
                let (links, headings) = analyze_markdown(&note.body)?;
                session.index.notes.insert(
                    id.to_string(),
                    IndexedNote {
                        note,
                        links,
                        headings,
                    },
                );
            }
        }
    }
    rebuild_derived(&mut session.index);
    recover_canvas_index(session)?;
    save_index(session)?;
    end_journal(session)
}

/// A plugin write touches one object and one listing entry, so recovery only
/// has to make the listing agree with what is actually on disk.
fn recover_plugin_index(session: &mut VaultSession) -> Result<(), String> {
    let mut plugins = HashMap::new();
    let objects = session.root_dir.join("objects");
    if objects.exists() {
        reject_symlink(&objects)?;
        for entry in fs::read_dir(objects).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".plugin.enc") else {
                continue;
            };
            if Uuid::parse_str(id).is_ok() {
                let plugin = load_plugin(session, id)?;
                plugins.insert(id.to_string(), PluginSummary::from(&plugin));
            }
        }
    }
    store_plugin_index(session, &plugins)
}

fn refresh_session_index(session: &mut VaultSession) -> Result<(), String> {
    session.index = read_index(session)?;
    if session.index.derived != DERIVED_LAYOUT {
        recover_canvas_index(session)?;
    }
    recover_pending_journal(session)
}

fn with_vault_write<T>(
    session: &mut VaultSession,
    operation: impl FnOnce(&mut VaultSession) -> Result<T, String>,
) -> Result<T, String> {
    let _guard = VaultWriteGuard::acquire(&session.vault_dir)?;
    refresh_session_index(session)?;
    operation(session)
}

fn save_index(session: &mut VaultSession) -> Result<(), String> {
    session.index.version = 2;
    session.index.derived = DERIVED_LAYOUT;
    session.index.generated_at = now();
    let payload = encrypt(
        &serde_json::to_vec(&session.index).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        INDEX_AAD,
    )?;
    write_atomic(
        &session.root_dir.join("index.enc"),
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )
}

fn archive_note(session: &VaultSession, note: &NoteDocument) -> Result<(), String> {
    let path = session
        .root_dir
        .join("history")
        .join(&note.id)
        .join(format!("{}.note.enc", note.revision));
    if path.exists() {
        return Ok(());
    }
    let payload = encrypt(
        &serde_json::to_vec(note).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        &history_aad(&note.id, note.revision),
    )?;
    write_atomic(
        &path,
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )
}

fn analyze_markdown(body: &str) -> Result<(Vec<WikiLink>, Vec<Heading>), String> {
    let fenced_code = Regex::new(r"(?s)```.*?```|~~~.*?~~~").map_err(|error| error.to_string())?;
    let inline_code = Regex::new(r"`[^`\n]*`").map_err(|error| error.to_string())?;
    let visible = fenced_code.replace_all(body, " ");
    let visible = inline_code.replace_all(&visible, " ");
    let link_re =
        Regex::new(r"(!)?\[\[([^\]|#^]+)(?:#([^\]|^]+))?(?:\^([^\]|]+))?(?:\|([^\]]+))?\]\]")
            .map_err(|error| error.to_string())?;
    let heading_re =
        Regex::new(r"(?m)^(#{1,6})\s+(.+?)\s*#*$").map_err(|error| error.to_string())?;
    let links = link_re
        .captures_iter(&visible)
        .map(|capture| WikiLink {
            raw: capture
                .get(0)
                .map(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            target: capture
                .get(2)
                .map(|value| value.as_str().trim())
                .unwrap_or_default()
                .to_string(),
            heading: capture
                .get(3)
                .map(|value| value.as_str().trim().to_string()),
            block_ref: capture
                .get(4)
                .map(|value| value.as_str().trim().to_string()),
            alias: capture
                .get(5)
                .map(|value| value.as_str().trim().to_string()),
            embed: capture.get(1).is_some(),
        })
        .collect();
    let headings = heading_re
        .captures_iter(&visible)
        .map(|capture| {
            let text = capture
                .get(2)
                .map(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            Heading {
                level: capture
                    .get(1)
                    .map(|value| value.as_str().len())
                    .unwrap_or(1),
                slug: normalized_text(&text)
                    .chars()
                    .filter_map(|character| {
                        if character.is_alphanumeric() {
                            Some(character)
                        } else if character.is_whitespace() || character == '-' {
                            Some('-')
                        } else {
                            None
                        }
                    })
                    .collect::<String>()
                    .split('-')
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join("-"),
                text,
            }
        })
        .collect();
    Ok((links, headings))
}

fn normalized_text(value: &str) -> String {
    value.nfkc().flat_map(char::to_lowercase).collect()
}

fn without_markdown_extension(value: &str) -> &str {
    if value
        .get(value.len().saturating_sub(3)..)
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".md"))
    {
        &value[..value.len() - 3]
    } else {
        value
    }
}

fn normalized(value: &str) -> String {
    let replaced = value.trim().replace('\\', "/");
    normalized_text(without_markdown_extension(&replaced))
}

fn add_owner(map: &mut HashMap<String, Vec<String>>, label: String, id: &str) {
    let owners = map.entry(label).or_default();
    if !owners.iter().any(|owner| owner == id) {
        owners.push(id.to_string());
    }
}

fn resolve_link(index: &DocumentIndex, link: &WikiLink) -> Option<String> {
    let target = normalized(&link.target);
    if let Some(id) = index
        .path_owners
        .get(&target)
        .and_then(|owners| owners.first())
        .filter(|id| index.notes.contains_key(*id))
    {
        return Some(id.clone());
    }
    let candidates: HashSet<_> = index
        .name_owners
        .get(&target)
        .into_iter()
        .chain(index.basename_owners.get(&target))
        .flatten()
        .filter(|id| index.notes.contains_key(*id))
        .cloned()
        .collect();
    (candidates.len() == 1).then(|| candidates.into_iter().next().unwrap())
}

fn rebuild_derived(index: &mut DocumentIndex) {
    index.backlinks.clear();
    index.resolved_links.clear();
    index.unresolved.clear();
    index.link_sources.clear();
    index.path_owners.clear();
    index.name_owners.clear();
    index.basename_owners.clear();
    let ids: Vec<String> = index.notes.keys().cloned().collect();
    for id in &ids {
        if let Some((path, basename, names, link_targets)) = index.notes.get(id).map(|note| {
            let path = normalized(&note.note.path);
            let basename = note.note.path.rsplit('/').next().unwrap_or(&note.note.path);
            let mut names = vec![normalized_text(&note.note.title)];
            names.extend(note.note.aliases.iter().map(|alias| normalized_text(alias)));
            let link_targets = note
                .links
                .iter()
                .map(|link| normalized(&link.target))
                .collect::<Vec<_>>();
            (path, normalized(basename), names, link_targets)
        }) {
            add_owner(&mut index.path_owners, path, id);
            add_owner(&mut index.basename_owners, basename, id);
            for name in names {
                add_owner(&mut index.name_owners, name, id);
            }
            for target in link_targets {
                let sources = index.link_sources.entry(target).or_default();
                if !sources.contains(id) {
                    sources.push(id.clone());
                }
            }
        }
    }
    for owners in index
        .path_owners
        .values_mut()
        .chain(index.name_owners.values_mut())
        .chain(index.basename_owners.values_mut())
    {
        owners.sort();
        owners.dedup();
    }
    for id in ids {
        let links = index
            .notes
            .get(&id)
            .map(|note| note.links.clone())
            .unwrap_or_default();
        let resolved: Vec<Option<String>> =
            links.iter().map(|link| resolve_link(index, link)).collect();
        let unresolved: Vec<WikiLink> = links
            .iter()
            .zip(&resolved)
            .filter(|(_, target)| target.is_none())
            .map(|(link, _)| link.clone())
            .collect();
        if !unresolved.is_empty() {
            index.unresolved.insert(id.clone(), unresolved);
        }
        for target in resolved.iter().flatten() {
            if target != &id {
                let sources = index.backlinks.entry(target.clone()).or_default();
                if !sources.contains(&id) {
                    sources.push(id.clone());
                }
            }
        }
        index.resolved_links.insert(id, resolved);
    }
}

fn resolve_id(index: &DocumentIndex, reference: &str) -> Result<String, String> {
    if index.notes.contains_key(reference) {
        return Ok(reference.to_string());
    }
    let mut matches = HashSet::new();
    if let Ok(path) = validate_note_path(reference) {
        if let Some(owners) = index.path_owners.get(&normalized(&path)) {
            matches.extend(
                owners
                    .iter()
                    .filter(|id| index.notes.contains_key(*id))
                    .cloned(),
            );
        }
    }
    let target = normalized_text(without_markdown_extension(reference));
    if let Some(owners) = index.name_owners.get(&target) {
        matches.extend(
            owners
                .iter()
                .filter(|id| index.notes.contains_key(*id))
                .cloned(),
        );
    }
    let matches: Vec<_> = matches.into_iter().collect();
    match matches.as_slice() {
        [] => Err(format!("note not found: {reference}")),
        [id] => Ok(id.clone()),
        _ => Err(format!("ambiguous note reference: {reference}")),
    }
}

fn store_note(
    session: &mut VaultSession,
    note: NoteDocument,
    archive: Option<NoteDocument>,
) -> Result<NoteDocument, String> {
    if note.body.len() > MAX_NOTE_BYTES {
        return Err("note body cannot exceed 25 MiB".into());
    }
    validate_note_path(&note.path)?;
    if note.title.trim().is_empty()
        || note.title.len() > 300
        || note
            .title
            .chars()
            .any(|character| character == '\0' || character == '\n' || character == '\r')
    {
        return Err("invalid note title".into());
    }
    if note.aliases.len() > 64 || note.tags.len() > 64 {
        return Err("a note may carry at most 64 tags and 64 aliases".into());
    }
    for value in note.aliases.iter().chain(note.tags.iter()) {
        if value.trim().is_empty()
            || value.chars().count() > 160
            || value
                .chars()
                .any(|character| character == '\0' || character == '\n' || character == '\r')
        {
            return Err(
                "tags and aliases must be non-empty single-line values of at most 160 characters"
                    .into(),
            );
        }
    }
    let mut identity_labels = archive
        .as_ref()
        .map(note_identity_labels)
        .unwrap_or_default();
    identity_labels.extend(note_identity_labels(&note));
    begin_note_journal(session, std::slice::from_ref(&note.id))?;
    if let Some(previous) = archive.as_ref() {
        archive_note(session, previous)?;
    }
    let payload = encrypt(
        &serde_json::to_vec(&note).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        &note_aad(&note.id),
    )?;
    let object_path = note_path(&session.root_dir, &note.id)?;
    write_atomic(
        &object_path,
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )?;
    let (links, headings) = analyze_markdown(&note.body)?;
    session.index.notes.insert(
        note.id.clone(),
        IndexedNote {
            note: note.clone(),
            links,
            headings,
        },
    );
    rebuild_derived(&mut session.index);
    refresh_canvases_for_note_change(session, &note.id, &identity_labels)?;
    save_index(session)?;
    end_journal(session)?;
    Ok(note)
}

/// The `documents` key and the `attachmentId` key for this vault.
///
/// Three branches, in this order. A keyring is authoritative when present. A
/// legacy manifest keeps every check it has today, including the cost the
/// legacy format fixed at 32768 — that constant is legacy-only now, and no
/// keyring cost is ever compared against a compiled-in value. A directory with
/// neither is a brand-new vault and is created keyring-native.
///
/// "No manifest" is not "empty vault": a vault used only through the key-value
/// commands has no document manifest but does have `audit.meta.json` and
/// `*.kv.enc`. Writing a keyring beside those would put a random audit key in
/// front of a chain signed with the key derived from `audit.meta.json`, so a
/// vault holding any legacy marker keeps the legacy path and waits for
/// `vbrain migrate`.
fn open_vault_keys(
    vault_dir: &Path,
    root_dir: &Path,
    passphrase: &str,
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>), String> {
    if let Some(file) = keyring::read(vault_dir)? {
        let keys = keyring::unwrap_keyring(&file, passphrase)?;
        return Ok((keys.documents.clone(), keys.attachment_id.clone()));
    }

    let manifest_path = root_dir.join("manifest.json");
    if manifest_path.exists() {
        reject_symlink(&manifest_path)?;
        let raw = fs::read(&manifest_path).map_err(|error| error.to_string())?;
        let probe: ManifestVersion =
            serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
        if probe.version == 2 {
            return Err(
                "This vault was upgraded to a keyring, but keyring.json is missing or unreadable."
                    .into(),
            );
        }
        let manifest: Manifest = serde_json::from_slice(&raw).map_err(|error| error.to_string())?;
        if manifest.version != 1 || manifest.kdf.name != "scrypt" || manifest.kdf.n != 32768 {
            return Err("unsupported document vault manifest".into());
        }
        let salt = BASE64
            .decode(&manifest.kdf.salt)
            .map_err(|_| "invalid manifest salt")?;
        let key = derive_key(passphrase, &salt)?;
        if verifier(key.as_ref())? != manifest.verifier {
            return Err("wrong passphrase or damaged manifest".into());
        }
        let attachment_id_key = key.clone();
        return Ok((key, attachment_id_key));
    }

    if vault_holds_legacy_material(vault_dir) {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        let manifest = Manifest {
            version: 1,
            kdf: KdfManifest {
                name: "scrypt".into(),
                n: 32768,
                salt: BASE64.encode(salt),
            },
            verifier: verifier(key.as_ref())?,
        };
        write_atomic(
            &manifest_path,
            &serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
        )?;
        let attachment_id_key = key.clone();
        return Ok((key, attachment_id_key));
    }

    let keys = keyring::random_key_set();
    let slot = keyring::wrap_key_set(&keys, passphrase, keyring::DEFAULT_SCRYPT_LOG_N)?;
    keyring::write(
        vault_dir,
        &keyring::KeyringFile {
            version: keyring::KEYRING_VERSION,
            slots: vec![slot],
        },
    )?;
    write_atomic(&manifest_path, MANIFEST_TOMBSTONE.as_bytes())?;
    // Read back rather than trusting what we just generated: this proves the
    // keyring on disk unwraps before one object is encrypted under it.
    let written = keyring::read(vault_dir)?.ok_or("failed to create a vault keyring")?;
    let opened = keyring::unwrap_keyring(&written, passphrase)?;
    Ok((opened.documents.clone(), opened.attachment_id.clone()))
}

/// The legacy markers `detectVaultFormat` in `src/keyring.ts` looks for, minus
/// the document manifest, which the caller has already ruled out.
fn vault_holds_legacy_material(vault_dir: &Path) -> bool {
    for marker in ["audit.meta.json", "grants.enc", "schema.json"] {
        if vault_dir.join(marker).exists() {
            return true;
        }
    }
    fs::read_dir(vault_dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".kv.enc"))
        })
    })
}

fn open_session(vault_path: &str, passphrase: &str) -> Result<VaultSession, String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    let vault_dir = PathBuf::from(vault_path);
    fs::create_dir_all(&vault_dir).map_err(|error| error.to_string())?;
    let vault_dir = fs::canonicalize(vault_dir).map_err(|error| error.to_string())?;
    let _guard = VaultWriteGuard::acquire(&vault_dir)?;
    let root_dir = vault_dir.join("documents");
    reject_symlink(&root_dir)?;
    fs::create_dir_all(&root_dir).map_err(|error| error.to_string())?;

    let (key, attachment_id_key) = open_vault_keys(&vault_dir, &root_dir, passphrase)?;

    let index_path = root_dir.join("index.enc");
    let index_existed = index_path.exists();
    let mut session = VaultSession {
        vault_dir,
        root_dir,
        key,
        attachment_id_key,
        index: DocumentIndex::empty(),
    };
    refresh_session_index(&mut session)?;
    if !index_existed {
        save_index(&mut session)?;
    }
    Ok(session)
}

/// Deterministic label propagation over the resolved-link graph.
///
/// The graph view colours notes by community, so the same vault must produce the
/// same colours on every unlock. Nothing here is random: labels start as each
/// note's position in the caller's already-sorted id list, nodes are visited in
/// that order, and a tie between two equally common neighbour labels always
/// falls to the lower label. Each round is O(V + E), so a 100k-note vault stays
/// well inside the interaction budget.
fn cluster_nodes(ids: &[String], edges: &[GraphEdge]) -> HashMap<String, usize> {
    let position: HashMap<&str, usize> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect();
    let mut neighbours: Vec<Vec<usize>> = vec![Vec::new(); ids.len()];
    for edge in edges {
        if let (Some(&source), Some(&target)) = (
            position.get(edge.source.as_str()),
            position.get(edge.target.as_str()),
        ) {
            if source != target {
                neighbours[source].push(target);
                neighbours[target].push(source);
            }
        }
    }

    let mut labels: Vec<usize> = (0..ids.len()).collect();
    for _ in 0..MAX_CLUSTER_ROUNDS {
        let mut changed = false;
        for node in 0..ids.len() {
            if neighbours[node].is_empty() {
                continue;
            }
            let mut counts: HashMap<usize, usize> = HashMap::new();
            for &neighbour in &neighbours[node] {
                *counts.entry(labels[neighbour]).or_default() += 1;
            }
            // Most common neighbour label, lowest label wins a tie. The ordering
            // is total, so the winner never depends on hash iteration order.
            let mut best: Option<(usize, usize)> = None;
            for (&label, &count) in &counts {
                best = match best {
                    Some((top, winner)) if top > count || (top == count && winner <= label) => {
                        Some((top, winner))
                    }
                    _ => Some((count, label)),
                };
            }
            if let Some((_, label)) = best {
                if labels[node] != label {
                    labels[node] = label;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    // Renumber so cluster 0 is always the largest community, and equally sized
    // communities are ordered by their first member.
    let mut members: HashMap<usize, Vec<usize>> = HashMap::new();
    for (node, &label) in labels.iter().enumerate() {
        members.entry(label).or_default().push(node);
    }
    let mut groups: Vec<Vec<usize>> = members.into_values().collect();
    groups.sort_by(|left, right| {
        right
            .len()
            .cmp(&left.len())
            .then_with(|| left[0].cmp(&right[0]))
    });
    let mut clusters = HashMap::with_capacity(ids.len());
    for (cluster, group) in groups.into_iter().enumerate() {
        for node in group {
            clusters.insert(ids[node].clone(), cluster);
        }
    }
    clusters
}

fn build_graph(index: &DocumentIndex) -> KnowledgeGraph {
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let mut edges = vec![];
    for (source, targets) in &index.resolved_links {
        for target in targets.iter().flatten() {
            if source != target && seen.insert((source.as_str(), target.as_str())) {
                edges.push(GraphEdge {
                    source: source.clone(),
                    target: target.clone(),
                });
            }
        }
    }
    edges.sort_by(|left, right| {
        left.source
            .cmp(&right.source)
            .then_with(|| left.target.cmp(&right.target))
    });

    let mut degree: HashMap<&str, usize> = HashMap::new();
    for edge in &edges {
        *degree.entry(edge.source.as_str()).or_default() += 1;
        *degree.entry(edge.target.as_str()).or_default() += 1;
    }
    let mut nodes: Vec<_> = index
        .notes
        .values()
        .map(|indexed| GraphNode {
            id: indexed.note.id.clone(),
            title: indexed.note.title.clone(),
            path: indexed.note.path.clone(),
            tags: indexed.note.tags.clone(),
            degree: degree
                .get(indexed.note.id.as_str())
                .copied()
                .unwrap_or_default(),
            cluster: 0,
        })
        .collect();
    nodes.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.id.cmp(&right.id))
    });

    let ids: Vec<String> = nodes.iter().map(|node| node.id.clone()).collect();
    let clusters = cluster_nodes(&ids, &edges);
    for node in &mut nodes {
        node.cluster = clusters.get(&node.id).copied().unwrap_or_default();
    }
    KnowledgeGraph { nodes, edges }
}

fn saved_views_path(session: &VaultSession) -> PathBuf {
    session.root_dir.join("views.enc")
}

fn load_saved_views(session: &VaultSession) -> Result<Vec<SavedView>, String> {
    let path = saved_views_path(session);
    if !path.exists() {
        return Ok(vec![]);
    }
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let file: SavedViewFile =
        serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), SAVED_VIEWS_AAD)?)
            .map_err(|error| error.to_string())?;
    if file.version != 1 {
        return Err("unsupported saved view file version".into());
    }
    Ok(file.views)
}

fn write_saved_views(session: &VaultSession, views: &[SavedView]) -> Result<(), String> {
    let file = SavedViewFile {
        version: 1,
        views: views.to_vec(),
    };
    let payload = encrypt(
        &serde_json::to_vec(&file).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        SAVED_VIEWS_AAD,
    )?;
    write_atomic(
        &saved_views_path(session),
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )
}

fn normalize_view(mut view: SavedView, existing: &[SavedView]) -> Result<SavedView, String> {
    view.name = view.name.trim().to_string();
    if view.name.is_empty() || view.name.chars().count() > 120 {
        return Err("a saved view needs a name of 1-120 characters".into());
    }
    if view.id.chars().count() > 64 {
        return Err("invalid saved view ID".into());
    }
    if view.filter.chars().count() > 500 || view.columns.len() > 64 || view.tags.len() > 64 {
        return Err("saved view is too large".into());
    }
    view.direction = if view.direction == "desc" {
        "desc".into()
    } else {
        "asc".into()
    };
    let timestamp = now();
    view.created_at = existing
        .iter()
        .find(|item| item.id == view.id)
        .map(|item| item.created_at.clone())
        .unwrap_or_else(|| timestamp.clone());
    view.updated_at = timestamp;
    if view.id.trim().is_empty() {
        view.id = Uuid::new_v4().to_string();
    }
    Ok(view)
}

/// Read-modify-write of one typed property. The caller holds the session lock
/// for the whole call, so a table cell edit cannot interleave with the editor's
/// own save, and the write goes through store_note so revision, history
/// archive and link index all stay consistent.
fn set_property(
    session: &mut VaultSession,
    reference: &str,
    key: &str,
    value: Option<Value>,
) -> Result<PropertyRow, String> {
    let name = key.trim().to_string();
    if name.is_empty() || name.chars().count() > 120 {
        return Err("a property name must be 1-120 characters".into());
    }
    let id = resolve_id(&session.index, reference)?;
    let existing = session
        .index
        .notes
        .get(&id)
        .ok_or("note not found")?
        .note
        .clone();
    let mut note = existing.clone();
    if !note.properties.is_object() {
        note.properties = empty_object();
    }
    let properties = note
        .properties
        .as_object_mut()
        .ok_or("note properties are not an object")?;
    match value {
        Some(next) => {
            properties.insert(name, next);
        }
        None => {
            properties.remove(&name);
        }
    }
    note.updated_at = now();
    note.revision = existing.revision + 1;
    let stored = store_note(session, note, Some(existing))?;
    Ok(PropertyRow::from(&stored))
}

fn save_existing_note(
    session: &mut VaultSession,
    mut note: NoteDocument,
) -> Result<NoteDocument, String> {
    let existing = session
        .index
        .notes
        .get(&note.id)
        .ok_or("note not found")?
        .note
        .clone();
    if note.revision != existing.revision {
        return Err(format!(
            "note revision conflict: editor has {}, current revision is {}",
            note.revision, existing.revision
        ));
    }
    note.version = 1;
    note.path = validate_note_path(&note.path)?;
    note.created_at = existing.created_at.clone();
    note.updated_at = now();
    note.revision = existing.revision + 1;
    if note.frontmatter_source.is_none() {
        note.frontmatter_source = existing.frontmatter_source.clone();
    }
    store_note(session, note, Some(existing))
}

fn note_history_dir(session: &VaultSession, id: &str) -> Result<PathBuf, String> {
    Uuid::parse_str(id).map_err(|_| "invalid note ID")?;
    Ok(session.root_dir.join("history").join(id))
}

/// A history directory holds both `<n>.note.enc` and `<n>.canvas.enc`, so the
/// suffix — not the directory — is what says which document a revision belongs
/// to.
fn archived_revisions(session: &VaultSession, id: &str) -> Result<Vec<u64>, String> {
    let directory = note_history_dir(session, id)?;
    if !directory.exists() {
        return Ok(Vec::new());
    }
    reject_symlink(&directory)?;
    let mut revisions = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(number) = name.strip_suffix(".note.enc") {
            if let Ok(revision) = number.parse::<u64>() {
                revisions.push(revision);
            }
        }
    }
    revisions.sort_unstable();
    Ok(revisions)
}

fn load_revision(session: &VaultSession, id: &str, revision: u64) -> Result<NoteDocument, String> {
    let path = note_history_dir(session, id)?.join(format!("{revision}.note.enc"));
    reject_symlink(&path)?;
    let payload: EncryptedPayload = serde_json::from_slice(
        &fs::read(&path).map_err(|_| format!("revision {revision} not found for note {id}"))?,
    )
    .map_err(|error| error.to_string())?;
    let note: NoteDocument = serde_json::from_slice(&decrypt(
        &payload,
        session.key.as_ref(),
        &history_aad(id, revision),
    )?)
    .map_err(|error| error.to_string())?;
    if note.id != id || note.revision != revision {
        return Err("note revision identity check failed".into());
    }
    Ok(note)
}

/// History outlives the note, so a history lookup also accepts an ID the live
/// index no longer knows. It accepts only an ID there: the titles and aliases a
/// deleted note answered to may since have moved to a different note.
fn resolve_history_id(session: &VaultSession, reference: &str) -> Result<String, String> {
    if let Ok(id) = resolve_id(&session.index, reference) {
        return Ok(id);
    }
    if Uuid::parse_str(reference).is_ok() && note_history_dir(session, reference)?.is_dir() {
        return Ok(reference.to_string());
    }
    Err(format!("note not found: {reference}"))
}

fn path_is_taken(session: &VaultSession, logical_path: &str, except: &str) -> bool {
    session.index.notes.values().any(|note| {
        note.note.id != except && normalized(&note.note.path) == normalized(logical_path)
    })
}

fn deleted_notes(session: &VaultSession) -> Result<Vec<DeletedNote>, String> {
    let history = session.root_dir.join("history");
    if !history.exists() {
        return Ok(Vec::new());
    }
    reject_symlink(&history)?;
    let mut deleted = Vec::new();
    for entry in fs::read_dir(history).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if Uuid::parse_str(&id).is_err() || session.index.notes.contains_key(&id) {
            continue;
        }
        let Some(latest) = archived_revisions(session, &id)?.into_iter().max() else {
            continue;
        };
        let note = load_revision(session, &id, latest)?;
        deleted.push(DeletedNote {
            id,
            path: note.path,
            title: note.title,
            revision: latest,
            updated_at: note.updated_at,
        });
    }
    deleted.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    Ok(deleted)
}

fn rename_note_in(
    session: &mut VaultSession,
    reference: &str,
    new_path: &str,
    new_title: Option<&str>,
) -> Result<NoteDocument, String> {
    let id = resolve_id(&session.index, reference)?;
    let existing = session
        .index
        .notes
        .get(&id)
        .ok_or("note not found")?
        .note
        .clone();
    let logical_path = validate_note_path(new_path)?;
    if path_is_taken(session, &logical_path, &id) {
        return Err(format!("a note already exists at {logical_path}"));
    }
    let mut note = existing.clone();
    note.path = logical_path;
    if let Some(title) = new_title.map(str::trim).filter(|value| !value.is_empty()) {
        note.title = title.to_string();
    }
    note.updated_at = now();
    note.revision = existing.revision + 1;
    store_note(session, note, Some(existing))
}

/// Deleting archives the live revision before unlinking the object, so the note
/// stays recoverable from `history/<id>/` afterwards.
fn remove_note_in(session: &mut VaultSession, reference: &str) -> Result<NoteSummary, String> {
    let id = resolve_id(&session.index, reference)?;
    let note = load_note(session, &id)?;
    let identity_labels = note_identity_labels(&note);
    begin_note_journal(session, std::slice::from_ref(&id))?;
    archive_note(session, &note)?;
    let object = note_path(&session.root_dir, &id)?;
    reject_symlink(&object)?;
    if object.exists() {
        fs::remove_file(&object).map_err(|error| error.to_string())?;
    }
    session.index.notes.remove(&id);
    rebuild_derived(&mut session.index);
    refresh_canvases_for_note_change(session, &id, &identity_labels)?;
    save_index(session)?;
    end_journal(session)?;
    Ok(NoteSummary::from(&note))
}

/// Restoring writes the historical content forward as a new revision rather
/// than rewinding the counter, so nothing already archived is invalidated.
fn restore_note_in(
    session: &mut VaultSession,
    reference: &str,
    revision: u64,
) -> Result<NoteDocument, String> {
    let id = resolve_history_id(session, reference)?;
    let historical = load_revision(session, &id, revision)?;
    let current = session.index.notes.get(&id).map(|note| note.note.clone());
    let base = match current.as_ref() {
        Some(note) => note.revision,
        None => archived_revisions(session, &id)?
            .into_iter()
            .max()
            .unwrap_or(0),
    };
    if path_is_taken(session, &historical.path, &id) {
        return Err(format!(
            "another note now occupies {} — move it before restoring",
            historical.path
        ));
    }
    let mut note = historical;
    note.updated_at = now();
    note.revision = base + 1;
    store_note(session, note, current)
}

/// The template variables the TypeScript core already renders: `{{title}}`,
/// `{{path}}`, `{{date:YYYY-MM-DD}}`, `{{time:HH:mm}}`, `{{year}}`, `{{month}}`,
/// `{{day}}` and caller-supplied names. Dates come from the local clock, so a
/// note filed "today" lands on the day the person is actually having.
struct TemplateContext {
    title: String,
    path: String,
    date: DateTime<Local>,
    variables: HashMap<String, String>,
}

fn format_local_date(date: &DateTime<Local>, format: &str) -> String {
    let characters: Vec<char> = format.chars().collect();
    let mut rendered = String::new();
    let mut index = 0;
    while index < characters.len() {
        let four: String = characters[index..].iter().take(4).collect();
        if four == "YYYY" {
            rendered.push_str(&date.format("%Y").to_string());
            index += 4;
            continue;
        }
        let two: String = characters[index..].iter().take(2).collect();
        let replacement = match two.as_str() {
            "MM" => Some("%m"),
            "DD" => Some("%d"),
            "HH" => Some("%H"),
            "mm" => Some("%M"),
            "ss" => Some("%S"),
            _ => None,
        };
        match replacement {
            Some(specifier) => {
                rendered.push_str(&date.format(specifier).to_string());
                index += 2;
            }
            None => {
                rendered.push(characters[index]);
                index += 1;
            }
        }
    }
    rendered
}

fn parse_local_date(input: Option<&str>) -> Result<DateTime<Local>, String> {
    let Some(text) = input.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Local::now());
    };
    let date = NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .map_err(|_| "a daily note date must use YYYY-MM-DD".to_string())?;
    date.and_hms_opt(12, 0, 0)
        .and_then(|naive| Local.from_local_datetime(&naive).single())
        .ok_or_else(|| format!("{text} has no unambiguous local midday on this device"))
}

impl TemplateContext {
    fn render_text(&self, text: &str) -> Result<String, String> {
        let pattern = Regex::new(r"\{\{\s*([\w.-]+)(?::([^}]+))?\s*\}\}")
            .map_err(|error| error.to_string())?;
        Ok(pattern
            .replace_all(text, |capture: &regex::Captures| {
                let name = capture.get(1).map_or("", |value| value.as_str());
                let format = capture.get(2).map(|value| value.as_str().trim());
                match name {
                    "date" => format_local_date(&self.date, format.unwrap_or("YYYY-MM-DD")),
                    "time" => format_local_date(&self.date, format.unwrap_or("HH:mm")),
                    "title" => self.title.clone(),
                    "path" => self.path.clone(),
                    "year" => format_local_date(&self.date, "YYYY"),
                    "month" => format_local_date(&self.date, "MM"),
                    "day" => format_local_date(&self.date, "DD"),
                    other => self
                        .variables
                        .get(other)
                        .cloned()
                        .unwrap_or_else(|| capture[0].to_string()),
                }
            })
            .into_owned())
    }

    fn render_value(&self, value: &Value) -> Result<Value, String> {
        Ok(match value {
            Value::String(text) => Value::String(self.render_text(text)?),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| self.render_value(item))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Value::Object(fields) => {
                let mut rendered = serde_json::Map::new();
                for (key, item) in fields {
                    rendered.insert(key.clone(), self.render_value(item)?);
                }
                Value::Object(rendered)
            }
            other => other.clone(),
        })
    }
}

/// A template call: which template, where it lands, and what the caller adds on
/// top of the template's own tags and properties.
struct TemplateRequest<'a> {
    template: &'a str,
    path: &'a str,
    title: Option<&'a str>,
    date: DateTime<Local>,
    variables: HashMap<String, String>,
    tags: Vec<String>,
    properties: serde_json::Map<String, Value>,
}

fn create_from_template_in(
    session: &mut VaultSession,
    request: TemplateRequest,
) -> Result<NoteDocument, String> {
    let template_id = resolve_id(&session.index, request.template)?;
    let template = load_note(session, &template_id)?;
    let logical_path = validate_note_path(request.path)?;
    if path_is_taken(session, &logical_path, "") {
        return Err(format!("a note already exists at {logical_path}"));
    }
    let basename = logical_path
        .rsplit('/')
        .next()
        .unwrap_or(&logical_path)
        .strip_suffix(".md")
        .unwrap_or(&logical_path)
        .to_string();
    let chosen = request
        .title
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&basename)
        .to_string();
    let context = TemplateContext {
        title: chosen.clone(),
        path: logical_path.clone(),
        date: request.date,
        variables: request.variables,
    };
    let mut properties = serde_json::Map::new();
    if let Some(fields) = template.properties.as_object() {
        for (key, value) in fields {
            properties.insert(key.clone(), context.render_value(value)?);
        }
    }
    for (key, value) in request.properties {
        properties.insert(key, value);
    }
    let mut tags: Vec<String> = template
        .tags
        .iter()
        .filter(|tag| tag.as_str() != "template")
        .cloned()
        .collect();
    for tag in request.tags {
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    let stamp = now();
    let note = NoteDocument {
        version: 1,
        id: Uuid::new_v4().to_string(),
        path: logical_path,
        title: context.render_text(&chosen)?,
        body: context.render_text(&template.body)?,
        aliases: vec![],
        tags,
        properties: Value::Object(properties),
        created_at: stamp.clone(),
        updated_at: stamp,
        revision: 1,
        frontmatter_source: None,
    };
    store_note(session, note, None)
}

/// Idempotent by logical path: the first call for a day creates the note, every
/// later call opens the same one.
fn open_daily_note_in(
    session: &mut VaultSession,
    date_text: Option<&str>,
    folder: Option<&str>,
    template: Option<&str>,
) -> Result<DailyNote, String> {
    let date = parse_local_date(date_text)?;
    let folder = folder
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Daily")
        .replace('\\', "/")
        .trim_matches('/')
        .to_string();
    let filename = format_local_date(&date, "YYYY-MM-DD");
    let logical_path = validate_note_path(&if folder.is_empty() {
        filename.clone()
    } else {
        format!("{folder}/{filename}")
    })?;
    let existing = session
        .index
        .notes
        .values()
        .find(|note| normalized(&note.note.path) == normalized(&logical_path))
        .map(|note| note.note.id.clone());
    if let Some(id) = existing {
        return Ok(DailyNote {
            note: load_note(session, &id)?,
            created: false,
        });
    }
    let mut properties = serde_json::Map::new();
    properties.insert("date".into(), Value::String(filename.clone()));
    let note = match template.map(str::trim).filter(|value| !value.is_empty()) {
        Some(reference) => create_from_template_in(
            session,
            TemplateRequest {
                template: reference,
                path: &logical_path,
                title: Some(&filename),
                date,
                variables: HashMap::new(),
                tags: vec!["daily".into()],
                properties,
            },
        )?,
        None => {
            let stamp = now();
            store_note(
                session,
                NoteDocument {
                    version: 1,
                    id: Uuid::new_v4().to_string(),
                    path: logical_path,
                    title: filename.clone(),
                    body: format!("# {filename}\n\n"),
                    aliases: vec![],
                    tags: vec!["daily".into()],
                    properties: Value::Object(properties),
                    created_at: stamp.clone(),
                    updated_at: stamp,
                    revision: 1,
                    frontmatter_source: None,
                },
                None,
            )?
        }
    };
    Ok(DailyNote {
        note,
        created: true,
    })
}

fn plugin_aad(id: &str) -> String {
    format!("secondbrain-vault:plugin:v1:{id}")
}

/// A plugin's settings live in their own object, so writing a setting never
/// rewrites the code and a reader of the settings never decrypts the code.
fn plugin_store_aad(id: &str) -> String {
    format!("secondbrain-vault:plugin-store:v1:{id}")
}

fn plugin_object_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    Uuid::parse_str(id).map_err(|_| "invalid plugin ID")?;
    Ok(root.join("objects").join(format!("{id}.plugin.enc")))
}

fn plugin_store_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    Uuid::parse_str(id).map_err(|_| "invalid plugin ID")?;
    Ok(root.join("objects").join(format!("{id}.pluginstore.enc")))
}

fn plugin_policy_path(root: &Path) -> PathBuf {
    root.join("plugin-policy.enc")
}

fn append_signature_frame(payload: &mut Vec<u8>, value: &str) {
    payload.extend_from_slice(value.len().to_string().as_bytes());
    payload.push(b':');
    payload.extend_from_slice(value.as_bytes());
}

/// Language-neutral payload shared with `src/plugin-signatures.ts`.
fn plugin_signature_payload(manifest: &PluginManifest, source: &str) -> Vec<u8> {
    let mut capabilities = manifest.capabilities.clone();
    capabilities.sort();
    let mut payload = PLUGIN_SIGNATURE_PREFIX.to_vec();
    for value in [
        manifest.manifest_version.to_string(),
        manifest.id.clone(),
        manifest.name.clone(),
        manifest.version.clone(),
        manifest.description.clone(),
        manifest.author.clone(),
        capabilities.len().to_string(),
    ] {
        append_signature_frame(&mut payload, &value);
    }
    for capability in capabilities {
        append_signature_frame(&mut payload, &capability);
    }
    append_signature_frame(&mut payload, source);
    payload
}

fn decode_base64_url(value: &str, label: &str) -> Result<Vec<u8>, String> {
    let decoded = BASE64_URL
        .decode(value)
        .map_err(|_| format!("invalid plugin {label} encoding"))?;
    if BASE64_URL.encode(&decoded) != value {
        return Err(format!("invalid plugin {label} encoding"));
    }
    Ok(decoded)
}

fn verify_plugin_signature(
    manifest: &PluginManifest,
    source: &str,
) -> Result<Option<PluginSignatureInfo>, String> {
    let Some(encoded) = manifest.signature.as_deref() else {
        return Ok(None);
    };
    let parts: Vec<_> = encoded.split(':').collect();
    if parts.len() != 3 || parts[0] != "ed25519" {
        return Err("plugin signature must use ed25519:<public-key>:<signature>".into());
    }
    let raw_key = decode_base64_url(parts[1], "public key")?;
    let raw_key: [u8; 32] = raw_key
        .try_into()
        .map_err(|_| "plugin signature public key must be 32 bytes")?;
    let raw_signature = decode_base64_url(parts[2], "signature")?;
    let signature = Signature::from_slice(&raw_signature)
        .map_err(|_| "plugin Ed25519 signature must be 64 bytes")?;
    VerifyingKey::from_bytes(&raw_key)
        .map_err(|_| "invalid plugin Ed25519 public key")?
        .verify(&plugin_signature_payload(manifest, source), &signature)
        .map_err(|_| "plugin signature verification failed; the manifest or source was changed")?;
    Ok(Some(PluginSignatureInfo {
        algorithm: "ed25519".into(),
        key_id: format!("{:x}", Sha256::digest(raw_key)),
    }))
}

fn load_plugin_policy(session: &VaultSession) -> Result<PluginSecurityPolicy, String> {
    let path = plugin_policy_path(&session.root_dir);
    if !path.exists() {
        return Ok(PluginSecurityPolicy::default());
    }
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let mut policy: PluginSecurityPolicy =
        serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), PLUGIN_POLICY_AAD)?)
            .map_err(|error| error.to_string())?;
    if policy.version != 1 || policy.revoked_signers.len() > 1_000 {
        return Err("invalid plugin security policy".into());
    }
    for key_id in &mut policy.revoked_signers {
        *key_id = key_id.to_lowercase();
        if key_id.len() != 64
            || !key_id
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err("invalid plugin signer revocation list".into());
        }
    }
    policy.revoked_signers.sort();
    policy.revoked_signers.dedup();
    Ok(policy)
}

fn save_plugin_policy(session: &VaultSession, policy: &PluginSecurityPolicy) -> Result<(), String> {
    let mut normalized = policy.clone();
    normalized.version = 1;
    normalized.revoked_signers.sort();
    normalized.revoked_signers.dedup();
    let payload = encrypt(
        &serde_json::to_vec(&normalized).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        PLUGIN_POLICY_AAD,
    )?;
    write_atomic(
        &plugin_policy_path(&session.root_dir),
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )
}

fn plugin_allowed(plugin: &PluginPackage, policy: &PluginSecurityPolicy) -> bool {
    if plugin
        .signature
        .as_ref()
        .is_some_and(|signature| policy.revoked_signers.contains(&signature.key_id))
    {
        return false;
    }
    !policy.restricted_mode || plugin.signature.is_some()
}

fn summarize_plugin(plugin: &PluginPackage, policy: &PluginSecurityPolicy) -> PluginSummary {
    let mut summary = PluginSummary::from(plugin);
    if summary
        .signer
        .as_ref()
        .is_some_and(|key_id| policy.revoked_signers.contains(key_id))
    {
        summary.signature_status = "revoked".into();
        summary.signed = false;
        summary.enabled = false;
    } else if policy.restricted_mode && summary.signature_status == "unsigned" {
        summary.enabled = false;
    }
    summary
}

fn single_line(value: &str, field: &str, max: usize) -> Result<String, String> {
    let text = value.trim();
    if text.is_empty() || text.chars().count() > max || text.chars().any(char::is_control) {
        return Err(format!(
            "plugin manifest {field} must be a single line of 1-{max} characters"
        ));
    }
    Ok(text.to_string())
}

/// Refuses anything it does not fully understand. An unknown capability is an
/// error rather than a field to drop, because dropping it would install a
/// plugin whose reach this build cannot describe to the person approving it.
fn validate_plugin_manifest(manifest: PluginManifest) -> Result<PluginManifest, String> {
    if manifest.manifest_version != 1 {
        return Err(format!(
            "unsupported plugin manifest version: {}",
            manifest.manifest_version
        ));
    }
    let id = single_line(&manifest.id, "id", 64)?.to_lowercase();
    let id_ok = id.len() >= 2
        && id
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && id.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        });
    if !id_ok {
        return Err("plugin id must be 2-64 lower-case letters, numbers or '-'".into());
    }
    let version = single_line(&manifest.version, "version", 40)?;
    let mut parts = version.split('-').next().unwrap_or_default().split('.');
    let numeric = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    }) && parts.next().is_none();
    if !numeric {
        return Err(format!(
            "plugin version must look like 1.2.3, got: {version}"
        ));
    }
    let mut capabilities: Vec<String> = Vec::new();
    for capability in &manifest.capabilities {
        if !PLUGIN_CAPABILITIES.contains(&capability.as_str()) {
            return Err(format!("unknown plugin capability: {capability}"));
        }
        if !capabilities.contains(capability) {
            capabilities.push(capability.clone());
        }
    }
    let signature = match manifest.signature.as_deref() {
        Some(value) => Some(single_line(value, "signature", 512)?),
        None => None,
    };
    Ok(PluginManifest {
        manifest_version: 1,
        id,
        name: single_line(&manifest.name, "name", 80)?,
        version,
        description: if manifest.description.trim().is_empty() {
            String::new()
        } else {
            single_line(&manifest.description, "description", 240)?
        },
        author: if manifest.author.trim().is_empty() {
            "unknown".into()
        } else {
            single_line(&manifest.author, "author", 80)?
        },
        capabilities,
        signature,
    })
}

fn validate_plugin_source(source: &str) -> Result<(), String> {
    if source.trim().is_empty() {
        return Err("a plugin needs non-empty source".into());
    }
    if source.len() > MAX_PLUGIN_SOURCE_BYTES {
        return Err(format!(
            "plugin source cannot exceed {} KiB",
            MAX_PLUGIN_SOURCE_BYTES / 1024
        ));
    }
    if source.contains('\0') {
        return Err("plugin source cannot contain a null byte".into());
    }
    Ok(())
}

fn indexed_plugins(session: &VaultSession) -> Result<HashMap<String, PluginSummary>, String> {
    match session.index.extra.get("plugins") {
        Some(value) => serde_json::from_value(value.clone()).map_err(|error| error.to_string()),
        None => Ok(HashMap::new()),
    }
}

fn store_plugin_index(
    session: &mut VaultSession,
    plugins: &HashMap<String, PluginSummary>,
) -> Result<(), String> {
    session.index.extra.insert(
        "plugins".into(),
        serde_json::to_value(plugins).map_err(|error| error.to_string())?,
    );
    Ok(())
}

fn load_plugin(session: &VaultSession, id: &str) -> Result<PluginPackage, String> {
    let path = plugin_object_path(&session.root_dir, id)?;
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|_| format!("plugin not found: {id}"))?)
            .map_err(|error| error.to_string())?;
    let plugin: PluginPackage =
        serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), &plugin_aad(id))?)
            .map_err(|error| error.to_string())?;
    if plugin.version != 1 || plugin.id != id {
        return Err("plugin identity check failed".into());
    }
    // Re-validated on the way out, not only on the way in: a manifest this
    // build cannot fully describe must never reach the runtime enforcing it.
    let manifest = validate_plugin_manifest(plugin.manifest)?;
    let signature = verify_plugin_signature(&manifest, &plugin.source)?;
    if plugin.signature.is_some() && plugin.signature != signature {
        return Err("plugin signature metadata does not match its signed package".into());
    }
    Ok(PluginPackage {
        manifest,
        signature,
        ..plugin
    })
}

fn resolve_plugin_id(session: &VaultSession, reference: &str) -> Result<String, String> {
    let plugins = indexed_plugins(session)?;
    if plugins.contains_key(reference) {
        return Ok(reference.to_string());
    }
    let wanted = reference.trim().to_lowercase();
    let matches: Vec<_> = plugins
        .values()
        .filter(|plugin| plugin.manifest_id == wanted || plugin.name.to_lowercase() == wanted)
        .map(|plugin| plugin.id.clone())
        .collect();
    match matches.as_slice() {
        [id] => Ok(id.clone()),
        [] => Err(format!("plugin not found: {reference}")),
        _ => Err(format!("ambiguous plugin reference: {reference}")),
    }
}

fn begin_plugin_journal(session: &VaultSession, id: &str) -> Result<(), String> {
    let journal = WriteJournal {
        version: 1,
        started_at: now(),
        scope: "plugins".into(),
        ids: vec![id.to_string()],
    };
    write_atomic(
        &journal_path(session),
        &serde_json::to_vec(&journal).map_err(|error| error.to_string())?,
    )
}

fn write_plugin(session: &mut VaultSession, plugin: &PluginPackage) -> Result<(), String> {
    let payload = encrypt(
        &serde_json::to_vec(plugin).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        &plugin_aad(&plugin.id),
    )?;
    write_atomic(
        &plugin_object_path(&session.root_dir, &plugin.id)?,
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )?;
    let mut plugins = indexed_plugins(session)?;
    plugins.insert(plugin.id.clone(), PluginSummary::from(plugin));
    store_plugin_index(session, &plugins)?;
    save_index(session)?;
    end_journal(session)
}

/// Installing takes the manifest and the source together on purpose: a plugin
/// whose declared reach and whose code arrived separately could be approved as
/// one thing and run as another.
fn install_plugin_in(
    session: &mut VaultSession,
    manifest: PluginManifest,
    source: String,
    enabled: Option<bool>,
) -> Result<PluginSummary, String> {
    let manifest = validate_plugin_manifest(manifest)?;
    validate_plugin_source(&source)?;
    let signature = verify_plugin_signature(&manifest, &source)?;
    let policy = load_plugin_policy(session)?;
    if signature
        .as_ref()
        .is_some_and(|signature| policy.revoked_signers.contains(&signature.key_id))
    {
        return Err(format!(
            "plugin signer is revoked: {}",
            signature.as_ref().expect("checked").key_id
        ));
    }
    if policy.restricted_mode && signature.is_none() {
        return Err("restricted mode accepts cryptographically signed plugins only".into());
    }
    let plugins = indexed_plugins(session)?;
    let existing = plugins
        .values()
        .find(|plugin| plugin.manifest_id == manifest.id)
        .cloned();
    if existing.is_none() && plugins.len() >= MAX_PLUGINS {
        return Err(format!("a vault may hold at most {MAX_PLUGINS} plugins"));
    }
    let id = existing
        .as_ref()
        .map(|plugin| plugin.id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if existing.is_none() && session.index.notes.contains_key(&id) {
        return Err(format!("document ID already exists: {id}"));
    }
    let previous = existing
        .as_ref()
        .map(|_| load_plugin(session, &id))
        .transpose()?;
    if previous
        .as_ref()
        .is_some_and(|plugin| plugin.signature.is_some())
        && signature.is_none()
    {
        return Err("a signed plugin cannot be updated with an unsigned package".into());
    }
    if let (Some(previous_signature), Some(next_signature)) = (
        previous
            .as_ref()
            .and_then(|plugin| plugin.signature.as_ref()),
        signature.as_ref(),
    ) {
        if previous_signature.key_id != next_signature.key_id {
            return Err(
                "plugin signer changed; remove the plugin and approve it as a new install".into(),
            );
        }
    }
    let stamp = now();
    let plugin = PluginPackage {
        version: 1,
        id,
        manifest,
        source,
        signature,
        // An update never silently re-enables a plugin the person turned off,
        // and never enables a new one without being asked to.
        enabled: enabled
            .or(previous.as_ref().map(|plugin| plugin.enabled))
            .unwrap_or(false),
        installed_at: previous
            .as_ref()
            .map(|plugin| plugin.installed_at.clone())
            .unwrap_or_else(|| stamp.clone()),
        updated_at: stamp,
        revision: existing.as_ref().map_or(0, |plugin| plugin.revision) + 1,
    };
    begin_plugin_journal(session, &plugin.id)?;
    write_plugin(session, &plugin)?;
    Ok(PluginSummary::from(&plugin))
}

fn set_plugin_enabled_in(
    session: &mut VaultSession,
    reference: &str,
    enabled: bool,
) -> Result<PluginSummary, String> {
    let id = resolve_plugin_id(session, reference)?;
    let current = load_plugin(session, &id)?;
    if enabled && !plugin_allowed(&current, &load_plugin_policy(session)?) {
        return Err("this plugin is blocked by restricted mode or signer revocation".into());
    }
    let plugin = PluginPackage {
        enabled,
        updated_at: now(),
        ..current
    };
    begin_plugin_journal(session, &id)?;
    write_plugin(session, &plugin)?;
    Ok(PluginSummary::from(&plugin))
}

fn remove_plugin_in(session: &mut VaultSession, reference: &str) -> Result<PluginSummary, String> {
    let id = resolve_plugin_id(session, reference)?;
    let plugin = load_plugin(session, &id)?;
    begin_plugin_journal(session, &id)?;
    for path in [
        plugin_object_path(&session.root_dir, &id)?,
        plugin_store_path(&session.root_dir, &id)?,
    ] {
        reject_symlink(&path)?;
        if path.exists() {
            fs::remove_file(&path).map_err(|error| error.to_string())?;
        }
    }
    let mut plugins = indexed_plugins(session)?;
    plugins.remove(&id);
    store_plugin_index(session, &plugins)?;
    save_index(session)?;
    end_journal(session)?;
    Ok(PluginSummary::from(&plugin))
}

fn read_plugin_storage(
    session: &VaultSession,
    id: &str,
) -> Result<HashMap<String, String>, String> {
    let path = plugin_store_path(&session.root_dir, id)?;
    if !path.exists() {
        return Ok(HashMap::new());
    }
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    serde_json::from_slice(&decrypt(
        &payload,
        session.key.as_ref(),
        &plugin_store_aad(id),
    )?)
    .map_err(|error| error.to_string())
}

fn write_plugin_storage(
    session: &VaultSession,
    id: &str,
    data: &HashMap<String, String>,
) -> Result<(), String> {
    let serialized = serde_json::to_vec(data).map_err(|error| error.to_string())?;
    if serialized.len() > MAX_PLUGIN_STORAGE_BYTES {
        return Err(format!(
            "plugin storage cannot exceed {} KiB",
            MAX_PLUGIN_STORAGE_BYTES / 1024
        ));
    }
    for key in data.keys() {
        if key.chars().count() > 160 {
            return Err("a plugin storage key cannot exceed 160 characters".into());
        }
    }
    let payload = encrypt(&serialized, session.key.as_ref(), &plugin_store_aad(id))?;
    write_atomic(
        &plugin_store_path(&session.root_dir, id)?,
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )
}

fn workspace_path(session: &VaultSession) -> PathBuf {
    session.root_dir.join("workspace.enc")
}

fn load_workspace(session: &VaultSession) -> Result<WorkspaceState, String> {
    let path = workspace_path(session);
    if !path.exists() {
        return Ok(WorkspaceState::empty());
    }
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let state: WorkspaceState =
        serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), WORKSPACE_AAD)?)
            .map_err(|error| error.to_string())?;
    if state.version != 1 {
        return Err("unsupported workspace file version".into());
    }
    Ok(state)
}

fn write_workspace(session: &VaultSession, state: &WorkspaceState) -> Result<(), String> {
    let payload = encrypt(
        &serde_json::to_vec(state).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        WORKSPACE_AAD,
    )?;
    write_atomic(
        &workspace_path(session),
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )
}

fn normalize_workspace(
    mut state: WorkspaceState,
    previous: &WorkspaceState,
) -> Result<WorkspaceState, String> {
    state.version = 1;
    if state.bookmarks.len() > MAX_BOOKMARKS {
        return Err(format!(
            "a vault may hold at most {MAX_BOOKMARKS} bookmarks"
        ));
    }
    if state.layouts.len() > MAX_LAYOUTS {
        return Err(format!("a vault may hold at most {MAX_LAYOUTS} workspaces"));
    }
    let timestamp = now();

    let mut bookmarks: Vec<Bookmark> = vec![];
    for mut bookmark in state.bookmarks {
        bookmark.label = bookmark.label.trim().to_string();
        if bookmark.id.trim().is_empty()
            || bookmark.id.chars().count() > 64
            || bookmark.label.chars().count() > 300
        {
            return Err("invalid bookmark".into());
        }
        if bookmarks.iter().any(|existing| existing.id == bookmark.id) {
            continue;
        }
        if bookmark.created_at.is_empty() {
            bookmark.created_at = timestamp.clone();
        }
        bookmarks.push(bookmark);
    }

    let mut layouts: Vec<WorkspaceLayout> = vec![];
    for mut layout in state.layouts {
        layout.name = layout.name.trim().to_string();
        if layout.name.is_empty() || layout.name.chars().count() > 120 {
            return Err("a workspace needs a name of 1-120 characters".into());
        }
        if layout.id.chars().count() > 64 || layout.tabs.len() > 64 {
            return Err("invalid workspace".into());
        }
        layout.created_at = previous
            .layouts
            .iter()
            .find(|existing| existing.id == layout.id)
            .map(|existing| existing.created_at.clone())
            .unwrap_or_else(|| timestamp.clone());
        layout.updated_at = timestamp.clone();
        if layout.id.trim().is_empty() {
            layout.id = Uuid::new_v4().to_string();
        }
        if layouts.iter().any(|existing| existing.id == layout.id) {
            return Err("two workspaces cannot share an ID".into());
        }
        layouts.push(layout);
    }
    layouts.sort_by(|left, right| {
        left.name
            .to_lowercase()
            .cmp(&right.name.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });

    Ok(WorkspaceState {
        version: 1,
        bookmarks,
        layouts,
    })
}

/// Every name a note answers to, longest first so "Least exposure" is matched
/// before a shorter alias that happens to be a prefix of it.
fn mention_names(note: &NoteDocument) -> Vec<String> {
    let mut names: Vec<String> = vec![];
    for candidate in std::iter::once(&note.title).chain(note.aliases.iter()) {
        let value = candidate.trim();
        if value.is_empty() {
            continue;
        }
        let lowered = value.to_lowercase();
        if !names
            .iter()
            .any(|existing| existing.to_lowercase() == lowered)
        {
            names.push(value.to_string());
        }
    }
    names.sort_by_key(|name| std::cmp::Reverse(name.chars().count()));
    names
}

/// Character ranges already covered by a wikilink, so an existing link is never
/// reported — or rewritten — as an unlinked mention.
fn wikilink_spans(body: &[char]) -> Vec<(usize, usize)> {
    let mut spans = vec![];
    let mut index = 0;
    while index + 1 < body.len() {
        if body[index] == '[' && body[index + 1] == '[' {
            let mut cursor = index + 2;
            while cursor + 1 < body.len() && !(body[cursor] == ']' && body[cursor + 1] == ']') {
                cursor += 1;
            }
            let end = if cursor + 1 < body.len() {
                cursor + 2
            } else {
                body.len()
            };
            spans.push((index, end));
            index = end;
        } else {
            index += 1;
        }
    }
    spans
}

fn is_word_char(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Whole-word, case-insensitive occurrences of one name outside every wikilink.
fn find_mentions(body: &[char], name: &[char], spans: &[(usize, usize)]) -> Vec<usize> {
    let mut hits = vec![];
    if name.is_empty() || name.len() > body.len() {
        return hits;
    }
    let mut index = 0;
    while index + name.len() <= body.len() {
        if spans
            .iter()
            .any(|(start, end)| index >= *start && index < *end)
        {
            index += 1;
            continue;
        }
        let after = index + name.len();
        let matches = (index == 0 || !is_word_char(body[index - 1]))
            && (after >= body.len() || !is_word_char(body[after]))
            && name.iter().zip(&body[index..after]).all(|(left, right)| {
                left.eq_ignore_ascii_case(right) || left.to_lowercase().eq(right.to_lowercase())
            });
        if matches {
            hits.push(index);
            index = after;
        } else {
            index += 1;
        }
    }
    hits
}

fn excerpt_around(body: &[char], start: usize, length: usize) -> String {
    let from = start.saturating_sub(60);
    let to = (start + length + 60).min(body.len());
    let slice: String = body[from..to].iter().collect();
    let trimmed = slice.split_whitespace().collect::<Vec<_>>().join(" ");
    format!(
        "{}{trimmed}{}",
        if from > 0 { "…" } else { "" },
        if to < body.len() { "…" } else { "" }
    )
}

/// Notes that name this one in plain text without linking it. Notes that already
/// link here are backlinks, not mentions, so they are skipped.
fn unlinked_mentions(index: &DocumentIndex, target_id: &str) -> Vec<UnlinkedMention> {
    let Some(target) = index.notes.get(target_id) else {
        return vec![];
    };
    let names = mention_names(&target.note);
    let lowered: Vec<String> = names.iter().map(|name| name.to_lowercase()).collect();
    let linked: HashSet<&str> = index
        .backlinks
        .get(target_id)
        .into_iter()
        .flatten()
        .map(|source| source.as_str())
        .collect();

    let mut mentions = vec![];
    for indexed in index.notes.values() {
        let note = &indexed.note;
        if note.id == target_id || linked.contains(note.id.as_str()) {
            continue;
        }
        // Cheap rejection first: the character scan below only runs for bodies
        // that contain the text at all.
        let haystack = note.body.to_lowercase();
        if !lowered.iter().any(|name| haystack.contains(name)) {
            continue;
        }
        let body: Vec<char> = note.body.chars().collect();
        let spans = wikilink_spans(&body);
        for name in &names {
            let needle: Vec<char> = name.chars().collect();
            let hits = find_mentions(&body, &needle, &spans);
            if hits.is_empty() {
                continue;
            }
            mentions.push(UnlinkedMention {
                note: NoteSummary::from(note),
                name: name.clone(),
                count: hits.len(),
                excerpt: excerpt_around(&body, hits[0], needle.len()),
            });
            break;
        }
    }
    mentions.sort_by(|left, right| left.note.path.cmp(&right.note.path));
    mentions.truncate(MAX_MENTIONS);
    mentions
}

/// Turn every unlinked mention of the target inside one source note into a
/// wikilink. The surface text the writer chose is preserved with an alias link
/// whenever it is not the target's title.
fn link_mention(session: &mut VaultSession, source: &str, target: &str) -> Result<usize, String> {
    let source_id = resolve_id(&session.index, source)?;
    let target_id = resolve_id(&session.index, target)?;
    if source_id == target_id {
        return Err("a note cannot link to itself".into());
    }
    let target_note = session
        .index
        .notes
        .get(&target_id)
        .ok_or("note not found")?
        .note
        .clone();
    let existing = session
        .index
        .notes
        .get(&source_id)
        .ok_or("note not found")?
        .note
        .clone();
    let body: Vec<char> = existing.body.chars().collect();
    let spans = wikilink_spans(&body);

    let mut hits: Vec<(usize, usize)> = vec![];
    for name in mention_names(&target_note) {
        let needle: Vec<char> = name.chars().collect();
        for start in find_mentions(&body, &needle, &spans) {
            hits.push((start, needle.len()));
        }
    }
    hits.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(&left.1)));
    let mut chosen: Vec<(usize, usize)> = vec![];
    for (start, length) in hits {
        if chosen
            .last()
            .is_some_and(|(previous, span)| start < previous + span)
        {
            continue;
        }
        chosen.push((start, length));
    }
    if chosen.is_empty() {
        return Err("no unlinked mention of that note remains".into());
    }

    let mut rebuilt = String::with_capacity(existing.body.len() + chosen.len() * 8);
    let mut cursor = 0;
    for (start, length) in &chosen {
        rebuilt.extend(&body[cursor..*start]);
        let surface: String = body[*start..*start + *length].iter().collect();
        if surface == target_note.title {
            rebuilt.push_str(&format!("[[{}]]", target_note.title));
        } else {
            rebuilt.push_str(&format!("[[{}|{surface}]]", target_note.title));
        }
        cursor = start + length;
    }
    rebuilt.extend(&body[cursor..]);

    let mut note = existing.clone();
    note.body = rebuilt;
    note.updated_at = now();
    note.revision = existing.revision + 1;
    store_note(session, note, Some(existing))?;
    Ok(chosen.len())
}

#[tauri::command(async)]
fn unlock_vault(
    vault_path: String,
    passphrase: String,
    state: State<'_, AppState>,
) -> Result<VaultInfo, String> {
    let session = open_session(&vault_path, &passphrase)?;
    let info = VaultInfo {
        name: session
            .vault_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Vault")
            .to_string(),
        path: session.vault_dir.to_string_lossy().into_owned(),
        note_count: session.index.notes.len(),
    };
    *state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")? = Some(session);
    Ok(info)
}

#[tauri::command(async)]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    *state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")? = None;
    Ok(())
}

#[tauri::command(async)]
fn list_notes(state: State<'_, AppState>) -> Result<Vec<NoteSummary>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut notes: Vec<_> = session
        .index
        .notes
        .values()
        .map(|note| NoteSummary::from(&note.note))
        .collect();
    notes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(notes)
}

#[tauri::command(async)]
fn get_note(reference: String, state: State<'_, AppState>) -> Result<NoteDocument, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_id(&session.index, &reference)?;
    load_note(session, &id)
}

#[tauri::command(async)]
fn save_note(note: NoteDocument, state: State<'_, AppState>) -> Result<NoteDocument, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| save_existing_note(session, note))
}

#[tauri::command(async)]
fn create_note(
    path: String,
    title: String,
    state: State<'_, AppState>,
) -> Result<NoteDocument, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let logical_path = validate_note_path(&path)?;
        if session
            .index
            .notes
            .values()
            .any(|note| normalized(&note.note.path) == normalized(&logical_path))
        {
            return Err(format!("a note already exists at {logical_path}"));
        }
        let timestamp = now();
        let note = NoteDocument {
            version: 1,
            id: Uuid::new_v4().to_string(),
            path: logical_path,
            title: title.trim().to_string(),
            body: format!("# {}\n\n", title.trim()),
            aliases: vec![],
            tags: vec![],
            properties: empty_object(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            revision: 1,
            frontmatter_source: None,
        };
        store_note(session, note, None)
    })
}

#[tauri::command(async)]
fn rename_note(
    reference: String,
    path: String,
    title: Option<String>,
    state: State<'_, AppState>,
) -> Result<NoteDocument, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        rename_note_in(session, &reference, &path, title.as_deref())
    })
}

#[tauri::command(async)]
fn delete_note(reference: String, state: State<'_, AppState>) -> Result<NoteSummary, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| remove_note_in(session, &reference))
}

#[tauri::command(async)]
fn list_deleted_notes(state: State<'_, AppState>) -> Result<Vec<DeletedNote>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    deleted_notes(session)
}

#[tauri::command(async)]
fn list_note_revisions(
    reference: String,
    state: State<'_, AppState>,
) -> Result<Vec<RevisionInfo>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_history_id(session, &reference)?;
    let mut revisions = Vec::new();
    for revision in archived_revisions(session, &id)? {
        let note = load_revision(session, &id, revision)?;
        revisions.push(RevisionInfo {
            revision,
            updated_at: note.updated_at,
            current: false,
        });
    }
    if let Some(current) = session.index.notes.get(&id) {
        revisions.push(RevisionInfo {
            revision: current.note.revision,
            updated_at: current.note.updated_at.clone(),
            current: true,
        });
    }
    revisions.sort_by_key(|item| std::cmp::Reverse(item.revision));
    Ok(revisions)
}

#[tauri::command(async)]
fn get_note_revision(
    reference: String,
    revision: u64,
    state: State<'_, AppState>,
) -> Result<NoteDocument, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_history_id(session, &reference)?;
    load_revision(session, &id, revision)
}

#[tauri::command(async)]
fn restore_note_revision(
    reference: String,
    revision: u64,
    state: State<'_, AppState>,
) -> Result<NoteDocument, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        restore_note_in(session, &reference, revision)
    })
}

#[tauri::command(async)]
fn list_templates(state: State<'_, AppState>) -> Result<Vec<NoteSummary>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut templates: Vec<_> = session
        .index
        .notes
        .values()
        .filter(|note| note.note.tags.iter().any(|tag| tag == "template"))
        .map(|note| NoteSummary::from(&note.note))
        .collect();
    templates.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(templates)
}

#[tauri::command(async)]
fn create_from_template(
    template: String,
    path: String,
    title: Option<String>,
    variables: Option<HashMap<String, String>>,
    date: Option<String>,
    state: State<'_, AppState>,
) -> Result<NoteDocument, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    let stamp = parse_local_date(date.as_deref())?;
    with_vault_write(session, |session| {
        create_from_template_in(
            session,
            TemplateRequest {
                template: &template,
                path: &path,
                title: title.as_deref(),
                date: stamp,
                variables: variables.unwrap_or_default(),
                tags: Vec::new(),
                properties: serde_json::Map::new(),
            },
        )
    })
}

#[tauri::command(async)]
fn open_daily_note(
    date: Option<String>,
    folder: Option<String>,
    template: Option<String>,
    state: State<'_, AppState>,
) -> Result<DailyNote, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        open_daily_note_in(
            session,
            date.as_deref(),
            folder.as_deref(),
            template.as_deref(),
        )
    })
}

#[tauri::command(async)]
fn list_plugins(state: State<'_, AppState>) -> Result<Vec<PluginSummary>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let policy = load_plugin_policy(session)?;
    let mut plugins = Vec::new();
    for summary in indexed_plugins(session)?.into_values() {
        let plugin = load_plugin(session, &summary.id)?;
        plugins.push(summarize_plugin(&plugin, &policy));
    }
    plugins.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(plugins)
}

/// The only command that hands back plugin code. The webview needs it to build
/// the sandbox worker; nothing else does.
#[tauri::command(async)]
fn get_plugin(reference: String, state: State<'_, AppState>) -> Result<PluginPackage, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_plugin_id(session, &reference)?;
    let plugin = load_plugin(session, &id)?;
    if plugin_allowed(&plugin, &load_plugin_policy(session)?) {
        Ok(plugin)
    } else {
        Ok(PluginPackage {
            enabled: false,
            ..plugin
        })
    }
}

#[tauri::command(async)]
fn get_plugin_security_policy(state: State<'_, AppState>) -> Result<PluginSecurityPolicy, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    load_plugin_policy(guard.as_ref().ok_or("vault is locked")?)
}

#[tauri::command(async)]
fn set_plugin_restricted_mode(
    restricted_mode: bool,
    state: State<'_, AppState>,
) -> Result<PluginSecurityPolicy, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let mut policy = load_plugin_policy(session)?;
        policy.restricted_mode = restricted_mode;
        save_plugin_policy(session, &policy)?;
        Ok(policy)
    })
}

#[tauri::command(async)]
fn revoke_plugin_signer(
    reference: String,
    state: State<'_, AppState>,
) -> Result<PluginSecurityPolicy, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let id = resolve_plugin_id(session, &reference)?;
        let plugin = load_plugin(session, &id)?;
        let key_id = plugin
            .signature
            .ok_or("an unsigned plugin has no signer to revoke")?
            .key_id;
        let mut policy = load_plugin_policy(session)?;
        if !policy.revoked_signers.contains(&key_id) {
            policy.revoked_signers.push(key_id.clone());
        }
        save_plugin_policy(session, &policy)?;
        let ids: Vec<_> = indexed_plugins(session)?.into_keys().collect();
        for id in ids {
            let candidate = load_plugin(session, &id)?;
            if candidate.enabled
                && candidate
                    .signature
                    .as_ref()
                    .is_some_and(|signature| signature.key_id == key_id)
            {
                set_plugin_enabled_in(session, &id, false)?;
            }
        }
        Ok(policy)
    })
}

#[tauri::command(async)]
fn restore_plugin_signer(
    key_id: String,
    state: State<'_, AppState>,
) -> Result<PluginSecurityPolicy, String> {
    let normalized = key_id.trim().to_lowercase();
    if normalized.len() != 64
        || !normalized
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("invalid plugin signer key ID".into());
    }
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let mut policy = load_plugin_policy(session)?;
        policy.revoked_signers.retain(|entry| entry != &normalized);
        save_plugin_policy(session, &policy)?;
        Ok(policy)
    })
}

#[tauri::command(async)]
fn install_plugin(
    manifest: PluginManifest,
    source: String,
    enabled: Option<bool>,
    state: State<'_, AppState>,
) -> Result<PluginSummary, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        install_plugin_in(session, manifest, source, enabled)
    })
}

#[tauri::command(async)]
fn set_plugin_enabled(
    reference: String,
    enabled: bool,
    state: State<'_, AppState>,
) -> Result<PluginSummary, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        set_plugin_enabled_in(session, &reference, enabled)
    })
}

#[tauri::command(async)]
fn delete_plugin(reference: String, state: State<'_, AppState>) -> Result<PluginSummary, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| remove_plugin_in(session, &reference))
}

#[tauri::command(async)]
fn get_plugin_storage(
    reference: String,
    state: State<'_, AppState>,
) -> Result<HashMap<String, String>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_plugin_id(session, &reference)?;
    read_plugin_storage(session, &id)
}

#[tauri::command(async)]
fn set_plugin_storage(
    reference: String,
    data: HashMap<String, String>,
    state: State<'_, AppState>,
) -> Result<HashMap<String, String>, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let id = resolve_plugin_id(session, &reference)?;
        write_plugin_storage(session, &id, &data)?;
        Ok(data)
    })
}

#[tauri::command(async)]
fn search_notes(
    query: String,
    limit: usize,
    state: State<'_, AppState>,
) -> Result<Vec<SearchHit>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut tags = vec![];
    let mut paths = vec![];
    let mut required = vec![];
    let mut excluded = vec![];
    for raw in query.split_whitespace() {
        let negative = raw.starts_with('-');
        let term = raw.trim_start_matches('-').trim_matches('"').to_lowercase();
        if let Some(tag) = term.strip_prefix("tag:") {
            tags.push(tag.trim_start_matches('#').to_string());
        } else if let Some(path) = term.strip_prefix("path:") {
            paths.push(path.to_string());
        } else if negative {
            excluded.push(term);
        } else if !term.is_empty() {
            required.push(term);
        }
    }
    let mut hits = vec![];
    for indexed in session.index.notes.values() {
        let note = &indexed.note;
        let title = note.title.to_lowercase();
        let body = note.body.to_lowercase();
        let note_path = note.path.to_lowercase();
        let aliases = note.aliases.join(" ").to_lowercase();
        let note_tags: Vec<_> = note.tags.iter().map(|tag| tag.to_lowercase()).collect();
        let properties = note.properties.to_string().to_lowercase();
        let all = format!(
            "{title}\n{aliases}\n{}\n{note_path}\n{properties}\n{body}",
            note_tags.join(" ")
        );
        if tags.iter().any(|tag| !note_tags.contains(tag))
            || paths.iter().any(|part| !note_path.contains(part))
            || excluded.iter().any(|term| all.contains(term))
            || required.iter().any(|term| !all.contains(term))
        {
            continue;
        }
        let mut score = if required.is_empty() { 1 } else { 0 };
        for term in &required {
            if &title == term {
                score += 40;
            } else if title.contains(term) {
                score += 20;
            }
            if aliases.contains(term) {
                score += 14;
            }
            if note_tags.iter().any(|tag| tag.contains(term)) {
                score += 10;
            }
            if note_path.contains(term) {
                score += 8;
            }
            score += body.matches(term).count().min(10) as u32;
            if properties.contains(term) {
                score += 4;
            }
        }
        let plain = note
            .body
            .replace(['#', '*', '_', '[', ']', '`'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let excerpt = plain.chars().take(180).collect();
        hits.push(SearchHit {
            note: NoteSummary::from(note),
            score,
            excerpt,
        });
    }
    hits.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.note.updated_at.cmp(&left.note.updated_at))
    });
    hits.truncate(limit.clamp(1, 100));
    Ok(hits)
}

#[tauri::command(async)]
fn get_backlinks(
    reference: String,
    state: State<'_, AppState>,
) -> Result<Vec<NoteSummary>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_id(&session.index, &reference)?;
    let mut notes: Vec<_> = session
        .index
        .backlinks
        .get(&id)
        .into_iter()
        .flatten()
        .filter_map(|source| session.index.notes.get(source))
        .map(|note| NoteSummary::from(&note.note))
        .collect();
    notes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(notes)
}

#[tauri::command(async)]
fn get_knowledge_graph(state: State<'_, AppState>) -> Result<KnowledgeGraph, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    Ok(build_graph(&session.index))
}

#[tauri::command(async)]
fn list_property_rows(state: State<'_, AppState>) -> Result<Vec<PropertyRow>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut rows: Vec<_> = session
        .index
        .notes
        .values()
        .map(|indexed| PropertyRow::from(&indexed.note))
        .collect();
    rows.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(rows)
}

#[tauri::command(async)]
fn update_note_property(
    reference: String,
    key: String,
    value: Option<Value>,
    state: State<'_, AppState>,
) -> Result<PropertyRow, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        set_property(session, &reference, &key, value)
    })
}

#[tauri::command(async)]
fn list_saved_views(state: State<'_, AppState>) -> Result<Vec<SavedView>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    load_saved_views(session)
}

#[tauri::command(async)]
fn save_saved_view(view: SavedView, state: State<'_, AppState>) -> Result<Vec<SavedView>, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let mut views = load_saved_views(session)?;
        let stored = normalize_view(view, &views)?;
        match views.iter().position(|existing| existing.id == stored.id) {
            Some(index) => views[index] = stored,
            None => {
                if views.len() >= MAX_SAVED_VIEWS {
                    return Err(format!(
                        "a vault may hold at most {MAX_SAVED_VIEWS} saved views"
                    ));
                }
                views.push(stored);
            }
        }
        views.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        write_saved_views(session, &views)?;
        Ok(views)
    })
}

#[tauri::command(async)]
fn delete_saved_view(id: String, state: State<'_, AppState>) -> Result<Vec<SavedView>, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let mut views = load_saved_views(session)?;
        let before = views.len();
        views.retain(|view| view.id != id);
        if views.len() == before {
            return Err(format!("saved view not found: {id}"));
        }
        write_saved_views(session, &views)?;
        Ok(views)
    })
}

#[tauri::command(async)]
fn get_workspace_state(state: State<'_, AppState>) -> Result<WorkspaceState, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    load_workspace(session)
}

#[tauri::command(async)]
fn save_workspace_state(
    workspace: WorkspaceState,
    state: State<'_, AppState>,
) -> Result<WorkspaceState, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let previous = load_workspace(session)?;
        let normalized = normalize_workspace(workspace, &previous)?;
        write_workspace(session, &normalized)?;
        Ok(normalized)
    })
}

#[tauri::command(async)]
fn get_unlinked_mentions(
    reference: String,
    state: State<'_, AppState>,
) -> Result<Vec<UnlinkedMention>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_id(&session.index, &reference)?;
    Ok(unlinked_mentions(&session.index, &id))
}

#[tauri::command(async)]
fn link_unlinked_mention(
    source: String,
    target: String,
    state: State<'_, AppState>,
) -> Result<Vec<UnlinkedMention>, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        link_mention(session, &source, &target)?;
        let id = resolve_id(&session.index, &target)?;
        Ok(unlinked_mentions(&session.index, &id))
    })
}

fn canvas_aad(id: &str) -> String {
    format!("secondbrain-vault:canvas:v1:{id}")
}

fn canvas_history_aad(id: &str, revision: u64) -> String {
    format!("secondbrain-vault:canvas-history:v1:{id}:{revision}")
}

fn canvas_object_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    Uuid::parse_str(id).map_err(|_| "invalid canvas ID")?;
    Ok(root.join("objects").join(format!("{id}.canvas.enc")))
}

fn normalize_canvas_path(input: &str) -> Result<String, String> {
    let mut value = input.trim().replace('\\', "/");
    if !value.to_lowercase().ends_with(".canvas") {
        value.push_str(".canvas");
    }
    if value.len() > 512
        || value.starts_with('/')
        || value.as_bytes().get(1) == Some(&b':')
        || value
            .chars()
            .any(|character| character == '\0' || character.is_control())
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("invalid logical canvas path".into());
    }
    Ok(value)
}

fn canvas_title(input: Option<&str>, canvas_path: &str) -> Result<String, String> {
    let fallback = canvas_path
        .rsplit('/')
        .next()
        .unwrap_or(canvas_path)
        .strip_suffix(".canvas")
        .unwrap_or(canvas_path);
    let title = input.unwrap_or(fallback).trim();
    if title.is_empty() || title.len() > 300 || title.chars().any(char::is_control) {
        return Err("canvas title must be between 1 and 300 characters".into());
    }
    Ok(title.to_string())
}

fn validate_canvas(nodes: &[Value], edges: &[Value]) -> Result<(), String> {
    if nodes.len() > MAX_CANVAS_NODES || edges.len() > MAX_CANVAS_EDGES {
        return Err(format!(
            "a canvas may contain at most {MAX_CANVAS_NODES} nodes and {MAX_CANVAS_EDGES} edges"
        ));
    }
    let id_pattern = Regex::new(r"^[A-Za-z0-9_-]{1,64}$").map_err(|error| error.to_string())?;
    let attachment_pattern = Regex::new(r"^[a-f0-9]{64}$").map_err(|error| error.to_string())?;
    let mut node_ids = HashSet::new();
    for raw in nodes {
        let node = raw
            .as_object()
            .ok_or("every canvas node must be an object")?;
        let id = node.get("id").and_then(Value::as_str).unwrap_or_default();
        if !id_pattern.is_match(id) || !node_ids.insert(id.to_string()) {
            return Err(format!("invalid or duplicate canvas node ID: {id}"));
        }
        for key in ["x", "y", "width", "height"] {
            let value = node
                .get(key)
                .and_then(Value::as_i64)
                .ok_or_else(|| format!("canvas node {id}: {key} must be a finite integer"))?;
            if value.abs() > 10_000_000 || ((key == "width" || key == "height") && value < 1) {
                return Err(format!("canvas node {id}: invalid {key}"));
            }
        }
        match node.get("type").and_then(Value::as_str) {
            Some("text") if node.get("text").and_then(Value::as_str).is_some() => {}
            Some("file") if node.get("file").and_then(Value::as_str).is_some() => {
                let note_id = node.get("noteId").and_then(Value::as_str);
                let attachment_id = node.get("attachmentId").and_then(Value::as_str);
                if note_id.is_some() && attachment_id.is_some() {
                    return Err(format!(
                        "canvas node {id}: a file cannot name both note and attachment IDs"
                    ));
                }
                if note_id.is_some_and(|value| Uuid::parse_str(value).is_err())
                    || attachment_id.is_some_and(|value| !attachment_pattern.is_match(value))
                {
                    return Err(format!("canvas node {id}: invalid document identity"));
                }
            }
            Some("group") => {}
            Some("link") => {
                let url = node.get("url").and_then(Value::as_str).unwrap_or_default();
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(format!(
                        "canvas node {id}: only http and https links are allowed"
                    ));
                }
            }
            _ => {
                return Err(format!(
                    "canvas node {id}: unsupported or incomplete node type"
                ))
            }
        }
    }
    let mut edge_ids = HashSet::new();
    for raw in edges {
        let edge = raw
            .as_object()
            .ok_or("every canvas edge must be an object")?;
        let id = edge.get("id").and_then(Value::as_str).unwrap_or_default();
        if !id_pattern.is_match(id) || !edge_ids.insert(id.to_string()) {
            return Err(format!("invalid or duplicate canvas edge ID: {id}"));
        }
        for key in ["fromNode", "toNode"] {
            let endpoint = edge.get(key).and_then(Value::as_str).unwrap_or_default();
            if !node_ids.contains(endpoint) {
                return Err(format!("canvas edge {id}: {key} does not name a node"));
            }
        }
    }
    Ok(())
}

fn load_canvas(session: &VaultSession, id: &str) -> Result<CanvasDocument, String> {
    let path = canvas_object_path(&session.root_dir, id)?;
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|_| format!("canvas not found: {id}"))?)
            .map_err(|error| error.to_string())?;
    let canvas: CanvasDocument =
        serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), &canvas_aad(id))?)
            .map_err(|error| error.to_string())?;
    if canvas.version != 1 || canvas.id != id {
        return Err("canvas identity check failed".into());
    }
    validate_canvas(&canvas.nodes, &canvas.edges)?;
    Ok(canvas)
}

fn indexed_canvases(session: &VaultSession) -> Result<HashMap<String, IndexedCanvas>, String> {
    match session.index.extra.get("canvases") {
        Some(value) => serde_json::from_value(value.clone()).map_err(|error| error.to_string()),
        None => Ok(HashMap::new()),
    }
}

fn index_canvas(index: &DocumentIndex, canvas: &CanvasDocument) -> Result<IndexedCanvas, String> {
    let mut note_refs = HashSet::new();
    let mut attachment_refs = HashSet::new();
    let mut unresolved = Vec::new();
    for node in &canvas.nodes {
        if let Some(id) = node.get("noteId").and_then(Value::as_str) {
            note_refs.insert(id.to_string());
        }
        if let Some(id) = node.get("attachmentId").and_then(Value::as_str) {
            attachment_refs.insert(id.to_string());
        }
        if node.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(text) = node.get("text").and_then(Value::as_str) {
                for link in analyze_markdown(text)?.0 {
                    if let Some(id) = resolve_link(index, &link) {
                        note_refs.insert(id);
                    } else {
                        unresolved.push(link);
                    }
                }
            }
        }
    }
    let mut note_refs: Vec<_> = note_refs.into_iter().collect();
    let mut attachment_refs: Vec<_> = attachment_refs.into_iter().collect();
    note_refs.sort();
    attachment_refs.sort();
    Ok(IndexedCanvas {
        id: canvas.id.clone(),
        path: canvas.path.clone(),
        title: canvas.title.clone(),
        updated_at: canvas.updated_at.clone(),
        revision: canvas.revision,
        node_count: canvas.nodes.len(),
        edge_count: canvas.edges.len(),
        note_refs,
        attachment_refs,
        unresolved,
    })
}

fn note_identity_labels(note: &NoteDocument) -> HashSet<String> {
    let basename = note.path.rsplit('/').next().unwrap_or(&note.path);
    std::iter::once(normalized(&note.path))
        .chain(std::iter::once(normalized(basename)))
        .chain(std::iter::once(normalized(&note.title)))
        .chain(note.aliases.iter().map(|alias| normalized(alias)))
        .collect()
}

fn refresh_canvases_for_note_change(
    session: &mut VaultSession,
    note_id: &str,
    identity_labels: &HashSet<String>,
) -> Result<(), String> {
    let mut canvases = indexed_canvases(session)?;
    if canvases.is_empty() {
        return Ok(());
    }
    let canvas_refs: HashMap<String, Vec<String>> = session
        .index
        .extra
        .get("canvasRefs")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| error.to_string())?
        .unwrap_or_default();
    let mut candidates: HashSet<String> = canvas_refs
        .get(note_id)
        .into_iter()
        .flatten()
        .cloned()
        .collect();
    for label in identity_labels {
        for owner in session
            .index
            .path_owners
            .get(label)
            .into_iter()
            .chain(session.index.name_owners.get(label))
            .chain(session.index.basename_owners.get(label))
            .flatten()
        {
            if let Some(refs) = canvas_refs.get(owner) {
                candidates.extend(refs.iter().cloned());
            }
        }
    }
    for canvas in canvases.values() {
        if canvas
            .unresolved
            .iter()
            .any(|link| identity_labels.contains(&normalized(&link.target)))
        {
            candidates.insert(canvas.id.clone());
        }
    }
    for id in candidates {
        let canvas = load_canvas(session, &id)?;
        canvases.insert(id, index_canvas(&session.index, &canvas)?);
    }
    store_canvas_index(session, &canvases)
}

fn store_canvas_index(
    session: &mut VaultSession,
    canvases: &HashMap<String, IndexedCanvas>,
) -> Result<(), String> {
    let mut note_refs: HashMap<String, Vec<String>> = HashMap::new();
    let mut attachment_refs: HashMap<String, Vec<String>> = HashMap::new();
    let mut path_owners: HashMap<String, Vec<String>> = HashMap::new();
    for canvas in canvases.values() {
        for note_id in &canvas.note_refs {
            note_refs
                .entry(note_id.clone())
                .or_default()
                .push(canvas.id.clone());
        }
        for attachment_id in &canvas.attachment_refs {
            attachment_refs
                .entry(attachment_id.clone())
                .or_default()
                .push(canvas.id.clone());
        }
        let basename = canvas
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&canvas.path)
            .strip_suffix(".canvas")
            .unwrap_or(&canvas.path);
        for label in [&canvas.path, &canvas.title, basename] {
            path_owners
                .entry(normalized_text(label))
                .or_default()
                .push(canvas.id.clone());
        }
    }
    for values in note_refs.values_mut() {
        values.sort();
        values.dedup();
    }
    for values in attachment_refs.values_mut() {
        values.sort();
        values.dedup();
    }
    for values in path_owners.values_mut() {
        values.sort();
        values.dedup();
    }
    session.index.extra.insert(
        "canvases".into(),
        serde_json::to_value(canvases).map_err(|error| error.to_string())?,
    );
    session.index.extra.insert(
        "canvasRefs".into(),
        serde_json::to_value(note_refs).map_err(|error| error.to_string())?,
    );
    session.index.extra.insert(
        "canvasAttachmentRefs".into(),
        serde_json::to_value(attachment_refs).map_err(|error| error.to_string())?,
    );
    session.index.extra.insert(
        "canvasPathOwners".into(),
        serde_json::to_value(path_owners).map_err(|error| error.to_string())?,
    );
    Ok(())
}

fn recover_canvas_index(session: &mut VaultSession) -> Result<(), String> {
    let mut canvases = HashMap::new();
    let objects = session.root_dir.join("objects");
    if objects.exists() {
        reject_symlink(&objects)?;
        for entry in fs::read_dir(objects).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".canvas.enc") else {
                continue;
            };
            if Uuid::parse_str(id).is_ok() {
                let canvas = load_canvas(session, id)?;
                canvases.insert(id.to_string(), index_canvas(&session.index, &canvas)?);
            }
        }
    }
    store_canvas_index(session, &canvases)
}

fn resolve_canvas_id(session: &VaultSession, reference: &str) -> Result<String, String> {
    let canvases = indexed_canvases(session)?;
    if canvases.contains_key(reference) {
        return Ok(reference.to_string());
    }
    let normalized = reference.trim().replace('\\', "/").to_lowercase();
    let with_extension = if normalized.ends_with(".canvas") {
        normalized.clone()
    } else {
        format!("{normalized}.canvas")
    };
    let matches: Vec<_> = canvases
        .values()
        .filter(|canvas| {
            let basename = canvas
                .path
                .rsplit('/')
                .next()
                .unwrap_or(&canvas.path)
                .strip_suffix(".canvas")
                .unwrap_or(&canvas.path);
            canvas.path.to_lowercase() == with_extension
                || canvas.title.to_lowercase() == normalized
                || basename.to_lowercase() == normalized
        })
        .map(|canvas| canvas.id.clone())
        .collect();
    match matches.as_slice() {
        [id] => Ok(id.clone()),
        [] => Err(format!("canvas not found: {reference}")),
        _ => Err(format!("ambiguous canvas reference: {reference}")),
    }
}

fn archive_canvas(session: &VaultSession, canvas: &CanvasDocument) -> Result<(), String> {
    let path = session
        .root_dir
        .join("history")
        .join(&canvas.id)
        .join(format!("{}.canvas.enc", canvas.revision));
    if path.exists() {
        return Ok(());
    }
    let payload = encrypt(
        &serde_json::to_vec(canvas).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        &canvas_history_aad(&canvas.id, canvas.revision),
    )?;
    write_atomic(
        &path,
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )
}

fn begin_canvas_journal(session: &VaultSession, id: &str) -> Result<(), String> {
    let journal = WriteJournal {
        version: 1,
        started_at: now(),
        scope: "canvases".into(),
        ids: vec![id.to_string()],
    };
    write_atomic(
        &journal_path(session),
        &serde_json::to_vec(&journal).map_err(|error| error.to_string())?,
    )
}

fn put_canvas(session: &mut VaultSession, input: CanvasInput) -> Result<CanvasDocument, String> {
    validate_canvas(&input.nodes, &input.edges)?;
    let serialized_size = serde_json::to_vec(&(&input.nodes, &input.edges))
        .map_err(|error| error.to_string())?
        .len();
    if serialized_size > MAX_CANVAS_BYTES {
        return Err("a canvas cannot exceed 8 MiB serialized".into());
    }
    let canvas_path = normalize_canvas_path(&input.path)?;
    let mut canvases = indexed_canvases(session)?;
    let by_path = canvases
        .values()
        .find(|canvas| canvas.path.eq_ignore_ascii_case(&canvas_path))
        .cloned();
    if let (Some(requested), Some(owner)) = (&input.id, &by_path) {
        if requested != &owner.id {
            return Err(format!("another canvas already uses path: {canvas_path}"));
        }
    }
    let existing = input
        .id
        .as_ref()
        .and_then(|id| canvases.get(id).cloned())
        .or(by_path);
    if let (Some(base), Some(current)) = (input.base_revision, existing.as_ref()) {
        if base != current.revision {
            return Err(format!(
                "canvas revision conflict: expected revision {base}, current revision {}",
                current.revision
            ));
        }
    }
    let id = existing
        .as_ref()
        .map(|canvas| canvas.id.clone())
        .or(input.id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    Uuid::parse_str(&id).map_err(|_| "invalid canvas ID")?;
    if session.index.notes.contains_key(&id) && existing.is_none() {
        return Err(format!("document ID already exists: {id}"));
    }
    let previous = existing
        .as_ref()
        .map(|_| load_canvas(session, &id))
        .transpose()?;
    let stamp = now();
    let canvas = CanvasDocument {
        version: 1,
        id: id.clone(),
        path: canvas_path.clone(),
        title: canvas_title(input.title.as_deref(), &canvas_path)?,
        nodes: input.nodes,
        edges: input.edges,
        created_at: previous
            .as_ref()
            .map(|canvas| canvas.created_at.clone())
            .or(input.created_at)
            .unwrap_or_else(|| stamp.clone()),
        updated_at: stamp,
        revision: existing.as_ref().map_or(1, |canvas| canvas.revision + 1),
    };
    begin_canvas_journal(session, &id)?;
    if let Some(previous) = &previous {
        archive_canvas(session, previous)?;
    }
    let payload = encrypt(
        &serde_json::to_vec(&canvas).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        &canvas_aad(&id),
    )?;
    write_atomic(
        &canvas_object_path(&session.root_dir, &id)?,
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )?;
    canvases.insert(id, index_canvas(&session.index, &canvas)?);
    store_canvas_index(session, &canvases)?;
    save_index(session)?;
    end_journal(session)?;
    Ok(canvas)
}

impl From<&IndexedCanvas> for CanvasSummary {
    fn from(canvas: &IndexedCanvas) -> Self {
        Self {
            id: canvas.id.clone(),
            path: canvas.path.clone(),
            title: canvas.title.clone(),
            node_count: canvas.node_count,
            edge_count: canvas.edge_count,
            updated_at: canvas.updated_at.clone(),
            revision: canvas.revision,
        }
    }
}

#[tauri::command(async)]
fn list_canvases(state: State<'_, AppState>) -> Result<Vec<CanvasSummary>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut result: Vec<_> = indexed_canvases(session)?
        .values()
        .map(CanvasSummary::from)
        .collect();
    result.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(result)
}

#[tauri::command(async)]
fn get_canvas(reference: String, state: State<'_, AppState>) -> Result<CanvasDocument, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_canvas_id(session, &reference)?;
    load_canvas(session, &id)
}

#[tauri::command(async)]
fn save_canvas(input: CanvasInput, state: State<'_, AppState>) -> Result<CanvasDocument, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| put_canvas(session, input))
}

#[tauri::command(async)]
fn delete_canvas(reference: String, state: State<'_, AppState>) -> Result<CanvasDocument, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| {
        let id = resolve_canvas_id(session, &reference)?;
        let canvas = load_canvas(session, &id)?;
        begin_canvas_journal(session, &id)?;
        archive_canvas(session, &canvas)?;
        let path = canvas_object_path(&session.root_dir, &id)?;
        reject_symlink(&path)?;
        fs::remove_file(path).map_err(|error| error.to_string())?;
        let mut canvases = indexed_canvases(session)?;
        canvases.remove(&id);
        store_canvas_index(session, &canvases)?;
        save_index(session)?;
        end_journal(session)?;
        Ok(canvas)
    })
}

/// Content-addressed, chunk-encrypted attachments.
///
/// This is the same on-disk shape the TypeScript core writes, because both
/// implementations have to read one vault: `attachments/<id>/manifest.enc`
/// beside `attachments/<id>/<n>.chunk.enc`, where `<id>` is
/// `HMAC-SHA256(vault key, "secondbrain-vault:attachment-id:v1\0" || bytes)`.
/// Keying the address means two vaults never agree on an ID for the same file,
/// so a directory listing tells an observer nothing about what is stored.
///
/// Each chunk authenticates its own index, so chunks cannot be reordered or
/// swapped between attachments without failing decryption. `test/fixtures/`
/// carries an attachment written by the TypeScript core that these functions
/// must still be able to open.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentInfo {
    id: String,
    filename: String,
    mime: String,
    size: usize,
    chunks: usize,
    created_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentContent {
    info: AttachmentInfo,
    /// Base64: the webview receives bytes over JSON IPC or not at all.
    data: String,
}

fn attachment_manifest_aad(id: &str) -> String {
    format!("secondbrain-vault:attachment-manifest:v1:{id}")
}

fn attachment_chunk_aad(id: &str, index: usize) -> String {
    format!("secondbrain-vault:attachment-chunk:v1:{id}:{index}")
}

fn attachment_id(key: &[u8], data: &[u8]) -> Result<String, String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).map_err(|_| "invalid HMAC key")?;
    mac.update(b"secondbrain-vault:attachment-id:v1\0");
    mac.update(data);
    Ok(hex_lower(&mac.finalize().into_bytes()))
}

fn attachment_dir(root: &Path, id: &str) -> Result<PathBuf, String> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("invalid attachment ID".into());
    }
    let dir = root.join("attachments").join(id);
    reject_symlink(&dir)?;
    Ok(dir)
}

fn attachment_manifest_path(root: &Path, id: &str) -> Result<PathBuf, String> {
    Ok(attachment_dir(root, id)?.join("manifest.enc"))
}

fn validate_attachment_filename(input: &str) -> Result<String, String> {
    let value = input.trim().to_string();
    if value.is_empty()
        || value.chars().count() > 255
        || value
            .chars()
            .any(|character| character == '\0' || character == '\r' || character == '\n')
    {
        return Err("invalid attachment filename".into());
    }
    Ok(value)
}

fn validate_attachment_mime(input: &str) -> Result<String, String> {
    let value = input.trim().to_lowercase();
    let pattern = Regex::new(r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$")
        .map_err(|error| error.to_string())?;
    if !pattern.is_match(&value) {
        return Err("invalid attachment MIME type".into());
    }
    Ok(value)
}

fn read_attachment_manifest(session: &VaultSession, id: &str) -> Result<AttachmentInfo, String> {
    let path = attachment_manifest_path(&session.root_dir, id)?;
    if !path.is_file() {
        return Err(format!("attachment not found: {id}"));
    }
    reject_symlink(&path)?;
    let payload: EncryptedPayload =
        serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let info: AttachmentInfo = serde_json::from_slice(&decrypt(
        &payload,
        session.key.as_ref(),
        &attachment_manifest_aad(id),
    )?)
    .map_err(|error| error.to_string())?;
    if info.id != id || info.chunks == 0 || info.size > MAX_ATTACHMENT_BYTES {
        return Err("attachment manifest identity check failed".into());
    }
    Ok(info)
}

/// Storing the same bytes twice is a no-op that returns the first manifest, so
/// embedding one image in fifty notes costs one copy. There is no advisory
/// vault lock in this core yet, and content addressing is what makes that
/// survivable: two writers racing on identical bytes write identical chunks to
/// the same paths, and every chunk write is atomic on its own.
fn put_attachment(
    session: &VaultSession,
    data: &[u8],
    filename: &str,
    mime: &str,
) -> Result<AttachmentInfo, String> {
    if data.is_empty() || data.len() > MAX_ATTACHMENT_BYTES {
        return Err("attachments must be between 1 byte and 250 MiB".into());
    }
    let filename = validate_attachment_filename(filename)?;
    let mime = validate_attachment_mime(mime)?;
    let id = attachment_id(session.attachment_id_key.as_ref(), data)?;
    let manifest_path = attachment_manifest_path(&session.root_dir, &id)?;
    if manifest_path.is_file() {
        return read_attachment_manifest(session, &id);
    }

    let dir = attachment_dir(&session.root_dir, &id)?;
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let chunks = data.len().div_ceil(ATTACHMENT_CHUNK_SIZE);
    for index in 0..chunks {
        let start = index * ATTACHMENT_CHUNK_SIZE;
        let end = usize::min(start + ATTACHMENT_CHUNK_SIZE, data.len());
        let payload = encrypt(
            &data[start..end],
            session.key.as_ref(),
            &attachment_chunk_aad(&id, index),
        )?;
        write_atomic(
            &dir.join(format!("{index}.chunk.enc")),
            &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
        )?;
    }

    let info = AttachmentInfo {
        id: id.clone(),
        filename,
        mime,
        size: data.len(),
        chunks,
        created_at: now(),
    };
    let payload = encrypt(
        &serde_json::to_vec(&info).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        &attachment_manifest_aad(&id),
    )?;
    write_atomic(
        &manifest_path,
        &serde_json::to_vec(&payload).map_err(|error| error.to_string())?,
    )?;
    Ok(info)
}

fn get_attachment(session: &VaultSession, id: &str) -> Result<(AttachmentInfo, Vec<u8>), String> {
    let info = read_attachment_manifest(session, id)?;
    let dir = attachment_dir(&session.root_dir, id)?;
    let mut data = Vec::with_capacity(info.size);
    for index in 0..info.chunks {
        let path = dir.join(format!("{index}.chunk.enc"));
        if !path.is_file() {
            return Err(format!("missing attachment chunk {index}"));
        }
        reject_symlink(&path)?;
        let payload: EncryptedPayload =
            serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        data.extend_from_slice(&decrypt(
            &payload,
            session.key.as_ref(),
            &attachment_chunk_aad(id, index),
        )?);
    }
    if data.len() != info.size
        || attachment_id(session.attachment_id_key.as_ref(), &data)? != info.id
    {
        return Err("attachment integrity check failed".into());
    }
    Ok((info, data))
}

fn load_attachments(session: &VaultSession) -> Result<Vec<AttachmentInfo>, String> {
    let root = session.root_dir.join("attachments");
    if !root.is_dir() {
        return Ok(vec![]);
    }
    reject_symlink(&root)?;
    let mut infos = Vec::new();
    for entry in fs::read_dir(&root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(id) = name.to_str() else { continue };
        let Ok(manifest) = attachment_manifest_path(&session.root_dir, id) else {
            continue;
        };
        if !manifest.is_file() {
            continue;
        }
        infos.push(read_attachment_manifest(session, id)?);
    }
    infos.sort_by(|left, right| {
        left.filename
            .to_lowercase()
            .cmp(&right.filename.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(infos)
}

fn remove_attachment(session: &VaultSession, id: &str) -> Result<AttachmentInfo, String> {
    let info = read_attachment_manifest(session, id)?;
    fs::remove_dir_all(attachment_dir(&session.root_dir, id)?)
        .map_err(|error| error.to_string())?;
    Ok(info)
}

#[tauri::command(async)]
fn add_attachment(
    filename: String,
    mime: String,
    data: String,
    state: State<'_, AppState>,
) -> Result<AttachmentInfo, String> {
    if data.len() > MAX_ATTACHMENT_BYTES / 3 * 4 + 4 {
        return Err("attachments must be between 1 byte and 250 MiB".into());
    }
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    let bytes = BASE64
        .decode(data.as_bytes())
        .map_err(|_| "attachment data must be base64")?;
    with_vault_write(session, |session| {
        put_attachment(session, &bytes, &filename, &mime)
    })
}

#[tauri::command(async)]
fn read_attachment(id: String, state: State<'_, AppState>) -> Result<AttachmentContent, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let (info, data) = get_attachment(session, &id)?;
    Ok(AttachmentContent {
        info,
        data: BASE64.encode(data),
    })
}

#[tauri::command(async)]
fn list_attachments(state: State<'_, AppState>) -> Result<Vec<AttachmentInfo>, String> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    load_attachments(session)
}

#[tauri::command(async)]
fn delete_attachment(id: String, state: State<'_, AppState>) -> Result<AttachmentInfo, String> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    with_vault_write(session, |session| remove_attachment(session, &id))
}

/// Opens the operating system's folder chooser and reports back only the path
/// the person selected, or `None` when they dismissed it. Typing a path by hand
/// stays supported; this exists so a vault does not have to be spelled out.
#[tauri::command(async)]
fn pick_vault_directory(app: AppHandle) -> Result<Option<String>, String> {
    let chosen = app
        .dialog()
        .file()
        .set_title("Choose a vault folder")
        .blocking_pick_folder();
    let Some(chosen) = chosen else {
        return Ok(None);
    };
    let path = chosen.into_path().map_err(|error| error.to_string())?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            pick_vault_directory,
            unlock_vault,
            lock_vault,
            list_notes,
            get_note,
            save_note,
            create_note,
            rename_note,
            delete_note,
            list_deleted_notes,
            list_note_revisions,
            get_note_revision,
            restore_note_revision,
            list_templates,
            create_from_template,
            open_daily_note,
            list_plugins,
            get_plugin,
            get_plugin_security_policy,
            set_plugin_restricted_mode,
            revoke_plugin_signer,
            restore_plugin_signer,
            install_plugin,
            set_plugin_enabled,
            delete_plugin,
            get_plugin_storage,
            set_plugin_storage,
            search_notes,
            get_backlinks,
            get_knowledge_graph,
            list_property_rows,
            update_note_property,
            list_saved_views,
            save_saved_view,
            delete_saved_view,
            get_workspace_state,
            save_workspace_state,
            get_unlinked_mentions,
            link_unlinked_mention,
            list_canvases,
            get_canvas,
            save_canvas,
            delete_canvas,
            add_attachment,
            read_attachment,
            list_attachments,
            delete_attachment,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vault Brain");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_vault(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vault-brain-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn encrypted_payload_round_trip_and_authentication() {
        let key = [7u8; 32];
        let payload = encrypt(b"private knowledge", &key, "test-context").unwrap();
        assert_eq!(
            decrypt(&payload, &key, "test-context").unwrap(),
            b"private knowledge"
        );
        assert!(decrypt(&payload, &key, "different-context").is_err());

        let mut tampered = payload;
        tampered.ciphertext = BASE64.encode(b"not the original ciphertext");
        assert!(decrypt(&tampered, &key, "test-context").is_err());
    }

    #[test]
    fn logical_paths_reject_escape_and_absolute_inputs() {
        assert_eq!(
            validate_note_path("Projects/Launch").unwrap(),
            "Projects/Launch.md"
        );
        for unsafe_path in [
            "../outside.md",
            "a/../../outside.md",
            "/root.md",
            "C:/root.md",
            "a//b.md",
        ] {
            assert!(
                validate_note_path(unsafe_path).is_err(),
                "accepted unsafe path: {unsafe_path}"
            );
        }
    }

    #[test]
    fn rust_and_typescript_derive_the_same_visible_markdown_structure() {
        let markdown = "# Crème_ Brûlée -- Test!\n\n`[[Inline]]`\n\n```md\n[[Fence]]\n# Hidden\n```\n\n[[Visible]]";
        let (links, headings) = analyze_markdown(markdown).unwrap();
        assert_eq!(
            links
                .iter()
                .map(|link| link.target.as_str())
                .collect::<Vec<_>>(),
            ["Visible"]
        );
        assert_eq!(headings.len(), 1);
        assert_eq!(headings[0].text, "Crème_ Brûlée -- Test!");
        assert_eq!(headings[0].slug, "crème-brûlée-test");
    }

    #[test]
    fn vault_reopens_and_rejects_the_wrong_passphrase() {
        let path = temporary_vault("unlock");
        let path_text = path.to_string_lossy().into_owned();
        let first = open_session(&path_text, "correct horse battery staple").unwrap();
        assert_eq!(first.index.version, 2);
        drop(first);
        assert!(open_session(&path_text, "wrong passphrase").is_err());
        assert!(open_session(&path_text, "correct horse battery staple").is_ok());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_fresh_vault_is_created_keyring_native() {
        let path = temporary_vault("keyring-native");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "correct horse battery staple").unwrap();
        let vault_dir = session.vault_dir.clone();
        drop(session);

        assert!(vault_dir.join("keyring.json").exists());
        assert_eq!(
            fs::read_to_string(vault_dir.join("documents").join("manifest.json")).unwrap(),
            "{\n  \"version\": 2,\n  \"keyring\": true\n}\n"
        );
        // The keyring on disk is the one that opens: no cached key material here.
        assert!(open_session(&path_text, "correct horse battery staple").is_ok());
        assert!(open_session(&path_text, "wrong passphrase").is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_keyring_vault_missing_its_keyring_explains_itself() {
        let path = temporary_vault("keyring-lost");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "correct horse battery staple").unwrap();
        let vault_dir = session.vault_dir.clone();
        drop(session);
        fs::remove_file(vault_dir.join("keyring.json")).unwrap();

        let error = open_session(&path_text, "correct horse battery staple").unwrap_err();
        assert!(
            error.contains("upgraded to a keyring"),
            "unhelpful refusal: {error}"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_legacy_key_value_vault_does_not_gain_a_keyring() {
        let path = temporary_vault("legacy-kv");
        fs::create_dir_all(&path).unwrap();
        // What a pre-keyring release leaves behind for a key-value-only vault.
        fs::write(path.join("health.kv.enc"), "{}").unwrap();
        fs::write(
            path.join("audit.meta.json"),
            "{\"version\":1,\"salt\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}",
        )
        .unwrap();
        let path_text = path.to_string_lossy().into_owned();

        let session = open_session(&path_text, "correct horse battery staple").unwrap();
        let vault_dir = session.vault_dir.clone();
        drop(session);

        assert!(
            !vault_dir.join("keyring.json").exists(),
            "a keyring beside a legacy audit chain would orphan it"
        );
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(vault_dir.join("documents").join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.version, 1);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn desktop_writer_uses_the_shared_lock_and_reclaims_a_stale_holder() {
        let path = temporary_vault("writer-lock");
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        let lock_path = path.join(VAULT_LOCK_FILENAME);

        let held = VaultWriteGuard::acquire(&path).unwrap();
        assert!(lock_path.is_file());
        let error = match VaultWriteGuard::acquire(&path) {
            Ok(_) => panic!("a second writer acquired a live lock"),
            Err(error) => error,
        };
        assert!(error.contains("vault is being written by process"));
        drop(held);
        assert!(!lock_path.exists(), "the owner releases its lock");

        let stale = VaultLockRecord {
            token: Uuid::new_v4().to_string(),
            pid: 999_999,
            host: "crashed-host".into(),
            acquired_at: "1970-01-01T00:00:00.000Z".into(),
        };
        fs::write(&lock_path, serde_json::to_vec(&stale).unwrap()).unwrap();
        let reclaimed = VaultWriteGuard::acquire(&path).unwrap();
        assert_ne!(read_lock_record(&lock_path).unwrap().token, stale.token);
        drop(reclaimed);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn unlock_recovers_an_object_write_left_ahead_of_the_index() {
        let path = temporary_vault("desktop-journal");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "journal passphrase").unwrap();
        let original = seeded_note("Inbox/Crash.md", "Crash", "# Before");
        store_note(&mut session, original.clone(), None).unwrap();

        let mut updated = original.clone();
        updated.body = "# After\n\nObject landed; index did not.".into();
        updated.revision = 2;
        updated.updated_at = now();
        begin_note_journal(&session, std::slice::from_ref(&updated.id)).unwrap();
        let payload = encrypt(
            &serde_json::to_vec(&updated).unwrap(),
            session.key.as_ref(),
            &note_aad(&updated.id),
        )
        .unwrap();
        write_atomic(
            &note_path(&session.root_dir, &updated.id).unwrap(),
            &serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        drop(session);

        let reopened = open_session(&path_text, "journal passphrase").unwrap();
        assert_eq!(reopened.index.notes[&updated.id].note.body, updated.body);
        assert!(
            !journal_path(&reopened).exists(),
            "successful replay clears the journal"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_stale_desktop_editor_cannot_overwrite_a_newer_process() {
        let path = temporary_vault("revision-conflict");
        let path_text = path.to_string_lossy().into_owned();
        let mut first = open_session(&path_text, "conflict passphrase").unwrap();
        let original = seeded_note("Inbox/Shared.md", "Shared", "# Original");
        with_vault_write(&mut first, |session| {
            store_note(session, original.clone(), None)
        })
        .unwrap();
        let stale = original.clone();

        let mut second = open_session(&path_text, "conflict passphrase").unwrap();
        let mut newer = original.clone();
        newer.body = "# Written elsewhere".into();
        with_vault_write(&mut second, |session| save_existing_note(session, newer)).unwrap();

        let mut stale_edit = stale;
        stale_edit.body = "# Stale editor overwrite".into();
        let error = with_vault_write(&mut first, |session| {
            save_existing_note(session, stale_edit)
        })
        .unwrap_err();
        assert!(error.contains("revision conflict"));
        assert_eq!(
            first.index.notes[&original.id].note.body,
            "# Written elsewhere"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn note_updates_are_persisted_and_archived() {
        let path = temporary_vault("note");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "test passphrase").unwrap();
        let timestamp = now();
        let id = Uuid::new_v4().to_string();
        let original = NoteDocument {
            version: 1,
            id: id.clone(),
            path: "Inbox/First.md".into(),
            title: "First".into(),
            body: "# First\n\nLinks to [[Second]].".into(),
            aliases: vec![],
            tags: vec!["test".into()],
            properties: empty_object(),
            created_at: timestamp.clone(),
            updated_at: timestamp.clone(),
            revision: 1,
            frontmatter_source: None,
        };
        store_note(&mut session, original.clone(), None).unwrap();
        let mut updated = original.clone();
        updated.body.push_str("\n\nUpdated.");
        updated.revision = 2;
        updated.updated_at = now();
        store_note(&mut session, updated.clone(), Some(original)).unwrap();
        drop(session);

        let reopened = open_session(&path_text, "test passphrase").unwrap();
        assert_eq!(load_note(&reopened, &id).unwrap().body, updated.body);
        assert!(reopened
            .root_dir
            .join("history")
            .join(&id)
            .join("1.note.enc")
            .is_file());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn desktop_writes_the_shared_lookup_layout_without_forcing_a_cli_rebuild() {
        let path = temporary_vault("lookup-layout");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "lookup passphrase").unwrap();
        let mut note = seeded_note(
            "Projects/Ｒoadmap.md",
            "North Ｓtar",
            "# Direction\n\nSee [[Exposure]].",
        );
        note.aliases = vec!["Exposure".into()];
        store_note(&mut session, note.clone(), None).unwrap();

        assert_eq!(session.index.derived, DERIVED_LAYOUT);
        assert_eq!(
            session.index.path_owners["projects/roadmap"],
            [note.id.clone()]
        );
        assert_eq!(session.index.basename_owners["roadmap"], [note.id.clone()]);
        assert_eq!(session.index.name_owners["north star"], [note.id.clone()]);
        assert_eq!(session.index.name_owners["exposure"], [note.id.clone()]);
        assert_eq!(resolve_id(&session.index, "North Star").unwrap(), note.id);

        let payload: EncryptedPayload =
            serde_json::from_slice(&fs::read(session.root_dir.join("index.enc")).unwrap()).unwrap();
        let stored: Value =
            serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), INDEX_AAD).unwrap())
                .unwrap();
        assert_eq!(stored["derived"], DERIVED_LAYOUT);
        assert_eq!(stored["pathOwners"]["projects/roadmap"][0], note.id);
        for field in [
            "canvases",
            "canvasRefs",
            "canvasAttachmentRefs",
            "canvasPathOwners",
        ] {
            assert!(stored[field].is_object(), "missing shared field: {field}");
        }
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn canvas_text_links_follow_note_identity_changes_in_the_shared_index() {
        let path = temporary_vault("canvas-link-index");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "canvas link passphrase").unwrap();
        let original = seeded_note("Notes/Target.md", "Target", "# Target");
        store_note(&mut session, original.clone(), None).unwrap();
        let canvas = put_canvas(
            &mut session,
            CanvasInput {
                id: None,
                path: "Boards/Links".into(),
                title: None,
                nodes: vec![serde_json::json!({
                    "id": "text-1",
                    "type": "text",
                    "text": "[[Target]] and [[Missing]]",
                    "x": 0,
                    "y": 0,
                    "width": 240,
                    "height": 120
                })],
                edges: vec![],
                created_at: None,
                base_revision: None,
            },
        )
        .unwrap();

        let refs: HashMap<String, Vec<String>> =
            serde_json::from_value(session.index.extra["canvasRefs"].clone()).unwrap();
        assert_eq!(
            refs[&original.id].as_slice(),
            std::slice::from_ref(&canvas.id)
        );
        let canvases = indexed_canvases(&session).unwrap();
        assert_eq!(canvases[&canvas.id].unresolved[0].target, "Missing");

        let mut renamed = original.clone();
        renamed.path = "Notes/Renamed.md".into();
        renamed.title = "Renamed".into();
        renamed.revision = 2;
        renamed.updated_at = now();
        store_note(&mut session, renamed, Some(original.clone())).unwrap();

        let refs: HashMap<String, Vec<String>> =
            serde_json::from_value(session.index.extra["canvasRefs"].clone()).unwrap();
        assert!(!refs.contains_key(&original.id));
        let canvases = indexed_canvases(&session).unwrap();
        let unresolved: HashSet<_> = canvases[&canvas.id]
            .unresolved
            .iter()
            .map(|link| link.target.as_str())
            .collect();
        assert_eq!(unresolved, HashSet::from(["Target", "Missing"]));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn renaming_a_note_moves_it_and_rebinds_its_links() {
        let path = temporary_vault("rename");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "rename passphrase").unwrap();
        let target = seeded_note("Inbox/First.md", "First", "# First");
        let source = seeded_note("Inbox/Second.md", "Second", "Points at [[First]].");
        with_vault_write(&mut session, |session| {
            store_note(session, target.clone(), None)?;
            store_note(session, source.clone(), None)
        })
        .unwrap();
        assert_eq!(
            session.index.backlinks.get(&target.id),
            Some(&vec![source.id.clone()])
        );

        let renamed = with_vault_write(&mut session, |session| {
            rename_note_in(session, "First", "Archive/Renamed", Some("Renamed"))
        })
        .unwrap();
        assert_eq!(renamed.path, "Archive/Renamed.md");
        assert_eq!(renamed.title, "Renamed");
        assert_eq!(renamed.revision, target.revision + 1);
        assert_eq!(renamed.created_at, target.created_at);
        // The wikilink still says [[First]], so it no longer resolves.
        assert!(!session.index.backlinks.contains_key(&target.id));
        assert!(session.index.unresolved.contains_key(&source.id));
        assert!(resolve_id(&session.index, "Renamed").is_ok());
        assert!(session
            .root_dir
            .join("history")
            .join(&target.id)
            .join("1.note.enc")
            .is_file());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_rename_cannot_take_a_path_another_note_owns() {
        let path = temporary_vault("rename-collision");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "rename passphrase").unwrap();
        let first = seeded_note("Inbox/First.md", "First", "# First");
        let second = seeded_note("Inbox/Second.md", "Second", "# Second");
        with_vault_write(&mut session, |session| {
            store_note(session, first.clone(), None)?;
            store_note(session, second, None)
        })
        .unwrap();

        let error = with_vault_write(&mut session, |session| {
            rename_note_in(session, "First", "Inbox/Second.md", None)
        })
        .unwrap_err();
        assert!(error.contains("already exists"));
        assert_eq!(session.index.notes[&first.id].note.path, "Inbox/First.md");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_deleted_note_keeps_its_history_and_can_be_restored() {
        let path = temporary_vault("delete-restore");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "delete passphrase").unwrap();
        let original = seeded_note("Inbox/Draft.md", "Draft", "# Draft\n\nFirst pass.");
        with_vault_write(&mut session, |session| {
            store_note(session, original.clone(), None)
        })
        .unwrap();
        let mut edited = original.clone();
        edited.body = "# Draft\n\nSecond pass.".into();
        with_vault_write(&mut session, |session| save_existing_note(session, edited)).unwrap();

        let removed =
            with_vault_write(&mut session, |session| remove_note_in(session, "Draft")).unwrap();
        assert_eq!(removed.id, original.id);
        assert!(!session.index.notes.contains_key(&original.id));
        assert!(!note_path(&session.root_dir, &original.id).unwrap().exists());

        let deleted = deleted_notes(&session).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].id, original.id);
        assert_eq!(deleted[0].revision, 2);

        let revisions = archived_revisions(&session, &original.id).unwrap();
        assert_eq!(revisions, vec![1, 2]);

        let restored = with_vault_write(&mut session, |session| {
            restore_note_in(session, &original.id, 1)
        })
        .unwrap();
        assert_eq!(restored.body, "# Draft\n\nFirst pass.");
        assert_eq!(restored.revision, 3);
        assert!(deleted_notes(&session).unwrap().is_empty());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn history_lookups_reject_a_reference_that_is_not_an_id() {
        let path = temporary_vault("history-reference");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "history passphrase").unwrap();
        assert!(resolve_history_id(&session, "Nothing here").is_err());
        assert!(resolve_history_id(&session, "../escape").is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn local_date_tokens_are_matched_longest_first() {
        let date = Local
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(2026, 8, 30)
                    .unwrap()
                    .and_hms_opt(9, 5, 7)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(format_local_date(&date, "YYYY-MM-DD"), "2026-08-30");
        // MM is the month and mm is the minute, so a mixed pattern must not
        // collapse into one of them.
        assert_eq!(format_local_date(&date, "MM/DD HH:mm:ss"), "08/30 09:05:07");
        assert_eq!(format_local_date(&date, "Week YYYY"), "Week 2026");
    }

    #[test]
    fn a_template_renders_its_body_and_properties() {
        let path = temporary_vault("template");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "template passphrase").unwrap();
        let mut template = seeded_note(
            "Templates/Meeting.md",
            "Meeting",
            "# {{title}}\n\n{{date:YYYY-MM-DD}} with {{client}} — {{unknown}}",
        );
        template.tags = vec!["template".into(), "meeting".into()];
        template.properties = serde_json::json!({ "client": "{{client}}", "opened": "{{date}}" });
        with_vault_write(&mut session, |session| store_note(session, template, None)).unwrap();

        let created = with_vault_write(&mut session, |session| {
            create_from_template_in(
                session,
                TemplateRequest {
                    template: "Meeting",
                    path: "Meetings/Kickoff",
                    title: Some("Kickoff"),
                    date: parse_local_date(Some("2026-08-30")).unwrap(),
                    variables: HashMap::from([("client".to_string(), "Acme".to_string())]),
                    tags: Vec::new(),
                    properties: serde_json::Map::new(),
                },
            )
        })
        .unwrap();

        assert_eq!(created.path, "Meetings/Kickoff.md");
        assert_eq!(created.title, "Kickoff");
        assert_eq!(
            created.body,
            "# Kickoff\n\n2026-08-30 with Acme — {{unknown}}"
        );
        assert_eq!(created.properties["client"], "Acme");
        assert_eq!(created.properties["opened"], "2026-08-30");
        // The marker tag stays on the template; the rest comes along.
        assert_eq!(created.tags, vec!["meeting".to_string()]);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn the_daily_note_is_created_once_and_then_opened() {
        let path = temporary_vault("daily");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "daily passphrase").unwrap();

        let first = with_vault_write(&mut session, |session| {
            open_daily_note_in(session, Some("2026-08-30"), Some("Journal"), None)
        })
        .unwrap();
        assert!(first.created);
        assert_eq!(first.note.path, "Journal/2026-08-30.md");
        assert_eq!(first.note.tags, vec!["daily".to_string()]);
        assert_eq!(first.note.properties["date"], "2026-08-30");

        let second = with_vault_write(&mut session, |session| {
            open_daily_note_in(session, Some("2026-08-30"), Some("Journal"), None)
        })
        .unwrap();
        assert!(!second.created);
        assert_eq!(second.note.id, first.note.id);
        assert_eq!(second.note.revision, first.note.revision);
        assert_eq!(session.index.notes.len(), 1);

        // A calendar day that does not exist and a wrong layout are both
        // rejected before anything is written.
        for rejected in ["2026-02-30", "30-08-2026"] {
            let error = with_vault_write(&mut session, |session| {
                open_daily_note_in(session, Some(rejected), None, None)
            })
            .unwrap_err();
            assert!(error.contains("YYYY-MM-DD"), "unexpected error: {error}");
        }
        assert_eq!(session.index.notes.len(), 1);
        fs::remove_dir_all(path).unwrap();
    }

    fn seeded_manifest(capabilities: &[&str]) -> PluginManifest {
        PluginManifest {
            manifest_version: 1,
            id: "word-count".into(),
            name: "Word count".into(),
            version: "1.0.0".into(),
            description: "Counts words".into(),
            author: "someone".into(),
            capabilities: capabilities.iter().map(|value| value.to_string()).collect(),
            signature: None,
        }
    }

    /// The desktop sandbox enforces the TypeScript table at call time; this
    /// core refuses an unknown capability at install time. Both have to name
    /// the same set, or a plugin could be installed here describing a reach the
    /// runtime cannot enforce — or refused here for a capability that works.
    #[test]
    fn plugin_capabilities_match_the_typescript_core() {
        let source = fs::read_to_string("../src/plugins.ts").expect("read src/plugins.ts");
        let start = source
            .find("export const PLUGIN_CAPABILITIES = [")
            .expect("PLUGIN_CAPABILITIES not found");
        let body = &source[start..];
        let end = body
            .find("] as const;")
            .expect("unterminated capability list");
        let listed: Vec<String> = body[..end]
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim().trim_end_matches(',');
                trimmed
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .map(|value| value.to_string())
            })
            .collect();
        assert_eq!(listed, PLUGIN_CAPABILITIES.to_vec());
    }

    fn typescript_signed_manifest() -> PluginManifest {
        PluginManifest {
            manifest_version: 1,
            id: "word-count".into(),
            name: "Word count".into(),
            version: "1.0.0".into(),
            description: "Counts words in the open note".into(),
            author: "someone".into(),
            capabilities: vec!["notes:read".into(), "ui:panel".into()],
            // Produced by `signPluginPackage` with a deterministic 32-byte
            // seed. This pins the byte format across the two implementations.
            signature: Some("ed25519:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw:77BlVonLJQ9XJTmBnF3A3kW4Jj1IExU-5DuxgfI-opQFMqdXNCZOJuOwZ4Uim_sv7LevQsrkIjwHKHwuQhy8CA".into()),
        }
    }

    #[test]
    fn a_typescript_signed_package_verifies_in_the_rust_core() {
        let manifest = validate_plugin_manifest(typescript_signed_manifest()).unwrap();
        let verified = verify_plugin_signature(&manifest, "verified")
            .unwrap()
            .unwrap();
        assert_eq!(verified.algorithm, "ed25519");
        assert_eq!(
            verified.key_id,
            "fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889"
        );
        assert!(verify_plugin_signature(&manifest, "changed").is_err());
    }

    #[test]
    fn restricted_mode_and_revocation_block_plugins_at_the_rust_boundary() {
        let path = temporary_vault("plugin-policy");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "plugin policy passphrase").unwrap();
        let mut policy = PluginSecurityPolicy {
            restricted_mode: true,
            ..PluginSecurityPolicy::default()
        };
        save_plugin_policy(&session, &policy).unwrap();

        let unsigned = with_vault_write(&mut session, |session| {
            install_plugin_in(session, seeded_manifest(&[]), "unsigned".into(), None)
        })
        .unwrap_err();
        assert!(unsigned.contains("signed plugins only"));

        let installed = with_vault_write(&mut session, |session| {
            install_plugin_in(
                session,
                typescript_signed_manifest(),
                "verified".into(),
                Some(true),
            )
        })
        .unwrap();
        assert_eq!(installed.signature_status, "verified");
        assert!(installed.enabled);

        policy
            .revoked_signers
            .push(installed.signer.clone().unwrap());
        save_plugin_policy(&session, &policy).unwrap();
        let plugin = load_plugin(&session, &installed.id).unwrap();
        assert!(!plugin_allowed(
            &plugin,
            &load_plugin_policy(&session).unwrap()
        ));
        let blocked = with_vault_write(&mut session, |session| {
            set_plugin_enabled_in(session, &installed.id, true)
        })
        .unwrap_err();
        assert!(blocked.contains("blocked"));
        assert_eq!(
            summarize_plugin(&plugin, &policy).signature_status,
            "revoked"
        );

        drop(session);
        let reopened = open_session(&path_text, "plugin policy passphrase").unwrap();
        assert_eq!(
            load_plugin_policy(&reopened).unwrap().revoked_signers.len(),
            1
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_plugin_round_trips_encrypted_and_starts_disabled() {
        let path = temporary_vault("plugin");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "plugin passphrase").unwrap();
        let source = "vbrain.ui.panel('Words', '12');".to_string();

        let installed = with_vault_write(&mut session, |session| {
            install_plugin_in(
                session,
                seeded_manifest(&["notes:read", "ui:panel"]),
                source.clone(),
                None,
            )
        })
        .unwrap();

        assert!(!installed.enabled, "a new plugin never runs unasked");
        assert_eq!(installed.revision, 1);
        assert_eq!(installed.manifest_id, "word-count");
        assert_eq!(installed.source_bytes, source.len());

        let object =
            fs::read_to_string(plugin_object_path(&session.root_dir, &installed.id).unwrap())
                .unwrap();
        assert!(
            !object.contains("ui.panel"),
            "plugin code is encrypted at rest"
        );
        assert!(!object.contains("Word count"));

        let enabled = with_vault_write(&mut session, |session| {
            set_plugin_enabled_in(session, "word-count", true)
        })
        .unwrap();
        assert!(enabled.enabled);

        drop(session);
        let reopened = open_session(&path_text, "plugin passphrase").unwrap();
        let loaded = load_plugin(&reopened, &installed.id).unwrap();
        assert_eq!(loaded.source, source);
        assert!(loaded.enabled);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn an_unknown_capability_is_refused_rather_than_trimmed() {
        let error =
            validate_plugin_manifest(seeded_manifest(&["notes:read", "network:all"])).unwrap_err();
        assert!(error.contains("network:all"), "unexpected error: {error}");

        for broken in [
            PluginManifest {
                id: "Word Count".into(),
                ..seeded_manifest(&[])
            },
            PluginManifest {
                version: "one".into(),
                ..seeded_manifest(&[])
            },
            PluginManifest {
                manifest_version: 2,
                ..seeded_manifest(&[])
            },
            PluginManifest {
                name: " ".into(),
                ..seeded_manifest(&[])
            },
        ] {
            assert!(validate_plugin_manifest(broken).is_err());
        }

        // A duplicate collapses, and the id is normalized rather than rejected.
        let parsed = validate_plugin_manifest(PluginManifest {
            id: "WORD-COUNT".into(),
            ..seeded_manifest(&["notes:read", "notes:read"])
        })
        .unwrap();
        assert_eq!(parsed.id, "word-count");
        assert_eq!(parsed.capabilities, vec!["notes:read".to_string()]);
    }

    #[test]
    fn removing_a_plugin_takes_its_settings_with_it() {
        let path = temporary_vault("plugin-remove");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "plugin passphrase").unwrap();
        let installed = with_vault_write(&mut session, |session| {
            install_plugin_in(session, seeded_manifest(&["storage"]), "// s".into(), None)
        })
        .unwrap();

        let mut settings = HashMap::new();
        settings.insert("lastRun".to_string(), "2026-08-31".to_string());
        write_plugin_storage(&session, &installed.id, &settings).unwrap();
        assert_eq!(
            read_plugin_storage(&session, &installed.id).unwrap(),
            settings
        );

        let store = plugin_store_path(&session.root_dir, &installed.id).unwrap();
        assert!(!fs::read_to_string(&store).unwrap().contains("2026-08-31"));

        with_vault_write(&mut session, |session| {
            remove_plugin_in(session, "word-count")
        })
        .unwrap();

        assert!(!store.exists(), "settings do not outlive the plugin");
        assert!(indexed_plugins(&session).unwrap().is_empty());
        assert!(resolve_plugin_id(&session, "word-count").is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_plugin_object_cannot_be_read_as_a_note() {
        let path = temporary_vault("plugin-confusion");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "plugin passphrase").unwrap();
        let installed = with_vault_write(&mut session, |session| {
            install_plugin_in(session, seeded_manifest(&[]), "// s".into(), None)
        })
        .unwrap();

        // The AAD names the object type, so opening one as another fails GCM
        // authentication rather than needing a check that could be forgotten.
        assert!(load_note(&session, &installed.id).is_err());
        assert!(load_canvas(&session, &installed.id).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn an_interrupted_plugin_write_is_recovered_on_unlock() {
        let path = temporary_vault("plugin-journal");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "plugin passphrase").unwrap();
        let installed = with_vault_write(&mut session, |session| {
            install_plugin_in(session, seeded_manifest(&[]), "// s".into(), None)
        })
        .unwrap();

        // Simulate a crash between the object write and the index write: drop
        // the listing, then leave the journal behind as the write would have.
        session.index.extra.remove("plugins");
        save_index(&mut session).unwrap();
        begin_plugin_journal(&session, &installed.id).unwrap();
        drop(session);

        let reopened = open_session(&path_text, "plugin passphrase").unwrap();

        let plugins = indexed_plugins(&reopened).unwrap();
        assert_eq!(
            plugins.len(),
            1,
            "unlock rebuilds the listing from the objects"
        );
        assert_eq!(plugins[&installed.id].manifest_id, "word-count");
        assert!(!journal_path(&reopened).exists());
        fs::remove_dir_all(path).unwrap();
    }

    fn seeded_note(path: &str, title: &str, body: &str) -> NoteDocument {
        let timestamp = now();
        NoteDocument {
            version: 1,
            id: Uuid::new_v4().to_string(),
            path: path.into(),
            title: title.into(),
            body: body.into(),
            aliases: vec![],
            tags: vec![],
            properties: empty_object(),
            created_at: timestamp.clone(),
            updated_at: timestamp,
            revision: 1,
            frontmatter_source: None,
        }
    }

    fn edge(source: &str, target: &str) -> GraphEdge {
        GraphEdge {
            source: source.into(),
            target: target.into(),
        }
    }

    #[test]
    fn communities_are_deterministic_and_keep_disjoint_groups_apart() {
        let ids: Vec<String> = (0..6).map(|index| format!("n{index}")).collect();
        // Two triangles with no link between them.
        let edges = vec![
            edge("n0", "n1"),
            edge("n1", "n2"),
            edge("n2", "n0"),
            edge("n3", "n4"),
            edge("n4", "n5"),
            edge("n5", "n3"),
        ];
        let first = cluster_nodes(&ids, &edges);
        assert_eq!(
            first,
            cluster_nodes(&ids, &edges),
            "clustering must not drift between runs"
        );
        assert_eq!(first["n0"], first["n1"]);
        assert_eq!(first["n0"], first["n2"]);
        assert_eq!(first["n3"], first["n4"]);
        assert_eq!(first["n3"], first["n5"]);
        assert_ne!(
            first["n0"], first["n3"],
            "unlinked groups must not share a community"
        );
    }

    #[test]
    fn unlinked_notes_get_their_own_community_and_the_largest_is_numbered_first() {
        let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let clusters = cluster_nodes(&ids, &[edge("a", "b")]);
        assert_eq!(clusters["a"], clusters["b"]);
        assert_ne!(clusters["c"], clusters["a"]);
        assert_eq!(clusters["a"], 0);
        assert_eq!(clusters["c"], 1);
    }

    #[test]
    fn the_graph_clusters_linked_notes_and_counts_their_degree() {
        let path = temporary_vault("graph");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "graph passphrase").unwrap();

        let first = seeded_note("Atlas/First.md", "First", "# First\n\nSee [[Second]].");
        let second = seeded_note(
            "Atlas/Second.md",
            "Second",
            "# Second\n\nBack to [[First]].",
        );
        let lonely = seeded_note("Atlas/Lonely.md", "Lonely", "# Lonely\n\nNo links here.");
        for note in [&first, &second, &lonely] {
            store_note(&mut session, note.clone(), None).unwrap();
        }

        let graph = build_graph(&session.index);
        let cluster_of = |id: &str| {
            graph
                .nodes
                .iter()
                .find(|node| node.id == id)
                .unwrap()
                .cluster
        };
        let degree_of = |id: &str| {
            graph
                .nodes
                .iter()
                .find(|node| node.id == id)
                .unwrap()
                .degree
        };
        assert_eq!(cluster_of(&first.id), cluster_of(&second.id));
        assert_ne!(cluster_of(&lonely.id), cluster_of(&first.id));
        assert_eq!(degree_of(&lonely.id), 0);
        assert!(degree_of(&first.id) >= 1);
        assert!(
            graph
                .nodes
                .windows(2)
                .all(|pair| pair[0].path <= pair[1].path),
            "nodes ship in a stable order"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn saved_views_round_trip_encrypted_and_refuse_nameless_entries() {
        let path = temporary_vault("views");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "view passphrase").unwrap();
        assert!(
            load_saved_views(&session).unwrap().is_empty(),
            "a fresh vault has no saved views"
        );

        let view = normalize_view(
            SavedView {
                id: String::new(),
                name: "  Open questions  ".into(),
                filter: "status".into(),
                tags: vec!["research".into()],
                sort: "status".into(),
                direction: "sideways".into(),
                columns: vec!["status".into()],
                created_at: String::new(),
                updated_at: String::new(),
            },
            &[],
        )
        .unwrap();
        assert_eq!(view.name, "Open questions");
        assert_eq!(
            view.direction, "asc",
            "an unknown direction falls back to ascending"
        );
        assert!(!view.id.is_empty(), "a new view is given an ID");

        write_saved_views(&session, std::slice::from_ref(&view)).unwrap();
        let raw = fs::read(saved_views_path(&session)).unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("Open questions"),
            "saved views must never hit disk in the clear"
        );
        drop(session);

        let reopened = open_session(&path_text, "view passphrase").unwrap();
        let stored = load_saved_views(&reopened).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "Open questions");

        let mut nameless = view.clone();
        nameless.name = "   ".into();
        assert!(normalize_view(nameless, &stored).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn editing_one_property_archives_the_previous_revision_and_leaves_the_body_alone() {
        let path = temporary_vault("property");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "property passphrase").unwrap();
        let note = seeded_note(
            "Atlas/Tracked.md",
            "Tracked",
            "# Tracked\n\nBody stays put.",
        );
        store_note(&mut session, note.clone(), None).unwrap();

        let row = set_property(
            &mut session,
            &note.id,
            " status ",
            Some(Value::String("living".into())),
        )
        .unwrap();
        assert_eq!(row.properties["status"], Value::String("living".into()));

        let reloaded = load_note(&session, &note.id).unwrap();
        assert_eq!(reloaded.revision, 2);
        assert_eq!(
            reloaded.body, note.body,
            "a cell edit must not rewrite the note body"
        );
        assert!(session
            .root_dir
            .join("history")
            .join(&note.id)
            .join("1.note.enc")
            .is_file());

        let cleared = set_property(&mut session, &note.id, "status", None).unwrap();
        assert!(
            cleared.properties.get("status").is_none(),
            "passing no value deletes the property"
        );
        assert!(set_property(&mut session, &note.id, "   ", Some(Value::Bool(true))).is_err());
        assert!(set_property(
            &mut session,
            "Atlas/Missing.md",
            "status",
            Some(Value::Bool(true))
        )
        .is_err());
        fs::remove_dir_all(path).unwrap();
    }

    fn mention_vault(label: &str) -> (PathBuf, VaultSession, NoteDocument, NoteDocument) {
        let path = temporary_vault(label);
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "mention passphrase").unwrap();

        let mut target = seeded_note(
            "Atlas/Least exposure.md",
            "Least exposure",
            "# Least exposure\n\nThe principle itself.",
        );
        target.aliases = vec!["Exposure".into()];
        let mentioning = seeded_note(
            "Atlas/Notes.md",
            "Notes",
            "Least exposure matters here. See also least exposure again later on.",
        );
        let partial = seeded_note(
            "Atlas/Partial.md",
            "Partial",
            "Least exposures is a different word entirely.",
        );
        let linking = seeded_note(
            "Atlas/Linked.md",
            "Linked",
            "Already points at [[Least exposure]] the proper way.",
        );
        for note in [&target, &mentioning, &partial, &linking] {
            store_note(&mut session, note.clone(), None).unwrap();
        }
        (path, session, target, mentioning)
    }

    #[test]
    fn unlinked_mentions_skip_links_backlinks_and_partial_words() {
        let (path, session, target, _) = mention_vault("mentions");
        let mentions = unlinked_mentions(&session.index, &target.id);

        let titles: Vec<_> = mentions
            .iter()
            .map(|mention| mention.note.title.as_str())
            .collect();
        assert_eq!(titles, vec!["Notes"], "only the plain-text mention counts");
        assert_eq!(
            mentions[0].name, "Least exposure",
            "the longest matching name wins"
        );
        assert_eq!(mentions[0].count, 2);
        assert!(mentions[0].excerpt.contains("Least exposure matters here"));

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn linking_a_mention_rewrites_the_text_and_keeps_the_writer_s_wording() {
        let (path, mut session, target, mentioning) = mention_vault("link-mention");
        assert_eq!(
            link_mention(&mut session, &mentioning.id, &target.id).unwrap(),
            2
        );

        let updated = load_note(&session, &mentioning.id).unwrap();
        assert!(updated.body.contains("[[Least exposure]] matters here"));
        assert!(
            updated
                .body
                .contains("[[Least exposure|least exposure]] again"),
            "lower-case wording survives as an alias link"
        );
        assert_eq!(updated.revision, 2);
        assert!(session
            .root_dir
            .join("history")
            .join(&mentioning.id)
            .join("1.note.enc")
            .is_file());
        assert!(
            unlinked_mentions(&session.index, &target.id).is_empty(),
            "a linked note is a backlink, not a mention"
        );
        assert!(
            link_mention(&mut session, &mentioning.id, &target.id).is_err(),
            "nothing left to link"
        );

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn notes_reject_blank_or_multiline_aliases() {
        let path = temporary_vault("aliases");
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "alias passphrase").unwrap();
        let note = seeded_note("Atlas/Named.md", "Named", "# Named\n\nBody.");

        for bad in ["   ", "line\nbreak", "line\rbreak"] {
            let mut broken = note.clone();
            broken.aliases = vec![bad.into()];
            assert!(
                store_note(&mut session, broken, None).is_err(),
                "accepted bad alias: {bad:?}"
            );
        }
        let mut tagged = note.clone();
        tagged.tags = vec![" ".into()];
        assert!(store_note(&mut session, tagged, None).is_err());

        let mut good = note.clone();
        good.aliases = vec!["North star".into()];
        assert!(store_note(&mut session, good, None).is_ok());

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn workspace_state_round_trips_encrypted_and_refuses_a_nameless_layout() {
        let path = temporary_vault("workspace");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "workspace passphrase").unwrap();
        assert!(load_workspace(&session).unwrap().bookmarks.is_empty());

        let state = normalize_workspace(
            WorkspaceState {
                version: 1,
                bookmarks: vec![
                    Bookmark {
                        id: "note-a".into(),
                        label: "  Principles  ".into(),
                        created_at: String::new(),
                    },
                    Bookmark {
                        id: "note-a".into(),
                        label: "Duplicate".into(),
                        created_at: String::new(),
                    },
                ],
                layouts: vec![WorkspaceLayout {
                    id: String::new(),
                    name: "  Morning review  ".into(),
                    tabs: vec!["note-a".into()],
                    active: Some("note-a".into()),
                    secondary: None,
                    view: "notes".into(),
                    created_at: String::new(),
                    updated_at: String::new(),
                }],
            },
            &WorkspaceState::empty(),
        )
        .unwrap();
        assert_eq!(state.bookmarks.len(), 1, "a note is bookmarked once");
        assert_eq!(state.bookmarks[0].label, "Principles");
        assert_eq!(state.layouts[0].name, "Morning review");
        assert!(!state.layouts[0].id.is_empty());

        write_workspace(&session, &state).unwrap();
        let raw = fs::read(workspace_path(&session)).unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("Morning review"),
            "workspace names must not hit disk in the clear"
        );
        drop(session);

        let reopened = open_session(&path_text, "workspace passphrase").unwrap();
        let stored = load_workspace(&reopened).unwrap();
        assert_eq!(stored.layouts.len(), 1);
        assert_eq!(stored.layouts[0].tabs, vec!["note-a".to_string()]);

        let mut nameless = stored.clone();
        nameless.layouts[0].name = "  ".into();
        assert!(normalize_workspace(nameless, &stored).is_err());

        fs::remove_dir_all(path).unwrap();
    }

    fn attachment_session(label: &str) -> (PathBuf, VaultSession) {
        let path = temporary_vault(label);
        let session = open_session(&path.to_string_lossy(), "attachment passphrase").unwrap();
        (path, session)
    }

    /// 1 MiB plus a remainder, so the chunk loop has to handle a short tail.
    fn spanning_bytes() -> Vec<u8> {
        let mut data = vec![0x5au8; ATTACHMENT_CHUNK_SIZE + 137];
        data[..25].copy_from_slice(b"private attachment prefix");
        data
    }

    fn files_in(dir: &Path) -> Vec<PathBuf> {
        let mut paths: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        paths.sort();
        paths
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    #[test]
    fn attachments_deduplicate_by_content_and_chunk_at_one_mebibyte() {
        let (path, session) = attachment_session("attachment-round-trip");
        let data = spanning_bytes();

        let first = put_attachment(
            &session,
            &data,
            "  private-report.bin  ",
            "APPLICATION/Octet-Stream",
        )
        .unwrap();
        assert_eq!(
            first.chunks, 2,
            "a 1 MiB + 137 byte payload spans two chunks"
        );
        assert_eq!(first.size, data.len());
        assert_eq!(
            first.filename, "private-report.bin",
            "the stored filename is trimmed"
        );
        assert_eq!(
            first.mime, "application/octet-stream",
            "the stored MIME type is lowercased"
        );

        let duplicate =
            put_attachment(&session, &data, "a-different-name.bin", "text/plain").unwrap();
        assert_eq!(
            duplicate.id, first.id,
            "identical bytes address the same attachment"
        );
        assert_eq!(
            duplicate.filename, first.filename,
            "the first manifest wins; the bytes are not rewritten"
        );

        let (info, restored) = get_attachment(&session, &first.id).unwrap();
        assert_eq!(info.id, first.id);
        assert_eq!(restored, data);

        let listed = load_attachments(&session).unwrap();
        assert_eq!(
            listed.len(),
            1,
            "the duplicate did not create a second attachment"
        );
        assert_eq!(listed[0].id, first.id);

        let dir = attachment_dir(&session.root_dir, &first.id).unwrap();
        assert!(dir.join("0.chunk.enc").is_file());
        assert!(dir.join("1.chunk.enc").is_file());
        assert!(dir.join("manifest.enc").is_file());

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn neither_attachment_bytes_nor_their_filename_reach_disk_in_the_clear() {
        let (path, session) = attachment_session("attachment-secrecy");
        let info = put_attachment(
            &session,
            &spanning_bytes(),
            "private-report.bin",
            "application/octet-stream",
        )
        .unwrap();

        let dir = attachment_dir(&session.root_dir, &info.id).unwrap();
        let on_disk: String = files_in(&dir)
            .iter()
            .map(|file| String::from_utf8_lossy(&fs::read(file).unwrap()).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !on_disk.contains("private attachment prefix"),
            "attachment bytes must be encrypted"
        );
        assert!(
            !on_disk.contains("private-report.bin"),
            "the filename lives in the encrypted manifest"
        );
        assert!(
            !on_disk.contains("application/octet-stream"),
            "the MIME type lives in the encrypted manifest"
        );

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn chunks_and_manifests_are_bound_to_the_attachment_they_belong_to() {
        let (path, session) = attachment_session("attachment-binding");
        let spanning = put_attachment(
            &session,
            &spanning_bytes(),
            "spanning.bin",
            "application/octet-stream",
        )
        .unwrap();
        let other = put_attachment(
            &session,
            b"a second attachment",
            "other.bin",
            "application/octet-stream",
        )
        .unwrap();
        let dir = attachment_dir(&session.root_dir, &spanning.id).unwrap();

        let first_chunk = fs::read(dir.join("0.chunk.enc")).unwrap();
        let second_chunk = fs::read(dir.join("1.chunk.enc")).unwrap();
        fs::write(dir.join("0.chunk.enc"), &second_chunk).unwrap();
        fs::write(dir.join("1.chunk.enc"), &first_chunk).unwrap();
        assert!(
            get_attachment(&session, &spanning.id).is_err(),
            "a chunk authenticates its own index"
        );
        fs::write(dir.join("0.chunk.enc"), &first_chunk).unwrap();
        fs::write(dir.join("1.chunk.enc"), &second_chunk).unwrap();
        assert!(
            get_attachment(&session, &spanning.id).is_ok(),
            "restoring the order restores the attachment"
        );

        let mut payload: EncryptedPayload = serde_json::from_slice(&first_chunk).unwrap();
        payload.ciphertext = BASE64.encode(b"substituted ciphertext");
        fs::write(
            dir.join("0.chunk.enc"),
            serde_json::to_vec(&payload).unwrap(),
        )
        .unwrap();
        assert!(
            get_attachment(&session, &spanning.id).is_err(),
            "a tampered chunk fails authentication"
        );

        let other_dir = attachment_dir(&session.root_dir, &other.id).unwrap();
        fs::copy(other_dir.join("manifest.enc"), dir.join("manifest.enc")).unwrap();
        assert!(
            read_attachment_manifest(&session, &spanning.id).is_err(),
            "a manifest authenticates the attachment ID it was written for"
        );

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn a_missing_chunk_is_reported_instead_of_returning_a_short_file() {
        let (path, session) = attachment_session("attachment-missing-chunk");
        let info = put_attachment(
            &session,
            &spanning_bytes(),
            "spanning.bin",
            "application/octet-stream",
        )
        .unwrap();
        fs::remove_file(
            attachment_dir(&session.root_dir, &info.id)
                .unwrap()
                .join("1.chunk.enc"),
        )
        .unwrap();

        let error = get_attachment(&session, &info.id).unwrap_err();
        assert!(
            error.contains("missing attachment chunk 1"),
            "unexpected error: {error}"
        );

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn attachment_inputs_reject_empty_bytes_unusable_names_and_malformed_mime_types() {
        let (path, session) = attachment_session("attachment-validation");
        assert!(put_attachment(&session, b"", "empty.bin", "application/octet-stream").is_err());
        for name in ["", "   ", "line\nbreak.bin", "nul\0byte.bin"] {
            assert!(
                put_attachment(&session, b"payload", name, "application/octet-stream").is_err(),
                "accepted unusable filename: {name:?}"
            );
        }
        for mime in [
            "",
            "application",
            "application/",
            "/octet-stream",
            "application/octet stream",
            "app;lication/x",
        ] {
            assert!(
                put_attachment(&session, b"payload", "file.bin", mime).is_err(),
                "accepted malformed MIME type: {mime:?}"
            );
        }
        assert!(
            put_attachment(&session, b"payload", &"a".repeat(256), "text/plain").is_err(),
            "filenames are bounded"
        );
        assert!(put_attachment(&session, b"payload", &"a".repeat(255), "text/plain").is_ok());

        for id in [
            "",
            "../../escape",
            "ATTACHMENT",
            &"g".repeat(64),
            &"a".repeat(63),
        ] {
            assert!(
                attachment_dir(&session.root_dir, id).is_err(),
                "accepted unsafe attachment ID: {id:?}"
            );
        }
        assert!(
            get_attachment(&session, &"a".repeat(64)).is_err(),
            "an unknown attachment is not found"
        );

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn removing_an_attachment_takes_every_chunk_with_it() {
        let (path, session) = attachment_session("attachment-removal");
        let info = put_attachment(
            &session,
            &spanning_bytes(),
            "spanning.bin",
            "application/octet-stream",
        )
        .unwrap();
        let dir = attachment_dir(&session.root_dir, &info.id).unwrap();

        assert_eq!(remove_attachment(&session, &info.id).unwrap().id, info.id);
        assert!(!dir.exists(), "the whole attachment directory is gone");
        assert!(load_attachments(&session).unwrap().is_empty());
        assert!(
            remove_attachment(&session, &info.id).is_err(),
            "removing twice reports the attachment is gone"
        );

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    /// The cross-implementation gate: this attachment was written by the
    /// TypeScript core (`scripts/make-fixtures.mjs`). If the Rust core drifts on
    /// the ID derivation, the AAD strings, the chunk layout or the manifest
    /// fields, it can no longer open what the CLI wrote — and this fails.
    #[test]
    fn an_attachment_written_by_the_typescript_core_still_opens() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("test")
            .join("fixtures")
            .join("documents-attachments-v1");
        assert!(fixture.is_dir(), "missing fixture: {}", fixture.display());

        let path = temporary_vault("attachment-fixture");
        copy_tree(&fixture, &path);
        let session = open_session(&path.to_string_lossy(), "fixture-only-passphrase").unwrap();

        let listed = load_attachments(&session).unwrap();
        assert_eq!(listed.len(), 2, "the fixture ships two attachments");
        assert_eq!(listed[0].filename, "frozen-note.txt");
        assert_eq!(listed[0].mime, "text/plain");
        assert_eq!(listed[1].filename, "frozen-payload.bin");
        assert_eq!(listed[1].mime, "application/octet-stream");

        let (info, text) = get_attachment(&session, &listed[0].id).unwrap();
        assert_eq!(info.chunks, 1);
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "This attachment was written by the TypeScript core and must stay readable.\n"
        );

        let (binary_info, binary) = get_attachment(&session, &listed[1].id).unwrap();
        assert_eq!(binary.len(), binary_info.size);
        assert_eq!(binary, (0u8..=255).cycle().take(4096).collect::<Vec<u8>>());

        // Content addressing only works if both cores derive the same ID, so
        // recompute it here rather than trusting the directory name.
        assert_eq!(
            attachment_id(session.attachment_id_key.as_ref(), &binary).unwrap(),
            binary_info.id
        );

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }
}
