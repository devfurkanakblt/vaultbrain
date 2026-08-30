use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
const INDEX_AAD: &str = "secondbrain-vault:document-index:v1";
const KEY_CHECK_CONTEXT: &str = "secondbrain-vault:document-key:v1";
const MAX_NOTE_BYTES: usize = 25 * 1024 * 1024;
const SAVED_VIEWS_AAD: &str = "secondbrain-vault:saved-views:v1";
const MAX_SAVED_VIEWS: usize = 200;
const MAX_CLUSTER_ROUNDS: usize = 20;
const WORKSPACE_AAD: &str = "secondbrain-vault:workspace:v1";
const MAX_BOOKMARKS: usize = 500;
const MAX_LAYOUTS: usize = 100;
const MAX_MENTIONS: usize = 50;

#[derive(Default)]
struct AppState {
    session: Mutex<Option<VaultSession>>,
}

struct VaultSession {
    vault_dir: PathBuf,
    root_dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
    index: DocumentIndex,
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
}

impl DocumentIndex {
    fn empty() -> Self {
        Self {
            version: 2,
            generated_at: now(),
            notes: HashMap::new(),
            backlinks: HashMap::new(),
            resolved_links: HashMap::new(),
            unresolved: HashMap::new(),
            link_sources: HashMap::new(),
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
        Self { version: 1, bookmarks: vec![], layouts: vec![] }
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

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
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
    let iv = BASE64.decode(&payload.iv).map_err(|_| "invalid payload IV")?;
    let tag = BASE64.decode(&payload.auth_tag).map_err(|_| "invalid authentication tag")?;
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

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("target has no parent directory")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    reject_symlink(path)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("vault"),
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
    let destination_wide: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
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

fn reject_symlink(path: &Path) -> Result<(), String> {
    if path.exists() && fs::symlink_metadata(path).map_err(|error| error.to_string())?.file_type().is_symlink() {
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
        || value.chars().any(|character| character == '\0' || character.is_control())
        || value.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("invalid logical Markdown path".into());
    }
    Ok(value)
}

fn load_note(session: &VaultSession, id: &str) -> Result<NoteDocument, String> {
    let path = note_path(&session.root_dir, id)?;
    reject_symlink(&path)?;
    let payload: EncryptedPayload = serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let note: NoteDocument = serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), &note_aad(id))?)
        .map_err(|error| error.to_string())?;
    if note.id != id || note.version != 1 {
        return Err("note identity check failed".into());
    }
    Ok(note)
}

fn save_index(session: &mut VaultSession) -> Result<(), String> {
    session.index.version = 2;
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
    write_atomic(&path, &serde_json::to_vec(&payload).map_err(|error| error.to_string())?)
}

fn analyze_markdown(body: &str) -> Result<(Vec<WikiLink>, Vec<Heading>), String> {
    let link_re = Regex::new(r"(!)?\[\[([^\]|#^]+)(?:#([^\]|^]+))?(?:\^([^\]|]+))?(?:\|([^\]]+))?\]\]")
        .map_err(|error| error.to_string())?;
    let heading_re = Regex::new(r"(?m)^(#{1,6})\s+(.+?)\s*#*$").map_err(|error| error.to_string())?;
    let links = link_re
        .captures_iter(body)
        .map(|capture| WikiLink {
            raw: capture.get(0).map(|value| value.as_str()).unwrap_or_default().to_string(),
            target: capture.get(2).map(|value| value.as_str().trim()).unwrap_or_default().to_string(),
            heading: capture.get(3).map(|value| value.as_str().trim().to_string()),
            block_ref: capture.get(4).map(|value| value.as_str().trim().to_string()),
            alias: capture.get(5).map(|value| value.as_str().trim().to_string()),
            embed: capture.get(1).is_some(),
        })
        .collect();
    let headings = heading_re
        .captures_iter(body)
        .map(|capture| {
            let text = capture.get(2).map(|value| value.as_str()).unwrap_or_default().to_string();
            Heading {
                level: capture.get(1).map(|value| value.as_str().len()).unwrap_or(1),
                slug: text
                    .to_lowercase()
                    .chars()
                    .map(|character| if character.is_alphanumeric() { character } else { '-' })
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

fn normalized(value: &str) -> String {
    value.trim().trim_end_matches(".md").to_lowercase()
}

fn resolve_link(index: &DocumentIndex, link: &WikiLink) -> Option<String> {
    let target = normalized(&link.target);
    if let Some(note) = index.notes.values().find(|note| normalized(&note.note.path) == target) {
        return Some(note.note.id.clone());
    }
    let candidates: Vec<_> = index
        .notes
        .values()
        .filter(|note| {
            let basename = note.note.path.rsplit('/').next().unwrap_or(&note.note.path);
            normalized(&note.note.title) == target
                || normalized(basename) == target
                || note.note.aliases.iter().any(|alias| normalized(alias) == target)
        })
        .collect();
    (candidates.len() == 1).then(|| candidates[0].note.id.clone())
}

fn rebuild_derived(index: &mut DocumentIndex) {
    index.backlinks.clear();
    index.resolved_links.clear();
    index.unresolved.clear();
    index.link_sources.clear();
    let ids: Vec<String> = index.notes.keys().cloned().collect();
    for id in &ids {
        if let Some(note) = index.notes.get(id) {
            for link in &note.links {
                let sources = index.link_sources.entry(normalized(&link.target)).or_default();
                if !sources.contains(id) {
                    sources.push(id.clone());
                }
            }
        }
    }
    for id in ids {
        let links = index.notes.get(&id).map(|note| note.links.clone()).unwrap_or_default();
        let resolved: Vec<Option<String>> = links.iter().map(|link| resolve_link(index, link)).collect();
        let unresolved: Vec<WikiLink> = links
            .iter()
            .zip(&resolved)
            .filter_map(|(link, target)| target.is_none().then(|| link.clone()))
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
    let reference_path = validate_note_path(reference).ok();
    let target = normalized(reference);
    let matches: Vec<_> = index
        .notes
        .values()
        .filter(|note| {
            reference_path.as_ref().is_some_and(|path| normalized(&note.note.path) == normalized(path))
                || normalized(&note.note.title) == target
                || note.note.aliases.iter().any(|alias| normalized(alias) == target)
        })
        .collect();
    match matches.as_slice() {
        [] => Err(format!("note not found: {reference}")),
        [note] => Ok(note.note.id.clone()),
        _ => Err(format!("ambiguous note reference: {reference}")),
    }
}

fn store_note(session: &mut VaultSession, note: NoteDocument, archive: Option<NoteDocument>) -> Result<NoteDocument, String> {
    if note.body.len() > MAX_NOTE_BYTES {
        return Err("note body cannot exceed 25 MiB".into());
    }
    validate_note_path(&note.path)?;
    if note.title.trim().is_empty() || note.title.len() > 300 || note.title.chars().any(|character| character == '\0' || character == '\n' || character == '\r') {
        return Err("invalid note title".into());
    }
    if note.aliases.len() > 64 || note.tags.len() > 64 {
        return Err("a note may carry at most 64 tags and 64 aliases".into());
    }
    for value in note.aliases.iter().chain(note.tags.iter()) {
        if value.trim().is_empty()
            || value.chars().count() > 160
            || value.chars().any(|character| character == '\0' || character == '\n' || character == '\r')
        {
            return Err("tags and aliases must be non-empty single-line values of at most 160 characters".into());
        }
    }
    if let Some(previous) = archive.as_ref() {
        archive_note(session, previous)?;
    }
    let payload = encrypt(
        &serde_json::to_vec(&note).map_err(|error| error.to_string())?,
        session.key.as_ref(),
        &note_aad(&note.id),
    )?;
    let object_path = note_path(&session.root_dir, &note.id)?;
    write_atomic(&object_path, &serde_json::to_vec(&payload).map_err(|error| error.to_string())?)?;
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
    save_index(session)?;
    Ok(note)
}

fn open_session(vault_path: &str, passphrase: &str) -> Result<VaultSession, String> {
    if passphrase.is_empty() {
        return Err("passphrase cannot be empty".into());
    }
    let vault_dir = PathBuf::from(vault_path);
    fs::create_dir_all(&vault_dir).map_err(|error| error.to_string())?;
    let vault_dir = fs::canonicalize(vault_dir).map_err(|error| error.to_string())?;
    let root_dir = vault_dir.join("documents");
    reject_symlink(&root_dir)?;
    fs::create_dir_all(&root_dir).map_err(|error| error.to_string())?;
    let manifest_path = root_dir.join("manifest.json");

    let (key, _manifest) = if manifest_path.exists() {
        reject_symlink(&manifest_path)?;
        let manifest: Manifest = serde_json::from_slice(&fs::read(&manifest_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        if manifest.version != 1 || manifest.kdf.name != "scrypt" || manifest.kdf.n != 32768 {
            return Err("unsupported document vault manifest".into());
        }
        let salt = BASE64.decode(&manifest.kdf.salt).map_err(|_| "invalid manifest salt")?;
        let key = derive_key(passphrase, &salt)?;
        if verifier(key.as_ref())? != manifest.verifier {
            return Err("wrong passphrase or damaged manifest".into());
        }
        (key, manifest)
    } else {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(passphrase, &salt)?;
        let manifest = Manifest {
            version: 1,
            kdf: KdfManifest { name: "scrypt".into(), n: 32768, salt: BASE64.encode(salt) },
            verifier: verifier(key.as_ref())?,
        };
        write_atomic(&manifest_path, &serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?)?;
        (key, manifest)
    };

    let index_path = root_dir.join("index.enc");
    let mut index = if index_path.exists() {
        reject_symlink(&index_path)?;
        let payload: EncryptedPayload = serde_json::from_slice(&fs::read(&index_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        serde_json::from_slice::<DocumentIndex>(&decrypt(&payload, key.as_ref(), INDEX_AAD)?)
            .map_err(|error| error.to_string())?
    } else {
        DocumentIndex::empty()
    };
    if index.version != 2 {
        index.version = 2;
        rebuild_derived(&mut index);
    }
    let mut session = VaultSession { vault_dir, root_dir, key, index };
    if !index_path.exists() {
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
    let position: HashMap<&str, usize> = ids.iter().enumerate().map(|(index, id)| (id.as_str(), index)).collect();
    let mut neighbours: Vec<Vec<usize>> = vec![Vec::new(); ids.len()];
    for edge in edges {
        if let (Some(&source), Some(&target)) = (position.get(edge.source.as_str()), position.get(edge.target.as_str())) {
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
                    Some((top, winner)) if top > count || (top == count && winner <= label) => Some((top, winner)),
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
    groups.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left[0].cmp(&right[0])));
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
                edges.push(GraphEdge { source: source.clone(), target: target.clone() });
            }
        }
    }
    edges.sort_by(|left, right| left.source.cmp(&right.source).then_with(|| left.target.cmp(&right.target)));

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
            degree: degree.get(indexed.note.id.as_str()).copied().unwrap_or_default(),
            cluster: 0,
        })
        .collect();
    nodes.sort_by(|left, right| left.path.cmp(&right.path).then_with(|| left.id.cmp(&right.id)));

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
    let payload: EncryptedPayload = serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let file: SavedViewFile = serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), SAVED_VIEWS_AAD)?)
        .map_err(|error| error.to_string())?;
    if file.version != 1 {
        return Err("unsupported saved view file version".into());
    }
    Ok(file.views)
}

fn write_saved_views(session: &VaultSession, views: &[SavedView]) -> Result<(), String> {
    let file = SavedViewFile { version: 1, views: views.to_vec() };
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
    view.direction = if view.direction == "desc" { "desc".into() } else { "asc".into() };
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
fn set_property(session: &mut VaultSession, reference: &str, key: &str, value: Option<Value>) -> Result<PropertyRow, String> {
    let name = key.trim().to_string();
    if name.is_empty() || name.chars().count() > 120 {
        return Err("a property name must be 1-120 characters".into());
    }
    let id = resolve_id(&session.index, reference)?;
    let existing = session.index.notes.get(&id).ok_or("note not found")?.note.clone();
    let mut note = existing.clone();
    if !note.properties.is_object() {
        note.properties = empty_object();
    }
    let properties = note.properties.as_object_mut().ok_or("note properties are not an object")?;
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

fn workspace_path(session: &VaultSession) -> PathBuf {
    session.root_dir.join("workspace.enc")
}

fn load_workspace(session: &VaultSession) -> Result<WorkspaceState, String> {
    let path = workspace_path(session);
    if !path.exists() {
        return Ok(WorkspaceState::empty());
    }
    reject_symlink(&path)?;
    let payload: EncryptedPayload = serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let state: WorkspaceState = serde_json::from_slice(&decrypt(&payload, session.key.as_ref(), WORKSPACE_AAD)?)
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

fn normalize_workspace(mut state: WorkspaceState, previous: &WorkspaceState) -> Result<WorkspaceState, String> {
    state.version = 1;
    if state.bookmarks.len() > MAX_BOOKMARKS {
        return Err(format!("a vault may hold at most {MAX_BOOKMARKS} bookmarks"));
    }
    if state.layouts.len() > MAX_LAYOUTS {
        return Err(format!("a vault may hold at most {MAX_LAYOUTS} workspaces"));
    }
    let timestamp = now();

    let mut bookmarks: Vec<Bookmark> = vec![];
    for mut bookmark in state.bookmarks {
        bookmark.label = bookmark.label.trim().to_string();
        if bookmark.id.trim().is_empty() || bookmark.id.chars().count() > 64 || bookmark.label.chars().count() > 300 {
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
        left.name.to_lowercase().cmp(&right.name.to_lowercase()).then_with(|| left.id.cmp(&right.id))
    });

    Ok(WorkspaceState { version: 1, bookmarks, layouts })
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
        if !names.iter().any(|existing| existing.to_lowercase() == lowered) {
            names.push(value.to_string());
        }
    }
    names.sort_by(|left, right| right.chars().count().cmp(&left.chars().count()));
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
            let end = if cursor + 1 < body.len() { cursor + 2 } else { body.len() };
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
        if spans.iter().any(|(start, end)| index >= *start && index < *end) {
            index += 1;
            continue;
        }
        let after = index + name.len();
        let matches = (index == 0 || !is_word_char(body[index - 1]))
            && (after >= body.len() || !is_word_char(body[after]))
            && name
                .iter()
                .zip(&body[index..after])
                .all(|(left, right)| left.eq_ignore_ascii_case(right) || left.to_lowercase().eq(right.to_lowercase()));
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
    format!("{}{trimmed}{}", if from > 0 { "…" } else { "" }, if to < body.len() { "…" } else { "" })
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
    let target_note = session.index.notes.get(&target_id).ok_or("note not found")?.note.clone();
    let existing = session.index.notes.get(&source_id).ok_or("note not found")?.note.clone();
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
        if chosen.last().is_some_and(|(previous, span)| start < previous + span) {
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
fn unlock_vault(vault_path: String, passphrase: String, state: State<'_, AppState>) -> Result<VaultInfo, String> {
    let session = open_session(&vault_path, &passphrase)?;
    let info = VaultInfo {
        name: session.vault_dir.file_name().and_then(|name| name.to_str()).unwrap_or("Vault").to_string(),
        path: session.vault_dir.to_string_lossy().into_owned(),
        note_count: session.index.notes.len(),
    };
    *state.session.lock().map_err(|_| "vault session lock poisoned")? = Some(session);
    Ok(info)
}

#[tauri::command(async)]
fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    *state.session.lock().map_err(|_| "vault session lock poisoned")? = None;
    Ok(())
}

#[tauri::command(async)]
fn list_notes(state: State<'_, AppState>) -> Result<Vec<NoteSummary>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut notes: Vec<_> = session.index.notes.values().map(|note| NoteSummary::from(&note.note)).collect();
    notes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(notes)
}

#[tauri::command(async)]
fn get_note(reference: String, state: State<'_, AppState>) -> Result<NoteDocument, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_id(&session.index, &reference)?;
    load_note(session, &id)
}

#[tauri::command(async)]
fn save_note(mut note: NoteDocument, state: State<'_, AppState>) -> Result<NoteDocument, String> {
    let mut guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    let existing = session.index.notes.get(&note.id).ok_or("note not found")?.note.clone();
    note.version = 1;
    note.path = validate_note_path(&note.path)?;
    note.created_at = existing.created_at.clone();
    note.updated_at = now();
    note.revision = existing.revision + 1;
    store_note(session, note, Some(existing))
}

#[tauri::command(async)]
fn create_note(path: String, title: String, state: State<'_, AppState>) -> Result<NoteDocument, String> {
    let mut guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    let logical_path = validate_note_path(&path)?;
    if session.index.notes.values().any(|note| normalized(&note.note.path) == normalized(&logical_path)) {
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
    };
    store_note(session, note, None)
}

#[tauri::command(async)]
fn search_notes(query: String, limit: usize, state: State<'_, AppState>) -> Result<Vec<SearchHit>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut tags = vec![];
    let mut paths = vec![];
    let mut required = vec![];
    let mut excluded = vec![];
    for raw in query.split_whitespace() {
        let negative = raw.starts_with('-');
        let term = raw.trim_start_matches('-').trim_matches('"').to_lowercase();
        if let Some(tag) = term.strip_prefix("tag:") { tags.push(tag.trim_start_matches('#').to_string()); }
        else if let Some(path) = term.strip_prefix("path:") { paths.push(path.to_string()); }
        else if negative { excluded.push(term); }
        else if !term.is_empty() { required.push(term); }
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
        let all = format!("{title}\n{aliases}\n{}\n{note_path}\n{properties}\n{body}", note_tags.join(" "));
        if tags.iter().any(|tag| !note_tags.contains(tag)) || paths.iter().any(|part| !note_path.contains(part)) || excluded.iter().any(|term| all.contains(term)) || required.iter().any(|term| !all.contains(term)) { continue; }
        let mut score = if required.is_empty() { 1 } else { 0 };
        for term in &required {
            if &title == term { score += 40; } else if title.contains(term) { score += 20; }
            if aliases.contains(term) { score += 14; }
            if note_tags.iter().any(|tag| tag.contains(term)) { score += 10; }
            if note_path.contains(term) { score += 8; }
            score += body.matches(term).count().min(10) as u32;
            if properties.contains(term) { score += 4; }
        }
        let plain = note.body.replace(['#', '*', '_', '[', ']', '`'], " ").split_whitespace().collect::<Vec<_>>().join(" ");
        let excerpt = plain.chars().take(180).collect();
        hits.push(SearchHit { note: NoteSummary::from(note), score, excerpt });
    }
    hits.sort_by(|left, right| right.score.cmp(&left.score).then_with(|| right.note.updated_at.cmp(&left.note.updated_at)));
    hits.truncate(limit.clamp(1, 100));
    Ok(hits)
}

#[tauri::command(async)]
fn get_backlinks(reference: String, state: State<'_, AppState>) -> Result<Vec<NoteSummary>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
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
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    Ok(build_graph(&session.index))
}

#[tauri::command(async)]
fn list_property_rows(state: State<'_, AppState>) -> Result<Vec<PropertyRow>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut rows: Vec<_> = session.index.notes.values().map(|indexed| PropertyRow::from(&indexed.note)).collect();
    rows.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(rows)
}

#[tauri::command(async)]
fn update_note_property(reference: String, key: String, value: Option<Value>, state: State<'_, AppState>) -> Result<PropertyRow, String> {
    let mut guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    set_property(session, &reference, &key, value)
}

#[tauri::command(async)]
fn list_saved_views(state: State<'_, AppState>) -> Result<Vec<SavedView>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    load_saved_views(session)
}

#[tauri::command(async)]
fn save_saved_view(view: SavedView, state: State<'_, AppState>) -> Result<Vec<SavedView>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut views = load_saved_views(session)?;
    let stored = normalize_view(view, &views)?;
    match views.iter().position(|existing| existing.id == stored.id) {
        Some(index) => views[index] = stored,
        None => {
            if views.len() >= MAX_SAVED_VIEWS {
                return Err(format!("a vault may hold at most {MAX_SAVED_VIEWS} saved views"));
            }
            views.push(stored);
        }
    }
    views.sort_by(|left, right| {
        left.name.to_lowercase().cmp(&right.name.to_lowercase()).then_with(|| left.id.cmp(&right.id))
    });
    write_saved_views(session, &views)?;
    Ok(views)
}

#[tauri::command(async)]
fn delete_saved_view(id: String, state: State<'_, AppState>) -> Result<Vec<SavedView>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut views = load_saved_views(session)?;
    let before = views.len();
    views.retain(|view| view.id != id);
    if views.len() == before {
        return Err(format!("saved view not found: {id}"));
    }
    write_saved_views(session, &views)?;
    Ok(views)
}

#[tauri::command(async)]
fn get_workspace_state(state: State<'_, AppState>) -> Result<WorkspaceState, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    load_workspace(session)
}

#[tauri::command(async)]
fn save_workspace_state(workspace: WorkspaceState, state: State<'_, AppState>) -> Result<WorkspaceState, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let previous = load_workspace(session)?;
    let normalized = normalize_workspace(workspace, &previous)?;
    write_workspace(session, &normalized)?;
    Ok(normalized)
}

#[tauri::command(async)]
fn get_unlinked_mentions(reference: String, state: State<'_, AppState>) -> Result<Vec<UnlinkedMention>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let id = resolve_id(&session.index, &reference)?;
    Ok(unlinked_mentions(&session.index, &id))
}

#[tauri::command(async)]
fn link_unlinked_mention(source: String, target: String, state: State<'_, AppState>) -> Result<Vec<UnlinkedMention>, String> {
    let mut guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_mut().ok_or("vault is locked")?;
    link_mention(session, &source, &target)?;
    let id = resolve_id(&session.index, &target)?;
    Ok(unlinked_mentions(&session.index, &id))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            unlock_vault,
            lock_vault,
            list_notes,
            get_note,
            save_note,
            create_note,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running SecondBrain Vault");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_vault(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("secondbrain-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn encrypted_payload_round_trip_and_authentication() {
        let key = [7u8; 32];
        let payload = encrypt(b"private knowledge", &key, "test-context").unwrap();
        assert_eq!(decrypt(&payload, &key, "test-context").unwrap(), b"private knowledge");
        assert!(decrypt(&payload, &key, "different-context").is_err());

        let mut tampered = payload;
        tampered.ciphertext = BASE64.encode(b"not the original ciphertext");
        assert!(decrypt(&tampered, &key, "test-context").is_err());
    }

    #[test]
    fn logical_paths_reject_escape_and_absolute_inputs() {
        assert_eq!(validate_note_path("Projects/Launch").unwrap(), "Projects/Launch.md");
        for unsafe_path in ["../outside.md", "a/../../outside.md", "/root.md", "C:/root.md", "a//b.md"] {
            assert!(validate_note_path(unsafe_path).is_err(), "accepted unsafe path: {unsafe_path}");
        }
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
        assert!(reopened.root_dir.join("history").join(&id).join("1.note.enc").is_file());
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
        }
    }

    fn edge(source: &str, target: &str) -> GraphEdge {
        GraphEdge { source: source.into(), target: target.into() }
    }

    #[test]
    fn communities_are_deterministic_and_keep_disjoint_groups_apart() {
        let ids: Vec<String> = (0..6).map(|index| format!("n{index}")).collect();
        // Two triangles with no link between them.
        let edges = vec![
            edge("n0", "n1"), edge("n1", "n2"), edge("n2", "n0"),
            edge("n3", "n4"), edge("n4", "n5"), edge("n5", "n3"),
        ];
        let first = cluster_nodes(&ids, &edges);
        assert_eq!(first, cluster_nodes(&ids, &edges), "clustering must not drift between runs");
        assert_eq!(first["n0"], first["n1"]);
        assert_eq!(first["n0"], first["n2"]);
        assert_eq!(first["n3"], first["n4"]);
        assert_eq!(first["n3"], first["n5"]);
        assert_ne!(first["n0"], first["n3"], "unlinked groups must not share a community");
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
        let second = seeded_note("Atlas/Second.md", "Second", "# Second\n\nBack to [[First]].");
        let lonely = seeded_note("Atlas/Lonely.md", "Lonely", "# Lonely\n\nNo links here.");
        for note in [&first, &second, &lonely] {
            store_note(&mut session, note.clone(), None).unwrap();
        }

        let graph = build_graph(&session.index);
        let cluster_of = |id: &str| graph.nodes.iter().find(|node| node.id == id).unwrap().cluster;
        let degree_of = |id: &str| graph.nodes.iter().find(|node| node.id == id).unwrap().degree;
        assert_eq!(cluster_of(&first.id), cluster_of(&second.id));
        assert_ne!(cluster_of(&lonely.id), cluster_of(&first.id));
        assert_eq!(degree_of(&lonely.id), 0);
        assert!(degree_of(&first.id) >= 1);
        assert!(graph.nodes.windows(2).all(|pair| pair[0].path <= pair[1].path), "nodes ship in a stable order");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn saved_views_round_trip_encrypted_and_refuse_nameless_entries() {
        let path = temporary_vault("views");
        let path_text = path.to_string_lossy().into_owned();
        let session = open_session(&path_text, "view passphrase").unwrap();
        assert!(load_saved_views(&session).unwrap().is_empty(), "a fresh vault has no saved views");

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
        assert_eq!(view.direction, "asc", "an unknown direction falls back to ascending");
        assert!(!view.id.is_empty(), "a new view is given an ID");

        write_saved_views(&session, std::slice::from_ref(&view)).unwrap();
        let raw = fs::read(saved_views_path(&session)).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("Open questions"), "saved views must never hit disk in the clear");
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
        let note = seeded_note("Atlas/Tracked.md", "Tracked", "# Tracked\n\nBody stays put.");
        store_note(&mut session, note.clone(), None).unwrap();

        let row = set_property(&mut session, &note.id, " status ", Some(Value::String("living".into()))).unwrap();
        assert_eq!(row.properties["status"], Value::String("living".into()));

        let reloaded = load_note(&session, &note.id).unwrap();
        assert_eq!(reloaded.revision, 2);
        assert_eq!(reloaded.body, note.body, "a cell edit must not rewrite the note body");
        assert!(session.root_dir.join("history").join(&note.id).join("1.note.enc").is_file());

        let cleared = set_property(&mut session, &note.id, "status", None).unwrap();
        assert!(cleared.properties.get("status").is_none(), "passing no value deletes the property");
        assert!(set_property(&mut session, &note.id, "   ", Some(Value::Bool(true))).is_err());
        assert!(set_property(&mut session, "Atlas/Missing.md", "status", Some(Value::Bool(true))).is_err());
        fs::remove_dir_all(path).unwrap();
    }

    fn mention_vault(label: &str) -> (PathBuf, VaultSession, NoteDocument, NoteDocument) {
        let path = temporary_vault(label);
        let path_text = path.to_string_lossy().into_owned();
        let mut session = open_session(&path_text, "mention passphrase").unwrap();

        let mut target = seeded_note("Atlas/Least exposure.md", "Least exposure", "# Least exposure\n\nThe principle itself.");
        target.aliases = vec!["Exposure".into()];
        let mentioning = seeded_note(
            "Atlas/Notes.md",
            "Notes",
            "Least exposure matters here. See also least exposure again later on.",
        );
        let partial = seeded_note("Atlas/Partial.md", "Partial", "Least exposures is a different word entirely.");
        let linking = seeded_note("Atlas/Linked.md", "Linked", "Already points at [[Least exposure]] the proper way.");
        for note in [&target, &mentioning, &partial, &linking] {
            store_note(&mut session, note.clone(), None).unwrap();
        }
        (path, session, target, mentioning)
    }

    #[test]
    fn unlinked_mentions_skip_links_backlinks_and_partial_words() {
        let (path, session, target, _) = mention_vault("mentions");
        let mentions = unlinked_mentions(&session.index, &target.id);

        let titles: Vec<_> = mentions.iter().map(|mention| mention.note.title.as_str()).collect();
        assert_eq!(titles, vec!["Notes"], "only the plain-text mention counts");
        assert_eq!(mentions[0].name, "Least exposure", "the longest matching name wins");
        assert_eq!(mentions[0].count, 2);
        assert!(mentions[0].excerpt.contains("Least exposure matters here"));

        drop(session);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn linking_a_mention_rewrites_the_text_and_keeps_the_writer_s_wording() {
        let (path, mut session, target, mentioning) = mention_vault("link-mention");
        assert_eq!(link_mention(&mut session, &mentioning.id, &target.id).unwrap(), 2);

        let updated = load_note(&session, &mentioning.id).unwrap();
        assert!(updated.body.contains("[[Least exposure]] matters here"));
        assert!(updated.body.contains("[[Least exposure|least exposure]] again"), "lower-case wording survives as an alias link");
        assert_eq!(updated.revision, 2);
        assert!(session.root_dir.join("history").join(&mentioning.id).join("1.note.enc").is_file());
        assert!(unlinked_mentions(&session.index, &target.id).is_empty(), "a linked note is a backlink, not a mention");
        assert!(link_mention(&mut session, &mentioning.id, &target.id).is_err(), "nothing left to link");

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
            assert!(store_note(&mut session, broken, None).is_err(), "accepted bad alias: {bad:?}");
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
                    Bookmark { id: "note-a".into(), label: "  Principles  ".into(), created_at: String::new() },
                    Bookmark { id: "note-a".into(), label: "Duplicate".into(), created_at: String::new() },
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
        assert!(!String::from_utf8_lossy(&raw).contains("Morning review"), "workspace names must not hit disk in the clear");
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
}
