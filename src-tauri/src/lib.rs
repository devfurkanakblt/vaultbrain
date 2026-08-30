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
    collections::HashMap,
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
#[serde(rename_all = "camelCase")]
struct GraphNode {
    id: String,
    title: String,
    path: String,
    tags: Vec<String>,
    degree: usize,
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
    let mut edges = vec![];
    for (source, targets) in &session.index.resolved_links {
        for target in targets.iter().flatten() {
            if source != target && !edges.iter().any(|edge: &GraphEdge| edge.source == *source && edge.target == *target) {
                edges.push(GraphEdge { source: source.clone(), target: target.clone() });
            }
        }
    }
    let mut degree: HashMap<&str, usize> = HashMap::new();
    for edge in &edges {
        *degree.entry(&edge.source).or_default() += 1;
        *degree.entry(&edge.target).or_default() += 1;
    }
    let mut nodes: Vec<_> = session.index.notes.values().map(|indexed| GraphNode {
        id: indexed.note.id.clone(),
        title: indexed.note.title.clone(),
        path: indexed.note.path.clone(),
        tags: indexed.note.tags.clone(),
        degree: degree.get(indexed.note.id.as_str()).copied().unwrap_or_default(),
    }).collect();
    nodes.sort_by(|left, right| left.path.cmp(&right.path));
    edges.sort_by(|left, right| left.source.cmp(&right.source).then_with(|| left.target.cmp(&right.target)));
    Ok(KnowledgeGraph { nodes, edges })
}

#[tauri::command(async)]
fn list_property_rows(state: State<'_, AppState>) -> Result<Vec<PropertyRow>, String> {
    let guard = state.session.lock().map_err(|_| "vault session lock poisoned")?;
    let session = guard.as_ref().ok_or("vault is locked")?;
    let mut rows: Vec<_> = session.index.notes.values().map(|indexed| PropertyRow {
        id: indexed.note.id.clone(),
        path: indexed.note.path.clone(),
        title: indexed.note.title.clone(),
        tags: indexed.note.tags.clone(),
        properties: indexed.note.properties.clone(),
        updated_at: indexed.note.updated_at.clone(),
    }).collect();
    rows.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(rows)
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
}
