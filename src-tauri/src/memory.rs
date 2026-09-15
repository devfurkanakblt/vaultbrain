//! Owner-controlled personal-memory state.
//!
//! This module deliberately has no filesystem, vault-path, passphrase, or key
//! parameters in its public DTOs.  It is a child of the desktop core so all
//! encrypted persistence and document writes stay behind the unlocked-session
//! boundary.

use super::*;
use std::io::Read as IoRead;
#[cfg(windows)]
use std::thread;
#[cfg(windows)]
use std::time::{Duration, Instant};
#[cfg(windows)]
use tauri::Manager;

#[cfg(windows)]
const MAX_CANDIDATES: usize = 200;
#[cfg(windows)]
const MAX_QUERY: usize = 512;
#[cfg(any(windows, test))]
const MAX_QUEUE: usize = 500;
#[cfg(any(windows, test))]
const MAX_SOURCE_ID: usize = 240;
#[cfg(any(windows, test))]
const MAX_SOURCE_PATH: usize = 4 * 1024;
#[cfg(any(windows, test))]
const QUEUE_TTL_DAYS: i64 = 7;
const MAX_CLIENT_BYTES: usize = 64 * 1024;
#[cfg(windows)]
const MAX_PIPE_WIRE_BYTES: usize = 128 * 1024;
#[cfg(windows)]
const PIPE_DEADLINE: Duration = Duration::from_secs(2);
#[cfg(windows)]
const PIPE_POLL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryStatusDto {
    pub(crate) state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) enrolled_at: Option<String>,
    pub(crate) paired: bool,
    pub(crate) paused: bool,
    pub(crate) queued: usize,
    pub(crate) review: usize,
    pub(crate) failed: usize,
    pub(crate) expired: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) last_capture_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model: Option<String>,
    pub(crate) compatibility_reasons: Vec<String>,
    pub(crate) generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryPairingDto {
    pub(crate) pairing_id: String,
    pub(crate) state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryEvidence {
    pub(crate) message_id: String,
    pub(crate) quote: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryCandidateDto {
    pub(crate) id: String,
    pub(crate) kind: String,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) evidence: Vec<MemoryEvidence>,
    pub(crate) source_kind: String,
    pub(crate) sensitive: bool,
    #[serde(default)]
    pub(crate) links: Vec<String>,
    #[serde(default)]
    pub(crate) target_id: Option<String>,
    #[serde(default)]
    pub(crate) base_revision: Option<u64>,
    pub(crate) created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryNoteDto {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) title: String,
    pub(crate) revision: u64,
    pub(crate) pinned: bool,
    pub(crate) forgotten: bool,
    pub(crate) updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemoryScopeDto {
    pub(crate) kind: String,
    pub(crate) id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg(any(windows, test))]
struct MemoryHookPayload {
    version: u8,
    event: String,
    session_id: String,
    turn_id: String,
    transcript_path: String,
    created_at: String,
}

fn pending_queue_state() -> String {
    "pending".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueuePointer {
    id: String,
    source_key: String,
    #[serde(default)]
    event: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    turn_id: String,
    #[serde(default)]
    transcript_path: String,
    #[serde(default)]
    created_at: String,
    received_at: String,
    expires_at: String,
    #[serde(default = "pending_queue_state")]
    state: String,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    retry_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemoryControl {
    version: u8,
    #[serde(default)]
    enrolled_at: Option<String>,
    #[serde(default)]
    pairing_id: Option<String>,
    #[serde(default)]
    paired: bool,
    #[serde(default)]
    fingerprint: String,
    #[serde(default)]
    paused: bool,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    review: Vec<MemoryCandidateDto>,
    #[serde(default)]
    queue: Vec<QueuePointer>,
    #[serde(default)]
    failed: usize,
    #[serde(default)]
    expired: usize,
    #[serde(default)]
    last_capture_at: Option<String>,
    #[serde(default)]
    pinned: HashSet<String>,
    #[serde(default)]
    tombstones: HashSet<String>,
    #[serde(default)]
    exclusions: HashSet<String>,
}

impl Default for MemoryControl {
    fn default() -> Self {
        Self {
            version: 1,
            enrolled_at: None,
            pairing_id: None,
            paired: false,
            fingerprint: String::new(),
            paused: false,
            model: Some("gpt-5.6-luna".into()),
            review: vec![],
            queue: vec![],
            failed: 0,
            expired: 0,
            last_capture_at: None,
            pinned: HashSet::new(),
            tombstones: HashSet::new(),
            exclusions: HashSet::new(),
        }
    }
}

const CONTROL_NOTE_ID: &str = "00000000-0000-4000-8000-000000000015";

fn fingerprint(session: &VaultSession) -> Result<String, String> {
    if !keyring::keyring_path(&session.vault_dir).exists() || session.audit_key.is_none() {
        return Err("memory requires a migrated keyring vault".into());
    }
    // Bind the enrollment to key material identity, not slot wrapping bytes:
    // changing a passphrase re-wraps keyring.json but must not break pairing.
    // Pairing follows the dedicated keyed-KV identity. A passphrase re-wrap
    // leaves it unchanged, while a re-key or identity rotation creates a new
    // pairing boundary.
    Ok(BASE64_URL.encode(Sha256::digest(session.kv_key.as_ref())))
}

fn load(session: &VaultSession) -> Result<MemoryControl, String> {
    let path = note_path(&session.root_dir, CONTROL_NOTE_ID)?;
    if !path.exists() {
        return Ok(MemoryControl::default());
    }
    let note = load_note(session, CONTROL_NOTE_ID)?;
    let control: MemoryControl =
        serde_json::from_str(&note.body).map_err(|_| "memory control is unavailable")?;
    if control.version != 1 {
        return Err("memory control version is unsupported".into());
    }
    if control.paired && control.fingerprint != fingerprint(session)? {
        return Err("memory pairing requires re-enrollment".into());
    }
    Ok(control)
}

fn save(session: &mut VaultSession, control: &MemoryControl) -> Result<(), String> {
    let body = serde_json::to_string(control).map_err(|_| "memory control is unavailable")?;
    let previous = session
        .index
        .notes
        .get(CONTROL_NOTE_ID)
        .map(|v| v.note.clone());
    let timestamp = now();
    let note = NoteDocument {
        version: 1,
        id: CONTROL_NOTE_ID.into(),
        path: "Memory/.system.md".into(),
        title: "Memory system".into(),
        body,
        aliases: vec![],
        tags: vec!["memory-system".into()],
        properties: serde_json::json!({"memorySystem":true,"hidden":true}),
        created_at: previous
            .as_ref()
            .map(|v| v.created_at.clone())
            .unwrap_or_else(|| timestamp.clone()),
        updated_at: timestamp,
        revision: previous.as_ref().map(|v| v.revision + 1).unwrap_or(1),
        frontmatter_source: None,
    };
    store_note(session, note, previous).map(|_| ())
}

fn parse_timestamp(value: &str, name: &str) -> Result<DateTime<chrono::FixedOffset>, String> {
    if !bounded(value, 80) {
        return Err(format!("invalid {name}"));
    }
    DateTime::parse_from_rfc3339(value).map_err(|_| format!("invalid {name}"))
}

#[cfg(any(windows, test))]
fn source_path_is_safe(value: &str) -> bool {
    if !bounded(value, MAX_SOURCE_PATH)
        || value
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n' | '\t'))
    {
        return false;
    }
    let normalized = value.replace('\\', "/");
    let bytes = normalized.as_bytes();
    let rooted =
        normalized.starts_with('/') || (bytes.len() >= 3 && bytes[1] == b':' && bytes[2] == b'/');
    rooted && !normalized.split('/').any(|part| part == "..")
}

#[cfg(any(windows, test))]
fn bounded_reference(value: &str, max: usize) -> bool {
    bounded(value, max) && !value.chars().any(|character| character.is_control())
}

#[cfg(any(windows, test))]
fn validate_hook_payload(
    payload: &MemoryHookPayload,
) -> Result<DateTime<chrono::FixedOffset>, String> {
    if payload.version != 1
        || !matches!(payload.event.as_str(), "Stop" | "PreCompact" | "SessionEnd")
        || !bounded_reference(&payload.session_id, MAX_SOURCE_ID)
        || !bounded_reference(&payload.turn_id, MAX_SOURCE_ID)
        || !source_path_is_safe(&payload.transcript_path)
    {
        return Err("invalid memory hook payload".into());
    }
    let created_at = parse_timestamp(&payload.created_at, "createdAt")?;
    // A hook is a pointer only. Validate every existing path component, but
    // allow a transcript that is still being finalized by the client.
    reject_symlink(Path::new(&payload.transcript_path))
        .map_err(|_| "invalid memory source reference".to_string())?;
    Ok(created_at)
}

#[cfg(any(windows, test))]
fn parse_hook_payload(value: &Value) -> Result<MemoryHookPayload, String> {
    let payload: MemoryHookPayload = serde_json::from_value(value.clone())
        .map_err(|_| "invalid memory hook payload".to_string())?;
    validate_hook_payload(&payload)?;
    Ok(payload)
}

#[cfg(any(windows, test))]
fn source_key(payload: &MemoryHookPayload) -> String {
    Sha256::digest(format!("{}\0{}", payload.session_id, payload.turn_id).as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(any(windows, test))]
fn enqueue_pointer(
    control: &mut MemoryControl,
    payload: MemoryHookPayload,
    received_at: &str,
) -> Result<Value, String> {
    let created_at = validate_hook_payload(&payload)?;
    let received = parse_timestamp(received_at, "receivedAt")?;
    let enrolled_at = control
        .enrolled_at
        .as_deref()
        .ok_or_else(|| "memory is not enrolled".to_string())?;
    let enrolled = parse_timestamp(enrolled_at, "enrolledAt")?;
    if created_at <= enrolled {
        return Ok(serde_json::json!({
            "accepted": false,
            "duplicate": false,
            "reason": "before_enrollment"
        }));
    }

    // Expired references are no longer deliverable. Removing them here keeps
    // the durable queue bounded while retaining the aggregate count for UI
    // status and audit evidence.
    let mut retained = Vec::with_capacity(control.queue.len());
    let mut expired = 0usize;
    for pointer in control.queue.drain(..) {
        let keep = parse_timestamp(&pointer.expires_at, "expiresAt")
            .map(|expires| expires > received)
            .unwrap_or(false);
        if keep {
            retained.push(pointer);
        } else {
            expired += 1;
        }
    }
    control.queue = retained;
    control.expired = control.expired.saturating_add(expired);

    let key = source_key(&payload);
    if control
        .queue
        .iter()
        .any(|pointer| pointer.source_key == key)
    {
        return Ok(serde_json::json!({
            "accepted": true,
            "duplicate": true,
            "id": key
        }));
    }
    if control.queue.len() >= MAX_QUEUE {
        return Err("memory queue is full".into());
    }
    let expires_at = (received + chrono::Duration::days(QUEUE_TTL_DAYS))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    control.queue.push(QueuePointer {
        id: key.clone(),
        source_key: key.clone(),
        event: payload.event,
        session_id: payload.session_id,
        turn_id: payload.turn_id,
        transcript_path: payload.transcript_path,
        created_at: created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        received_at: received.to_rfc3339_opts(SecondsFormat::Millis, true),
        expires_at: expires_at.clone(),
        state: pending_queue_state(),
        attempts: 0,
        retry_at: None,
    });
    control.last_capture_at = Some(received.to_rfc3339_opts(SecondsFormat::Millis, true));
    Ok(serde_json::json!({
        "accepted": true,
        "duplicate": false,
        "id": key,
        "expiresAt": expires_at
    }))
}

#[cfg(windows)]
fn enqueue_source(session: &mut VaultSession, params: Option<&Value>) -> Result<Value, String> {
    let mut control = load(session)?;
    if !control.paired || control.paused {
        return Err("memory capture is unavailable".into());
    }
    let value = params.ok_or_else(|| "invalid memory hook payload".to_string())?;
    let payload = parse_hook_payload(value)?;
    let result = enqueue_pointer(&mut control, payload, &now())?;
    // A stale pre-enrollment hook has no state transition. Every other valid
    // request is persisted before its acceptance response reaches the helper;
    // this is the durable acceptance point for the capture cursor.
    if result.get("reason").and_then(Value::as_str) != Some("before_enrollment") {
        save(session, &control)?;
    }
    Ok(result)
}

fn status(control: &MemoryControl, generation: u64) -> MemoryStatusDto {
    let state = if !control.paired {
        "disabled"
    } else if control.paused {
        "paused"
    } else {
        "ready"
    };
    let current = Utc::now();
    let queued = control
        .queue
        .iter()
        .filter(|pointer| {
            (pointer.state == "pending" || pointer.state == "processing")
                && parse_timestamp(&pointer.expires_at, "expiresAt")
                    .is_ok_and(|expires| expires.with_timezone(&Utc) > current)
        })
        .count();
    MemoryStatusDto {
        state: state.into(),
        enrolled_at: control.enrolled_at.clone(),
        paired: control.paired,
        paused: control.paused,
        queued,
        review: control.review.len(),
        failed: control.failed,
        expired: control.expired,
        last_capture_at: control.last_capture_at.clone(),
        model: control.model.clone(),
        compatibility_reasons: vec![],
        generation,
    }
}

fn bounded(value: &str, max: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max
        && !value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
}
#[cfg(any(windows, test))]
fn has_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("password=")
        || lower.contains("api_key")
        || lower.contains("authorization: bearer")
        || lower.contains("-----begin private key")
}
#[cfg(any(windows, test))]
fn validate_candidate(candidate: &MemoryCandidateDto) -> Result<(), String> {
    if !matches!(
        candidate.kind.as_str(),
        "preference" | "fact" | "project" | "decision" | "goal" | "task" | "person" | "concept"
    ) || !matches!(candidate.source_kind.as_str(), "user-stated" | "inference")
        || !bounded(&candidate.title, 400)
        || !bounded(&candidate.body, 16_000)
        || candidate.evidence.is_empty()
        || candidate.evidence.len() > 8
        || candidate.links.len() > 16
        || has_secret(&candidate.title)
        || has_secret(&candidate.body)
    {
        return Err("memory candidate was rejected".into());
    }
    for evidence in &candidate.evidence {
        if !bounded(&evidence.message_id, 256)
            || !bounded(&evidence.quote, 2_000)
            || has_secret(&evidence.quote)
        {
            return Err("memory candidate was rejected".into());
        }
    }
    for link in &candidate.links {
        if !bounded(link, 512) || link.contains("..") || link.contains('\\') {
            return Err("memory candidate was rejected".into());
        }
    }
    Ok(())
}

pub(crate) fn pair_begin(session: &mut VaultSession) -> Result<MemoryPairingDto, String> {
    let mut control = load(session)?;
    if control.paired {
        return Err("memory is already paired".into());
    }
    let id = Uuid::new_v4().to_string();
    control.pairing_id = Some(id.clone());
    save(session, &control)?;
    Ok(MemoryPairingDto {
        pairing_id: id,
        state: "awaitingConfirmation".into(),
    })
}
pub(crate) fn pair_complete(
    session: &mut VaultSession,
    pairing_id: &str,
    generation: u64,
) -> Result<MemoryStatusDto, String> {
    #[cfg(not(windows))]
    {
        let _ = (session, pairing_id, generation);
        Err("personal memory is supported only on Windows".into())
    }

    #[cfg(windows)]
    {
        let mut control = load(session)?;
        if control.pairing_id.as_deref() != Some(pairing_id) {
            return Err("memory pairing confirmation was not found".into());
        }
        control.paired = true;
        control.enrolled_at = Some(now());
        control.fingerprint = fingerprint(session)?;
        control.pairing_id = None;
        #[cfg(windows)]
        write_pairing_material(&control.fingerprint)?;
        save(session, &control)?;
        Ok(status(&control, generation))
    }
}
pub(crate) fn pair_cancel(session: &mut VaultSession, pairing_id: &str) -> Result<(), String> {
    let mut control = load(session)?;
    if control.pairing_id.as_deref() != Some(pairing_id) {
        return Err("memory pairing confirmation was not found".into());
    }
    control.pairing_id = None;
    save(session, &control)
}
pub(crate) fn get_status(
    session: &VaultSession,
    generation: u64,
) -> Result<MemoryStatusDto, String> {
    Ok(status(&load(session)?, generation))
}
pub(crate) fn set_paused(
    session: &mut VaultSession,
    paused: bool,
    generation: u64,
) -> Result<MemoryStatusDto, String> {
    let mut c = load(session)?;
    if !c.paired {
        return Err("memory is not paired".into());
    }
    c.paused = paused;
    save(session, &c)?;
    Ok(status(&c, generation))
}
pub(crate) fn exclude_scope(
    session: &mut VaultSession,
    kind: &str,
    id: &str,
    generation: u64,
) -> Result<MemoryStatusDto, String> {
    if !matches!(kind, "session" | "project") || !bounded(id, 512) {
        return Err("invalid memory exclusion".into());
    }
    let mut c = load(session)?;
    c.exclusions.insert(format!("{kind}:{id}"));
    save(session, &c)?;
    Ok(status(&c, generation))
}
pub(crate) fn list_review(session: &VaultSession) -> Result<Vec<MemoryCandidateDto>, String> {
    Ok(load(session)?.review)
}
#[cfg(windows)]
pub(crate) fn enqueue_review(
    session: &mut VaultSession,
    mut candidate: MemoryCandidateDto,
) -> Result<(), String> {
    validate_candidate(&candidate)?;
    let mut c = load(session)?;
    if !c.paired || c.paused {
        return Err("memory is unavailable".into());
    }
    if c.review.len() >= MAX_CANDIDATES {
        return Err("memory review queue is full".into());
    }
    candidate.id = Uuid::new_v4().to_string();
    candidate.created_at = now();
    c.review.push(candidate);
    save(session, &c)
}
pub(crate) fn approve(session: &mut VaultSession, id: &str) -> Result<MemoryNoteDto, String> {
    let mut c = load(session)?;
    let pos = c
        .review
        .iter()
        .position(|v| v.id == id)
        .ok_or("memory candidate was not found")?;
    let candidate = c.review.remove(pos);
    if candidate.source_kind != "user-stated" {
        return Err("memory candidate requires manual editing before approval".into());
    }
    let slug: String = candidate
        .title
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ' || *c == '-')
        .collect::<String>()
        .trim()
        .replace(' ', "-");
    let path = validate_note_path(&format!(
        "Memory/{}-{}.md",
        slug.chars().take(80).collect::<String>(),
        &candidate.id[..8]
    ))?;
    let timestamp = now();
    let note = NoteDocument {
        version: 1,
        id: Uuid::new_v4().to_string(),
        path,
        title: candidate.title.clone(),
        body: format!("# {}\n\n{}\n", candidate.title, candidate.body),
        aliases: vec![],
        tags: vec!["memory".into()],
        properties: serde_json::json!({"memory":true,"sourceKind":candidate.source_kind,"candidateId":candidate.id}),
        created_at: timestamp.clone(),
        updated_at: timestamp,
        revision: 1,
        frontmatter_source: None,
    };
    let note = store_note(session, note, None)?;
    save(session, &c)?;
    Ok(MemoryNoteDto {
        id: note.id.clone(),
        path: note.path,
        title: note.title,
        revision: note.revision,
        pinned: c.pinned.contains(&note.id),
        forgotten: false,
        updated_at: note.updated_at,
    })
}
pub(crate) fn reject(session: &mut VaultSession, id: &str) -> Result<(), String> {
    let mut c = load(session)?;
    let before = c.review.len();
    c.review.retain(|v| v.id != id);
    if c.review.len() == before {
        return Err("memory candidate was not found".into());
    }
    save(session, &c)
}
pub(crate) fn set_pinned(
    session: &mut VaultSession,
    id: &str,
    pinned: bool,
) -> Result<MemoryNoteDto, String> {
    let mut c = load(session)?;
    let note = load_note(session, id)?;
    if !note.tags.iter().any(|tag| tag == "memory") {
        return Err("note is not a memory record".into());
    }
    if pinned {
        c.pinned.insert(id.into());
    } else {
        c.pinned.remove(id);
    }
    save(session, &c)?;
    Ok(MemoryNoteDto {
        id: note.id,
        path: note.path,
        title: note.title,
        revision: note.revision,
        pinned,
        forgotten: c.tombstones.contains(id),
        updated_at: note.updated_at,
    })
}
pub(crate) fn forget(session: &mut VaultSession, id: &str) -> Result<(), String> {
    let mut c = load(session)?;
    let note = load_note(session, id)?;
    if !note.tags.iter().any(|tag| tag == "memory") {
        return Err("note is not a memory record".into());
    }
    c.tombstones.insert(id.into());
    c.queue.retain(|p| p.source_key != id);
    save(session, &c)
}
pub(crate) fn relearn(session: &mut VaultSession, id: &str) -> Result<(), String> {
    let mut c = load(session)?;
    if !c.tombstones.remove(id) {
        return Err("memory tombstone was not found".into());
    }
    save(session, &c)
}
pub(crate) fn disconnect(session: &mut VaultSession) -> Result<(), String> {
    let mut c = load(session)?;
    c.paired = false;
    c.pairing_id = None;
    c.fingerprint.clear();
    c.queue.clear();
    // Before saving: if the bearer secret survives, the vault must not record
    // a disconnect the pipe server would not honor.
    #[cfg(windows)]
    delete_pairing_material()?;
    save(session, &c)
}

#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\vaultbrain-memory-v1";

/// Pairing material is a random bearer secret protected with the current
/// Windows user's DPAPI. It never enters a Node configuration or request.
#[cfg(windows)]
fn pairing_store() -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("memory pairing storage is unavailable")?;
    Ok(PathBuf::from(base)
        .join("VaultBrain")
        .join("memory-client.v1.dpapi"))
}
#[cfg(windows)]
fn protect_current_user(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB},
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        if CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        ) == 0
        {
            return Err("memory pairing storage is unavailable".into());
        }
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut _);
        Ok(result)
    }
}
#[cfg(windows)]
fn unprotect_current_user(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        if CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        ) == 0
        {
            return Err("memory pairing is unavailable".into());
        }
        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        LocalFree(output.pbData as *mut _);
        Ok(result)
    }
}
#[cfg(windows)]
fn write_pairing_material(fingerprint: &str) -> Result<(), String> {
    let mut secret = [0u8; 32];
    UnwrapErr(SysRng).fill_bytes(&mut secret);
    let record = serde_json::json!({"version":1,"secret":BASE64_URL.encode(secret),"fingerprint":fingerprint});
    let protected = protect_current_user(
        &serde_json::to_vec(&record).map_err(|_| "memory pairing storage is unavailable")?,
    )?;
    let path = pairing_store()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "memory pairing storage is unavailable")?;
    }
    write_atomic(&path, &protected)
}
#[cfg(windows)]
fn delete_pairing_material() -> Result<(), String> {
    // Without LOCALAPPDATA no pairing material can have been written.
    let Ok(path) = pairing_store() else {
        return Ok(());
    };
    remove_pairing_file(&path)
}
/// The pipe server authorizes a client by this file alone, so a removal that
/// did not remove is reported, never ignored. A missing file (never paired)
/// is not an error. No retry.
#[cfg(windows)]
fn remove_pairing_file(path: &Path) -> Result<(), String> {
    const NOT_REMOVED: &str = "memory pairing material could not be removed";
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(NOT_REMOVED.into()),
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(NOT_REMOVED.into()),
    }
}

#[cfg(windows)]
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}
#[cfg(windows)]
fn broker_secret() -> Result<Vec<u8>, String> {
    let path = pairing_store()?;
    let raw = read_limited(&path, 64 * 1024, "memory pairing")
        .map_err(|_| "memory pairing is unavailable")?;
    let plain = unprotect_current_user(&raw)?;
    let value: Value =
        serde_json::from_slice(&plain).map_err(|_| "memory pairing is unavailable")?;
    let encoded = value
        .get("secret")
        .and_then(Value::as_str)
        .ok_or("memory pairing is unavailable")?;
    let secret = BASE64_URL
        .decode(encoded)
        .map_err(|_| "memory pairing is unavailable")?;
    if secret.len() != 32 {
        return Err("memory pairing is unavailable".into());
    }
    Ok(secret)
}
#[cfg(windows)]
pub(crate) fn start_broker(app: AppHandle) {
    std::thread::spawn(move || loop {
        broker_once(&app);
    });
}
#[cfg(not(windows))]
pub(crate) fn start_broker(_: AppHandle) {}
#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

/// Security descriptor owned by the broker pipe.  The descriptor is built
/// from the interactive user's SID and released with LocalFree after the
/// server has stopped creating pipe instances.
#[cfg(windows)]
struct PipeSecurity {
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(
                    self.descriptor as windows_sys::Win32::Foundation::HLOCAL,
                );
            }
            self.descriptor = std::ptr::null_mut();
        }
    }
}

/// Build a protected DACL which grants full pipe access only to the current
/// interactive user.  `PIPE_REJECT_REMOTE_CLIENTS` is still set on the pipe
/// itself; the DACL closes the local cross-user path as well.
#[cfg(windows)]
fn pipe_security() -> Result<PipeSecurity, String> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err("memory broker security is unavailable".into());
        }

        let mut required = 0u32;
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
        if required == 0 {
            CloseHandle(token);
            return Err("memory broker security is unavailable".into());
        }

        let mut token_info = vec![0u8; required as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            token_info.as_mut_ptr() as *mut _,
            required,
            &mut required,
        ) == 0
        {
            CloseHandle(token);
            return Err("memory broker security is unavailable".into());
        }

        let token_user = std::ptr::read_unaligned(token_info.as_ptr() as *const TOKEN_USER);
        let mut sid_text = std::ptr::null_mut();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) == 0 || sid_text.is_null() {
            CloseHandle(token);
            return Err("memory broker security is unavailable".into());
        }

        let mut sid_len = 0usize;
        while sid_len < 256 && *sid_text.add(sid_len) != 0 {
            sid_len += 1;
        }
        let sid = if sid_len == 0 || sid_len == 256 {
            String::new()
        } else {
            String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, sid_len))
        };
        LocalFree(sid_text as windows_sys::Win32::Foundation::HLOCAL);
        CloseHandle(token);
        if sid.is_empty() || !sid.starts_with("S-") {
            return Err("memory broker security is unavailable".into());
        }

        let descriptor_text = wide(&format!("D:P(A;;GA;;;{sid})"));
        let mut descriptor = std::ptr::null_mut();
        let mut descriptor_size = 0u32;
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            1,
            &mut descriptor,
            &mut descriptor_size,
        ) == 0
            || descriptor.is_null()
            || descriptor_size == 0
        {
            if !descriptor.is_null() {
                LocalFree(descriptor as windows_sys::Win32::Foundation::HLOCAL);
            }
            return Err("memory broker security is unavailable".into());
        }
        Ok(PipeSecurity { descriptor })
    }
}

/// Read exactly one bounded request from the helper's stdin.  A helper is a
/// one-shot process, so accepting a second line would make framing ambiguous
/// and could leave attacker-controlled bytes queued for a later operation.
fn read_client_input<R: IoRead>(reader: R) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(1024);
    reader
        .take((MAX_CLIENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "memory request is unavailable".to_string())?;
    if bytes.len() > MAX_CLIENT_BYTES {
        return Err("memory request exceeds its size limit".into());
    }
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.iter().any(|byte| *byte == b'\r' || *byte == b'\n') {
        return Err("memory request framing is invalid".into());
    }
    String::from_utf8(bytes).map_err(|_| "memory request is not UTF-8".into())
}

fn supported_method(method: &str) -> bool {
    matches!(
        method,
        "memory_bootstrap"
            | "memory_search"
            | "memory_read"
            | "memory_remember"
            | "memory_forget"
            | "memory_status"
            | "memory_enqueue"
            | "memory_disconnect"
    )
}

#[cfg(windows)]
fn memory_note(note: &NoteDocument, c: &MemoryControl) -> MemoryNoteDto {
    MemoryNoteDto {
        id: note.id.clone(),
        path: note.path.clone(),
        title: note.title.clone(),
        revision: note.revision,
        pinned: c.pinned.contains(&note.id),
        forgotten: c.tombstones.contains(&note.id),
        updated_at: note.updated_at.clone(),
    }
}
#[cfg(windows)]
fn public_search(
    session: &VaultSession,
    params: Option<&Value>,
) -> Result<Vec<MemoryNoteDto>, String> {
    let c = load(session)?;
    let query = params
        .and_then(|v| v.get("query"))
        .and_then(Value::as_str)
        .ok_or("invalid request")?;
    if query.len() > MAX_QUERY {
        return Err("invalid request".into());
    }
    let limit = params
        .and_then(|v| v.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .min(50) as usize;
    let needle = query.to_ascii_lowercase();
    let mut notes: Vec<_> = session
        .index
        .notes
        .values()
        .filter(|v| {
            v.note.id != CONTROL_NOTE_ID
                && !c.tombstones.contains(&v.note.id)
                && v.note.tags.iter().any(|t| t == "memory")
                && (v.note.title.to_ascii_lowercase().contains(&needle)
                    || v.note.body.to_ascii_lowercase().contains(&needle))
        })
        .map(|v| memory_note(&v.note, &c))
        .collect();
    notes.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    notes.truncate(limit);
    Ok(notes)
}
#[cfg(windows)]
fn public_read(session: &VaultSession, params: Option<&Value>) -> Result<MemoryNoteDto, String> {
    let id = params
        .and_then(|v| v.get("id"))
        .and_then(Value::as_str)
        .ok_or("invalid request")?;
    if id == CONTROL_NOTE_ID {
        return Err("not found".into());
    }
    let c = load(session)?;
    if c.tombstones.contains(id) {
        return Err("not found".into());
    }
    let note = load_note(session, id)?;
    if !note.tags.iter().any(|t| t == "memory") {
        return Err("not found".into());
    }
    Ok(memory_note(&note, &c))
}
#[cfg(windows)]
fn public_remember(session: &mut VaultSession, params: Option<&Value>) -> Result<(), String> {
    let mut candidate: MemoryCandidateDto = serde_json::from_value(
        params
            .and_then(|v| v.get("candidate"))
            .cloned()
            .ok_or("invalid request")?,
    )
    .map_err(|_| "invalid request")?;
    candidate.id.clear();
    candidate.created_at.clear();
    enqueue_review(session, candidate)
}
#[cfg(windows)]
fn public_forget(session: &mut VaultSession, params: Option<&Value>) -> Result<(), String> {
    let id = params
        .and_then(|v| v.get("id"))
        .and_then(Value::as_str)
        .ok_or("invalid request")?;
    forget(session, id)
}
fn unavailable(code: &str) -> Value {
    serde_json::json!({"version":1,"ok":false,"error":{"code":code,"message":"memory service unavailable"}})
}

#[cfg(windows)]
fn request_shape_is_valid(request: &Value) -> bool {
    let Some(object) = request.as_object() else {
        return false;
    };
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "version" | "method" | "params"))
    {
        return false;
    }
    if object.get("version").and_then(Value::as_u64) != Some(1) {
        return false;
    }
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return false;
    };
    if !supported_method(method) {
        return false;
    }
    let Some(params) = object.get("params").and_then(Value::as_object) else {
        return false;
    };
    let (allowed, required): (&[&str], &[&str]) = match method {
        "memory_bootstrap" | "memory_status" | "memory_disconnect" => (&[], &[]),
        "memory_search" => (&["query", "limit"], &["query"]),
        "memory_read" | "memory_forget" => (&["id"], &["id"]),
        "memory_remember" => (&["candidate"], &["candidate"]),
        "memory_enqueue" => (
            &[
                "version",
                "event",
                "sessionId",
                "turnId",
                "transcriptPath",
                "createdAt",
            ],
            &[
                "version",
                "event",
                "sessionId",
                "turnId",
                "transcriptPath",
                "createdAt",
            ],
        ),
        _ => return false,
    };
    params.keys().all(|key| allowed.contains(&key.as_str()))
        && required.iter().all(|key| params.contains_key(*key))
}

#[cfg(windows)]
fn broker_response(app: &AppHandle, bytes: &[u8]) -> Value {
    if bytes.len() > MAX_PIPE_WIRE_BYTES {
        return unavailable("invalid_request");
    }
    let wire: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return unavailable("invalid_request"),
    };
    let Some(object) = wire.as_object() else {
        return unavailable("invalid_request");
    };
    if object
        .keys()
        .any(|key| key != "credential" && key != "request")
    {
        return unavailable("invalid_request");
    }

    let mut credential = object
        .get("credential")
        .and_then(Value::as_str)
        .and_then(|encoded| BASE64_URL.decode(encoded).ok());
    let mut expected = broker_secret().ok();
    let authorized = match (credential.as_deref(), expected.as_deref()) {
        (Some(actual), Some(wanted)) => constant_time_equal(actual, wanted),
        _ => false,
    };
    if let Some(value) = credential.as_mut() {
        value.fill(0);
    }
    if let Some(value) = expected.as_mut() {
        value.fill(0);
    }
    if !authorized {
        return unavailable("unauthorized");
    }

    let request = match object.get("request") {
        Some(value) if request_shape_is_valid(value) => value,
        _ => return unavailable("invalid_request"),
    };
    let method = request["method"].as_str().unwrap_or_default();
    let state = app.state::<AppState>();
    let generation = state.memory_generation.load(Ordering::Acquire);
    let mut guard = match state.session.lock() {
        Ok(value) => value,
        Err(_) => return unavailable("unavailable"),
    };
    let session: &mut VaultSession = match guard.as_mut() {
        Some(session) => session,
        None => {
            return if method == "memory_status" {
                serde_json::json!({
                    "version": 1,
                    "ok": true,
                    "result": {
                        "state": "locked",
                        "paired": false,
                        "paused": false,
                        "queued": 0,
                        "review": 0,
                        "failed": 0,
                        "expired": 0,
                        "compatibilityReasons": ["Unlock the vault to inspect memory status."],
                        "generation": generation,
                    }
                })
            } else {
                unavailable("locked")
            };
        }
    };

    let result = match method {
        "memory_status" => get_status(session, generation)
            .and_then(|value| serde_json::to_value(value).map_err(|_| "memory unavailable".into())),
        "memory_bootstrap" => Ok(serde_json::json!({"notes": []})),
        "memory_search" => public_search(session, request.get("params"))
            .and_then(|value| serde_json::to_value(value).map_err(|_| "memory unavailable".into())),
        "memory_read" => public_read(session, request.get("params"))
            .and_then(|value| serde_json::to_value(value).map_err(|_| "memory unavailable".into())),
        "memory_remember" => public_remember(session, request.get("params"))
            .map(|_| serde_json::json!({"accepted": "review"})),
        "memory_forget" => public_forget(session, request.get("params"))
            .map(|_| serde_json::json!({"forgotten": true})),
        "memory_disconnect" => {
            disconnect(session).map(|_| serde_json::json!({"disconnected": true}))
        }
        "memory_enqueue" => with_vault_write(session, |session| {
            enqueue_source(session, request.get("params"))
        }),
        _ => Err("unsupported method".into()),
    };
    match result {
        Ok(value) => serde_json::json!({"version": 1, "ok": true, "result": value}),
        Err(_) if method == "memory_enqueue" => unavailable("capture_unavailable"),
        Err(_) => unavailable("unavailable"),
    }
}

/// Bounded JSON-lines client entrypoint.  It deliberately fails closed until
/// the Windows current-user named-pipe broker is live; a stdin caller cannot
/// substitute a vault location or credential to bypass desktop ownership.
pub(crate) fn client_main() -> i32 {
    let input = match read_client_input(std::io::stdin().lock()) {
        Ok(value) => value,
        Err(_) => {
            println!("{}", unavailable("invalid_request"));
            return 1;
        }
    };
    println!("{}", client_response(&input));
    0
}
fn client_response(line: &str) -> Value {
    let value: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return unavailable("invalid_request"),
    };
    if value.get("version").and_then(Value::as_u64) != Some(1)
        || value.get("method").and_then(Value::as_str).is_none()
    {
        return unavailable("invalid_request");
    }
    let method = value["method"].as_str().unwrap();
    if !supported_method(method) {
        return unavailable("unsupported_method");
    }
    #[cfg(windows)]
    {
        pipe_request(value).unwrap_or_else(|_| unavailable("unavailable"))
    }
    #[cfg(not(windows))]
    {
        unavailable("unsupported")
    }
}
#[cfg(windows)]
fn broker_once(app: &AppHandle) {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX},
        System::Pipes::{
            DisconnectNamedPipe, PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_MESSAGE,
        },
    };
    let security = match pipe_security() {
        Ok(value) => value,
        Err(_) => {
            thread::sleep(PIPE_DEADLINE);
            return;
        }
    };
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.descriptor,
        bInheritHandle: 0,
    };
    let name = wide(PIPE_NAME);
    unsafe {
        let pipe = windows_sys::Win32::System::Pipes::CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_PIPE_WIRE_BYTES as u32,
            MAX_PIPE_WIRE_BYTES as u32,
            0,
            &attributes,
        );
        if pipe == INVALID_HANDLE_VALUE {
            return;
        }
        if wait_pipe_connection(pipe, Instant::now() + PIPE_DEADLINE) {
            if let Some(request) = read_pipe_message(pipe, Instant::now() + PIPE_DEADLINE) {
                let response = broker_response(app, &request).to_string();
                let _ =
                    write_pipe_message(pipe, response.as_bytes(), Instant::now() + PIPE_DEADLINE);
            }
            DisconnectNamedPipe(pipe);
        }
        CloseHandle(pipe);
    }
}

#[cfg(windows)]
fn wait_pipe_connection(pipe: windows_sys::Win32::Foundation::HANDLE, deadline: Instant) -> bool {
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING},
        System::Pipes::ConnectNamedPipe,
    };
    unsafe {
        loop {
            if ConnectNamedPipe(pipe, std::ptr::null_mut()) != 0 {
                return true;
            }
            let error = GetLastError();
            if error == ERROR_PIPE_CONNECTED {
                return true;
            }
            if error != ERROR_PIPE_LISTENING || Instant::now() >= deadline {
                return false;
            }
            thread::sleep(PIPE_POLL);
        }
    }
}

#[cfg(windows)]
fn read_pipe_message(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    deadline: Instant,
) -> Option<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_NO_DATA},
        Storage::FileSystem::ReadFile,
        System::Pipes::PeekNamedPipe,
    };
    let mut bytes = vec![0u8; MAX_PIPE_WIRE_BYTES];
    let mut total = 0usize;
    unsafe {
        loop {
            let mut available = 0u32;
            let mut left_in_message = 0u32;
            if PeekNamedPipe(
                pipe,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                &mut left_in_message,
            ) == 0
            {
                if GetLastError() == ERROR_NO_DATA && Instant::now() < deadline {
                    thread::sleep(PIPE_POLL);
                    continue;
                }
                return None;
            }
            if available == 0 {
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(PIPE_POLL);
                continue;
            }
            let room = MAX_PIPE_WIRE_BYTES - total;
            if available as usize > room || left_in_message as usize > room {
                return None;
            }
            let mut read = 0u32;
            if ReadFile(
                pipe,
                bytes[total..].as_mut_ptr(),
                available.min(room as u32),
                &mut read,
                std::ptr::null_mut(),
            ) == 0
                || read == 0
            {
                return None;
            }
            total += read as usize;
            if left_in_message == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return None;
            }
        }
    }
    bytes.truncate(total);
    Some(bytes)
}

#[cfg(windows)]
fn write_pipe_message(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    bytes: &[u8],
    deadline: Instant,
) -> bool {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    if bytes.len() > MAX_PIPE_WIRE_BYTES {
        return false;
    }
    let mut offset = 0usize;
    unsafe {
        while offset < bytes.len() {
            let mut written = 0u32;
            if WriteFile(
                pipe,
                bytes[offset..].as_ptr(),
                (bytes.len() - offset) as u32,
                &mut written,
                std::ptr::null_mut(),
            ) == 0
            {
                return false;
            }
            if written == 0 {
                if Instant::now() >= deadline {
                    return false;
                }
                thread::sleep(PIPE_POLL);
                continue;
            }
            offset += written as usize;
            if offset < bytes.len() && Instant::now() >= deadline {
                return false;
            }
        }
    }
    true
}

#[cfg(windows)]
fn server_process_is_expected(pipe: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FALSE},
        System::{
            Pipes::GetNamedPipeServerProcessId,
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };
    unsafe {
        let mut pid = 0u32;
        if GetNamedPipeServerProcessId(pipe, &mut pid) == 0 || pid == 0 {
            return false;
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if process.is_null() {
            return false;
        }
        let mut buffer = [0u16; 32_768];
        let mut size = buffer.len() as u32;
        let ok =
            QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut size)
                != 0;
        CloseHandle(process);
        if !ok || size == 0 {
            return false;
        }
        let actual = String::from_utf16_lossy(&buffer[..size as usize]);
        let expected = match std::env::current_exe() {
            Ok(value) => value,
            Err(_) => return false,
        };
        let actual = match fs::canonicalize(actual) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let expected = match fs::canonicalize(expected) {
            Ok(value) => value,
            Err(_) => return false,
        };
        actual
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.to_string_lossy())
    }
}

#[cfg(windows)]
fn pipe_request(request: Value) -> Result<Value, String> {
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
            INVALID_HANDLE_VALUE,
        },
        Storage::FileSystem::{CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING},
        System::Pipes::{
            SetNamedPipeHandleState, WaitNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_MESSAGE,
        },
    };
    let mut secret = broker_secret()?;
    unsafe {
        let name = wide(PIPE_NAME);
        if WaitNamedPipeW(
            name.as_ptr(),
            PIPE_DEADLINE.as_millis().min(u32::MAX as u128) as u32,
        ) == 0
            && GetLastError() != ERROR_PIPE_BUSY
        {
            secret.fill(0);
            return Err("memory service unavailable".into());
        }
        let pipe = CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        if pipe == INVALID_HANDLE_VALUE {
            secret.fill(0);
            return Err("memory service unavailable".into());
        }
        if !server_process_is_expected(pipe) {
            CloseHandle(pipe);
            secret.fill(0);
            return Err("memory service unavailable".into());
        }
        let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
        if SetNamedPipeHandleState(pipe, &mode, std::ptr::null(), std::ptr::null()) == 0 {
            CloseHandle(pipe);
            secret.fill(0);
            return Err("memory service unavailable".into());
        }
        let wire = serde_json::json!({"credential":BASE64_URL.encode(&secret),"request":request})
            .to_string();
        secret.fill(0);
        let mut sent = 0u32;
        if wire.len() > MAX_PIPE_WIRE_BYTES
            || WriteFile(
                pipe,
                wire.as_ptr(),
                wire.len() as u32,
                &mut sent,
                std::ptr::null_mut(),
            ) == 0
            || sent as usize != wire.len()
        {
            CloseHandle(pipe);
            return Err("memory service unavailable".into());
        }
        let response = match read_pipe_message(pipe, Instant::now() + PIPE_DEADLINE) {
            Some(value) => value,
            None => {
                CloseHandle(pipe);
                return Err("memory service unavailable".into());
            }
        };
        CloseHandle(pipe);
        serde_json::from_slice(&response).map_err(|_| "memory service unavailable".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn client_rejects_unknown_methods_without_echoing_input() {
        let response = client_response(r#"{"version":1,"method":"rm -rf"}"#);
        assert_eq!(response["error"]["code"], "unsupported_method");
    }
    #[test]
    fn secret_candidates_are_rejected_before_persistence() {
        let c = MemoryCandidateDto {
            id: "x".into(),
            kind: "fact".into(),
            title: "token".into(),
            body: "api_key=secret".into(),
            evidence: vec![MemoryEvidence {
                message_id: "m".into(),
                quote: "x".into(),
            }],
            source_kind: "user-stated".into(),
            sensitive: false,
            links: vec![],
            target_id: None,
            base_revision: None,
            created_at: String::new(),
        };
        assert!(validate_candidate(&c).is_err());
    }
    #[test]
    fn client_input_has_a_hard_total_limit_and_accepts_one_json_line() {
        let valid = br#"{"version":1,"method":"memory_status","params":{}}
"#;
        assert_eq!(
            read_client_input(Cursor::new(valid)).unwrap(),
            "{\"version\":1,\"method\":\"memory_status\",\"params\":{}}"
        );
        assert!(read_client_input(Cursor::new(vec![b'x'; MAX_CLIENT_BYTES + 1])).is_err());
        assert!(read_client_input(Cursor::new(b"{}\n{}\n")).is_err());
    }

    #[test]
    fn hook_queue_acceptance_is_post_enrollment_and_idempotent() {
        let mut control = MemoryControl {
            paired: true,
            enrolled_at: Some("2026-09-04T00:00:00.000Z".into()),
            ..MemoryControl::default()
        };
        let value = serde_json::json!({
            "version": 1,
            "event": "Stop",
            "sessionId": "session-1",
            "turnId": "turn-1",
            "transcriptPath": "C:\\synthetic\\rollout.jsonl",
            "createdAt": "2026-09-05T00:00:00.000Z"
        });
        let payload = parse_hook_payload(&value).unwrap();
        let first =
            enqueue_pointer(&mut control, payload.clone(), "2026-09-05T00:00:01.000Z").unwrap();
        assert_eq!(first["accepted"], true);
        assert_eq!(first["duplicate"], false);
        assert_eq!(control.queue.len(), 1);
        assert_eq!(control.queue[0].state, "pending");
        assert_eq!(
            control.queue[0].transcript_path,
            "C:\\synthetic\\rollout.jsonl"
        );

        let duplicate = enqueue_pointer(&mut control, payload, "2026-09-05T00:00:02.000Z").unwrap();
        assert_eq!(duplicate["accepted"], true);
        assert_eq!(duplicate["duplicate"], true);
        assert_eq!(control.queue.len(), 1);
    }

    #[test]
    fn hook_queue_rejects_content_traversal_and_pre_enrollment_records() {
        let mut control = MemoryControl {
            paired: true,
            enrolled_at: Some("2026-09-05T00:00:00.000Z".into()),
            ..MemoryControl::default()
        };
        let before = serde_json::json!({
            "version": 1,
            "event": "Stop",
            "sessionId": "session-1",
            "turnId": "turn-before",
            "transcriptPath": "C:\\synthetic\\rollout.jsonl",
            "createdAt": "2026-09-05T00:00:00.000Z"
        });
        let payload = parse_hook_payload(&before).unwrap();
        let skipped = enqueue_pointer(&mut control, payload, "2026-09-05T00:00:01.000Z").unwrap();
        assert_eq!(skipped["accepted"], false);
        assert_eq!(skipped["reason"], "before_enrollment");
        assert!(control.queue.is_empty());

        let mut traversal = before.clone();
        traversal["turnId"] = serde_json::json!("turn-traversal");
        traversal["transcriptPath"] = serde_json::json!("C:\\vault\\..\\outside.jsonl");
        assert!(parse_hook_payload(&traversal).is_err());
        traversal["transcriptPath"] = serde_json::json!("C:\\synthetic\\rollout.jsonl");
        traversal["text"] = serde_json::json!("raw transcript");
        assert!(parse_hook_payload(&traversal).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn broker_request_schema_rejects_unlisted_fields() {
        let valid = serde_json::json!({
            "version": 1,
            "method": "memory_search",
            "params": {"query": "tea", "limit": 5}
        });
        assert!(request_shape_is_valid(&valid));

        let mut extra = valid.clone();
        extra["vaultPath"] = serde_json::json!("C:\\\\private");
        assert!(!request_shape_is_valid(&extra));

        let bad_params = serde_json::json!({
            "version": 1,
            "method": "memory_status",
            "params": {"vaultPath": "C:\\\\private"}
        });
        assert!(!request_shape_is_valid(&bad_params));
    }

    /// A Windows user name may be non-ASCII, and it reaches LOCALAPPDATA,
    /// where the pairing secret lives.
    #[cfg(windows)]
    #[test]
    fn pairing_material_removal_is_verified_under_a_non_ascii_path() {
        let outer = std::env::temp_dir().join(format!("vault-brain-pairing-{}", Uuid::new_v4()));
        let dir = outer.join("Masaüstü").join("çğış-𝄞").join("VaultBrain");
        let text = dir.to_str().unwrap();
        assert!(!text.is_ascii());
        assert!(text.chars().any(|character| u32::from(character) > 0xFFFF));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("memory-client.v1.dpapi");
        fs::write(&path, b"protected pairing secret").unwrap();

        remove_pairing_file(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(
            fs::symlink_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        remove_pairing_file(&path).expect("a missing pairing file is not an error");

        // A removal that cannot remove is reported, and nothing is deleted.
        fs::create_dir(&path).unwrap();
        assert_eq!(
            remove_pairing_file(&path).unwrap_err(),
            "memory pairing material could not be removed"
        );
        assert!(path.is_dir());

        fs::remove_dir_all(&outer).unwrap();
        assert!(!outer.exists());
    }
}
