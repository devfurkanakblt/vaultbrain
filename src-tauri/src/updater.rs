use futures_util::future::{AbortHandle, Abortable};
use semver::Version;
use serde::Serialize;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_updater::{Update, UpdaterExt};

const UPDATE_EVENT: &str = "vaultbrain://update-state";
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_RELEASE_NOTES_CHARS: usize = 8_192;
const RELEASE_HOST: &str = "github.com";
const RELEASE_REPOSITORY_PATH: &str = "/devfurkanakblt/vaultbrain/releases/download/";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum UpdatePhase {
    #[default]
    Idle,
    Checking,
    UpToDate,
    Available,
    Downloading,
    Downloaded,
    Installing,
    Error,
}

impl UpdatePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Checking => "checking",
            Self::UpToDate => "upToDate",
            Self::Available => "available",
            Self::Downloading => "downloading",
            Self::Downloaded => "downloaded",
            Self::Installing => "installing",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateSnapshot {
    status: String,
    current_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    published_at: Option<String>,
    downloaded_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    can_cancel: bool,
}

#[derive(Default)]
struct UpdateController {
    phase: UpdatePhase,
    generation: u64,
    candidate: Option<Update>,
    downloaded: Option<Vec<u8>>,
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
    error: Option<String>,
    abort: Option<AbortHandle>,
}

pub(crate) struct UpdaterState {
    controller: Mutex<UpdateController>,
    install_gate: Arc<AtomicBool>,
}

impl Default for UpdaterState {
    fn default() -> Self {
        Self {
            controller: Mutex::new(UpdateController::default()),
            install_gate: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl UpdaterState {
    pub(crate) fn install_gate(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.install_gate)
    }

    pub(crate) fn installation_blocks_vault_access(&self) -> bool {
        self.install_gate.load(Ordering::Acquire)
    }
}

fn snapshot(controller: &UpdateController) -> UpdateSnapshot {
    let candidate = controller.candidate.as_ref();
    UpdateSnapshot {
        status: controller.phase.as_str().to_string(),
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        version: candidate.map(|update| update.version.clone()),
        notes: candidate.and_then(|update| {
            update
                .body
                .as_deref()
                .map(|notes| notes.chars().take(MAX_RELEASE_NOTES_CHARS).collect())
        }),
        published_at: candidate.and_then(|update| update.date.map(|date| date.to_string())),
        downloaded_bytes: controller.downloaded_bytes,
        total_bytes: controller.total_bytes,
        error: controller.error.clone(),
        can_cancel: controller.phase == UpdatePhase::Downloading,
    }
}

fn emit_snapshot(app: &AppHandle, value: &UpdateSnapshot) {
    let _ = app.emit(UPDATE_EVENT, value);
}

fn generic_failure(controller: &mut UpdateController, message: &str) -> UpdateSnapshot {
    controller.phase = UpdatePhase::Error;
    controller.abort = None;
    controller.downloaded = None;
    controller.downloaded_bytes = 0;
    controller.total_bytes = None;
    controller.error = Some(message.to_string());
    snapshot(controller)
}

fn update_operation_running(phase: UpdatePhase) -> bool {
    matches!(
        phase,
        UpdatePhase::Checking | UpdatePhase::Downloading | UpdatePhase::Installing
    )
}

fn download_or_signature_failure(controller: &mut UpdateController) -> UpdateSnapshot {
    generic_failure(
        controller,
        "The update download or signature verification failed.",
    )
}

fn is_supported_asset(asset: &str) -> bool {
    if asset.is_empty()
        || asset == "."
        || asset == ".."
        || asset.contains('/')
        || asset.contains('\\')
        || asset.chars().any(char::is_control)
    {
        return false;
    }
    #[cfg(target_os = "windows")]
    return asset.ends_with(".msi") || asset.ends_with("-setup.exe");
    #[cfg(target_os = "macos")]
    return asset.ends_with(".app.tar.gz");
    #[cfg(target_os = "linux")]
    return asset.ends_with(".deb");
    #[allow(unreachable_code)]
    false
}

fn validate_release_url(version: &str, url: &tauri::Url) -> Result<(), ()> {
    if url.scheme() != "https"
        || url.host_str() != Some(RELEASE_HOST)
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }

    let expected_prefix = format!("{RELEASE_REPOSITORY_PATH}v{version}/");
    let asset = url.path().strip_prefix(&expected_prefix).ok_or(())?;
    // Release artifact names generated by this project need no URL escapes other
    // than spaces. Rejecting every other escape keeps encoded separators and dot
    // segments out without accepting a second URL interpretation.
    let decoded_asset = asset.replace("%20", " ");
    if decoded_asset.contains('%') || !is_supported_asset(&decoded_asset) {
        return Err(());
    }
    Ok(())
}

fn validate_release_version(version: &str) -> Result<(), ()> {
    let current = Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| ())?;
    let offered = Version::parse(version).map_err(|_| ())?;
    if offered <= current || !offered.pre.is_empty() || !offered.build.is_empty() {
        return Err(());
    }
    Ok(())
}

fn validate_candidate(update: &Update) -> Result<(), ()> {
    validate_release_version(&update.version)?;
    validate_release_url(&update.version, &update.download_url)
}

#[tauri::command(async)]
pub(crate) fn update_status(state: State<'_, UpdaterState>) -> Result<UpdateSnapshot, String> {
    let controller = state
        .controller
        .lock()
        .map_err(|_| "update state unavailable".to_string())?;
    Ok(snapshot(&controller))
}

#[tauri::command(async)]
pub(crate) async fn check_for_update(
    app: AppHandle,
    state: State<'_, UpdaterState>,
) -> Result<UpdateSnapshot, String> {
    let generation = {
        let mut controller = state
            .controller
            .lock()
            .map_err(|_| "update state unavailable".to_string())?;
        if update_operation_running(controller.phase) {
            return Err("another update operation is already running".into());
        }
        controller.generation = controller.generation.wrapping_add(1);
        controller.phase = UpdatePhase::Checking;
        controller.candidate = None;
        controller.downloaded = None;
        controller.downloaded_bytes = 0;
        controller.total_bytes = None;
        controller.error = None;
        controller.abort = None;
        let value = snapshot(&controller);
        emit_snapshot(&app, &value);
        controller.generation
    };

    let result = match app.updater_builder().timeout(CHECK_TIMEOUT).build() {
        Ok(updater) => updater.check().await,
        Err(_) => {
            let mut controller = state
                .controller
                .lock()
                .map_err(|_| "update state unavailable".to_string())?;
            let value = generic_failure(
                &mut controller,
                "Update checking is not configured for this build.",
            );
            emit_snapshot(&app, &value);
            return Ok(value);
        }
    };

    let mut controller = state
        .controller
        .lock()
        .map_err(|_| "update state unavailable".to_string())?;
    if controller.generation != generation || controller.phase != UpdatePhase::Checking {
        return Err("update check was superseded".into());
    }
    let value = match result {
        Ok(Some(mut update)) if validate_candidate(&update).is_ok() => {
            update.timeout = Some(DOWNLOAD_TIMEOUT);
            controller.phase = UpdatePhase::Available;
            controller.candidate = Some(update);
            snapshot(&controller)
        }
        Ok(Some(_)) => generic_failure(&mut controller, "The update metadata was rejected."),
        Ok(None) => {
            controller.phase = UpdatePhase::UpToDate;
            snapshot(&controller)
        }
        Err(_) => generic_failure(&mut controller, "The update check failed."),
    };
    emit_snapshot(&app, &value);
    Ok(value)
}

#[tauri::command(async)]
pub(crate) async fn download_update(
    app: AppHandle,
    state: State<'_, UpdaterState>,
) -> Result<UpdateSnapshot, String> {
    let (generation, update, abort_registration) = {
        let mut controller = state
            .controller
            .lock()
            .map_err(|_| "update state unavailable".to_string())?;
        if controller.phase != UpdatePhase::Available && controller.phase != UpdatePhase::Error {
            return Err("no checked update is available for download".into());
        }
        let update = controller
            .candidate
            .clone()
            .ok_or_else(|| "no checked update is available for download".to_string())?;
        let (abort, registration) = AbortHandle::new_pair();
        controller.generation = controller.generation.wrapping_add(1);
        controller.phase = UpdatePhase::Downloading;
        controller.downloaded = None;
        controller.downloaded_bytes = 0;
        controller.total_bytes = None;
        controller.error = None;
        controller.abort = Some(abort);
        let value = snapshot(&controller);
        emit_snapshot(&app, &value);
        (controller.generation, update, registration)
    };

    let progress_app = app.clone();
    let result = Abortable::new(
        update.download(
            move |chunk, total| {
                let state = progress_app.state::<UpdaterState>();
                if let Ok(mut controller) = state.controller.lock() {
                    if controller.generation == generation
                        && controller.phase == UpdatePhase::Downloading
                    {
                        controller.downloaded_bytes =
                            controller.downloaded_bytes.saturating_add(chunk as u64);
                        controller.total_bytes = total;
                        let value = snapshot(&controller);
                        emit_snapshot(&progress_app, &value);
                    }
                };
            },
            || {},
        ),
        abort_registration,
    )
    .await;

    let mut controller = state
        .controller
        .lock()
        .map_err(|_| "update state unavailable".to_string())?;
    if controller.generation != generation || controller.phase != UpdatePhase::Downloading {
        return Ok(snapshot(&controller));
    }
    controller.abort = None;
    let value = match result {
        Ok(Ok(bytes)) => {
            controller.downloaded_bytes = bytes.len() as u64;
            controller.downloaded = Some(bytes);
            controller.phase = UpdatePhase::Downloaded;
            snapshot(&controller)
        }
        Err(_) => {
            controller.phase = UpdatePhase::Available;
            controller.downloaded_bytes = 0;
            controller.total_bytes = None;
            snapshot(&controller)
        }
        Ok(Err(_)) => download_or_signature_failure(&mut controller),
    };
    emit_snapshot(&app, &value);
    Ok(value)
}

#[tauri::command(async)]
pub(crate) fn cancel_update(
    app: AppHandle,
    state: State<'_, UpdaterState>,
) -> Result<UpdateSnapshot, String> {
    let mut controller = state
        .controller
        .lock()
        .map_err(|_| "update state unavailable".to_string())?;
    if controller.phase != UpdatePhase::Downloading {
        return Err("no update download is running".into());
    }
    if let Some(abort) = controller.abort.take() {
        abort.abort();
    }
    controller.generation = controller.generation.wrapping_add(1);
    controller.phase = UpdatePhase::Available;
    controller.downloaded = None;
    controller.downloaded_bytes = 0;
    controller.total_bytes = None;
    controller.error = None;
    let value = snapshot(&controller);
    emit_snapshot(&app, &value);
    Ok(value)
}

fn validate_install_preconditions(
    phase: UpdatePhase,
    vault_is_locked: bool,
    has_candidate: bool,
    has_downloaded: bool,
) -> Result<(), String> {
    if phase != UpdatePhase::Downloaded {
        return Err("a verified update must be downloaded before installation".into());
    }
    if !vault_is_locked {
        return Err("lock the vault before installing the update".into());
    }
    if !has_candidate || !has_downloaded {
        return Err("downloaded update state is incomplete".into());
    }
    Ok(())
}

pub(crate) fn begin_install(
    state: &UpdaterState,
    vault_is_locked: bool,
) -> Result<(Update, Vec<u8>), String> {
    let mut controller = state
        .controller
        .lock()
        .map_err(|_| "update state unavailable".to_string())?;
    validate_install_preconditions(
        controller.phase,
        vault_is_locked,
        controller.candidate.is_some(),
        controller.downloaded.is_some(),
    )?;
    // Preconditions above guarantee both values exist; keep the gate untouched
    // until after they have been obtained so a corrupt state cannot wedge vault
    // access closed.
    let update = controller
        .candidate
        .clone()
        .expect("candidate checked above");
    let bytes = controller
        .downloaded
        .take()
        .expect("download checked above");
    state.install_gate.store(true, Ordering::Release);
    controller.phase = UpdatePhase::Installing;
    controller.error = None;
    Ok((update, bytes))
}

pub(crate) fn fail_install(state: &UpdaterState) -> Result<UpdateSnapshot, String> {
    state.install_gate.store(false, Ordering::Release);
    let mut controller = state
        .controller
        .lock()
        .map_err(|_| "update state unavailable".to_string())?;
    Ok(generic_failure(
        &mut controller,
        "The update could not be installed.",
    ))
}

pub(crate) fn emit_current(
    app: &AppHandle,
    state: &UpdaterState,
) -> Result<UpdateSnapshot, String> {
    let controller = state
        .controller
        .lock()
        .map_err(|_| "update state unavailable".to_string())?;
    let value = snapshot(&controller);
    emit_snapshot(app, &value);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_assets_reject_paths_and_wrong_bundle_types() {
        assert!(!is_supported_asset("../Vault Brain.deb"));
        assert!(!is_supported_asset("nested/Vault Brain.deb"));
        assert!(!is_supported_asset("Vault Brain.exe.sig"));
        #[cfg(target_os = "windows")]
        assert!(is_supported_asset("Vault Brain_0.3.0_x64-setup.exe"));
        #[cfg(target_os = "macos")]
        assert!(is_supported_asset("Vault Brain.app.tar.gz"));
        #[cfg(target_os = "linux")]
        assert!(is_supported_asset("Vault Brain_0.3.0_amd64.deb"));
    }

    #[test]
    fn release_urls_are_bound_to_the_versioned_fixed_repository() {
        let asset = if cfg!(target_os = "windows") {
            "Vault%20Brain_0.3.0_x64-setup.exe"
        } else if cfg!(target_os = "macos") {
            "Vault%20Brain.app.tar.gz"
        } else {
            "Vault%20Brain_0.3.0_amd64.deb"
        };
        let valid = tauri::Url::parse(&format!(
            "https://github.com/devfurkanakblt/vaultbrain/releases/download/v0.3.0/{asset}"
        ))
        .unwrap();
        assert_eq!(validate_release_url("0.3.0", &valid), Ok(()));

        for rejected in [
            format!("http://github.com/devfurkanakblt/vaultbrain/releases/download/v0.3.0/{asset}"),
            format!("https://evil.example/devfurkanakblt/vaultbrain/releases/download/v0.3.0/{asset}"),
            format!("https://github.com/someone-else/vaultbrain/releases/download/v0.3.0/{asset}"),
            format!("https://github.com/devfurkanakblt/vaultbrain/releases/download/v9.9.9/{asset}"),
            format!("https://github.com/devfurkanakblt/vaultbrain/releases/download/v0.3.0/%2e%2e%2fsetup.deb"),
            format!("https://github.com/devfurkanakblt/vaultbrain/releases/download/v0.3.0/%5csetup.deb"),
            format!("https://github.com/devfurkanakblt/vaultbrain/releases/download/v0.3.0/{asset}?token=secret"),
            format!("https://github.com/devfurkanakblt/vaultbrain/releases/download/v0.3.0/{asset}#fragment"),
            format!("https://user@github.com/devfurkanakblt/vaultbrain/releases/download/v0.3.0/{asset}"),
        ] {
            let url = tauri::Url::parse(&rejected).unwrap();
            assert_eq!(validate_release_url("0.3.0", &url), Err(()), "accepted {rejected}");
        }
    }

    #[test]
    fn only_strict_stable_upgrades_are_accepted() {
        for rejected in [
            "not-semver",
            "0.1.9",
            "0.2.0",
            "0.3.0-beta.1",
            "0.3.0+rebuilt",
        ] {
            assert_eq!(
                validate_release_version(rejected),
                Err(()),
                "accepted {rejected}"
            );
        }
        assert_eq!(validate_release_version("0.3.0"), Ok(()));
    }

    #[test]
    fn install_preconditions_fail_closed_without_changing_the_gate() {
        let state = UpdaterState::default();
        for (phase, locked, candidate, downloaded) in [
            (UpdatePhase::Idle, true, false, false),
            (UpdatePhase::Available, true, true, false),
            (UpdatePhase::Downloaded, false, true, true),
            (UpdatePhase::Downloaded, true, false, true),
            (UpdatePhase::Downloaded, true, true, false),
        ] {
            assert!(validate_install_preconditions(phase, locked, candidate, downloaded).is_err());
            assert!(!state.installation_blocks_vault_access());
        }
        assert!(validate_install_preconditions(UpdatePhase::Downloaded, true, true, true).is_ok());
    }

    #[test]
    fn install_gate_is_fail_closed_and_released_after_failure() {
        let state = UpdaterState::default();
        state.install_gate.store(true, Ordering::Release);
        assert!(state.installation_blocks_vault_access());
        let value = fail_install(&state).unwrap();
        assert!(!state.installation_blocks_vault_access());
        assert_eq!(value.status, "error");
    }

    #[test]
    fn snapshots_never_make_non_download_operations_cancellable() {
        let mut controller = UpdateController::default();
        for phase in [
            UpdatePhase::Idle,
            UpdatePhase::Checking,
            UpdatePhase::Available,
            UpdatePhase::Downloaded,
            UpdatePhase::Installing,
            UpdatePhase::Error,
        ] {
            controller.phase = phase;
            assert!(!snapshot(&controller).can_cancel);
        }
        controller.phase = UpdatePhase::Downloading;
        assert!(snapshot(&controller).can_cancel);
    }

    #[test]
    fn check_refuses_every_overlapping_update_operation() {
        for phase in [
            UpdatePhase::Checking,
            UpdatePhase::Downloading,
            UpdatePhase::Installing,
        ] {
            assert!(update_operation_running(phase));
        }
        for phase in [
            UpdatePhase::Idle,
            UpdatePhase::UpToDate,
            UpdatePhase::Available,
            UpdatePhase::Downloaded,
            UpdatePhase::Error,
        ] {
            assert!(!update_operation_running(phase));
        }
    }

    #[test]
    fn download_or_signature_failure_discards_all_unverified_bytes() {
        let mut controller = UpdateController {
            phase: UpdatePhase::Downloading,
            downloaded: Some(vec![1, 2, 3]),
            downloaded_bytes: 3,
            total_bytes: Some(3),
            ..UpdateController::default()
        };
        let value = download_or_signature_failure(&mut controller);
        assert_eq!(controller.phase, UpdatePhase::Error);
        assert!(controller.downloaded.is_none());
        assert_eq!(value.downloaded_bytes, 0);
        assert_eq!(value.total_bytes, None);
        assert_eq!(
            value.error.as_deref(),
            Some("The update download or signature verification failed.")
        );
    }
}
