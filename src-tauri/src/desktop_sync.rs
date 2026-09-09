use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use tauri::{AppHandle, Manager};

const PROTOCOL_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopSyncRequest {
    version: u8,
    operation: String,
    pub vault_path: String,
    passphrase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment_request: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_head_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HelperRequest<'a> {
    version: u8,
    operation: &'a str,
    vault_path: &'a str,
    passphrase: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment_request: &'a Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_head_id: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_type: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_id: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_url: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_token: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_fingerprint: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    checkpoint_id: &'a Option<String>,
}

fn helper_request(request: &DesktopSyncRequest) -> HelperRequest<'_> {
    HelperRequest {
        version: request.version,
        operation: &request.operation,
        vault_path: &request.vault_path,
        passphrase: &request.passphrase,
        device_name: &request.device_name,
        device_id: &request.device_id,
        enrollment_request: &request.enrollment_request,
        selected_head_id: &request.selected_head_id,
        object_type: &request.object_type,
        object_id: &request.object_id,
        relay_url: &request.relay_url,
        relay_token: &request.relay_token,
        authority_fingerprint: &request.authority_fingerprint,
        checkpoint_id: &request.checkpoint_id,
    }
}

fn helper_runtime(app: &AppHandle) -> Result<(PathBuf, PathBuf), String> {
    let root = app
        .path()
        .resource_dir()
        .map_err(|_| "desktop sync helper resources are unavailable")?
        .join("resources")
        .join("desktop-sync");
    let runtime = root.join(if cfg!(windows) { "node.exe" } else { "node" });
    let helper = root.join("dist").join("desktop-sync-helper.js");
    if !runtime.is_file() || !helper.is_file() {
        return Err("This desktop build does not contain the signed sync helper runtime.".into());
    }
    Ok((runtime, helper))
}

/// Runs only the app-packaged runtime at a fixed resource path. The helper's
/// single request is written to its private stdin; no credential reaches argv,
/// an environment variable, stdout diagnostics, or the frontend.
pub fn execute(
    app: &AppHandle,
    request: DesktopSyncRequest,
    cancel: &AtomicBool,
) -> Result<Value, String> {
    if request.version != PROTOCOL_VERSION {
        return Err("Unsupported desktop sync protocol version.".into());
    }
    if request.vault_path.is_empty()
        || request.passphrase.is_empty()
        || request.passphrase.len() > 4096
    {
        return Err("Invalid desktop sync request.".into());
    }
    let body = serde_json::to_vec(&helper_request(&request))
        .map_err(|_| "Could not encode desktop sync request.")?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err("Desktop sync request exceeds the protocol limit.".into());
    }
    cancel.store(false, Ordering::Release);
    let (runtime, helper) = helper_runtime(app)?;
    let mut child = Command::new(runtime)
        .arg(helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Could not launch the packaged desktop sync helper.")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("Could not open the helper's private input.")?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or("Could not open the helper's private output.")?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.read_to_end(&mut bytes);
        (result, bytes)
    });
    if let Err(error) = stdin.write_all(&body) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        return Err(format!("Could not send the desktop sync request: {error}"));
    }
    drop(stdin);

    let status = loop {
        if cancel.load(Ordering::Acquire) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err("Desktop sync operation cancelled.".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(format!("Desktop sync helper did not finish: {error}"));
            }
        }
    };
    let (read_result, stdout) = reader
        .join()
        .map_err(|_| "Desktop sync helper output reader failed.")?;
    read_result.map_err(|_| "Desktop sync helper output could not be read.")?;
    if stdout.len() > MAX_RESPONSE_BYTES {
        return Err("Desktop sync helper returned an oversized response.".into());
    }
    let response: Value = serde_json::from_slice(&stdout)
        .map_err(|_| "Desktop sync helper returned an invalid response.")?;
    if !status.success() {
        return Err("Desktop sync helper rejected the operation.".into());
    }
    let result = response
        .get("result")
        .cloned()
        .ok_or("Desktop sync helper returned no result.")?;
    Ok(result)
}
