use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager};

const PROTOCOL_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Deserialize)]
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

fn read_response_limited(reader: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Desktop sync helper output could not be read.".to_string())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err("Desktop sync helper returned an oversized response.".into());
    }
    Ok(bytes)
}

fn validate_response(response: &Value, operation: &str) -> Result<Value, String> {
    if response.get("version").and_then(Value::as_u64) != Some(PROTOCOL_VERSION.into())
        || response.get("operation").and_then(Value::as_str) != Some(operation)
        || response.get("state").and_then(Value::as_str) != Some("complete")
    {
        return Err("Desktop sync helper returned an invalid response.".into());
    }
    response
        .get("result")
        .cloned()
        .ok_or("Desktop sync helper returned no result.".into())
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
    let mut command = Command::new(runtime);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
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
    let mut reader = Some(thread::spawn(move || read_response_limited(&mut stdout)));
    let mut output = None;
    // Writing may block if the helper stops consuming stdin. Keep cancellation
    // and the deadline live while the private writer is blocked.
    let writer = thread::spawn(move || {
        use zeroize::Zeroize;
        let mut body = body;
        let result = stdin.write_all(&body);
        body.zeroize();
        result
    });
    let started = Instant::now();
    let status = loop {
        if cancel.load(Ordering::Acquire) || started.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(reader) = reader.take() {
                let _ = reader.join();
            }
            let _ = writer.join();
            return Err("Desktop sync operation cancelled or timed out.".into());
        }
        if reader.as_ref().is_some_and(|reader| reader.is_finished()) {
            match reader.take().unwrap().join() {
                Ok(Ok(bytes)) => output = Some(bytes),
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = writer.join();
                    return Err(match result {
                        Ok(Err(error)) => error,
                        _ => "Desktop sync helper output reader failed.".into(),
                    });
                }
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(reader) = reader.take() {
                    let _ = reader.join();
                }
                let _ = writer.join();
                return Err(format!("Desktop sync helper did not finish: {error}"));
            }
        }
    };
    let stdout = match output {
        Some(bytes) => bytes,
        None => reader
            .take()
            .unwrap()
            .join()
            .map_err(|_| "Desktop sync helper output reader failed.")??,
    };
    writer
        .join()
        .map_err(|_| "Desktop sync helper input writer failed.")?
        .map_err(|_| "Could not send the desktop sync request.")?;
    let response: Value = serde_json::from_slice(&stdout)
        .map_err(|_| "Desktop sync helper returned an invalid response.")?;
    if !status.success() {
        return Err("Desktop sync helper rejected the operation.".into());
    }
    validate_response(&response, &request.operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_helper_responses_for_a_different_operation() {
        let response = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "operation": "pull",
            "state": "complete",
            "result": { "changes": 1 }
        });

        assert!(validate_response(&response, "push").is_err());
    }

    #[test]
    fn stops_reading_when_helper_output_exceeds_the_protocol_limit() {
        let mut input = std::io::Cursor::new(vec![0_u8; MAX_RESPONSE_BYTES + 1]);

        assert!(read_response_limited(&mut input).is_err());
    }
}
