//! Tauri command handlers — the IPC surface the webview calls.
//!
//! Mirrors the CLI subcommands but returns JSON-serializable structures for
//! the webview. Secrets travel via opaque tokens through `TokenStore`, NOT as
//! JS strings (with one documented deviation in `commit_passphrase`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use denc_core::{drive_linux, operations, pdf, planner, RecoveryKey, SecretBytes, VeraCryptDriver};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::secret_token::TokenStore;
use crate::sink::GuiSink;

#[derive(Clone)]
pub struct AppState {
    pub passphrase_tokens: TokenStore,
    pub recovery_key_tokens: TokenStore,
    pub cancel_flag: Arc<AtomicBool>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            passphrase_tokens: TokenStore::new(),
            recovery_key_tokens: TokenStore::new(),
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DriveInfo {
    pub path: String,
    pub size_bytes: u64,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub removable: bool,
    pub readonly: bool,
    pub is_system_drive: bool,
    pub display_summary: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionPlanSummary {
    pub drive_path: String,
    pub pre_shred: bool,
    pub warnings: Vec<String>,
    pub p1_size_bytes: u64,
    pub confirm_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResult {
    pub recovery_key_token: String,
    pub recovery_key_display: String,
    pub p2_partition: String,
    pub default_pdf_name: String,
}

// ---------- list_drives ----------

#[tauri::command]
pub fn list_drives() -> Result<Vec<DriveInfo>, String> {
    let drives = drive_linux::enumerate().map_err(|e| e.to_string())?;
    Ok(drives
        .into_iter()
        .map(|d| DriveInfo {
            path: d.path.display().to_string(),
            size_bytes: d.size_bytes,
            vendor: d.vendor.clone(),
            model: d.model.clone(),
            serial: d.serial.clone(),
            removable: d.removable,
            readonly: d.readonly,
            is_system_drive: d.is_system_drive(),
            display_summary: d.display_summary(),
        })
        .collect())
}

// ---------- plan_encrypt ----------

#[tauri::command]
pub fn plan_encrypt(path: String, shred: bool) -> Result<EncryptionPlanSummary, String> {
    let drives = drive_linux::enumerate().map_err(|e| e.to_string())?;
    let dev = std::path::PathBuf::from(&path);
    let drive = drive_linux::find_drive_by_path(&drives, &dev)
        .ok_or_else(|| format!("no drive found matching {}", path))?
        .clone();
    let plan = planner::format_and_encrypt(&drive, shred).map_err(|e| e.to_string())?;
    let confirm_token = drive
        .serial
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            drive
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string()
        });
    Ok(EncryptionPlanSummary {
        drive_path: plan.drive.display().to_string(),
        pre_shred: plan.pre_shred,
        warnings: plan.warnings,
        p1_size_bytes: plan.p1_size_bytes,
        confirm_token,
    })
}

// ---------- commit_passphrase ----------

/// Commit a webview-typed passphrase into the TokenStore. Returns an opaque
/// single-use token id.
///
/// **§8.2 deviation:** the passphrase travels from the webview's `<input
/// type=password>` through Tauri IPC as a JS string. The original DESIGN.md
/// §8.2 specifies a Rust-spawned native dialog so plaintext never lives in
/// JS. The wired-up GUI relaxes this for UX (user-visible "type twice to
/// confirm" fields). A future hardened-mode could fall back to
/// `request_passphrase` (still in this file) which spawns zenity from Rust.
#[tauri::command]
pub fn commit_passphrase(passphrase: String, state: State<'_, AppState>) -> Result<String, String> {
    let secret = SecretBytes::from(passphrase);
    state
        .passphrase_tokens
        .insert(secret)
        .map_err(|e| e.to_string())
}

// ---------- commit_recovery_key ----------

/// Decode and validate a webview-typed recovery key, then store it as a
/// single-use token. Returns the token id.
#[tauri::command]
pub fn commit_recovery_key(encoded: String, state: State<'_, AppState>) -> Result<String, String> {
    let key = RecoveryKey::decode(&encoded).map_err(|e| e.to_string())?;
    let bytes = SecretBytes::new(key.as_bytes().to_vec());
    state
        .recovery_key_tokens
        .insert(bytes)
        .map_err(|e| e.to_string())
}

// ---------- request_passphrase (retained for native-dialog mode) ----------

/// Spawn a native passphrase dialog (zenity / kdialog) from the Rust shell.
/// Returns the resulting token id, or `None` if the user cancelled.
///
/// Currently unused by the wired GUI (the wizard uses `commit_passphrase`),
/// but kept available for a future "hardened mode" toggle.
#[tauri::command]
pub async fn request_passphrase(
    label: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    let secret = crate::passphrase::prompt_passphrase(&label)
        .await
        .map_err(|e| e.to_string())?;
    let Some(secret) = secret else {
        return Ok(None);
    };
    let id = state
        .passphrase_tokens
        .insert(secret)
        .map_err(|e| e.to_string())?;
    Ok(Some(id))
}

// ---------- start_encrypt ----------

#[tauri::command]
pub async fn start_encrypt(
    drive_path: String,
    shred: bool,
    passphrase_token: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<EncryptResult, String> {
    let passphrase = state
        .passphrase_tokens
        .take(&passphrase_token)
        .ok_or_else(|| "passphrase token expired or already used".to_string())?;

    state.cancel_flag.store(false, Ordering::SeqCst);

    let drives = drive_linux::enumerate().map_err(|e| e.to_string())?;
    let dev = std::path::PathBuf::from(&drive_path);
    let drive = drive_linux::find_drive_by_path(&drives, &dev)
        .ok_or_else(|| format!("drive {} disappeared", drive_path))?
        .clone();
    let plan = planner::format_and_encrypt(&drive, shred).map_err(|e| e.to_string())?;

    let veracrypt = VeraCryptDriver::detect().map_err(|e| e.to_string())?;
    let sink = GuiSink::new(app.clone(), state.cancel_flag.clone());
    let recovery_tokens = state.recovery_key_tokens.clone();

    let out = tokio::task::spawn_blocking(move || {
        operations::encrypt_format(&plan, &passphrase, &veracrypt, &sink)
    })
    .await
    .map_err(|e| format!("encrypt task join: {}", e))?
    .map_err(|e| e.to_string())?;

    let display = out.recovery_key.encode_for_display();
    let key_bytes = SecretBytes::new(out.recovery_key.as_bytes().to_vec());
    let key_token = recovery_tokens
        .insert(key_bytes)
        .map_err(|e| e.to_string())?;

    let dev_name = dev
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("drive")
        .to_string();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let default_pdf_name = format!("recovery-{}-{}.pdf", dev_name, ts);

    Ok(EncryptResult {
        recovery_key_token: key_token,
        recovery_key_display: display,
        p2_partition: out.p2_partition.display().to_string(),
        default_pdf_name,
    })
}

// ---------- start_unlock ----------

#[tauri::command]
pub async fn start_unlock(
    drive_path: String,
    secret_token: String,
    kind: String, // "passphrase" | "recovery_key"
    mountpoint: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let drives = drive_linux::enumerate().map_err(|e| e.to_string())?;
    let dev = std::path::PathBuf::from(&drive_path);
    let drive = drive_linux::find_drive_by_path(&drives, &dev)
        .ok_or_else(|| format!("no drive found matching {}", drive_path))?
        .clone();
    let veracrypt = VeraCryptDriver::detect().map_err(|e| e.to_string())?;
    let mp = std::path::PathBuf::from(&mountpoint);
    if !mp.exists() {
        std::fs::create_dir_all(&mp)
            .map_err(|e| format!("create mountpoint {}: {}", mountpoint, e))?;
    }
    if !mp.is_dir() {
        return Err(format!("mountpoint {} is not a directory", mountpoint));
    }

    match kind.as_str() {
        "passphrase" => {
            let passphrase = state
                .passphrase_tokens
                .take(&secret_token)
                .ok_or_else(|| "passphrase token expired or already used".to_string())?;
            tokio::task::spawn_blocking(move || {
                operations::unlock_with_passphrase(&drive, &passphrase, &mp, &veracrypt)
            })
            .await
            .map_err(|e| format!("unlock task join: {}", e))?
            .map_err(|e| e.to_string())?;
        }
        "recovery_key" => {
            let raw = state
                .recovery_key_tokens
                .take(&secret_token)
                .ok_or_else(|| "recovery-key token expired or already used".to_string())?;
            if raw.len() != 32 {
                return Err("recovery-key buffer wrong length".into());
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(raw.as_bytes());
            let key = RecoveryKey::from_bytes(bytes);
            tokio::task::spawn_blocking(move || {
                operations::unlock_with_recovery_key(&drive, &key, &mp, &veracrypt)
            })
            .await
            .map_err(|e| format!("unlock task join: {}", e))?
            .map_err(|e| e.to_string())?;
        }
        other => return Err(format!("unknown unlock kind: {}", other)),
    }
    Ok(())
}

// ---------- dismount ----------

#[tauri::command]
pub async fn dismount(mountpoint: String) -> Result<(), String> {
    let veracrypt = VeraCryptDriver::detect().map_err(|e| e.to_string())?;
    let mp = std::path::PathBuf::from(mountpoint);
    tokio::task::spawn_blocking(move || veracrypt.dismount(&mp))
        .await
        .map_err(|e| format!("dismount task join: {}", e))?
        .map_err(|e| e.to_string())
}

// ---------- pick_folder ----------

/// Native folder picker (rfd). Returns the picked path or `None` if cancelled.
#[tauri::command]
pub async fn pick_folder() -> Result<Option<String>, String> {
    let picked = rfd::AsyncFileDialog::new()
        .set_title("Choose mountpoint")
        .pick_folder()
        .await;
    Ok(picked.map(|h| h.path().display().to_string()))
}

// ---------- save_recovery_pdf ----------

/// Native save-file dialog (rfd). If the user picks a path, write the
/// recovery-key PDF and return the path. If the user cancels, return `None`.
#[tauri::command]
pub async fn save_recovery_pdf(
    recovery_key_token: String,
    drive_label: String,
    default_name: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    // Pop the dialog FIRST so a user-cancel doesn't consume the token.
    let picked = rfd::AsyncFileDialog::new()
        .set_title("Save recovery key PDF")
        .set_file_name(&default_name)
        .add_filter("PDF", &["pdf"])
        .save_file()
        .await;
    let Some(handle) = picked else {
        return Ok(None);
    };
    let path = handle.path().to_path_buf();

    let secret = state
        .recovery_key_tokens
        .take(&recovery_key_token)
        .ok_or_else(|| "recovery-key token expired or already used".to_string())?;
    if secret.len() != 32 {
        return Err("recovery key buffer wrong length".into());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(secret.as_bytes());
    let key = RecoveryKey::from_bytes(bytes);
    pdf::export_recovery_pdf(&path, &key, &drive_label, std::time::SystemTime::now())
        .map_err(|e| e.to_string())?;
    Ok(Some(path.display().to_string()))
}

// ---------- cancel ----------

#[tauri::command]
pub fn cancel(state: State<'_, AppState>) -> Result<(), String> {
    state.cancel_flag.store(true, Ordering::SeqCst);
    state.passphrase_tokens.clear();
    Ok(())
}

#[allow(dead_code)]
fn default_pdf_path(device: &std::path::Path) -> PathBuf {
    let dev_name = device
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("drive");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PathBuf::from(format!("./recovery-{}-{}.pdf", dev_name, ts))
}
