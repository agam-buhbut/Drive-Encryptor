//! Native passphrase prompt. The webview never sees plaintext.
//!
//! Strategy:
//!   1. Try `zenity --password` if it's on PATH (most reliable on Linux).
//!   2. Fall back to `kdialog --password` if zenity is missing.
//!   3. If neither exists, return an error pointing at zenity install.
//!
//! `rfd` 0.15 does not expose a native password-input dialog; it's geared at
//! file/folder pickers. We deliberately do NOT roll our own GTK to avoid
//! pulling additional system deps.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use denc_core::SecretBytes;
use tokio::process::Command;

/// Prompt the user for a passphrase. Returns `None` if the user cancelled.
pub async fn prompt_passphrase(label: &str) -> Result<Option<SecretBytes>> {
    if let Some(path) = which("zenity") {
        return zenity(&path, label).await;
    }
    if let Some(path) = which("kdialog") {
        return kdialog(&path, label).await;
    }
    Err(anyhow!(
        "no native password dialog available — install `zenity` (`sudo apt install zenity`) and try again"
    ))
}

async fn zenity(path: &Path, label: &str) -> Result<Option<SecretBytes>> {
    let out = Command::new(path)
        .args(["--password", "--title", "DriveEncryptor", "--text", label])
        .output()
        .await
        .context("spawning zenity")?;
    match out.status.code() {
        Some(0) => {
            let mut s = String::from_utf8(out.stdout).context("zenity stdout not utf-8")?;
            // zenity appends a trailing newline.
            while matches!(s.chars().last(), Some('\n') | Some('\r')) {
                s.pop();
            }
            Ok(Some(SecretBytes::from(s)))
        }
        Some(1) => Ok(None), // user cancelled
        Some(other) => Err(anyhow!(
            "zenity exited with status {}: {}",
            other,
            String::from_utf8_lossy(&out.stderr)
        )),
        None => Err(anyhow!("zenity terminated by signal")),
    }
}

async fn kdialog(path: &Path, label: &str) -> Result<Option<SecretBytes>> {
    let out = Command::new(path)
        .args(["--password", label])
        .output()
        .await
        .context("spawning kdialog")?;
    match out.status.code() {
        Some(0) => {
            let mut s = String::from_utf8(out.stdout).context("kdialog stdout not utf-8")?;
            while matches!(s.chars().last(), Some('\n') | Some('\r')) {
                s.pop();
            }
            Ok(Some(SecretBytes::from(s)))
        }
        Some(_) => Ok(None),
        None => Err(anyhow!("kdialog terminated by signal")),
    }
}

fn which(prog: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(prog);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
