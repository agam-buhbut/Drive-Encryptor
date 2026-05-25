//! Secret-input abstraction.
//!
//! `operations::*` accepts a `&dyn SecretPrompt` for any secret it would
//! otherwise read directly from the user. The CLI plugs in `TtyPrompt`
//! (rpassword-backed). The future Tauri GUI will plug in an IPC-backed prompt
//! that spawns a native OS dialog — webview JS never sees plaintext.
//!
//! See DESIGN §8.2.

use crate::errors::{Error, Result};
use crate::keymat::SecretBytes;
use crate::recovery_key::RecoveryKey;

/// Abstraction over "ask the user for a secret."
///
/// Implementations: `TtyPrompt` (CLI), eventual `IpcPrompt` (GUI).
pub trait SecretPrompt {
    /// Ask the user for the encryption passphrase.
    fn passphrase(&self, label: &str) -> Result<SecretBytes>;
    /// Ask the user for the printed recovery key (decoded into 32 bytes).
    fn recovery_key(&self, label: &str) -> Result<RecoveryKey>;
}

/// `SecretPrompt` whose answer is already known. Used by tests and by callers
/// who have read the secret out-of-band (e.g. `--passphrase-stdin`).
pub struct StaticPrompt {
    pub passphrase: Option<SecretBytes>,
    pub recovery_key: Option<RecoveryKey>,
}

impl StaticPrompt {
    pub fn from_passphrase(p: SecretBytes) -> Self {
        Self {
            passphrase: Some(p),
            recovery_key: None,
        }
    }
    pub fn from_recovery_key(k: RecoveryKey) -> Self {
        Self {
            passphrase: None,
            recovery_key: Some(k),
        }
    }
}

impl SecretPrompt for StaticPrompt {
    fn passphrase(&self, _label: &str) -> Result<SecretBytes> {
        self.passphrase
            .clone()
            .ok_or_else(|| Error::InvalidInput("no passphrase available in StaticPrompt".into()))
    }
    fn recovery_key(&self, _label: &str) -> Result<RecoveryKey> {
        self.recovery_key
            .clone()
            .ok_or_else(|| Error::InvalidInput("no recovery key available in StaticPrompt".into()))
    }
}

/// `SecretPrompt` that reads from a tty via `rpassword`. The CLI's default.
pub struct TtyPrompt;

impl SecretPrompt for TtyPrompt {
    fn passphrase(&self, label: &str) -> Result<SecretBytes> {
        let s = rpassword::prompt_password(format!("{}: ", label))
            .map_err(|e| Error::InvalidInput(format!("read passphrase: {}", e)))?;
        Ok(SecretBytes::from(s))
    }
    fn recovery_key(&self, label: &str) -> Result<RecoveryKey> {
        let s = rpassword::prompt_password(format!("{}: ", label))
            .map_err(|e| Error::InvalidInput(format!("read recovery key: {}", e)))?;
        RecoveryKey::decode(&s)
    }
}
