use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("recovery.bin: {0}")]
    Escrow(String),

    #[error("recovery key: {0}")]
    RecoveryKey(String),

    #[error("kdf failed: {0}")]
    Kdf(String),

    #[error(
        "aead authentication failed (wrong passphrase or recovery key, or corrupted recovery.bin)"
    )]
    AeadAuth,

    #[error("veracrypt: {0}")]
    VeraCrypt(String),

    #[error("veracrypt binary not found on PATH (install with: sudo apt install veracrypt)")]
    VeraCryptMissing,

    #[error("veracrypt subprocess exited with status {status}: {stderr}")]
    VeraCryptExit { status: i32, stderr: String },

    #[error("drive enumeration: {0}")]
    DriveEnum(String),

    #[error("refused to operate on system drive ({0})")]
    SystemDriveRefused(String),

    #[error("drive {device} is in use by another process")]
    DriveBusy { device: PathBuf },

    #[error("plan refused: {0}")]
    PlanRefused(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("operation cancelled by user")]
    Cancelled,

    #[error("crypto rng failed: {0}")]
    Rng(String),
}
