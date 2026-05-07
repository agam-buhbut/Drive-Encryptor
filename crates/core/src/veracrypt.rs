//! VeraCrypt subprocess driver.
//!
//! VeraCrypt is the underlying AES-256-XTS engine. Our app talks to it only
//! through this module. Secret material reaches VeraCrypt as a **keyfile path**
//! pointing to a 0600 file under /dev/shm — the path itself is non-secret, so
//! it's safe on argv. We never use VeraCrypt's `--password=<...>` with a real
//! password (would leak via /proc/<pid>/cmdline). Volumes are configured for
//! keyfile-only unlock by passing `--password=` (empty).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

use crate::errors::{Error, Result};
use crate::escrow::MASTER_KEY_LEN;
use crate::keymat::SecretBytes;

#[derive(Debug, Clone, Copy)]
pub enum VeraCryptFilesystem {
    Exfat,
    Ntfs,
    /// Don't create a filesystem; caller will mkfs the mapped device themselves.
    None,
}

impl VeraCryptFilesystem {
    fn as_arg(self) -> &'static str {
        match self {
            Self::Exfat => "exfat",
            Self::Ntfs => "ntfs",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VeraCryptDriver {
    binary: PathBuf,
}

impl VeraCryptDriver {
    /// Locate `veracrypt` on PATH. Returns `Error::VeraCryptMissing` if absent.
    pub fn detect() -> Result<Self> {
        Self::detect_with_path(std::env::var_os("PATH").unwrap_or_default())
    }

    fn detect_with_path<P: AsRef<std::ffi::OsStr>>(path_var: P) -> Result<Self> {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("veracrypt");
            if candidate.is_file() {
                return Ok(Self { binary: candidate });
            }
        }
        Err(Error::VeraCryptMissing)
    }

    pub fn binary_path(&self) -> &Path {
        &self.binary
    }

    /// SHA-256 of the resolved binary. v0.1 logs this for traceability;
    /// v0.5 will compare against a vendored hash.
    pub fn binary_sha256(&self) -> Result<String> {
        let bytes = std::fs::read(&self.binary)?;
        let mut h = Sha256::new();
        h.update(&bytes);
        Ok(hex::encode(h.finalize()))
    }

    pub fn version(&self) -> Result<String> {
        let out = Command::new(&self.binary)
            .arg("--version")
            .stdin(Stdio::null())
            .output()?;
        if !out.status.success() {
            return Err(Error::VeraCryptExit {
                status: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Create an AES-256-XTS volume on `device` (e.g. /dev/sdX2 or /dev/loopNp2)
    /// with the given keyfile and inner filesystem. Always uses SHA-512 KDF
    /// and PIM=0 (VeraCrypt's defaults for max compatibility).
    pub fn create_volume(
        &self,
        device: &Path,
        keyfile: &MasterKeyfile,
        filesystem: VeraCryptFilesystem,
    ) -> Result<()> {
        let out = Command::new(&self.binary)
            .arg("--text")
            .arg("--create")
            .arg(device)
            .arg("--volume-type=normal")
            .arg("--encryption=AES")
            .arg("--hash=sha-512")
            .arg(format!("--filesystem={}", filesystem.as_arg()))
            .arg("--pim=0")
            .arg("--password=")
            .arg(format!("--keyfiles={}", keyfile.path().display()))
            .arg("--random-source=/dev/urandom")
            .arg("--quick")
            .arg("--non-interactive")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !out.status.success() {
            return Err(Error::VeraCryptExit {
                status: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(())
    }

    pub fn mount(
        &self,
        device: &Path,
        keyfile: &MasterKeyfile,
        mountpoint: &Path,
    ) -> Result<()> {
        let out = Command::new(&self.binary)
            .arg("--text")
            .arg("--non-interactive")
            .arg("--pim=0")
            .arg("--password=")
            .arg(format!("--keyfiles={}", keyfile.path().display()))
            .arg("--protect-hidden=no")
            .arg(device)
            .arg(mountpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !out.status.success() {
            return Err(Error::VeraCryptExit {
                status: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(())
    }

    pub fn dismount(&self, mountpoint_or_device: &Path) -> Result<()> {
        let out = Command::new(&self.binary)
            .arg("--text")
            .arg("--non-interactive")
            .arg("--dismount")
            .arg(mountpoint_or_device)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !out.status.success() {
            return Err(Error::VeraCryptExit {
                status: out.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        // VeraCrypt --dismount returns before the kernel finishes tearing down
        // the device-mapper node. A subsequent mount in the same slot will
        // fail with "device or resource busy" if we don't wait.
        std::thread::sleep(std::time::Duration::from_millis(500));
        Ok(())
    }
}

/// RAII guard for a master keyfile written to /dev/shm. Drops the file (with
/// best-effort overwrite) on scope exit.
#[derive(Debug)]
pub struct MasterKeyfile {
    path: PathBuf,
}

impl MasterKeyfile {
    /// Write the master to a 0600 file under /dev/shm with a random name.
    pub fn write(master: &SecretBytes) -> Result<Self> {
        if master.len() != MASTER_KEY_LEN {
            return Err(Error::VeraCrypt(format!(
                "master must be {} bytes, got {}",
                MASTER_KEY_LEN,
                master.len()
            )));
        }
        let mut name_rand = [0u8; 16];
        getrandom::getrandom(&mut name_rand).map_err(|e| Error::Rng(e.to_string()))?;
        let name = format!("denc-master-{}", hex::encode(name_rand));
        let path = PathBuf::from("/dev/shm").join(name);

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(master.as_bytes())?;
        f.sync_all()?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MasterKeyfile {
    fn drop(&mut self) {
        // Best-effort overwrite then unlink. If we can't open it, the file's
        // already gone or unwritable — either way, try to unlink.
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&self.path) {
            let _ = f.write_all(&[0u8; MASTER_KEY_LEN]);
            let _ = f.sync_all();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_missing_for_empty_path() {
        let err = VeraCryptDriver::detect_with_path("").unwrap_err();
        assert!(matches!(err, Error::VeraCryptMissing));
    }

    #[test]
    fn master_keyfile_write_and_drop() {
        let master = SecretBytes::new(vec![0x77; MASTER_KEY_LEN]);
        let path = {
            let kf = MasterKeyfile::write(&master).unwrap();
            assert!(kf.path().starts_with("/dev/shm"));
            assert!(kf.path().exists());
            // Permissions should be 0600.
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(kf.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            // Contents match.
            let read = std::fs::read(kf.path()).unwrap();
            assert_eq!(read, vec![0x77; MASTER_KEY_LEN]);
            kf.path().to_path_buf()
        };
        // After drop, file should be gone.
        assert!(!path.exists(), "MasterKeyfile not unlinked on drop");
    }

    #[test]
    fn master_keyfile_rejects_wrong_size() {
        let bad = SecretBytes::new(vec![0; 32]);
        let err = MasterKeyfile::write(&bad).unwrap_err();
        assert!(matches!(err, Error::VeraCrypt(_)));
    }
}
