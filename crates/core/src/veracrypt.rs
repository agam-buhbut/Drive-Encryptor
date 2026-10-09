//! VeraCrypt subprocess driver.
//!
//! VeraCrypt is the underlying AES-256-XTS engine. Our app talks to it only
//! through this module. Secret material reaches VeraCrypt as a **keyfile path**
//! of the form `/proc/<our pid>/fd/<n>` pointing at an anonymous memfd — the
//! path itself is non-secret, so it's safe on argv. We never use VeraCrypt's `--password=<...>` with a real
//! password (would leak via /proc/<pid>/cmdline). Volumes are configured for
//! keyfile-only unlock by passing `--password=` (empty).

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
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

    pub fn mount(&self, device: &Path, keyfile: &MasterKeyfile, mountpoint: &Path) -> Result<()> {
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

/// The master keyfile handed to VeraCrypt. It lives in an anonymous,
/// close-on-exec memfd and is exposed only as `/proc/<our pid>/fd/<n>`, which
/// VeraCrypt (same uid) can open. Nothing is ever linked into a filesystem, so
/// a killed or panicking process (release builds use `panic = "abort"`) leaves
/// no plaintext key behind — the kernel frees the memfd with the last fd.
#[derive(Debug)]
pub struct MasterKeyfile {
    file: std::fs::File,
    path: PathBuf,
}

impl MasterKeyfile {
    pub fn write(master: &SecretBytes) -> Result<Self> {
        if master.len() != MASTER_KEY_LEN {
            return Err(Error::VeraCrypt(format!(
                "master must be {} bytes, got {}",
                MASTER_KEY_LEN,
                master.len()
            )));
        }
        let fd = memfd_create(c"denc-master", MemFdCreateFlag::MFD_CLOEXEC)
            .map_err(std::io::Error::from)?;
        let mut file = std::fs::File::from(fd);
        file.write_all(master.as_bytes())?;
        let path = PathBuf::from(format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            file.as_raw_fd()
        ));
        Ok(Self { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MasterKeyfile {
    fn drop(&mut self) {
        // Scrub the pages before the fd closes; nothing to unlink.
        let _ = self.file.write_all_at(&[0u8; MASTER_KEY_LEN], 0);
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
        let is_our_memfd = |p: &Path| {
            std::fs::read_link(p)
                .map(|t| t.to_string_lossy().starts_with("/memfd:denc-master"))
                .unwrap_or(false)
        };
        let path = {
            let kf = MasterKeyfile::write(&master).unwrap();
            // Readable through the path handed to VeraCrypt (a same-uid process).
            let read = std::fs::read(kf.path()).unwrap();
            assert_eq!(read, vec![0x77; MASTER_KEY_LEN]);
            // Backed by an anonymous memfd, never a named file on any filesystem.
            assert!(
                is_our_memfd(kf.path()),
                "{:?}",
                std::fs::read_link(kf.path())
            );
            kf.path().to_path_buf()
        };
        // After drop the fd is closed. Parallel tests may reuse the fd number,
        // so only assert it no longer refers to our memfd.
        assert!(
            !is_our_memfd(&path),
            "MasterKeyfile fd still open after drop"
        );
    }

    #[test]
    fn master_keyfile_rejects_wrong_size() {
        let bad = SecretBytes::new(vec![0; 32]);
        let err = MasterKeyfile::write(&bad).unwrap_err();
        assert!(matches!(err, Error::VeraCrypt(_)));
    }
}
