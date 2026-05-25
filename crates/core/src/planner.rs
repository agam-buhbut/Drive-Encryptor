//! Pre-flight checks for an encryption operation.
//!
//! Hard refusals (DESIGN §6.2) raise `Error::*Refused` and cannot be overridden.
//! Soft warnings (DESIGN §6.3) are returned in the plan; the caller is
//! responsible for surfacing them and getting explicit confirmation.

use std::path::PathBuf;

use crate::drive_linux::Drive;
use crate::errors::{Error, Result};
use crate::veracrypt::VeraCryptFilesystem;

/// Minimum drive size we'll accept. Below this, P1 (10 MiB) plus VeraCrypt
/// metadata leaves no usable data area.
pub const MIN_DRIVE_BYTES: u64 = 100 * 1024 * 1024;
/// Size of the unencrypted FAT32 partition that holds recovery.bin.
pub const P1_SIZE_BYTES: u64 = 10 * 1024 * 1024;
/// Soft-warning threshold for "this will take a long time."
pub const LARGE_DRIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024; // 2 TiB

#[derive(Debug, Clone)]
pub struct EncryptionPlan {
    pub drive: PathBuf,
    pub mode: EncryptionMode,
    pub p1_size_bytes: u64,
    pub inner_filesystem: VeraCryptFilesystem,
    /// If true, overwrite the entire drive with CSPRNG bytes before laying out
    /// the new GPT. Defends against forensic recovery of pre-existing data
    /// (defeats most file-carving tools, makes ciphertext indistinguishable
    /// from random data even on the unused regions of the drive). Slow on
    /// large drives — see DESIGN §4.2.
    pub pre_shred: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum EncryptionMode {
    /// Wipe the drive and create an empty encrypted volume.
    Format,
}

/// Build an encryption plan for the given drive. The only mode is
/// "format-and-encrypt" (DESIGN §4.1); the optional `shred` flag adds a
/// CSPRNG overwrite pass before the GPT/VeraCrypt steps (DESIGN §4.2).
///
/// **Both options are destructive.** Existing data on the drive will be
/// unrecoverable. If the user wants to keep the drive's contents, they must
/// back them up themselves before running this.
pub fn format_and_encrypt(drive: &Drive, shred: bool) -> Result<EncryptionPlan> {
    if drive.is_system_drive() {
        return Err(Error::SystemDriveRefused(drive.path.display().to_string()));
    }
    if drive.readonly {
        return Err(Error::PlanRefused(format!(
            "{} is read-only",
            drive.path.display()
        )));
    }
    if drive.size_bytes < MIN_DRIVE_BYTES {
        return Err(Error::PlanRefused(format!(
            "{} is too small ({} bytes; minimum {} bytes)",
            drive.path.display(),
            drive.size_bytes,
            MIN_DRIVE_BYTES
        )));
    }

    let mut warnings = Vec::new();

    if drive.is_currently_mounted() {
        warnings.push(format!(
            "{}: at least one partition is currently mounted; will be unmounted",
            drive.path.display()
        ));
    }

    if drive.size_bytes >= LARGE_DRIVE_BYTES {
        let tib = drive.size_bytes as f64 / (1u64 << 40) as f64;
        warnings.push(format!(
            "{}: large drive ({:.2} TiB); encryption can take hours",
            drive.path.display(),
            tib
        ));
    }

    if shred && drive.size_bytes >= LARGE_DRIVE_BYTES {
        let tib = drive.size_bytes as f64 / (1u64 << 40) as f64;
        warnings.push(format!(
            "{}: --shred adds a {:.2} TiB CSPRNG overwrite pass on top; \
             expect this step alone to take many hours on spinning disks",
            drive.path.display(),
            tib
        ));
    }

    if !drive.removable {
        warnings.push(format!(
            "{}: non-removable (internal) drive; double-check this is the right device",
            drive.path.display()
        ));
    }

    let has_existing_veracrypt_signal = drive
        .partitions
        .iter()
        .any(|p| p.fstype.is_none() && p.size_bytes > 0);
    if has_existing_veracrypt_signal {
        warnings.push(format!(
            "{}: contains a partition with no recognizable filesystem; could be an existing VeraCrypt volume — re-encrypting will discard its key",
            drive.path.display()
        ));
    }

    Ok(EncryptionPlan {
        drive: drive.path.clone(),
        mode: EncryptionMode::Format,
        p1_size_bytes: P1_SIZE_BYTES,
        inner_filesystem: VeraCryptFilesystem::Exfat,
        pre_shred: shred,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drive_linux::{DriveKind, Partition};
    use std::path::PathBuf;

    fn fake_drive(
        path: &str,
        size: u64,
        removable: bool,
        readonly: bool,
        partitions: Vec<Partition>,
    ) -> Drive {
        Drive {
            path: PathBuf::from(path),
            kind: DriveKind::Disk,
            size_bytes: size,
            removable,
            readonly,
            serial: Some("TEST".into()),
            vendor: None,
            model: None,
            partitions,
        }
    }

    fn part(path: &str, size: u64, mountpoint: Option<&str>) -> Partition {
        Partition {
            path: PathBuf::from(path),
            size_bytes: size,
            fstype: Some("ext4".into()),
            mountpoint: mountpoint.map(String::from),
        }
    }

    #[test]
    fn refuses_system_drive() {
        let drive = fake_drive(
            "/dev/sda",
            500_000_000_000,
            false,
            false,
            vec![part("/dev/sda1", 500_000_000_000, Some("/"))],
        );
        let err = format_and_encrypt(&drive, false).unwrap_err();
        assert!(matches!(err, Error::SystemDriveRefused(_)));
    }

    #[test]
    fn refuses_readonly() {
        let drive = fake_drive("/dev/sdb", 16_000_000_000, true, true, vec![]);
        let err = format_and_encrypt(&drive, false).unwrap_err();
        assert!(matches!(err, Error::PlanRefused(s) if s.contains("read-only")));
    }

    #[test]
    fn refuses_too_small() {
        let drive = fake_drive("/dev/sdb", 50 * 1024 * 1024, true, false, vec![]);
        let err = format_and_encrypt(&drive, false).unwrap_err();
        assert!(matches!(err, Error::PlanRefused(s) if s.contains("too small")));
    }

    #[test]
    fn accepts_healthy_usb() {
        let drive = fake_drive(
            "/dev/sdb",
            16_000_000_000,
            true,
            false,
            vec![part("/dev/sdb1", 16_000_000_000, None)],
        );
        let plan = format_and_encrypt(&drive, false).unwrap();
        assert_eq!(plan.drive, PathBuf::from("/dev/sdb"));
        assert!(!plan.pre_shred);
        assert!(plan.warnings.is_empty(), "warnings: {:?}", plan.warnings);
    }

    #[test]
    fn shred_flag_propagates_to_plan() {
        let drive = fake_drive("/dev/sdb", 16_000_000_000, true, false, vec![]);
        let plan = format_and_encrypt(&drive, true).unwrap();
        assert!(plan.pre_shred);
    }

    #[test]
    fn warns_on_mounted_drive() {
        let drive = fake_drive(
            "/dev/sdb",
            16_000_000_000,
            true,
            false,
            vec![part("/dev/sdb1", 16_000_000_000, Some("/mnt/usb"))],
        );
        let plan = format_and_encrypt(&drive, false).unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("mounted")));
    }

    #[test]
    fn warns_on_large_drive() {
        let drive = fake_drive(
            "/dev/sdb",
            4 * 1024 * 1024 * 1024 * 1024,
            true,
            false,
            vec![],
        );
        let plan = format_and_encrypt(&drive, false).unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("large drive")));
    }

    #[test]
    fn shred_on_large_drive_adds_extra_warning() {
        let drive = fake_drive(
            "/dev/sdb",
            4 * 1024 * 1024 * 1024 * 1024,
            true,
            false,
            vec![],
        );
        let plan = format_and_encrypt(&drive, true).unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("--shred")));
    }

    #[test]
    fn warns_on_non_removable() {
        let drive = fake_drive(
            "/dev/sdb",
            500_000_000_000,
            false,
            false,
            vec![part("/dev/sdb1", 500_000_000_000, None)],
        );
        let plan = format_and_encrypt(&drive, false).unwrap();
        assert!(plan.warnings.iter().any(|w| w.contains("non-removable")));
    }
}
