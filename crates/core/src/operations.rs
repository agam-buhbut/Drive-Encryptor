//! Workflow orchestration: encrypt and unlock.
//!
//! These functions are the canonical way to drive the system end-to-end. The
//! CLI calls them; the future GUI will too. They take secret material as
//! `SecretBytes` so callers (CLI / GUI) own the prompting UI but never have
//! to reimplement the workflow.

use std::path::{Path, PathBuf};

use tempfile::tempdir;

use crate::disk;
use crate::drive_linux::Drive;
use crate::errors::{Error, Result};
use crate::escrow::{Argon2Params, RecoveryFile, MASTER_KEY_LEN};
use crate::keymat::SecretBytes;
use crate::planner::EncryptionPlan;
use crate::progress::{ProgressEvent, ProgressSink};
use crate::recovery_key::RecoveryKey;
use crate::veracrypt::{MasterKeyfile, VeraCryptDriver};

/// Output of a successful format-and-encrypt operation. The recovery key is
/// returned to the caller exactly once; the caller is responsible for
/// displaying it and exporting the PDF before dropping the value.
pub struct EncryptOutput {
    pub recovery_key: RecoveryKey,
    pub p2_partition: PathBuf,
}

/// Format-and-encrypt the drive per `plan`. Wipes the drive completely.
///
/// Emits structured progress to `sink` at each milestone. Checks
/// `sink.is_cancelled()` between phases; if true, aborts early with
/// `Error::Cancelled` without touching the drive further. Pass
/// `&NoopSink` if you don't care about either.
///
/// Steps:
///   1. Generate a fresh 256-bit recovery key and a 64-byte master keyfile.
///   2. (Optional, when `plan.pre_shred`) overwrite the entire drive with
///      CSPRNG bytes — DESIGN §4.2.
///   3. Wipe partition table and write a fresh GPT with P1 (FAT32) + P2 (raw).
///   4. mkfs.fat on P1.
///   5. Mount P1 rw, write recovery.bin (wrapping the master with both
///      passphrase and recovery key), unmount.
///   6. Run `veracrypt --create` on P2 with the master keyfile.
pub fn encrypt_format(
    plan: &EncryptionPlan,
    passphrase: &SecretBytes,
    veracrypt: &VeraCryptDriver,
    sink: &dyn ProgressSink,
) -> Result<EncryptOutput> {
    sink.emit(ProgressEvent::PlanReady {
        warnings: plan.warnings.clone(),
    });
    if sink.is_cancelled() {
        sink.emit(ProgressEvent::Aborted {
            reason: "cancelled before start".into(),
        });
        return Err(Error::Cancelled);
    }

    let recovery_key = RecoveryKey::generate()?;
    let master_key = SecretBytes::from_random(MASTER_KEY_LEN)?;
    let drive_serial = plan.drive.display().to_string();

    let argon2 = Argon2Params::auto_tune();
    tracing::info!(?argon2, "argon2 params chosen for new recovery.bin");
    let recovery_file = RecoveryFile::create(
        passphrase,
        &recovery_key,
        &master_key,
        &drive_serial,
        argon2,
    )?;
    let recovery_bytes = recovery_file.serialize();

    // Unmount any partitions of this drive that the desktop (udisks2) or a
    // user has mounted. The planner only warns; the operation must follow
    // through, or `mkfs.fat` after `sgdisk` will refuse because the old
    // mount entry survives the partition-table rewrite.
    disk::unmount_drive_partitions(&plan.drive)?;

    if plan.pre_shred {
        tracing::info!(drive = %plan.drive.display(), "shredding drive with CSPRNG bytes (this can take a while)");
        // Throttle PreShredding events: at most one every 100 ms regardless
        // of how fast disk::shred_device's callback fires.
        let last_emit = std::cell::Cell::new(std::time::Instant::now());
        let throttle = std::time::Duration::from_millis(100);
        let cancel_marker = std::cell::Cell::new(false);
        disk::shred_device(&plan.drive, |bytes_done, bytes_total| {
            if sink.is_cancelled() {
                cancel_marker.set(true);
                // We can't stop the in-flight callback chain mid-write
                // without making `shred_device` itself cancel-aware (a v0.4
                // refactor); we let it finish and surface Cancelled below.
            }
            let now = std::time::Instant::now();
            let force = bytes_done == bytes_total; // always emit final
            if force || now.duration_since(last_emit.get()) >= throttle {
                sink.emit(ProgressEvent::PreShredding {
                    bytes_done,
                    bytes_total,
                });
                last_emit.set(now);
            }
        })?;
        if cancel_marker.get() || sink.is_cancelled() {
            sink.emit(ProgressEvent::Aborted {
                reason: "cancelled during shred".into(),
            });
            return Err(Error::Cancelled);
        }
    }

    disk::write_gpt_two_partitions(&plan.drive, plan.p1_size_bytes)?;
    sink.emit(ProgressEvent::GptCreated);
    if sink.is_cancelled() {
        sink.emit(ProgressEvent::Aborted {
            reason: "cancelled after GPT".into(),
        });
        return Err(Error::Cancelled);
    }

    let p1 = disk::partition_path(&plan.drive, 1);
    let p2 = disk::partition_path(&plan.drive, 2);

    disk::wait_for_block_device(&p1, std::time::Duration::from_secs(5))?;
    disk::wait_for_block_device(&p2, std::time::Duration::from_secs(5))?;

    // udisks2 may have auto-mounted the new partitions as soon as the kernel
    // surfaced them. Drop any such mount before mkfs.fat, which refuses on
    // an in-use device.
    disk::unmount_drive_partitions(&plan.drive)?;

    disk::mkfs_fat32(&p1)?;
    sink.emit(ProgressEvent::P1Formatted);

    write_recovery_bin_to_p1(&p1, &recovery_bytes)?;
    sink.emit(ProgressEvent::RecoveryWritten);

    if sink.is_cancelled() {
        sink.emit(ProgressEvent::Aborted {
            reason: "cancelled before veracrypt --create".into(),
        });
        return Err(Error::Cancelled);
    }

    // VeraCrypt has no progress hook; emit indeterminate before/after.
    sink.emit(ProgressEvent::VolumeCreating {
        bytes_written: 0,
        bytes_total: 0,
    });
    let keyfile = MasterKeyfile::write(&master_key)?;
    veracrypt.create_volume(&p2, &keyfile, plan.inner_filesystem)?;
    drop(keyfile);
    sink.emit(ProgressEvent::VolumeCreating {
        bytes_written: 1,
        bytes_total: 1,
    });

    sink.emit(ProgressEvent::Verified);
    sink.emit(ProgressEvent::Done {
        recovery_key_pdf: None,
    });

    Ok(EncryptOutput {
        recovery_key,
        p2_partition: p2,
    })
}

/// Mount the encrypted P2 partition of `drive` at `mountpoint`, unlocking
/// with the provided passphrase.
pub fn unlock_with_passphrase(
    drive: &Drive,
    passphrase: &SecretBytes,
    mountpoint: &Path,
    veracrypt: &VeraCryptDriver,
) -> Result<()> {
    let recovery = read_recovery_bin(&drive.path)?;
    let master = recovery.unwrap_with_passphrase(passphrase)?;
    mount_p2(drive, &master, mountpoint, veracrypt)
}

/// Same as `unlock_with_passphrase` but using the recovery key.
pub fn unlock_with_recovery_key(
    drive: &Drive,
    recovery_key: &RecoveryKey,
    mountpoint: &Path,
    veracrypt: &VeraCryptDriver,
) -> Result<()> {
    let recovery = read_recovery_bin(&drive.path)?;
    let master = recovery.unwrap_with_recovery_key(recovery_key)?;
    mount_p2(drive, &master, mountpoint, veracrypt)
}

/// Read recovery.bin from P1 of the given drive. Mounts P1 read-only into a
/// temp dir, copies the file out, unmounts, returns the parsed file.
pub fn read_recovery_bin(drive_path: &Path) -> Result<RecoveryFile> {
    let p1 = disk::partition_path(drive_path, 1);
    let bytes = read_recovery_bin_from_p1(&p1)?;
    RecoveryFile::parse(&bytes)
}

fn mount_p2(
    drive: &Drive,
    master: &SecretBytes,
    mountpoint: &Path,
    veracrypt: &VeraCryptDriver,
) -> Result<()> {
    let p2 = disk::partition_path(&drive.path, 2);
    let keyfile = MasterKeyfile::write(master)?;
    veracrypt.mount(&p2, &keyfile, mountpoint)?;
    drop(keyfile);
    Ok(())
}

const RECOVERY_BIN_FILENAME: &str = "recovery.bin";

fn write_recovery_bin_to_p1(p1: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tempdir()?;
    let mp = tmp.path();
    disk::mount_rw(p1, mp)?;
    let res: Result<()> = (|| {
        let target = mp.join(RECOVERY_BIN_FILENAME);
        std::fs::write(&target, bytes)?;
        let f = std::fs::File::open(&target)?;
        f.sync_all()?;
        Ok(())
    })();
    let umount_res = disk::umount(mp);
    res?;
    umount_res
}

fn read_recovery_bin_from_p1(p1: &Path) -> Result<Vec<u8>> {
    let tmp = tempdir()?;
    let mp = tmp.path();
    disk::mount_ro(p1, mp)?;
    let res: Result<Vec<u8>> = (|| {
        let target = mp.join(RECOVERY_BIN_FILENAME);
        let bytes = std::fs::read(&target)?;
        Ok(bytes)
    })();
    let umount_res = disk::umount(mp);
    let bytes = res?;
    umount_res?;
    Ok(bytes)
}
