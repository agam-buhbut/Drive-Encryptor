//! Linux block-device subprocess helpers: GPT creation, FAT32 mkfs, mount/unmount.
//!
//! Like `veracrypt.rs`, these are thin wrappers around CLI tools. They exist
//! together because the format-and-encrypt flow uses them in sequence and we
//! want one set of subprocess hygiene rules.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::errors::{Error, Result};

// BLKRRPART = _IO(0x12, 95). The unsafe wrapper is generated at module scope
// because `ioctl_none!` expands to a function definition.
nix::ioctl_none!(blkrrpart_ioctl, 0x12, 95);

const SGDISK_CANDIDATES: &[&str] = &["/usr/sbin/sgdisk", "/sbin/sgdisk", "sgdisk"];
const MKFS_FAT_CANDIDATES: &[&str] = &["/usr/sbin/mkfs.fat", "/sbin/mkfs.fat", "mkfs.fat"];
const MOUNT_CANDIDATES: &[&str] = &["/usr/bin/mount", "/bin/mount", "mount"];
const UMOUNT_CANDIDATES: &[&str] = &["/usr/bin/umount", "/bin/umount", "umount"];
const PARTPROBE_CANDIDATES: &[&str] = &["/usr/sbin/partprobe", "/sbin/partprobe", "partprobe"];
const BLOCKDEV_CANDIDATES: &[&str] = &["/usr/sbin/blockdev", "/sbin/blockdev", "blockdev"];
const UDEVADM_CANDIDATES: &[&str] = &[
    "/usr/bin/udevadm",
    "/bin/udevadm",
    "/sbin/udevadm",
    "udevadm",
];

fn find(candidates: &[&str]) -> Result<PathBuf> {
    for c in candidates {
        if Path::new(c).is_file() {
            return Ok(PathBuf::from(c));
        }
    }
    // PATH lookup fallback for the bare names.
    if let Some(name) = candidates.last() {
        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(Error::DriveEnum(format!(
        "could not find any of: {}",
        candidates.join(", ")
    )))
}

fn run(prog: &Path, args: &[&str], on_err: impl Fn(String) -> Error) -> Result<()> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        return Err(on_err(format!(
            "{} {} → status {}: {}",
            prog.display(),
            args.join(" "),
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Wipe all partition table data on `device` and write a fresh GPT with
/// two partitions:
///   1. P1: `p1_size_bytes` aligned, type EBD0A0A2 (Microsoft basic data)
///   2. P2: rest of the disk, same type
///
/// Then signal the kernel to re-read the table.
pub fn write_gpt_two_partitions(device: &Path, p1_size_bytes: u64) -> Result<()> {
    let sgdisk = find(SGDISK_CANDIDATES)?;
    let device_str = device
        .to_str()
        .ok_or_else(|| Error::InvalidInput("device path is not valid UTF-8".into()))?;
    let p1_size_mib = p1_size_bytes / (1024 * 1024);
    if p1_size_mib < 1 {
        return Err(Error::InvalidInput("P1 size must be at least 1 MiB".into()));
    }
    // Not `sgdisk --zap-all`: on a stick that once held a hybrid ISO image
    // (corrupt primary GPT, valid backup) it zaps but exits 2, which used to
    // abort the run after the old table was already gone.
    wipe_partition_tables(device)?;
    // Two partitions: P1 = p1_size_mib MiB, P2 = rest.
    let p1_arg = format!("1:0:+{}M", p1_size_mib);
    let p1_type = "1:EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
    let p2_arg = "2:0:0";
    let p2_type = "2:EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
    let p1_label = "1:DENC-RECOVERY";
    let p2_label = "2:DENC-DATA";
    run(
        &sgdisk,
        &[
            "--clear",
            "--new",
            &p1_arg,
            "--typecode",
            p1_type,
            "--change-name",
            p1_label,
            "--new",
            p2_arg,
            "--typecode",
            p2_type,
            "--change-name",
            p2_label,
            device_str,
        ],
        |s| Error::DriveEnum(format!("sgdisk new: {}", s)),
    )?;
    force_partition_rescan(device);
    Ok(())
}

/// Zero the first and last MiB of `device`: MBR, primary GPT, backup GPT, and
/// ISO9660 / filesystem superblocks near the start all live there.
fn wipe_partition_tables(device: &Path) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    const SPAN: u64 = 1024 * 1024;
    let mut f = std::fs::OpenOptions::new().write(true).open(device)?;
    let total = f.seek(SeekFrom::End(0))?;
    let zeros = vec![0u8; SPAN.min(total) as usize];
    f.seek(SeekFrom::Start(0))?;
    f.write_all(&zeros)?;
    f.seek(SeekFrom::Start(total - zeros.len() as u64))?;
    f.write_all(&zeros)?;
    f.sync_all()?;
    Ok(())
}

/// Force the kernel to re-read `device`'s partition table. Belt-and-suspenders:
///   1. `BLKRRPART` ioctl — canonical kernel API; what `partprobe` and
///      `blockdev --rereadpt` both wrap. Most reliable on its own.
///      Retried on `EBUSY` (kernel may still hold refs from a recent umount).
///   2. `partprobe` (if installed) — also nudges udev to fire events.
///   3. `blockdev --rereadpt` — same kernel call as (1) but via util-linux.
///   4. `udevadm settle` — drain any queued device-node events so the new
///      partition nodes are visible to subsequent calls.
///
/// All four are best-effort; errors are tracing::warn-logged but not
/// propagated. Call after any tool that writes a partition table.
pub fn force_partition_rescan(device: &Path) {
    // BLKRRPART can briefly return EBUSY after a recent umount because the
    // kernel hasn't fully released the prior partition refs. Retry a few
    // times with a short sleep.
    let mut last_err: Option<Error> = None;
    for attempt in 0..5 {
        match blkrrpart(device) {
            Ok(()) => {
                last_err = None;
                break;
            }
            Err(e) => {
                tracing::debug!(attempt, error = %e, "BLKRRPART attempt failed");
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
    if let Some(e) = last_err {
        tracing::warn!(error = %e, "BLKRRPART ioctl gave up after retries");
    }

    let dev_str = device.to_string_lossy();
    if let Ok(partprobe) = find(PARTPROBE_CANDIDATES) {
        let _ = run(&partprobe, &[&dev_str], |s| {
            Error::DriveEnum(format!("partprobe: {}", s))
        });
    }
    if let Ok(blockdev) = find(BLOCKDEV_CANDIDATES) {
        let _ = run(&blockdev, &["--rereadpt", &dev_str], |s| {
            Error::DriveEnum(format!("blockdev --rereadpt: {}", s))
        });
    }
    // Drain udev event queue so newly-created partition nodes are visible.
    if let Ok(udevadm) = find(UDEVADM_CANDIDATES) {
        let _ = run(&udevadm, &["settle", "--timeout=5"], |s| {
            Error::DriveEnum(format!("udevadm settle: {}", s))
        });
    }
}

/// Fire the BLKRRPART ioctl on `device`. Internal; use `force_partition_rescan`
/// from outside this module — it composes BLKRRPART with the user-space
/// partprobe/blockdev fallbacks for maximum kernel-version coverage.
fn blkrrpart(device: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)?;
    let res = unsafe { blkrrpart_ioctl(f.as_raw_fd()) };
    match res {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::DriveEnum(format!(
            "BLKRRPART ioctl on {}: {}",
            device.display(),
            e
        ))),
    }
}

/// Create an empty FAT32 filesystem on `partition`. Label is "DENCRECOV"
/// (FAT label limit is 11 chars, alphanumeric).
pub fn mkfs_fat32(partition: &Path) -> Result<()> {
    let mkfs = find(MKFS_FAT_CANDIDATES)?;
    let partition_str = partition
        .to_str()
        .ok_or_else(|| Error::InvalidInput("partition path not UTF-8".into()))?;
    run(
        &mkfs,
        &["-F", "32", "-n", "DENCRECOV", partition_str],
        |s| Error::DriveEnum(format!("mkfs.fat: {}", s)),
    )
}

/// Compute the path to the `n`th partition of a disk.
/// Heuristic: if the disk name ends with a digit (loop0, mmcblk0, nvme0n1),
/// the partition is named with a "p" separator. Otherwise (sda, sdb), it's
/// just the digit appended.
pub fn partition_path(disk: &Path, n: u32) -> PathBuf {
    let name = disk.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let parent = disk.parent().unwrap_or_else(|| Path::new("/dev"));
    let suffix = if name
        .chars()
        .last()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("{}p{}", name, n)
    } else {
        format!("{}{}", name, n)
    };
    parent.join(suffix)
}

pub fn mount_ro(partition: &Path, mountpoint: &Path) -> Result<()> {
    wait_for_block_device(partition, std::time::Duration::from_secs(5))?;
    let mount = find(MOUNT_CANDIDATES)?;
    let part_str = partition.to_string_lossy();
    let mp_str = mountpoint.to_string_lossy();
    run(&mount, &["-o", "ro,noauto", &part_str, &mp_str], |s| {
        Error::DriveEnum(format!("mount ro: {}", s))
    })
}

pub fn mount_rw(partition: &Path, mountpoint: &Path) -> Result<()> {
    wait_for_block_device(partition, std::time::Duration::from_secs(5))?;
    let mount = find(MOUNT_CANDIDATES)?;
    let part_str = partition.to_string_lossy();
    let mp_str = mountpoint.to_string_lossy();
    run(&mount, &["-o", "rw,noauto", &part_str, &mp_str], |s| {
        Error::DriveEnum(format!("mount rw: {}", s))
    })
}

/// Poll until `path` exists as a block device. Used to bridge the gap between
/// `sgdisk` writing a new partition table and the kernel surfacing the
/// resulting device nodes (and the gap between rapid udev events that can
/// briefly remove a node from /dev).
pub fn wait_for_block_device(path: &Path, timeout: std::time::Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if path.exists() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::DriveEnum(format!(
                "kernel did not surface {} within {:?}",
                path.display(),
                timeout
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

pub fn umount(mountpoint: &Path) -> Result<()> {
    let umount = find(UMOUNT_CANDIDATES)?;
    let mp_str = mountpoint.to_string_lossy();
    run(&umount, &[&mp_str], |s| {
        Error::DriveEnum(format!("umount: {}", s))
    })
}

/// Unmount every mount whose source is `device` itself or one of its
/// partitions (`/dev/sda`, `/dev/sda1`, `/dev/sda2`, …). Used before
/// destructive operations to prevent
///
///   1. shred/sgdisk from corrupting an in-use filesystem, and
///   2. mkfs.fat from refusing because udisks2 auto-mounted the new
///      partition between `sgdisk` writing the GPT and our `mkfs.fat`.
///
/// No lazy (`umount -l`) fallback: a busy filesystem would stay live and keep
/// writing into the disk we are about to wipe, so we abort instead. udisks2
/// may re-auto-mount after we return — call this again right before each
/// step that expects an unmounted device.
pub fn unmount_drive_partitions(device: &Path) -> Result<()> {
    let umount = find(UMOUNT_CANDIDATES)?;
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    for line in mounts.lines() {
        let mut iter = line.split_whitespace();
        let (Some(src), Some(dst)) = (iter.next(), iter.next()) else {
            continue;
        };
        let src = unescape_mount_field(src);
        if !is_disk_or_its_partition(&src, device) {
            continue;
        }
        let dst = unescape_mount_field(dst);
        tracing::info!(src = %src.display(), dst = %dst.display(), "unmounting drive partition before destructive op");
        let out = Command::new(&umount)
            .arg(&dst)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        if !out.status.success() {
            return Err(Error::DriveEnum(format!(
                "umount {} failed: {} — close anything using the drive and retry",
                dst.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
    }
    // Drain udev events so udisks2 sees the unmount before any subsequent op.
    if let Ok(udevadm) = find(UDEVADM_CANDIDATES) {
        let _ = run(&udevadm, &["settle", "--timeout=5"], |s| {
            Error::DriveEnum(format!("udevadm settle: {}", s))
        });
    }
    Ok(())
}

/// True if `src` is `disk` itself or one of its partitions, decided by the
/// kernel's sysfs topology (`/sys/class/block/sdb1` → `.../block/sdb/sdb1`)
/// rather than name prefixes, which wrongly matched loop1 against loop10.
fn is_disk_or_its_partition(src: &Path, disk: &Path) -> bool {
    if src == disk {
        return true;
    }
    let (Some(src_name), Some(disk_name)) = (src.file_name(), disk.file_name()) else {
        return false;
    };
    src.parent() == disk.parent()
        && std::fs::canonicalize(Path::new("/sys/class/block").join(src_name))
            .ok()
            .is_some_and(|p| p.parent().and_then(|d| d.file_name()) == Some(disk_name))
}

/// Decode the octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash) that /proc/mounts uses in its device and mountpoint fields.
fn unescape_mount_field(s: &str) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b.get(i + 1..i + 4).filter(|d| {
            b[i] == b'\\'
                && (b'0'..=b'3').contains(&d[0])
                && d[1..].iter().all(|c| (b'0'..=b'7').contains(c))
        });
        if let Some(d) = octal {
            out.push((d[0] - b'0') * 64 + (d[1] - b'0') * 8 + (d[2] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    PathBuf::from(std::ffi::OsString::from_vec(out))
}

/// Overwrite `device` with cryptographically random bytes, end-to-end. Used
/// as the optional pre-shred step before `write_gpt_two_partitions` (DESIGN §4.2).
///
/// `progress` is called periodically with `(bytes_done, bytes_total)`. Caller
/// is responsible for converting that into UI/log output. We invoke it on
/// every chunk; the caller can throttle if it wants.
///
/// **Threat model honesty:** on SSD/NVMe, wear-levelling and the FTL mean a
/// single overwrite cannot guarantee that every physical cell is overwritten.
/// What this DOES guarantee is that the *logical* drive contents are random
/// and that ciphertext written afterwards is indistinguishable from prior
/// data on the unused regions of the volume — defeats most file-carving
/// recovery and frustrates "is this a freshly-created VeraCrypt volume?"
/// fingerprinting.
pub fn shred_device(device: &Path, mut progress: impl FnMut(u64, u64)) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)?;

    // Determine length via seek-to-end; works for block devices and files.
    let total = f.seek(SeekFrom::End(0))?;
    f.seek(SeekFrom::Start(0))?;
    if total == 0 {
        return Ok(());
    }

    const CHUNK: usize = 1024 * 1024; // 1 MiB
    let mut buf = vec![0u8; CHUNK];
    let mut done: u64 = 0;
    while done < total {
        let take = std::cmp::min(CHUNK as u64, total - done) as usize;
        getrandom::getrandom(&mut buf[..take]).map_err(|e| Error::Rng(e.to_string()))?;
        f.write_all(&buf[..take])?;
        done += take as u64;
        progress(done, total);
    }
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_path_simple_disk() {
        assert_eq!(
            partition_path(Path::new("/dev/sda"), 1),
            PathBuf::from("/dev/sda1")
        );
        assert_eq!(
            partition_path(Path::new("/dev/sdb"), 2),
            PathBuf::from("/dev/sdb2")
        );
    }

    #[test]
    fn shred_device_overwrites_contents() {
        // Use a regular file as a stand-in for a block device. shred_device
        // uses File::open + seek + write so this works.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img");
        // Pre-populate with a known repeating pattern so we can detect
        // any successful overwrite.
        let original = vec![0xAAu8; 4 * 1024 * 1024 + 7];
        std::fs::write(&path, &original).unwrap();

        let mut last_done = 0u64;
        let mut last_total = 0u64;
        shred_device(&path, |done, total| {
            last_done = done;
            last_total = total;
        })
        .unwrap();

        // Length unchanged.
        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), original.len());
        // Almost certainly differs from the all-0xAA pattern.
        assert_ne!(after, original);
        // Final progress callback saw the full length.
        assert_eq!(last_done, original.len() as u64);
        assert_eq!(last_total, original.len() as u64);
    }

    #[test]
    fn shred_device_zero_length_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        std::fs::write(&path, b"").unwrap();
        let mut called = false;
        shred_device(&path, |_, _| called = true).unwrap();
        assert!(!called, "progress should not be called for empty device");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn wipe_partition_tables_zeroes_head_and_tail_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img");
        let mib = 1024 * 1024;
        std::fs::write(&path, vec![0xAAu8; 4 * mib + 7]).unwrap();
        wipe_partition_tables(&path).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert_eq!(after.len(), 4 * mib + 7);
        assert!(after[..mib].iter().all(|&b| b == 0), "head not wiped");
        assert!(
            after[after.len() - mib..].iter().all(|&b| b == 0),
            "tail not wiped"
        );
        assert!(
            after[mib..after.len() - mib].iter().all(|&b| b == 0xAA),
            "middle touched"
        );

        // Smaller than one span: whole thing zeroed, no underflow.
        std::fs::write(&path, vec![0xAAu8; 1000]).unwrap();
        wipe_partition_tables(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![0u8; 1000]);
    }

    #[test]
    fn unescape_mount_field_decodes_proc_mounts_escapes() {
        assert_eq!(
            unescape_mount_field(r"/media/me/USB\040DISK"),
            PathBuf::from("/media/me/USB DISK")
        );
        assert_eq!(
            unescape_mount_field(r"a\011b\134c"),
            PathBuf::from("a\tb\\c")
        );
        assert_eq!(
            unescape_mount_field("/dev/sdb1"),
            PathBuf::from("/dev/sdb1")
        );
        // Incomplete or out-of-range escapes are left alone.
        assert_eq!(unescape_mount_field(r"x\04"), PathBuf::from(r"x\04"));
        assert_eq!(unescape_mount_field(r"x\777"), PathBuf::from(r"x\777"));
    }

    #[test]
    fn partition_path_p_suffix_devices() {
        assert_eq!(
            partition_path(Path::new("/dev/loop0"), 1),
            PathBuf::from("/dev/loop0p1")
        );
        assert_eq!(
            partition_path(Path::new("/dev/mmcblk0"), 2),
            PathBuf::from("/dev/mmcblk0p2")
        );
        assert_eq!(
            partition_path(Path::new("/dev/nvme0n1"), 3),
            PathBuf::from("/dev/nvme0n1p3")
        );
    }
}
