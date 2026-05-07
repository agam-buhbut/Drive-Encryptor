//! Privileged end-to-end integration test using a loop-mounted disk image.
//!
//! Both tests are `#[ignore]` because they need root + several CLI tools.
//!
//! Run with:
//!   cargo build --workspace
//!   sudo -E DENC_ALLOW_LOOP=1 cargo test --test losetup_e2e -- --ignored --nocapture
//!
//! Required tools on PATH: veracrypt, sgdisk, mkfs.fat, losetup, mount, umount.
//! Required env: DENC_ALLOW_LOOP=1 (so the planner accepts /dev/loopN).

use std::path::{Path, PathBuf};
use std::process::Command;

use denc_core::{
    disk, drive_linux, operations, planner, veracrypt::VeraCryptDriver, RecoveryKey, SecretBytes,
};

const TEST_PASSPHRASE: &str = "integration-test-passphrase-do-not-use-in-prod";

#[allow(dead_code)] // kept around for future debugging sessions
fn dump_state(label: &str, loop_dev: &Path) {
    eprintln!("---- state: {label} ----");
    let _ = Command::new("losetup")
        .args(["--list"])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    let prefix = loop_dev
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "loop0".into());
    let _ = Command::new("sh")
        .args(["-c", &format!("ls -la /dev/{}* 2>&1", prefix)])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    eprintln!("---- end state ----");
}

fn must_run(prog: &str, args: &[&str]) -> std::process::Output {
    let out = Command::new(prog).args(args).output().unwrap_or_else(|e| {
        panic!("failed to launch {} {:?}: {}", prog, args, e);
    });
    if !out.status.success() {
        panic!(
            "{} {:?} failed: stderr={} stdout={}",
            prog,
            args,
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
    }
    out
}

struct LoopGuard {
    dev: String,
}
impl Drop for LoopGuard {
    fn drop(&mut self) {
        // Best-effort detach; ignore failures.
        let _ = Command::new("losetup").args(["-d", &self.dev]).status();
    }
}

/// VeraCrypt 1.26.x's `--create` detaches the underlying loop device as part
/// of its internal cleanup, even when we pass a partition path. This breaks
/// every subsequent step of a loopback test. Real USB sticks don't have this
/// problem (they're not loop devices), so the workaround lives in the test
/// only: after each VeraCrypt operation, re-attach the loop if needed.
fn ensure_loop_attached(loop_dev: &Path, backing_file: &Path) {
    if is_loop_attached(loop_dev) {
        return;
    }
    eprintln!(
        "[test] VeraCrypt detached {}; re-attaching → {}",
        loop_dev.display(),
        backing_file.display()
    );
    let status = Command::new("losetup")
        .args([
            "--partscan",
            &loop_dev.to_string_lossy(),
            &backing_file.to_string_lossy(),
        ])
        .status()
        .expect("losetup --partscan");
    assert!(status.success(), "losetup re-attach failed");
    let p1 = denc_core::disk::partition_path(loop_dev, 1);
    for _ in 0..50 {
        if p1.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!(
        "partition node {} did not appear within 5s after re-attach",
        p1.display()
    );
}

fn is_loop_attached(loop_dev: &Path) -> bool {
    let out = Command::new("losetup")
        .args(["--list", "--noheadings", "-O", "NAME"])
        .output();
    let Ok(out) = out else { return false };
    let s = String::from_utf8_lossy(&out.stdout);
    let target = loop_dev.to_string_lossy();
    s.lines().any(|l| l.trim() == target)
}

fn make_image_and_loop(img_path: &Path, size_mib: u64) -> (PathBuf, LoopGuard) {
    let img_str = img_path.to_str().unwrap();
    must_run(
        "dd",
        &[
            "if=/dev/zero",
            &format!("of={}", img_str),
            "bs=1M",
            "count=0",
            &format!("seek={}", size_mib),
        ],
    );
    let out = must_run("losetup", &["--find", "--show", "--partscan", img_str]);
    let dev = String::from_utf8(out.stdout).unwrap().trim().to_string();
    (PathBuf::from(&dev), LoopGuard { dev })
}

fn unwrap_binary_path() -> PathBuf {
    // crates/cli/tests/... → workspace target/{debug,release}/denc-unwrap.
    // Try debug first; fall back to release if PROFILE says so.
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest).join("..").join("..");
    for profile in &["debug", "release"] {
        let candidate = workspace_root
            .join("target")
            .join(profile)
            .join("denc-unwrap");
        if candidate.is_file() {
            return candidate
                .canonicalize()
                .unwrap_or_else(|_| candidate.clone());
        }
    }
    panic!(
        "denc-unwrap binary not found in workspace target/. Run `cargo build --workspace` first."
    );
}

#[test]
#[ignore]
fn full_pipeline_loopback() {
    // SAFETY: in a test, we accept the env-var write race; the test is
    // single-threaded re: this var.
    unsafe {
        std::env::set_var("DENC_ALLOW_LOOP", "1");
    }

    let img_dir = tempfile::tempdir().unwrap();
    let img_path = img_dir.path().join("test.img");
    let (loop_dev, _guard) = make_image_and_loop(&img_path, 256);
    eprintln!("loop device: {}", loop_dev.display());

    let drives = drive_linux::enumerate().unwrap();
    let drive = drive_linux::find_drive_by_path(&drives, &loop_dev)
        .unwrap_or_else(|| {
            panic!(
                "loop device {} not enumerated (is DENC_ALLOW_LOOP=1?)",
                loop_dev.display()
            )
        })
        .clone();

    let plan = planner::format_and_encrypt(&drive, false).unwrap();
    let veracrypt = VeraCryptDriver::detect().unwrap();
    eprintln!("veracrypt: {}", veracrypt.binary_path().display());

    let passphrase = SecretBytes::from(TEST_PASSPHRASE);
    let out = operations::encrypt_format(&plan, &passphrase, &veracrypt, &denc_core::NoopSink).unwrap();
    let recovery_encoded = out.recovery_key.encode();
    eprintln!("recovery key: {}", recovery_encoded);
    drop(out);
    ensure_loop_attached(&loop_dev, &img_path);

    // Unlock with passphrase, write a file, dismount.
    let mp_dir = tempfile::tempdir().unwrap();
    let mountpoint = mp_dir.path();
    operations::unlock_with_passphrase(&drive, &passphrase, mountpoint, &veracrypt).unwrap();
    let test_file = mountpoint.join("hello.txt");
    let test_content = b"DriveEncryptor v0.1 e2e test payload";
    std::fs::write(&test_file, test_content).unwrap();
    let read_back = std::fs::read(&test_file).unwrap();
    assert_eq!(read_back, test_content);
    veracrypt.dismount(mountpoint).unwrap();
    ensure_loop_attached(&loop_dev, &img_path);

    // Unlock with recovery key, read file back.
    let recovered_key = RecoveryKey::decode(&recovery_encoded).unwrap();
    operations::unlock_with_recovery_key(&drive, &recovered_key, mountpoint, &veracrypt).unwrap();
    let read_back2 = std::fs::read(&test_file).unwrap();
    assert_eq!(
        read_back2, test_content,
        "data after recovery-key unlock did not match"
    );
    veracrypt.dismount(mountpoint).unwrap();
    ensure_loop_attached(&loop_dev, &img_path);
}

#[test]
#[ignore]
fn cross_tool_unwrap_then_stock_veracrypt() {
    unsafe {
        std::env::set_var("DENC_ALLOW_LOOP", "1");
    }

    let img_dir = tempfile::tempdir().unwrap();
    let img_path = img_dir.path().join("test.img");
    let (loop_dev, _guard) = make_image_and_loop(&img_path, 256);

    let drives = drive_linux::enumerate().unwrap();
    let drive = drive_linux::find_drive_by_path(&drives, &loop_dev)
        .unwrap()
        .clone();
    let plan = planner::format_and_encrypt(&drive, false).unwrap();
    let veracrypt = VeraCryptDriver::detect().unwrap();
    let passphrase = SecretBytes::from(TEST_PASSPHRASE);
    let _out = operations::encrypt_format(&plan, &passphrase, &veracrypt, &denc_core::NoopSink).unwrap();
    ensure_loop_attached(&loop_dev, &img_path);

    // Read recovery.bin off P1 the same way a power user would.
    let p1 = disk::partition_path(&loop_dev, 1);
    let p2 = disk::partition_path(&loop_dev, 2);
    let p1_mount = tempfile::tempdir().unwrap();
    disk::mount_ro(&p1, p1_mount.path()).unwrap();
    let recovery_bin_path = p1_mount.path().join("recovery.bin");
    let recovery_bin_copy = img_dir.path().join("recovery.bin.copy");
    std::fs::copy(&recovery_bin_path, &recovery_bin_copy).unwrap();
    disk::umount(p1_mount.path()).unwrap();

    // Pipe the passphrase to denc-unwrap, capture master key on stdout.
    let unwrap_bin = unwrap_binary_path();
    eprintln!("denc-unwrap: {}", unwrap_bin.display());
    let mut cmd = Command::new(&unwrap_bin);
    cmd.arg(&recovery_bin_copy)
        .arg("--secret-stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(TEST_PASSPHRASE.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    let unwrap_out = child.wait_with_output().unwrap();
    assert!(
        unwrap_out.status.success(),
        "denc-unwrap failed: {}",
        String::from_utf8_lossy(&unwrap_out.stderr)
    );
    let master = unwrap_out.stdout;
    assert_eq!(master.len(), 64);

    // Hand the master key to STOCK veracrypt.
    let master_key_file = img_dir.path().join("master.key");
    std::fs::write(&master_key_file, &master).unwrap();
    let p2_mount = tempfile::tempdir().unwrap();
    let mount_out = Command::new(veracrypt.binary_path())
        .args([
            "--text",
            "--non-interactive",
            "--pim=0",
            "--password=",
            &format!("--keyfiles={}", master_key_file.display()),
            "--protect-hidden=no",
            p2.to_str().unwrap(),
            p2_mount.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        mount_out.status.success(),
        "stock veracrypt mount failed: stderr={} stdout={}",
        String::from_utf8_lossy(&mount_out.stderr),
        String::from_utf8_lossy(&mount_out.stdout)
    );

    // Confirm we can list the mounted dir.
    let _entries: Vec<_> = std::fs::read_dir(p2_mount.path()).unwrap().collect();

    // Dismount.
    let _ = Command::new(veracrypt.binary_path())
        .args([
            "--text",
            "--non-interactive",
            "--dismount",
            p2_mount.path().to_str().unwrap(),
        ])
        .status();
}
