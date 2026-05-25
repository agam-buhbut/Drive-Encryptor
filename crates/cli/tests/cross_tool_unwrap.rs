//! Cross-tool verification: a recovery.bin produced by denc_core must be
//! decodable by the published spec-reference binary `denc-unwrap`.
//!
//! This is the *non-privileged* analogue of the cross_tool half of
//! `losetup_e2e.rs`: it produces the bytes synthetically (no real disk
//! involved) and shells out to the workspace's debug build of denc-unwrap.
//! Catches any drift between the core wire-format encoder and the published
//! reference decoder *without* needing sudo/losetup.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use denc_core::escrow::{Argon2Params, RecoveryFile, MASTER_KEY_LEN};
use denc_core::keymat::SecretBytes;
use denc_core::recovery_key::RecoveryKey;

const TEST_PASSPHRASE: &str = "correct horse battery staple";

fn unwrap_binary_path() -> PathBuf {
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

fn pipe_secret_to_unwrap(recovery_bin: &Path, secret: &[u8], extra_args: &[&str]) -> Vec<u8> {
    let bin = unwrap_binary_path();
    let mut cmd = Command::new(&bin);
    cmd.arg(recovery_bin).arg("--secret-stdin");
    for a in extra_args {
        cmd.arg(a);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {}", bin.display(), e));
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(secret)
        .expect("write secret to denc-unwrap stdin");
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("wait_with_output");
    assert!(
        out.status.success(),
        "denc-unwrap failed: status={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
fn denc_unwrap_decodes_passphrase_wrap() {
    let master = vec![0xA5u8; MASTER_KEY_LEN];
    let recovery_key = RecoveryKey::from_bytes([0xC3; 32]);
    let params = Argon2Params {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };
    let f = RecoveryFile::create_explicit(
        &SecretBytes::from(TEST_PASSPHRASE),
        &recovery_key,
        &SecretBytes::new(master.clone()),
        "CROSSTOOL01",
        params,
        [0x11; 16],
        [0x22; 16],
        [0x33; 12],
        [0x44; 12],
        1_700_000_000,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("recovery.bin");
    std::fs::write(&bin_path, f.serialize()).unwrap();

    let recovered = pipe_secret_to_unwrap(&bin_path, TEST_PASSPHRASE.as_bytes(), &[]);
    assert_eq!(recovered.len(), MASTER_KEY_LEN);
    assert_eq!(recovered, master, "recovered master keyfile mismatch");
}

#[test]
fn denc_unwrap_decodes_recovery_key_wrap() {
    let master = vec![0x5Au8; MASTER_KEY_LEN];
    let recovery_key = RecoveryKey::from_bytes([0xDE; 32]);
    let params = Argon2Params {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };
    let f = RecoveryFile::create_explicit(
        &SecretBytes::from("ignored"),
        &recovery_key,
        &SecretBytes::new(master.clone()),
        "CROSSTOOL02",
        params,
        [0xAA; 16],
        [0xBB; 16],
        [0xCC; 12],
        [0xDD; 12],
        1_700_000_000,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("recovery.bin");
    std::fs::write(&bin_path, f.serialize()).unwrap();

    let encoded = recovery_key.encode();
    let recovered = pipe_secret_to_unwrap(&bin_path, encoded.as_bytes(), &["--recovery-key"]);
    assert_eq!(recovered.len(), MASTER_KEY_LEN);
    assert_eq!(recovered, master, "recovered master keyfile mismatch");
}

#[test]
fn denc_unwrap_rejects_wrong_passphrase() {
    let master = vec![0u8; MASTER_KEY_LEN];
    let recovery_key = RecoveryKey::from_bytes([1; 32]);
    let params = Argon2Params {
        memory_kib: 8,
        iterations: 1,
        parallelism: 1,
    };
    let f = RecoveryFile::create_explicit(
        &SecretBytes::from(TEST_PASSPHRASE),
        &recovery_key,
        &SecretBytes::new(master),
        "CROSSTOOL03",
        params,
        [1; 16],
        [2; 16],
        [3; 12],
        [4; 12],
        1_700_000_000,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let bin_path = dir.path().join("recovery.bin");
    std::fs::write(&bin_path, f.serialize()).unwrap();

    let bin = unwrap_binary_path();
    let mut child = Command::new(&bin)
        .arg(&bin_path)
        .arg("--secret-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"wrong-passphrase")
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success(), "denc-unwrap should have failed");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("aead") || stderr.contains("authentication"),
        "expected aead-auth error, got: {}",
        stderr
    );
}
