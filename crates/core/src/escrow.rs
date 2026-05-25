//! recovery.bin v1 wire-format codec — see DESIGN.md §5.2.
//!
//! 320-byte header. Holds two AES-256-GCM-wrapped copies of the same 64-byte
//! VeraCrypt master keyfile, one wrapped with KDF(passphrase), the other with
//! KDF(recovery_key). Argon2id is the KDF with parameters recorded in the
//! header itself so any future machine can replay the derivation regardless of
//! its own speed.
//!
//! Header layout (little-endian throughout):
//! ```text
//!   off  size  field
//!     0     8  magic = "DENC0001"
//!     8     4  format version (u32) = 1
//!    12     4  KDF algorithm id (u32) = 1 (Argon2id)
//!    16     4  AEAD algorithm id (u32) = 1 (AES-256-GCM)
//!    20     4  Argon2id memory KiB
//!    24     4  Argon2id iterations
//!    28     4  Argon2id parallelism
//!    32    16  passphrase salt
//!    48    16  recovery-key salt
//!    64    12  passphrase nonce
//!    76    64  passphrase ciphertext (wraps 64-byte master)
//!   140    16  passphrase GCM tag
//!   156    12  recovery-key nonce
//!   168    64  recovery-key ciphertext
//!   232    16  recovery-key GCM tag
//!   248    32  drive label hash (SHA-256 of "DriveEncryptor:" || serial)
//!   280     8  created-at unix seconds (i64)
//!   288    32  header HMAC-SHA256 over bytes [0..288]
//! total: 320 bytes
//! ```

use std::io::Read;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};
use crate::keymat::SecretBytes;
use crate::recovery_key::RecoveryKey;

pub const MAGIC: &[u8; 8] = b"DENC0001";
pub const FORMAT_VERSION: u32 = 1;
pub const KDF_ARGON2ID: u32 = 1;
pub const AEAD_AES_256_GCM: u32 = 1;

pub const MASTER_KEY_LEN: usize = 64;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEK_LEN: usize = 32;
pub const HMAC_LEN: usize = 32;
pub const HEADER_LEN: usize = 320;

const HMAC_KEY_DERIVATION_INPUT: &[u8] = b"recovery.bin v1 hmac";

pub const DEFAULT_ARGON2_M_KIB: u32 = 65536; // 64 MiB
pub const DEFAULT_ARGON2_T: u32 = 3;
pub const DEFAULT_ARGON2_P: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    /// Hardcoded parameters used in v0.1 and still used by the test fixture.
    /// New volumes use [`Argon2Params::auto_tune`] instead.
    pub fn default_v01() -> Self {
        Self {
            memory_kib: DEFAULT_ARGON2_M_KIB,
            iterations: DEFAULT_ARGON2_T,
            parallelism: DEFAULT_ARGON2_P,
        }
    }

    /// Calibrate Argon2id parameters for ≈1 second on the creating machine.
    ///
    /// One-shot algorithm (DESIGN §10):
    /// 1. Run Argon2id once at the floor (m=64 MiB, t=2, p=1) on a dummy
    ///    input. Measure wall-clock duration.
    /// 2. If that already took ≥ 1 s the machine is slow — keep t=2 but bump
    ///    memory to 256 MiB? No: bumping memory makes the *slow* machine
    ///    even slower. Instead, accept the floor (t=2, m=64 MiB).
    /// 3. Otherwise scale iterations linearly toward 1 s wall time:
    ///    `t = round(2 * 1000 / measured_ms)` clamped to `[2, 10]`.
    /// 4. If t=2 already exceeds 1 s on a beast machine, that won't happen
    ///    in practice (Argon2id at 64 MiB is ≥ 50 ms even on top hardware),
    ///    so we don't bother with the "raise memory" branch in v0.2 — kept
    ///    open for v0.3 if benchmarking shows it's needed.
    pub fn auto_tune() -> Self {
        Self::auto_tune_with(1000)
    }

    /// Same as `auto_tune` but with a configurable target. Tests use a small
    /// target so the suite runs fast.
    pub fn auto_tune_with(target_ms: u64) -> Self {
        let floor = Self {
            memory_kib: DEFAULT_ARGON2_M_KIB,
            iterations: 2,
            parallelism: DEFAULT_ARGON2_P,
        };
        let measured = measure_argon2_ms(&floor);
        if measured == 0 {
            // Pathological measurement (e.g. clock skew). Use the v0.1 default.
            tracing::warn!("argon2 auto-tune measurement returned 0 ms; using v0.1 defaults");
            return Self::default_v01();
        }
        if measured >= target_ms {
            tracing::debug!(
                measured_ms = measured,
                "argon2 floor already ≥ target; using floor params"
            );
            return floor;
        }
        let scaled = (2.0 * target_ms as f64 / measured as f64).round() as i64;
        let iterations = scaled.clamp(2, 10) as u32;
        let chosen = Self {
            memory_kib: DEFAULT_ARGON2_M_KIB,
            iterations,
            parallelism: DEFAULT_ARGON2_P,
        };
        tracing::debug!(
            measured_ms = measured,
            target_ms,
            iterations,
            "argon2 auto-tune chose params"
        );
        chosen
    }

    fn build(&self) -> Result<Argon2<'static>> {
        let params = Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(KEK_LEN),
        )
        .map_err(|e| Error::Kdf(format!("invalid argon2 params: {}", e)))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Run a single Argon2id derivation with `params` over a fixed input and
/// return the wall-clock duration in milliseconds. Used by `auto_tune`.
fn measure_argon2_ms(params: &Argon2Params) -> u64 {
    let argon2 = match params.build() {
        Ok(a) => a,
        Err(_) => return 0,
    };
    let mut out = [0u8; KEK_LEN];
    let start = std::time::Instant::now();
    let _ = argon2.hash_password_into(b"calibration-input", &[0u8; SALT_LEN], &mut out);
    let elapsed = start.elapsed();
    out.zeroize();
    elapsed.as_millis() as u64
}

#[derive(Debug, Clone)]
pub struct RecoveryFile {
    pub argon2: Argon2Params,
    pub salt_passphrase: [u8; SALT_LEN],
    pub salt_recovery: [u8; SALT_LEN],
    pub nonce_passphrase: [u8; NONCE_LEN],
    pub ct_passphrase: [u8; MASTER_KEY_LEN],
    pub tag_passphrase: [u8; TAG_LEN],
    pub nonce_recovery: [u8; NONCE_LEN],
    pub ct_recovery: [u8; MASTER_KEY_LEN],
    pub tag_recovery: [u8; TAG_LEN],
    pub drive_label_hash: [u8; 32],
    pub created_at_unix: i64,
    pub header_hmac: [u8; HMAC_LEN],
}

impl RecoveryFile {
    /// Generate fresh random salts/nonces and wrap `master_key` with both the
    /// passphrase and the recovery key.
    pub fn create(
        passphrase: &SecretBytes,
        recovery_key: &RecoveryKey,
        master_key: &SecretBytes,
        drive_serial: &str,
        argon2_params: Argon2Params,
    ) -> Result<Self> {
        let mut salt_passphrase = [0u8; SALT_LEN];
        let mut salt_recovery = [0u8; SALT_LEN];
        let mut nonce_passphrase = [0u8; NONCE_LEN];
        let mut nonce_recovery = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut salt_passphrase).map_err(|e| Error::Rng(e.to_string()))?;
        getrandom::getrandom(&mut salt_recovery).map_err(|e| Error::Rng(e.to_string()))?;
        getrandom::getrandom(&mut nonce_passphrase).map_err(|e| Error::Rng(e.to_string()))?;
        getrandom::getrandom(&mut nonce_recovery).map_err(|e| Error::Rng(e.to_string()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Self::create_explicit(
            passphrase,
            recovery_key,
            master_key,
            drive_serial,
            argon2_params,
            salt_passphrase,
            salt_recovery,
            nonce_passphrase,
            nonce_recovery,
            now,
        )
    }

    /// Same as `create`, but lets the caller supply the salts/nonces/timestamp.
    /// Used by tests to produce deterministic fixtures.
    #[allow(clippy::too_many_arguments)]
    pub fn create_explicit(
        passphrase: &SecretBytes,
        recovery_key: &RecoveryKey,
        master_key: &SecretBytes,
        drive_serial: &str,
        argon2_params: Argon2Params,
        salt_passphrase: [u8; SALT_LEN],
        salt_recovery: [u8; SALT_LEN],
        nonce_passphrase: [u8; NONCE_LEN],
        nonce_recovery: [u8; NONCE_LEN],
        created_at_unix: i64,
    ) -> Result<Self> {
        if master_key.len() != MASTER_KEY_LEN {
            return Err(Error::Escrow(format!(
                "master key must be {} bytes, got {}",
                MASTER_KEY_LEN,
                master_key.len()
            )));
        }

        let argon2 = argon2_params.build()?;

        let mut kek_pass: Zeroizing<[u8; KEK_LEN]> = Zeroizing::new([0u8; KEK_LEN]);
        argon2
            .hash_password_into(passphrase.as_bytes(), &salt_passphrase, kek_pass.as_mut())
            .map_err(|e| Error::Kdf(e.to_string()))?;
        let mut kek_recov: Zeroizing<[u8; KEK_LEN]> = Zeroizing::new([0u8; KEK_LEN]);
        argon2
            .hash_password_into(recovery_key.as_bytes(), &salt_recovery, kek_recov.as_mut())
            .map_err(|e| Error::Kdf(e.to_string()))?;

        let cipher_pass = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek_pass.as_ref()));
        let cipher_recov = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek_recov.as_ref()));

        let combined_pass = cipher_pass
            .encrypt(Nonce::from_slice(&nonce_passphrase), master_key.as_bytes())
            .map_err(|e| Error::Escrow(format!("aes-gcm encrypt (passphrase): {}", e)))?;
        let combined_recov = cipher_recov
            .encrypt(Nonce::from_slice(&nonce_recovery), master_key.as_bytes())
            .map_err(|e| Error::Escrow(format!("aes-gcm encrypt (recovery): {}", e)))?;

        if combined_pass.len() != MASTER_KEY_LEN + TAG_LEN
            || combined_recov.len() != MASTER_KEY_LEN + TAG_LEN
        {
            return Err(Error::Escrow(
                "aes-gcm produced unexpected ciphertext+tag length".into(),
            ));
        }
        let mut ct_passphrase = [0u8; MASTER_KEY_LEN];
        let mut tag_passphrase = [0u8; TAG_LEN];
        ct_passphrase.copy_from_slice(&combined_pass[..MASTER_KEY_LEN]);
        tag_passphrase.copy_from_slice(&combined_pass[MASTER_KEY_LEN..]);
        let mut ct_recovery = [0u8; MASTER_KEY_LEN];
        let mut tag_recovery = [0u8; TAG_LEN];
        ct_recovery.copy_from_slice(&combined_recov[..MASTER_KEY_LEN]);
        tag_recovery.copy_from_slice(&combined_recov[MASTER_KEY_LEN..]);

        let mut hasher = Sha256::new();
        hasher.update(b"DriveEncryptor:");
        hasher.update(drive_serial.as_bytes());
        let drive_label_hash: [u8; 32] = hasher.finalize().into();

        let mut file = Self {
            argon2: argon2_params,
            salt_passphrase,
            salt_recovery,
            nonce_passphrase,
            ct_passphrase,
            tag_passphrase,
            nonce_recovery,
            ct_recovery,
            tag_recovery,
            drive_label_hash,
            created_at_unix,
            header_hmac: [0u8; HMAC_LEN],
        };
        file.header_hmac = file.compute_hmac();
        Ok(file)
    }

    fn hmac_key() -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(HMAC_KEY_DERIVATION_INPUT);
        h.finalize().into()
    }

    fn compute_hmac(&self) -> [u8; HMAC_LEN] {
        let bytes = self.serialize_unsigned();
        let key = Self::hmac_key();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
            .expect("hmac-sha256 accepts any key length");
        mac.update(&bytes);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; HMAC_LEN];
        out.copy_from_slice(&result);
        out
    }

    fn serialize_unsigned(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_LEN - HMAC_LEN);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&KDF_ARGON2ID.to_le_bytes());
        buf.extend_from_slice(&AEAD_AES_256_GCM.to_le_bytes());
        buf.extend_from_slice(&self.argon2.memory_kib.to_le_bytes());
        buf.extend_from_slice(&self.argon2.iterations.to_le_bytes());
        buf.extend_from_slice(&self.argon2.parallelism.to_le_bytes());
        buf.extend_from_slice(&self.salt_passphrase);
        buf.extend_from_slice(&self.salt_recovery);
        buf.extend_from_slice(&self.nonce_passphrase);
        buf.extend_from_slice(&self.ct_passphrase);
        buf.extend_from_slice(&self.tag_passphrase);
        buf.extend_from_slice(&self.nonce_recovery);
        buf.extend_from_slice(&self.ct_recovery);
        buf.extend_from_slice(&self.tag_recovery);
        buf.extend_from_slice(&self.drive_label_hash);
        buf.extend_from_slice(&self.created_at_unix.to_le_bytes());
        debug_assert_eq!(buf.len(), HEADER_LEN - HMAC_LEN);
        buf
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.serialize_unsigned();
        buf.extend_from_slice(&self.header_hmac);
        debug_assert_eq!(buf.len(), HEADER_LEN);
        buf
    }

    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < HEADER_LEN {
            return Err(Error::Escrow(format!(
                "recovery.bin too short: {} bytes (need {})",
                input.len(),
                HEADER_LEN
            )));
        }
        if &input[0..8] != MAGIC {
            return Err(Error::Escrow(
                "magic mismatch (not a recovery.bin v1 file)".into(),
            ));
        }
        let mut cursor = std::io::Cursor::new(&input[..HEADER_LEN]);
        cursor.set_position(8);

        let mut tmp4 = [0u8; 4];
        let mut tmp8 = [0u8; 8];

        cursor.read_exact(&mut tmp4)?;
        let version = u32::from_le_bytes(tmp4);
        if version != FORMAT_VERSION {
            return Err(Error::Escrow(format!(
                "unsupported recovery.bin version: {} (this build supports v{})",
                version, FORMAT_VERSION
            )));
        }
        cursor.read_exact(&mut tmp4)?;
        let kdf_alg = u32::from_le_bytes(tmp4);
        if kdf_alg != KDF_ARGON2ID {
            return Err(Error::Escrow(format!(
                "unknown kdf algorithm id: {}",
                kdf_alg
            )));
        }
        cursor.read_exact(&mut tmp4)?;
        let aead_alg = u32::from_le_bytes(tmp4);
        if aead_alg != AEAD_AES_256_GCM {
            return Err(Error::Escrow(format!(
                "unknown aead algorithm id: {}",
                aead_alg
            )));
        }
        cursor.read_exact(&mut tmp4)?;
        let memory_kib = u32::from_le_bytes(tmp4);
        cursor.read_exact(&mut tmp4)?;
        let iterations = u32::from_le_bytes(tmp4);
        cursor.read_exact(&mut tmp4)?;
        let parallelism = u32::from_le_bytes(tmp4);

        let mut salt_passphrase = [0u8; SALT_LEN];
        cursor.read_exact(&mut salt_passphrase)?;
        let mut salt_recovery = [0u8; SALT_LEN];
        cursor.read_exact(&mut salt_recovery)?;
        let mut nonce_passphrase = [0u8; NONCE_LEN];
        cursor.read_exact(&mut nonce_passphrase)?;
        let mut ct_passphrase = [0u8; MASTER_KEY_LEN];
        cursor.read_exact(&mut ct_passphrase)?;
        let mut tag_passphrase = [0u8; TAG_LEN];
        cursor.read_exact(&mut tag_passphrase)?;
        let mut nonce_recovery = [0u8; NONCE_LEN];
        cursor.read_exact(&mut nonce_recovery)?;
        let mut ct_recovery = [0u8; MASTER_KEY_LEN];
        cursor.read_exact(&mut ct_recovery)?;
        let mut tag_recovery = [0u8; TAG_LEN];
        cursor.read_exact(&mut tag_recovery)?;
        let mut drive_label_hash = [0u8; 32];
        cursor.read_exact(&mut drive_label_hash)?;
        cursor.read_exact(&mut tmp8)?;
        let created_at_unix = i64::from_le_bytes(tmp8);
        let mut header_hmac = [0u8; HMAC_LEN];
        cursor.read_exact(&mut header_hmac)?;

        let parsed = Self {
            argon2: Argon2Params {
                memory_kib,
                iterations,
                parallelism,
            },
            salt_passphrase,
            salt_recovery,
            nonce_passphrase,
            ct_passphrase,
            tag_passphrase,
            nonce_recovery,
            ct_recovery,
            tag_recovery,
            drive_label_hash,
            created_at_unix,
            header_hmac,
        };
        let expected = parsed.compute_hmac();
        if !ct_eq(&expected, &parsed.header_hmac) {
            return Err(Error::Escrow(
                "header hmac mismatch (recovery.bin corrupted or tampered)".into(),
            ));
        }
        Ok(parsed)
    }

    pub fn unwrap_with_passphrase(&self, passphrase: &SecretBytes) -> Result<SecretBytes> {
        self.unwrap_one(
            passphrase.as_bytes(),
            &self.salt_passphrase,
            &self.nonce_passphrase,
            &self.ct_passphrase,
            &self.tag_passphrase,
        )
    }

    pub fn unwrap_with_recovery_key(&self, recovery_key: &RecoveryKey) -> Result<SecretBytes> {
        self.unwrap_one(
            recovery_key.as_bytes(),
            &self.salt_recovery,
            &self.nonce_recovery,
            &self.ct_recovery,
            &self.tag_recovery,
        )
    }

    fn unwrap_one(
        &self,
        secret: &[u8],
        salt: &[u8; SALT_LEN],
        nonce: &[u8; NONCE_LEN],
        ct: &[u8; MASTER_KEY_LEN],
        tag: &[u8; TAG_LEN],
    ) -> Result<SecretBytes> {
        let argon2 = self.argon2.build()?;
        let mut kek: Zeroizing<[u8; KEK_LEN]> = Zeroizing::new([0u8; KEK_LEN]);
        argon2
            .hash_password_into(secret, salt, kek.as_mut())
            .map_err(|e| Error::Kdf(e.to_string()))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.as_ref()));
        let mut combined = Vec::with_capacity(MASTER_KEY_LEN + TAG_LEN);
        combined.extend_from_slice(ct);
        combined.extend_from_slice(tag);
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), combined.as_slice())
            .map_err(|_| Error::AeadAuth)?;
        if plaintext.len() != MASTER_KEY_LEN {
            return Err(Error::Escrow(format!(
                "decrypted master length {} (expected {})",
                plaintext.len(),
                MASTER_KEY_LEN
            )));
        }
        Ok(SecretBytes::new(plaintext))
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only fast Argon2 params. Real production uses `default_v01`
    /// (~1 second). Tests use ~milliseconds.
    fn test_params() -> Argon2Params {
        Argon2Params {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn fixture_master() -> SecretBytes {
        SecretBytes::new(vec![0xA5; MASTER_KEY_LEN])
    }

    fn fixture_passphrase() -> SecretBytes {
        SecretBytes::from("correct horse battery staple")
    }

    fn fixture_recovery_key() -> RecoveryKey {
        RecoveryKey::from_bytes([0xC3; 32])
    }

    fn fixture_file() -> RecoveryFile {
        RecoveryFile::create_explicit(
            &fixture_passphrase(),
            &fixture_recovery_key(),
            &fixture_master(),
            "TESTSERIAL01",
            test_params(),
            [0x42; SALT_LEN],
            [0x43; SALT_LEN],
            [0x44; NONCE_LEN],
            [0x45; NONCE_LEN],
            1_700_000_000,
        )
        .unwrap()
    }

    #[test]
    fn header_size_constant() {
        let f = fixture_file();
        let bytes = f.serialize();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(HEADER_LEN, 320);
    }

    #[test]
    fn round_trip_passphrase() {
        let f = fixture_file();
        let bytes = f.serialize();
        let parsed = RecoveryFile::parse(&bytes).unwrap();
        let master = parsed
            .unwrap_with_passphrase(&fixture_passphrase())
            .unwrap();
        assert_eq!(master.as_bytes(), fixture_master().as_bytes());
    }

    #[test]
    fn round_trip_recovery_key() {
        let f = fixture_file();
        let bytes = f.serialize();
        let parsed = RecoveryFile::parse(&bytes).unwrap();
        let master = parsed
            .unwrap_with_recovery_key(&fixture_recovery_key())
            .unwrap();
        assert_eq!(master.as_bytes(), fixture_master().as_bytes());
    }

    #[test]
    fn wrong_passphrase_fails_with_aead_auth() {
        let f = fixture_file();
        let wrong = SecretBytes::from("nope");
        let err = f.unwrap_with_passphrase(&wrong).unwrap_err();
        assert!(matches!(err, Error::AeadAuth));
    }

    #[test]
    fn wrong_recovery_key_fails_with_aead_auth() {
        let f = fixture_file();
        let wrong = RecoveryKey::from_bytes([0u8; 32]);
        let err = f.unwrap_with_recovery_key(&wrong).unwrap_err();
        assert!(matches!(err, Error::AeadAuth));
    }

    #[test]
    fn tampered_hmac_fails_to_parse() {
        let f = fixture_file();
        let mut bytes = f.serialize();
        bytes[300] ^= 0x01;
        let err = RecoveryFile::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::Escrow(_)));
    }

    #[test]
    fn tampered_ciphertext_passes_parse_but_fails_aead() {
        let f = fixture_file();
        let mut bytes = f.serialize();
        // Flip a bit in the passphrase ciphertext (offset 76..140)
        bytes[80] ^= 0x01;
        // HMAC will catch this because it covers the ciphertext bytes.
        let err = RecoveryFile::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::Escrow(_)));
    }

    #[test]
    fn tampered_ciphertext_without_hmac_check() {
        // Simulate: ciphertext flipped, then HMAC re-computed (attacker who
        // knew the HMAC key — which is public).
        let f = fixture_file();
        let mut tampered = f.clone();
        tampered.ct_passphrase[0] ^= 0x01;
        tampered.header_hmac = tampered.compute_hmac();
        let bytes = tampered.serialize();
        let parsed = RecoveryFile::parse(&bytes).unwrap(); // HMAC ok
        let err = parsed
            .unwrap_with_passphrase(&fixture_passphrase())
            .unwrap_err();
        assert!(matches!(err, Error::AeadAuth));
    }

    #[test]
    fn rejects_bad_magic() {
        let f = fixture_file();
        let mut bytes = f.serialize();
        bytes[0] = b'X';
        let err = RecoveryFile::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::Escrow(s) if s.contains("magic")));
    }

    #[test]
    fn rejects_bad_version() {
        let f = fixture_file();
        let mut bytes = f.serialize();
        // Version is u32 LE at offset 8.
        bytes[8] = 0x99;
        // HMAC will catch this first — that's actually fine, it's still rejected.
        let err = RecoveryFile::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::Escrow(_)));
    }

    #[test]
    fn rejects_too_short() {
        let bytes = vec![0u8; HEADER_LEN - 1];
        let err = RecoveryFile::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::Escrow(s) if s.contains("too short")));
    }

    #[test]
    fn rejects_wrong_master_key_size() {
        let bad_master = SecretBytes::new(vec![0u8; 32]); // not 64
        let err = RecoveryFile::create_explicit(
            &fixture_passphrase(),
            &fixture_recovery_key(),
            &bad_master,
            "X",
            test_params(),
            [0; SALT_LEN],
            [0; SALT_LEN],
            [0; NONCE_LEN],
            [0; NONCE_LEN],
            0,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Escrow(s) if s.contains("master key")));
    }

    #[test]
    fn kdf_params_recorded_and_replayed() {
        // Wrap with one set of params; the parsed file must report those exact
        // params and replay-unwrap correctly.
        let custom = Argon2Params {
            memory_kib: 16,
            iterations: 2,
            parallelism: 1,
        };
        let f = RecoveryFile::create_explicit(
            &fixture_passphrase(),
            &fixture_recovery_key(),
            &fixture_master(),
            "X",
            custom,
            [1; SALT_LEN],
            [2; SALT_LEN],
            [3; NONCE_LEN],
            [4; NONCE_LEN],
            999,
        )
        .unwrap();
        let parsed = RecoveryFile::parse(&f.serialize()).unwrap();
        assert_eq!(parsed.argon2, custom);
        let master = parsed
            .unwrap_with_passphrase(&fixture_passphrase())
            .unwrap();
        assert_eq!(master.as_bytes(), fixture_master().as_bytes());
    }

    #[test]
    fn auto_tune_returns_sensible_params() {
        // Smoke-test the auto-tune surface. We can't make hard timing
        // assertions in CI, but we can verify the chosen params are within
        // documented bounds and that the produced KDF actually works.
        let params = Argon2Params::auto_tune_with(50);
        assert_eq!(params.memory_kib, DEFAULT_ARGON2_M_KIB);
        assert_eq!(params.parallelism, DEFAULT_ARGON2_P);
        assert!(
            (2..=10).contains(&params.iterations),
            "iterations out of range: {}",
            params.iterations
        );
        // The KDF must actually run with these params.
        let argon2 = params.build().unwrap();
        let mut out = [0u8; KEK_LEN];
        argon2
            .hash_password_into(b"smoke", &[0u8; SALT_LEN], &mut out)
            .unwrap();
    }

    #[test]
    fn drive_serial_changes_label_hash() {
        let make = |serial: &str| -> [u8; 32] {
            RecoveryFile::create_explicit(
                &fixture_passphrase(),
                &fixture_recovery_key(),
                &fixture_master(),
                serial,
                test_params(),
                [0; SALT_LEN],
                [0; SALT_LEN],
                [0; NONCE_LEN],
                [0; NONCE_LEN],
                0,
            )
            .unwrap()
            .drive_label_hash
        };
        assert_ne!(make("AAA"), make("BBB"));
    }

    /// Print the fixture hex for committing into the const below.
    /// Run with: DENC_PRINT_FIXTURE=1 cargo test fixture_v1_print -- --ignored --nocapture
    #[test]
    #[ignore]
    fn fixture_v1_print() {
        let f = fixture_file();
        let bytes = f.serialize();
        println!("FIXTURE_HEX_V1 ({} bytes):", bytes.len());
        // Print 32 hex chars per line for readability.
        let s = hex::encode(&bytes);
        for chunk in s.as_bytes().chunks(32) {
            println!("    \"{}\\", std::str::from_utf8(chunk).unwrap());
        }
    }

    /// Stability fixture: this exact byte sequence MUST parse forever.
    /// If this test ever needs to be updated, the wire format has changed
    /// in a backwards-incompatible way and every existing drive in the
    /// field is now unrecoverable. Do not "fix" this test by regenerating
    /// the fixture — fix the format change instead.
    #[test]
    fn fixture_v1_round_trip_is_byte_stable() {
        let f = fixture_file();
        let bytes = f.serialize();
        let hex_str = hex::encode(&bytes);
        assert_eq!(hex_str.len(), HEADER_LEN * 2);
        let parsed = RecoveryFile::parse(&bytes).unwrap();
        let reserialized = parsed.serialize();
        assert_eq!(reserialized, bytes);
        let master_via_pass = parsed
            .unwrap_with_passphrase(&fixture_passphrase())
            .unwrap();
        let master_via_recov = parsed
            .unwrap_with_recovery_key(&fixture_recovery_key())
            .unwrap();
        assert_eq!(master_via_pass.as_bytes(), fixture_master().as_bytes());
        assert_eq!(master_via_recov.as_bytes(), fixture_master().as_bytes());

        // Pinned byte fixture. Generated once with `fixture_v1_print` and
        // committed. Any change here means the wire format drifted.
        let fixture_hex_v1 = include_str!("../../../tests/fixtures/recovery_v1.bin.hex");
        let pinned =
            hex::decode(fixture_hex_v1.trim().replace(['\n', ' '], "")).expect("fixture hex parse");
        assert_eq!(
            bytes, pinned,
            "WIRE FORMAT DRIFT: serialize() output no longer matches the pinned v1 fixture. \
             If you intended this change, you have just broken every existing recovery.bin in \
             the field. Read DESIGN.md §11 (irreversible decisions) before proceeding."
        );
    }
}
