//! denc-unwrap: extract the VeraCrypt master keyfile from a recovery.bin file.
//!
//! This is the **published spec reference** for the recovery.bin v1 wire format
//! (DESIGN.md §5.2). It is an INDEPENDENT REIMPLEMENTATION and intentionally
//! does NOT depend on the denc_core crate — that way, if denc_core changes the
//! wire format, this binary still works on existing drives.
//!
//! Usage:
//!   denc-unwrap <recovery.bin>                  # prompts for passphrase
//!   denc-unwrap <recovery.bin> --recovery-key   # prompts for recovery key
//!   denc-unwrap <recovery.bin> --secret-stdin   # reads secret from stdin
//!
//! Output: writes the 64-byte master keyfile to stdout. That keyfile is then
//! suitable as input to stock VeraCrypt:
//!   denc-unwrap recovery.bin > master.key
//!   veracrypt -t -k master.key --pim=0 --password= /dev/sdX2 /mnt/secure
//!
//! Hard cap: 400 lines (CI-enforced). Keep the spec readable in one sitting.

use std::io::Write;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::Parser;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// === Wire-format constants. These mirror DESIGN.md §5.2. ===
const MAGIC: &[u8; 8] = b"DENC0001";
const VERSION_V1: u32 = 1;
const KDF_ARGON2ID: u32 = 1;
const AEAD_AES_256_GCM: u32 = 1;
const HEADER_LEN: usize = 320;
const HMAC_LEN: usize = 32;
const MASTER_LEN: usize = 64;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEK_LEN: usize = 32;
const HMAC_KDS_INPUT: &[u8] = b"recovery.bin v1 hmac";

// === Recovery-key decoding constants. DESIGN.md §5.5. ===
const RK_GROUPS: usize = 16;
const RK_DIGITS_PER_GROUP: usize = 6;
const RK_TOTAL_DIGITS: usize = RK_GROUPS * RK_DIGITS_PER_GROUP;

#[derive(Parser)]
#[command(
    name = "denc-unwrap",
    version,
    about = "Extract the VeraCrypt master keyfile from a recovery.bin v1 file. \
             The published spec reference — independent of the main app."
)]
struct Cli {
    /// Path to recovery.bin (typically on the unencrypted P1 partition).
    file: PathBuf,
    /// Use the printed recovery key instead of the passphrase.
    #[arg(long)]
    recovery_key: bool,
    /// Read the secret from stdin (one line) instead of prompting.
    #[arg(long)]
    secret_stdin: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("denc-unwrap: error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let bytes = std::fs::read(&cli.file).with_context(|| format!("read {}", cli.file.display()))?;
    let header = parse_header(&bytes)?;

    let secret_raw: Zeroizing<Vec<u8>> = if cli.secret_stdin {
        Zeroizing::new(read_stdin_line()?)
    } else {
        let prompt = if cli.recovery_key {
            "Recovery key: "
        } else {
            "Passphrase: "
        };
        Zeroizing::new(prompt_secret(prompt)?)
    };

    // The KDF input is either the raw passphrase bytes or the 32-byte decoded
    // recovery key.
    let kdf_input: Zeroizing<Vec<u8>> = if cli.recovery_key {
        let as_str =
            std::str::from_utf8(&secret_raw).context("recovery key must be valid utf-8")?;
        let bytes = decode_recovery_key(as_str)?;
        Zeroizing::new(bytes.to_vec())
    } else {
        Zeroizing::new(secret_raw.to_vec())
    };

    let (salt, nonce, ct, tag) = if cli.recovery_key {
        (
            &header.salt_recovery,
            &header.nonce_recovery,
            &header.ct_recovery[..],
            &header.tag_recovery[..],
        )
    } else {
        (
            &header.salt_passphrase,
            &header.nonce_passphrase,
            &header.ct_passphrase[..],
            &header.tag_passphrase[..],
        )
    };

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            header.argon2_m_kib,
            header.argon2_t,
            header.argon2_p,
            Some(KEK_LEN),
        )
        .map_err(|e| anyhow::anyhow!("invalid argon2 params in header: {}", e))?,
    );
    let mut kek: Zeroizing<[u8; KEK_LEN]> = Zeroizing::new([0u8; KEK_LEN]);
    argon2
        .hash_password_into(&kdf_input, salt, kek.as_mut())
        .map_err(|e| anyhow::anyhow!("argon2 hash: {}", e))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.as_ref()));
    let mut combined = Vec::with_capacity(MASTER_LEN + TAG_LEN);
    combined.extend_from_slice(ct);
    combined.extend_from_slice(tag);
    let master = cipher
        .decrypt(Nonce::from_slice(nonce), combined.as_slice())
        .map_err(|_| {
            anyhow::anyhow!("aead authentication failed (wrong secret, or recovery.bin corrupted)")
        })?;
    if master.len() != MASTER_LEN {
        bail!(
            "decrypted master is {} bytes, expected {}",
            master.len(),
            MASTER_LEN
        );
    }

    std::io::stdout()
        .write_all(&master)
        .context("write master keyfile to stdout")?;
    Ok(())
}

struct Header {
    argon2_m_kib: u32,
    argon2_t: u32,
    argon2_p: u32,
    salt_passphrase: [u8; SALT_LEN],
    salt_recovery: [u8; SALT_LEN],
    nonce_passphrase: [u8; NONCE_LEN],
    ct_passphrase: [u8; MASTER_LEN],
    tag_passphrase: [u8; TAG_LEN],
    nonce_recovery: [u8; NONCE_LEN],
    ct_recovery: [u8; MASTER_LEN],
    tag_recovery: [u8; TAG_LEN],
}

fn parse_header(input: &[u8]) -> Result<Header> {
    if input.len() < HEADER_LEN {
        bail!(
            "file too short ({} bytes); recovery.bin v1 needs at least {}",
            input.len(),
            HEADER_LEN
        );
    }
    if &input[0..8] != MAGIC {
        bail!("magic mismatch (not a recovery.bin v1 file)");
    }
    let version = u32::from_le_bytes(input[8..12].try_into().unwrap());
    if version != VERSION_V1 {
        bail!(
            "unsupported recovery.bin version: {} (this tool supports v{})",
            version,
            VERSION_V1
        );
    }
    let kdf_alg = u32::from_le_bytes(input[12..16].try_into().unwrap());
    if kdf_alg != KDF_ARGON2ID {
        bail!("unknown kdf id in header: {}", kdf_alg);
    }
    let aead_alg = u32::from_le_bytes(input[16..20].try_into().unwrap());
    if aead_alg != AEAD_AES_256_GCM {
        bail!("unknown aead id in header: {}", aead_alg);
    }
    let argon2_m_kib = u32::from_le_bytes(input[20..24].try_into().unwrap());
    let argon2_t = u32::from_le_bytes(input[24..28].try_into().unwrap());
    let argon2_p = u32::from_le_bytes(input[28..32].try_into().unwrap());

    let mut salt_passphrase = [0u8; SALT_LEN];
    salt_passphrase.copy_from_slice(&input[32..48]);
    let mut salt_recovery = [0u8; SALT_LEN];
    salt_recovery.copy_from_slice(&input[48..64]);
    let mut nonce_passphrase = [0u8; NONCE_LEN];
    nonce_passphrase.copy_from_slice(&input[64..76]);
    let mut ct_passphrase = [0u8; MASTER_LEN];
    ct_passphrase.copy_from_slice(&input[76..140]);
    let mut tag_passphrase = [0u8; TAG_LEN];
    tag_passphrase.copy_from_slice(&input[140..156]);
    let mut nonce_recovery = [0u8; NONCE_LEN];
    nonce_recovery.copy_from_slice(&input[156..168]);
    let mut ct_recovery = [0u8; MASTER_LEN];
    ct_recovery.copy_from_slice(&input[168..232]);
    let mut tag_recovery = [0u8; TAG_LEN];
    tag_recovery.copy_from_slice(&input[232..248]);
    // Bytes [248..280] are the drive label hash; [280..288] is created-at.
    // Neither affects unwrap, so we don't bind them into structured fields.

    // Verify the integrity HMAC over bytes [0..288].
    let mut h = Sha256::new();
    h.update(HMAC_KDS_INPUT);
    let hmac_key: [u8; 32] = h.finalize().into();
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key).expect("hmac-sha256 takes any key length");
    mac.update(&input[..HEADER_LEN - HMAC_LEN]);
    let expected = mac.finalize().into_bytes();
    let actual = &input[HEADER_LEN - HMAC_LEN..HEADER_LEN];
    if !ct_eq(&expected, actual) {
        bail!("header hmac mismatch (recovery.bin corrupted or tampered)");
    }

    Ok(Header {
        argon2_m_kib,
        argon2_t,
        argon2_p,
        salt_passphrase,
        salt_recovery,
        nonce_passphrase,
        ct_passphrase,
        tag_passphrase,
        nonce_recovery,
        ct_recovery,
        tag_recovery,
    })
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

fn decode_recovery_key(s: &str) -> Result<[u8; 32]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '.')
        .collect();
    if cleaned.len() != RK_TOTAL_DIGITS {
        bail!(
            "recovery key must be {} digits after stripping separators (got {})",
            RK_TOTAL_DIGITS,
            cleaned.len()
        );
    }
    if !cleaned.chars().all(|c| c.is_ascii_digit()) {
        bail!("recovery key contains non-digit characters");
    }
    let mut bytes = [0u8; 32];
    for i in 0..RK_GROUPS {
        let start = i * RK_DIGITS_PER_GROUP;
        let end = start + RK_DIGITS_PER_GROUP;
        let group: u32 = cleaned[start..end]
            .parse()
            .map_err(|_| anyhow::anyhow!("group {} is not a valid number", i + 1))?;
        if group % 11 != 0 {
            bail!("group {} fails check digit (not divisible by 11)", i + 1);
        }
        let v = (group / 11) as u16;
        let be = v.to_be_bytes();
        bytes[i * 2] = be[0];
        bytes[i * 2 + 1] = be[1];
    }
    Ok(bytes)
}

fn prompt_secret(prompt: &str) -> Result<Vec<u8>> {
    let s = rpassword::prompt_password(prompt).context("prompt secret")?;
    Ok(s.into_bytes())
}

fn read_stdin_line() -> Result<Vec<u8>> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).context("read stdin")?;
    while matches!(buf.chars().last(), Some('\n') | Some('\r')) {
        buf.pop();
    }
    Ok(buf.into_bytes())
}
