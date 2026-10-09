use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use denc_core::{
    drive_linux, operations, pdf, planner, veracrypt::VeraCryptDriver, RecoveryKey, SecretBytes,
    TracingSink,
};

#[derive(Parser)]
#[command(
    name = "drive-encryptor",
    version,
    about = "Encrypt drives with AES-256-XTS via VeraCrypt + dual-unlock recovery escrow"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List candidate drives.
    List,
    /// Show details of one drive (including DriveEncryptor metadata, if encrypted).
    Info { device: PathBuf },
    /// Format and encrypt a drive. DESTROYS ALL DATA on the drive.
    /// Back up anything you want to keep BEFORE running this.
    Encrypt {
        device: PathBuf,
        /// Overwrite the entire drive with cryptographically random bytes
        /// before laying out the encrypted volume. Slow on large drives, but
        /// makes pre-existing data unrecoverable and the resulting volume
        /// indistinguishable from random across its full extent.
        #[arg(long)]
        shred: bool,
        /// Path to save the recovery key PDF. Default: ./recovery-<dev>-<ts>.pdf.
        #[arg(long)]
        save_recovery_pdf: Option<PathBuf>,
        /// Read passphrase from stdin (one line) instead of prompting on the tty.
        #[arg(long)]
        passphrase_stdin: bool,
        /// Skip the typed-confirmation prompt (for scripts/tests). DESTRUCTIVE.
        #[arg(long)]
        yes: bool,
    },
    /// Unlock an encrypted drive and mount it.
    Unlock {
        device: PathBuf,
        #[arg(long)]
        mountpoint: PathBuf,
        /// Use the printed recovery key instead of the passphrase.
        #[arg(long)]
        with_recovery_key: bool,
        /// Read the secret from stdin (one line) instead of prompting on the tty.
        #[arg(long)]
        secret_stdin: bool,
    },
    /// Dismount a previously-unlocked drive.
    Lock { mountpoint: PathBuf },
}

fn main() -> ExitCode {
    install_tracing();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::from(1)
        }
    }
}

fn install_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::List => cmd_list(),
        Cmd::Info { device } => cmd_info(&device),
        Cmd::Encrypt {
            device,
            shred,
            save_recovery_pdf,
            passphrase_stdin,
            yes,
        } => cmd_encrypt(
            &device,
            shred,
            save_recovery_pdf.as_deref(),
            passphrase_stdin,
            yes,
        ),
        Cmd::Unlock {
            device,
            mountpoint,
            with_recovery_key,
            secret_stdin,
        } => cmd_unlock(&device, &mountpoint, with_recovery_key, secret_stdin),
        Cmd::Lock { mountpoint } => cmd_lock(&mountpoint),
    }
}

fn cmd_list() -> Result<()> {
    let drives = drive_linux::enumerate().context("enumerate drives")?;
    if drives.is_empty() {
        println!("no candidate drives found");
        return Ok(());
    }
    for d in drives {
        println!("{}", d.display_summary());
    }
    Ok(())
}

fn cmd_info(device: &Path) -> Result<()> {
    let drives = drive_linux::enumerate()?;
    let drive = drive_linux::find_drive_by_path(&drives, device)
        .ok_or_else(|| anyhow::anyhow!("no drive found matching {}", device.display()))?;
    println!("{}", drive.display_summary());
    println!("partitions:");
    if drive.partitions.is_empty() {
        println!("  (none)");
    }
    for p in &drive.partitions {
        println!(
            "  {}  size={} bytes  fstype={}  mountpoint={}",
            p.path.display(),
            p.size_bytes,
            p.fstype.as_deref().unwrap_or("?"),
            p.mountpoint.as_deref().unwrap_or("-")
        );
    }

    // DriveEncryptor metadata, if present.
    match operations::read_recovery_bin(&drive.path) {
        Ok(rec) => {
            println!();
            println!("DriveEncryptor v1 metadata:");
            println!(
                "  argon2id:    m={} KiB, t={}, p={}",
                rec.argon2.memory_kib, rec.argon2.iterations, rec.argon2.parallelism
            );
            println!("  created:     unix {}", rec.created_at_unix);
            println!(
                "  drive label: SHA-256 {}…",
                &hex::encode(rec.drive_label_hash)[..16]
            );
        }
        Err(e) => {
            println!();
            println!("DriveEncryptor metadata: not found ({})", e);
        }
    }
    Ok(())
}

fn cmd_encrypt(
    device: &Path,
    shred: bool,
    save_recovery_pdf: Option<&Path>,
    passphrase_stdin: bool,
    yes: bool,
) -> Result<()> {
    let drives = drive_linux::enumerate()?;
    let drive = drive_linux::find_whole_disk(&drives, device)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no whole disk matching {} (pass the disk, e.g. /dev/sdb, not a partition)",
                device.display()
            )
        })?
        .clone();

    let plan = planner::format_and_encrypt(&drive, shred)?;

    println!(
        "Plan: {} {}",
        if plan.pre_shred {
            "shred + format-and-encrypt"
        } else {
            "format-and-encrypt"
        },
        drive.display_summary()
    );
    if !plan.warnings.is_empty() {
        println!("Warnings:");
        for w in &plan.warnings {
            println!("  - {}", w);
        }
    }

    if !yes {
        let confirm_token = drive
            .serial
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                drive
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string()
            });
        println!("\nThis will DESTROY ALL DATA on {}.", drive.path.display());
        if plan.pre_shred {
            println!("It will first overwrite the entire drive with random bytes (slow on large drives), then encrypt.");
        }
        println!(
            "If you want to keep the drive's current contents, abort now and back them up first."
        );
        println!("To confirm, type exactly: {}", confirm_token);
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != confirm_token {
            anyhow::bail!("confirmation does not match; aborting");
        }
    }

    let passphrase = if passphrase_stdin {
        read_secret_stdin()?
    } else {
        let p = read_secret_tty("Passphrase")?;
        if read_secret_tty("Confirm passphrase")?.as_bytes() != p.as_bytes() {
            anyhow::bail!("passphrases do not match; aborting");
        }
        p
    };
    operations::check_new_passphrase(&passphrase)?;

    let veracrypt = VeraCryptDriver::detect()?;
    let sha = veracrypt.binary_sha256()?;
    tracing::info!(
        binary = %veracrypt.binary_path().display(),
        sha256 = &sha[..16.min(sha.len())],
        "veracrypt binary located"
    );

    if plan.pre_shred {
        tracing::info!("shredding drive before encryption (this can take a while)");
    } else {
        tracing::info!("encrypting (no pre-shred)");
    }
    let out = operations::encrypt_format(&plan, &passphrase, &veracrypt, &TracingSink)?;

    println!();
    println!("=== RECOVERY KEY ===");
    println!("Save this somewhere safe. It is the ONLY way to recover your data");
    println!("if you forget your passphrase. The app will never display it again.");
    println!();
    println!("{}", out.recovery_key.encode_for_display());
    println!();
    println!("====================");

    // PDF export.
    let pdf_path = match save_recovery_pdf {
        Some(p) => p.to_path_buf(),
        None => default_pdf_path(&drive.path),
    };
    let drive_label = drive
        .serial
        .clone()
        .map(|s| format!("{} (serial {})", drive.path.display(), s))
        .unwrap_or_else(|| drive.path.display().to_string());
    pdf::export_recovery_pdf(
        &pdf_path,
        &out.recovery_key,
        &drive_label,
        std::time::SystemTime::now(),
    )?;
    println!();
    println!("Recovery key PDF saved to: {}", pdf_path.display());
    println!();
    println!("Encryption complete.");
    println!(
        "To unlock: drive-encryptor unlock {} --mountpoint /mnt/foo",
        drive.path.display()
    );
    Ok(())
}

fn default_pdf_path(device: &Path) -> PathBuf {
    let dev_name = device
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("drive");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    PathBuf::from(format!("./recovery-{}-{}.pdf", dev_name, ts))
}

fn cmd_unlock(
    device: &Path,
    mountpoint: &Path,
    with_recovery_key: bool,
    secret_stdin: bool,
) -> Result<()> {
    let drives = drive_linux::enumerate()?;
    let drive = drive_linux::find_drive_by_path(&drives, device)
        .ok_or_else(|| anyhow::anyhow!("no drive found matching {}", device.display()))?
        .clone();

    if !mountpoint.is_dir() {
        anyhow::bail!(
            "mountpoint {} is not an existing directory",
            mountpoint.display()
        );
    }

    let veracrypt = VeraCryptDriver::detect()?;

    if with_recovery_key {
        let raw = if secret_stdin {
            read_secret_stdin()?
        } else {
            read_secret_tty("Recovery key")?
        };
        let s = std::str::from_utf8(raw.as_bytes()).context("recovery key must be valid utf-8")?;
        let key = RecoveryKey::decode(s).map_err(|e| anyhow::anyhow!("{}", e))?;
        operations::unlock_with_recovery_key(&drive, &key, mountpoint, &veracrypt)?;
    } else {
        let passphrase = if secret_stdin {
            read_secret_stdin()?
        } else {
            read_secret_tty("Passphrase")?
        };
        operations::unlock_with_passphrase(&drive, &passphrase, mountpoint, &veracrypt)?;
    }

    println!(
        "unlocked: {} mounted at {}",
        drive.path.display(),
        mountpoint.display()
    );
    Ok(())
}

fn cmd_lock(mountpoint: &Path) -> Result<()> {
    let veracrypt = VeraCryptDriver::detect()?;
    veracrypt.dismount(mountpoint)?;
    println!("dismounted {}", mountpoint.display());
    Ok(())
}

fn read_secret_tty(label: &str) -> Result<SecretBytes> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("not running interactively; pass --passphrase-stdin or --secret-stdin");
    }
    let s = rpassword::prompt_password(format!("{}: ", label))?;
    Ok(SecretBytes::from(s))
}

fn read_secret_stdin() -> Result<SecretBytes> {
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    while matches!(buf.chars().last(), Some('\n') | Some('\r')) {
        buf.pop();
    }
    if buf.is_empty() {
        let mut more = String::new();
        std::io::stdin().read_to_string(&mut more)?;
        buf.push_str(more.trim_end_matches(['\r', '\n']));
    }
    Ok(SecretBytes::from(buf))
}
