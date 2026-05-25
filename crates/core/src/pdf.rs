//! Recovery-key PDF export (DESIGN §5.5).
//!
//! Single-page A4 PDF containing:
//! - Title and drive identifier.
//! - Creation date.
//! - The 16-group recovery key, monospace, 4 rows of 4 groups.
//! - A short explainer paragraph.
//!
//! Pure-Rust generation via `printpdf`; no external tools required.

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use printpdf::{BuiltinFont, Mm, PdfDocument};

use crate::errors::{Error, Result};
use crate::recovery_key::RecoveryKey;

/// Write a single-page PDF containing the recovery key, drive label, and
/// creation date to `path`. Caller picks the path and is responsible for
/// printing/storing it. The file is written with the user's default umask.
pub fn export_recovery_pdf(
    path: &Path,
    key: &RecoveryKey,
    drive_label: &str,
    created_at: SystemTime,
) -> Result<()> {
    // A4: 210 x 297 mm.
    let (doc, page, layer) =
        PdfDocument::new("DriveEncryptor Recovery Key", Mm(210.0), Mm(297.0), "main");
    let layer = doc.get_page(page).get_layer(layer);

    let title_font = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| Error::Io(std::io::Error::other(format!("printpdf: {}", e))))?;
    let body_font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| Error::Io(std::io::Error::other(format!("printpdf: {}", e))))?;
    let mono_font = doc
        .add_builtin_font(BuiltinFont::Courier)
        .map_err(|e| Error::Io(std::io::Error::other(format!("printpdf: {}", e))))?;
    let mono_bold = doc
        .add_builtin_font(BuiltinFont::CourierBold)
        .map_err(|e| Error::Io(std::io::Error::other(format!("printpdf: {}", e))))?;

    // Title block (top of page; PDF y-axis grows up from the bottom).
    layer.use_text(
        "DriveEncryptor — Drive Recovery Key",
        18.0,
        Mm(20.0),
        Mm(280.0),
        &title_font,
    );

    layer.use_text(
        format!("Drive: {}", drive_label),
        11.0,
        Mm(20.0),
        Mm(265.0),
        &body_font,
    );
    layer.use_text(
        format!("Created: {}", format_iso8601(created_at)),
        11.0,
        Mm(20.0),
        Mm(258.0),
        &body_font,
    );

    // Explainer (above the key, so attention falls to the key after reading).
    let explainer = [
        "This is the recovery key for the DriveEncryptor-encrypted volume named above.",
        "Either this key OR the passphrase you set will unlock the drive. Without one of",
        "them, the data on the drive is unrecoverable. Keep this page in a safe place;",
        "do not store it on the drive itself or on the same machine that holds the",
        "passphrase. Anyone holding both the drive and this key can decrypt the data.",
    ];
    let mut y = Mm(240.0);
    for line in explainer {
        layer.use_text(line, 10.0, Mm(20.0), y, &body_font);
        y = Mm(y.0 - 5.5);
    }

    // Recovery key block. 4 rows of 4 groups, monospace, large.
    layer.use_text("Recovery key:", 12.0, Mm(20.0), Mm(195.0), &title_font);

    let display = key.encode_for_display(); // 4 lines
    let mut yk = Mm(180.0);
    for row in display.lines() {
        layer.use_text(row, 16.0, Mm(20.0), yk, &mono_bold);
        yk = Mm(yk.0 - 9.0);
    }

    // Footer: how to use this key.
    let footer = [
        "To unlock with this key (CLI):",
        "  drive-encryptor unlock <device> --mountpoint <path> --with-recovery-key",
        "",
        "To unlock with the published spec-reference utility (no DriveEncryptor app needed):",
        "  denc-unwrap <recovery.bin> --recovery-key  >  master.key",
        "  veracrypt -t -k master.key --pim=0 --password= <device-partition-2> <mountpoint>",
    ];
    let mut yf = Mm(120.0);
    for line in footer {
        layer.use_text(line, 9.0, Mm(20.0), yf, &mono_font);
        yf = Mm(yf.0 - 5.0);
    }

    let out = File::create(path).map_err(Error::Io)?;
    doc.save(&mut BufWriter::new(out))
        .map_err(|e| Error::Io(std::io::Error::other(format!("printpdf save: {}", e))))?;
    Ok(())
}

fn format_iso8601(t: SystemTime) -> String {
    // Very small ISO-8601 formatter (no chrono dep). Honours UTC.
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = unix_to_ymdhms(secs as i64);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

/// Convert Unix seconds (UTC) to (year, month, day, hour, minute, second).
/// Civil-from-days algorithm (Howard Hinnant, public domain). Good for any
/// year [-32768, 32767]; we only ever call it with present-day values.
fn unix_to_ymdhms(unix_secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let secs_per_day: i64 = 86400;
    let days = unix_secs.div_euclid(secs_per_day);
    let secs_of_day = unix_secs.rem_euclid(secs_per_day) as u32;
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    // Days since 1970-01-01 → date.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unix_to_ymdhms_known_dates() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(unix_to_ymdhms(0), (1970, 1, 1, 0, 0, 0));
        // 2024-01-01 00:00:00 UTC
        assert_eq!(unix_to_ymdhms(1_704_067_200), (2024, 1, 1, 0, 0, 0));
        // 2024-12-31 23:59:59 UTC = 1735689599
        assert_eq!(unix_to_ymdhms(1_735_689_599), (2024, 12, 31, 23, 59, 59));
        // 2000-02-29 (leap day in century year — common bug)
        // 2000-02-29 12:00:00 UTC = 951825600
        assert_eq!(unix_to_ymdhms(951_825_600), (2000, 2, 29, 12, 0, 0));
    }

    #[test]
    fn export_writes_a_valid_pdf_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.pdf");
        let key = RecoveryKey::from_bytes([0u8; 32]);
        let created = UNIX_EPOCH + Duration::from_secs(1_704_067_200);
        export_recovery_pdf(&path, &key, "test-drive", created).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        // Valid PDFs start with "%PDF-".
        assert!(
            bytes.starts_with(b"%PDF-"),
            "not a PDF: starts with {:?}",
            &bytes[..8]
        );
        // Should not be tiny.
        assert!(
            bytes.len() > 500,
            "PDF suspiciously small: {} bytes",
            bytes.len()
        );
    }
}
