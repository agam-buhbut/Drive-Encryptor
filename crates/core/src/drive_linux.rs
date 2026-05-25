//! Linux drive enumeration via `lsblk -J`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::errors::{Error, Result};

#[derive(Debug, Clone)]
pub struct Drive {
    pub path: PathBuf,
    pub kind: DriveKind,
    pub size_bytes: u64,
    pub removable: bool,
    pub readonly: bool,
    pub serial: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone)]
pub struct Partition {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub fstype: Option<String>,
    pub mountpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriveKind {
    Disk,
    Loop,
}

impl Drive {
    pub fn is_system_drive(&self) -> bool {
        self.partitions
            .iter()
            .any(|p| p.mountpoint.as_deref() == Some("/"))
    }

    pub fn is_currently_mounted(&self) -> bool {
        self.partitions.iter().any(|p| {
            p.mountpoint
                .as_deref()
                .map(|m| !m.is_empty())
                .unwrap_or(false)
        })
    }

    pub fn display_summary(&self) -> String {
        let kind_str = match self.kind {
            DriveKind::Disk => "disk",
            DriveKind::Loop => "loop",
        };
        let vendor = self.vendor.as_deref().unwrap_or("").trim();
        let model = self.model.as_deref().unwrap_or("").trim();
        let label = match (vendor.is_empty(), model.is_empty()) {
            (true, true) => "(no vendor/model)".to_string(),
            (true, false) => model.to_string(),
            (false, true) => vendor.to_string(),
            (false, false) => format!("{} {}", vendor, model),
        };
        let gib = self.size_bytes as f64 / (1u64 << 30) as f64;
        format!(
            "{} [{}] {} — {:.2} GiB{}{}{}",
            self.path.display(),
            kind_str,
            label,
            gib,
            if self.removable { " (removable)" } else { "" },
            if self.readonly { " (read-only)" } else { "" },
            if self.is_system_drive() {
                " (SYSTEM)"
            } else {
                ""
            },
        )
    }
}

#[derive(Debug, Deserialize)]
struct LsblkRoot {
    blockdevices: Vec<LsblkNode>,
}

#[derive(Debug, Deserialize)]
struct LsblkNode {
    name: String,
    #[serde(rename = "type")]
    type_: Option<String>,
    size: Option<u64>,
    mountpoint: Option<String>,
    fstype: Option<String>,
    serial: Option<String>,
    rm: Option<bool>,
    ro: Option<bool>,
    vendor: Option<String>,
    model: Option<String>,
    children: Option<Vec<LsblkNode>>,
}

const LSBLK_FIELDS: &str = "NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE,SERIAL,RM,RO,VENDOR,MODEL";

/// Run `lsblk -J -b` and return all candidate drives.
/// Filters out virtual block devices (zram, ram, dm-, md) and
/// eMMC boot partitions (mmcblk*boot*). Loop devices are included
/// only when the `DENC_ALLOW_LOOP` env var is set (used by tests).
pub fn enumerate() -> Result<Vec<Drive>> {
    // Try /usr/bin/lsblk explicitly; fall back to PATH lookup.
    let out = run_lsblk()?;
    parse_lsblk(&out)
}

fn run_lsblk() -> Result<Vec<u8>> {
    let candidates = ["/usr/bin/lsblk", "/bin/lsblk", "lsblk"];
    let mut last_err: Option<std::io::Error> = None;
    for c in candidates {
        let cmd = Command::new(c)
            .arg("-J")
            .arg("-b")
            .arg("-o")
            .arg(LSBLK_FIELDS)
            .output();
        match cmd {
            Ok(out) if out.status.success() => return Ok(out.stdout),
            Ok(out) => {
                return Err(Error::DriveEnum(format!(
                    "lsblk exited with status {}: {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        }
    }
    Err(Error::DriveEnum(format!(
        "lsblk not found on PATH or standard locations: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no candidates".into())
    )))
}

fn parse_lsblk(json: &[u8]) -> Result<Vec<Drive>> {
    let root: LsblkRoot = serde_json::from_slice(json)
        .map_err(|e| Error::DriveEnum(format!("lsblk JSON parse: {}", e)))?;
    let allow_loop = std::env::var("DENC_ALLOW_LOOP").is_ok();
    let mut drives = Vec::new();
    for node in root.blockdevices {
        if !is_candidate_name(&node.name) {
            continue;
        }
        let kind = match node.type_.as_deref() {
            Some("disk") => DriveKind::Disk,
            Some("loop") if allow_loop => DriveKind::Loop,
            _ => continue,
        };
        let path = PathBuf::from(format!("/dev/{}", node.name));
        let partitions: Vec<Partition> = node
            .children
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.type_.as_deref() == Some("part"))
            .map(|c| Partition {
                path: PathBuf::from(format!("/dev/{}", c.name)),
                size_bytes: c.size.unwrap_or(0),
                fstype: c.fstype,
                mountpoint: c.mountpoint,
            })
            .collect();
        drives.push(Drive {
            path,
            kind,
            size_bytes: node.size.unwrap_or(0),
            removable: node.rm.unwrap_or(false),
            readonly: node.ro.unwrap_or(false),
            serial: node.serial,
            vendor: node.vendor,
            model: node.model,
            partitions,
        });
    }
    Ok(drives)
}

fn is_candidate_name(name: &str) -> bool {
    // Reject virtual block devices.
    let virtual_prefixes = ["zram", "ram", "dm-", "md"];
    if virtual_prefixes.iter().any(|p| name.starts_with(p)) {
        return false;
    }
    // Reject eMMC boot partitions exposed as separate disks: mmcblk*boot*
    if name.contains("boot") && name.starts_with("mmcblk") {
        return false;
    }
    true
}

/// Find the drive a given path belongs to, by exact path match or by
/// matching the drive containing a partition with that path.
pub fn find_drive_by_path<'a>(drives: &'a [Drive], path: &Path) -> Option<&'a Drive> {
    drives
        .iter()
        .find(|d| d.path == path || d.partitions.iter().any(|p| p.path == path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample lsblk output for a system with eMMC root, zram swap, and an
    /// external USB drive. Hand-edited from a real `lsblk -J` snapshot.
    const SAMPLE_LSBLK_JSON: &str = r#"
    {
       "blockdevices": [
          {
             "name": "mmcblk0",
             "type": "disk",
             "size": 125074145280,
             "mountpoint": null,
             "fstype": null,
             "serial": "0x004137d7",
             "rm": false, "ro": false,
             "vendor": null, "model": null,
             "children": [
                {"name":"mmcblk0p1","type":"part","size":1023410176,"mountpoint":"/boot/efi","fstype":"vfat","serial":null,"rm":false,"ro":false,"vendor":null,"model":null},
                {"name":"mmcblk0p2","type":"part","size":119961288704,"mountpoint":"/","fstype":"ext4","serial":null,"rm":false,"ro":false,"vendor":null,"model":null},
                {"name":"mmcblk0p3","type":"part","size":4087349248,"mountpoint":"[SWAP]","fstype":"swap","serial":null,"rm":false,"ro":false,"vendor":null,"model":null}
             ]
          },
          {
             "name": "zram0", "type": "disk", "size": 1952858112,
             "mountpoint": "[SWAP]", "fstype": "swap", "serial": null,
             "rm": false, "ro": false, "vendor": null, "model": null
          },
          {
             "name": "mmcblk0boot0", "type": "disk", "size": 4194304,
             "mountpoint": null, "fstype": null, "serial": "0x004137d7",
             "rm": false, "ro": true, "vendor": null, "model": null
          },
          {
             "name": "sdb", "type": "disk", "size": 32212254720,
             "mountpoint": null, "fstype": null, "serial": "ABCD1234",
             "rm": true, "ro": false,
             "vendor": "SanDisk", "model": "Cruzer",
             "children": [
                {"name":"sdb1","type":"part","size":32211206144,"mountpoint":null,"fstype":"vfat","serial":null,"rm":true,"ro":false,"vendor":null,"model":null}
             ]
          }
       ]
    }
    "#;

    #[test]
    fn parses_sample_and_filters_virtual() {
        let drives = parse_lsblk(SAMPLE_LSBLK_JSON.as_bytes()).unwrap();
        // Expected: mmcblk0 + sdb. zram0 + mmcblk0boot0 filtered out.
        let names: Vec<String> = drives
            .iter()
            .map(|d| d.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["mmcblk0", "sdb"]);
    }

    #[test]
    fn detects_system_drive() {
        let drives = parse_lsblk(SAMPLE_LSBLK_JSON.as_bytes()).unwrap();
        let mmcblk = drives.iter().find(|d| d.path.ends_with("mmcblk0")).unwrap();
        let sdb = drives.iter().find(|d| d.path.ends_with("sdb")).unwrap();
        assert!(mmcblk.is_system_drive());
        assert!(!sdb.is_system_drive());
    }

    #[test]
    fn detects_currently_mounted() {
        let drives = parse_lsblk(SAMPLE_LSBLK_JSON.as_bytes()).unwrap();
        let mmcblk = drives.iter().find(|d| d.path.ends_with("mmcblk0")).unwrap();
        let sdb = drives.iter().find(|d| d.path.ends_with("sdb")).unwrap();
        assert!(mmcblk.is_currently_mounted());
        assert!(!sdb.is_currently_mounted());
    }

    #[test]
    fn loop_devices_excluded_by_default() {
        let json = r#"{"blockdevices":[
            {"name":"loop0","type":"loop","size":1048576,"mountpoint":null,"fstype":null,"serial":null,"rm":false,"ro":false,"vendor":null,"model":null}
        ]}"#;
        // Ensure env not set during this assertion.
        assert!(std::env::var("DENC_ALLOW_LOOP").is_err(), "test pollution");
        let drives = parse_lsblk(json.as_bytes()).unwrap();
        assert!(drives.is_empty());
    }

    #[test]
    fn metadata_passthrough() {
        let drives = parse_lsblk(SAMPLE_LSBLK_JSON.as_bytes()).unwrap();
        let sdb = drives.iter().find(|d| d.path.ends_with("sdb")).unwrap();
        assert_eq!(sdb.serial.as_deref(), Some("ABCD1234"));
        assert_eq!(sdb.vendor.as_deref(), Some("SanDisk"));
        assert_eq!(sdb.model.as_deref(), Some("Cruzer"));
        assert_eq!(sdb.size_bytes, 32212254720);
        assert!(sdb.removable);
        assert!(!sdb.readonly);
        assert_eq!(sdb.partitions.len(), 1);
        assert_eq!(sdb.partitions[0].path, PathBuf::from("/dev/sdb1"));
    }

    #[test]
    fn find_drive_by_path_works_for_disk_and_partition() {
        let drives = parse_lsblk(SAMPLE_LSBLK_JSON.as_bytes()).unwrap();
        let by_disk = find_drive_by_path(&drives, Path::new("/dev/sdb"));
        let by_part = find_drive_by_path(&drives, Path::new("/dev/sdb1"));
        assert!(by_disk.is_some());
        assert!(by_part.is_some());
        assert_eq!(by_disk.unwrap().path, by_part.unwrap().path);
    }

    #[test]
    fn display_summary_includes_system_marker() {
        let drives = parse_lsblk(SAMPLE_LSBLK_JSON.as_bytes()).unwrap();
        let mmcblk = drives.iter().find(|d| d.path.ends_with("mmcblk0")).unwrap();
        assert!(mmcblk.display_summary().contains("SYSTEM"));
    }
}
