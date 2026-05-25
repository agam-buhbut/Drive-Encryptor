// mock-data.js — fake `Drive[]`, `EncryptionPlan.warnings`, `ProgressEvent`s,
// and a sample recovery key. In the real Tauri build these all come from
// denc_core via IPC; here they're hardcoded so the prototype runs in any browser.

window.MOCK = (function () {
  // Mirrors crates/core/src/drive_linux.rs::Drive (subset of fields the UI uses).
  const drives = [
    {
      path: "/dev/sda",
      kind: "Disk",
      size_bytes: 1024 * 1024 * 1024 * 1024 * 1, // 1.0 TiB
      removable: false,
      readonly: false,
      serial: "WD-WX12345SYS01",
      vendor: "WDC",
      model: "WD10EZEX-08WN4A0",
      partitions: [
        { path: "/dev/sda1", size_bytes: 512 * 1024 * 1024,                fstype: "vfat", mountpoint: "/boot/efi" },
        { path: "/dev/sda2", size_bytes: 1024 * 1024 * 1024 * 1024 * 1 - 512 * 1024 * 1024, fstype: "ext4", mountpoint: "/" },
      ],
      isSystem: true,            // matches Drive::is_system_drive()
      mounted:  true,            // Drive::is_currently_mounted()
    },
    {
      path: "/dev/sdb",
      kind: "Disk",
      size_bytes: 32 * 1024 * 1024 * 1024, // 32 GiB
      removable: true,
      readonly: false,
      serial: "USB-1234-ABCD-5678",
      vendor: "SanDisk",
      model: "Cruzer Blade",
      partitions: [
        { path: "/dev/sdb1", size_bytes: 32 * 1024 * 1024 * 1024 - 1 * 1024 * 1024, fstype: "vfat", mountpoint: "/media/usb0" },
      ],
      isSystem: false,
      mounted:  true,
    },
    {
      path: "/dev/sdc",
      kind: "Disk",
      size_bytes: 2 * 1024 * 1024 * 1024 * 1024, // 2 TiB
      removable: false,
      readonly: false,
      serial: "S5XXNX0NA12345",
      vendor: "Samsung",
      model: "SSD 870 EVO 2TB",
      partitions: [
        { path: "/dev/sdc1", size_bytes: 2 * 1024 * 1024 * 1024 * 1024, fstype: "ntfs", mountpoint: null },
      ],
      isSystem: false,
      mounted:  false,
    },
  ];

  // Lookup helpers -----------------------------------------------------

  function findDrive(path) { return drives.find(d => d.path === path); }

  function formatSize(bytes) {
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let v = bytes; let u = 0;
    while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
    return v >= 100 ? `${v.toFixed(0)} ${units[u]}` : `${v.toFixed(1)} ${units[u]}`;
  }

  // Mock of planner::format_and_encrypt(...).warnings — see crates/core/src/planner.rs.
  // Returns soft warnings the user must explicitly acknowledge.
  function planWarnings(drive, shred) {
    const ws = [];
    if (drive.mounted) {
      ws.push("One or more partitions on this drive are currently mounted. They will be unmounted before encryption begins.");
    }
    if (!drive.removable) {
      ws.push("This is a non-removable internal drive. Confirm you have not accidentally selected your data drive.");
    }
    if (drive.size_bytes >= 2 * 1024 ** 4) {
      ws.push("Drive is ≥ 2 TiB. Encryption can take several hours; do not interrupt power.");
    }
    if (shred && drive.size_bytes >= 2 * 1024 ** 4) {
      ws.push("Shred + ≥ 2 TiB drive: the random-overwrite pass will run for hours before encryption even starts.");
    }
    return ws;
  }

  // Mock of denc_core::progress::ProgressEvent — see crates/core/src/progress.rs.
  // Each item is a delay (ms) plus the event payload played back by encrypt-flow.js.
  function makeEncryptScript(shred) {
    const total = 32 * 1024 * 1024 * 1024; // matches /dev/sdb size; only used for ratios
    const script = [];
    script.push({ at: 0,    event: { kind: "plan_ready", warnings: [] } });

    if (shred) {
      // PreShredding fires ~10 Hz in the real backend; we sample 7 frames.
      for (let i = 1; i <= 7; i++) {
        script.push({
          at: 200 * i,
          event: { kind: "pre_shredding", bytes_done: Math.floor(total * i / 7), bytes_total: total },
        });
      }
    }

    const baseT = shred ? 1600 : 200;
    script.push({ at: baseT + 200, event: { kind: "gpt_created" } });
    script.push({ at: baseT + 600, event: { kind: "p1_formatted" } });
    script.push({ at: baseT + 900, event: { kind: "recovery_written" } });
    // VeraCrypt --create has no progress hook; backend emits indeterminate frames.
    script.push({ at: baseT + 1100, event: { kind: "volume_creating", bytes_written: 0, bytes_total: 0 } });
    script.push({ at: baseT + 4200, event: { kind: "volume_creating", bytes_written: 1, bytes_total: 1 } });
    script.push({ at: baseT + 4500, event: { kind: "verified" } });
    script.push({ at: baseT + 4900, event: { kind: "done", recovery_key_pdf: null } });
    return script;
  }

  // Sample 256-bit recovery key encoded BitLocker-style: 16 groups of 6 decimal
  // digits, each group divisible by 11 (16-bit value × 11). Matches the codec
  // in crates/core/src/recovery_key.rs so the mock will be accepted by the real
  // RecoveryKey::decode() once the backend is wired in.
  // 16 underlying values were picked spread across [0, 65535] and multiplied by 11.
  const recoveryKeyGroups = [
    "050908", // 4628 × 11
    "090794", // 8254 × 11
    "133100", // 12100 × 11
    "200618", // 18238 × 11
    "252450", // 22950 × 11
    "319055", // 29005 × 11
    "382800", // 34800 × 11
    "440220", // 40020 × 11
    "496232", // 45112 × 11
    "550000", // 50000 × 11
    "595980", // 54180 × 11
    "641300", // 58300 × 11
    "678700", // 61700 × 11
    "698500", // 63500 × 11
    "706200", // 64200 × 11
    "715000", // 65000 × 11
  ];

  function recoveryKeyCanonical() { return recoveryKeyGroups.join("-"); }
  function recoveryKeyForDisplay() {
    // 4 rows × 4 groups, mirrors RecoveryKey::encode_for_display()
    const rows = [];
    for (let i = 0; i < 4; i++) {
      rows.push(recoveryKeyGroups.slice(i * 4, i * 4 + 4));
    }
    return rows;
  }

  // Liberal parser used by the unlock wizard's recovery-key field. Mirrors
  // RecoveryKey::decode() — strips whitespace, dashes, dots, then expects 96
  // digits divisible by 11 in 16 groups. Returns null on parse failure.
  function parseRecoveryKey(input) {
    const stripped = input.replace(/[\s\-.]/g, "");
    if (!/^[0-9]{96}$/.test(stripped)) return null;
    const groups = [];
    for (let i = 0; i < 16; i++) {
      const g = stripped.slice(i * 6, i * 6 + 6);
      if (parseInt(g, 10) % 11 !== 0) return null;
      groups.push(g);
    }
    return groups;
  }

  // Read URL query string ?key=value pairs.
  function query() {
    const out = {};
    for (const [k, v] of new URL(window.location.href).searchParams) out[k] = v;
    return out;
  }

  return {
    drives,
    findDrive,
    formatSize,
    planWarnings,
    makeEncryptScript,
    recoveryKeyCanonical,
    recoveryKeyForDisplay,
    parseRecoveryKey,
    query,
  };
})();
