// mock-data.js (now Tauri-backed) — exposes the same `window.MOCK` namespace
// the design prototype used, but every method that touched fake data is now
// a thin wrapper around a Tauri command from `crates/gui/src/commands.rs`.
//
// Pages that previously read `MOCK.drives` synchronously must now `await
// MOCK.loadDrives()` first; the patched IIFEs in index/encrypt/unlock.html do.

window.MOCK = (function () {
  const tauri = window.__TAURI__ || {};
  const invoke = (tauri.core && tauri.core.invoke) ? tauri.core.invoke : null;
  const eventApi = tauri.event || null;

  let drives = [];
  let drivesLoaded = false;

  // Pull a fresh drive list from drive_linux::enumerate() via IPC.
  async function loadDrives() {
    if (!invoke) {
      console.warn("Tauri IPC not available; running outside the GUI shell.");
      drives = [];
      drivesLoaded = true;
      return drives;
    }
    const raw = await invoke("list_drives");
    // Map the Rust DriveInfo into the shape the design's HTML/JS expects.
    drives = raw.map((d) => ({
      path: d.path,
      kind: "Disk",
      size_bytes: d.size_bytes,
      removable: d.removable,
      readonly: d.readonly,
      serial: d.serial || "",
      vendor: d.vendor || "",
      model: d.model || "",
      partitions: [],
      isSystem: d.is_system_drive,
      mounted: false, // not yet exposed by the backend; Status column shows System/Idle only
    }));
    drivesLoaded = true;
    return drives;
  }

  function findDrive(path) {
    return drives.find((d) => d.path === path);
  }

  function formatSize(bytes) {
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let v = bytes;
    let u = 0;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u++;
    }
    return v >= 100 ? `${v.toFixed(0)} ${units[u]}` : `${v.toFixed(1)} ${units[u]}`;
  }

  // Plan warnings come from `planner::format_and_encrypt(&drive, shred)` via
  // the `plan_encrypt` IPC command. Returns the array of warning strings.
  async function planWarnings(drive, shred) {
    if (!invoke) return [];
    try {
      const summary = await invoke("plan_encrypt", { path: drive.path, shred: !!shred });
      return summary.warnings || [];
    } catch (e) {
      console.error("plan_encrypt failed:", e);
      return [`Plan failed: ${e}`];
    }
  }

  // Commit a JS-typed passphrase to the Rust shell's TokenStore. Returns the
  // opaque single-use token id.
  //
  // §8.2 deviation: this UX has the user type into a webview <input>, so the
  // passphrase briefly lives in JS strings before crossing IPC. The original
  // design's "native dialog (mocked)" banner already flagged this trade-off.
  async function commitPassphrase(s) {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("commit_passphrase", { passphrase: s });
  }

  async function commitRecoveryKey(encoded) {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("commit_recovery_key", { encoded });
  }

  // Start an encrypt operation. Resolves with the EncryptResult (recovery key
  // display + token + default PDF path).
  async function startEncrypt({ drivePath, shred, passphraseToken }) {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("start_encrypt", {
      drivePath,
      shred,
      passphraseToken,
    });
  }

  async function startUnlock({ drivePath, secretToken, kind, mountpoint }) {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("start_unlock", {
      drivePath,
      secretToken,
      kind,        // "passphrase" | "recovery_key"
      mountpoint,
    });
  }

  async function dismount(mountpoint) {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("dismount", { mountpoint });
  }

  async function cancel() {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("cancel");
  }

  // Spawn a native folder picker (rfd) on the Rust side. Returns the picked
  // path or null if the user cancelled.
  async function pickFolder() {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("pick_folder");
  }

  // Spawn a native save dialog (rfd) and write the recovery-key PDF if the
  // user picked a path. Returns the picked path or null.
  async function saveRecoveryPdf({ recoveryKeyToken, driveLabel, defaultName }) {
    if (!invoke) throw new Error("Tauri IPC not available");
    return await invoke("save_recovery_pdf", {
      recoveryKeyToken,
      driveLabel,
      defaultName,
    });
  }

  // Subscribe to `progress` events emitted by GuiSink. `cb(event)` is called
  // for each ProgressEvent. Returns an unlisten function.
  async function listenProgress(cb) {
    if (!eventApi) return () => {};
    return await eventApi.listen("progress", (e) => cb(e.payload));
  }

  // Liberal recovery-key parser, JS-side echo of RecoveryKey::decode(). Used
  // by the unlock wizard to give immediate format feedback before sending
  // the key to the backend. The backend re-validates.
  function parseRecoveryKey(input) {
    // \p{White_Space} is exactly Rust's char::is_whitespace; JS's \s differs
    // (it includes U+FEFF and omits U+0085).
    const stripped = input.replace(/[\p{White_Space}\-.]/gu, "");
    if (!/^[0-9]{96}$/.test(stripped)) return null;
    const groups = [];
    for (let i = 0; i < 16; i++) {
      const g = stripped.slice(i * 6, i * 6 + 6);
      const v = parseInt(g, 10);
      // Each group is a 16-bit value times 11, so at most 65535 * 11 = 720885.
      if (v % 11 !== 0 || v > 720885) return null;
      groups.push(g);
    }
    return groups;
  }

  // Escape text before it goes into an innerHTML template. Drive vendor,
  // model and serial come from the device itself (a USB stick can report
  // arbitrary strings), so they must never be parsed as markup.
  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
  }

  function query() {
    const out = {};
    for (const [k, v] of new URL(window.location.href).searchParams) out[k] = v;
    return out;
  }

  return {
    // synchronous accessors (require loadDrives() first)
    get drives() { return drives; },
    get drivesLoaded() { return drivesLoaded; },
    findDrive,

    // helpers
    formatSize,
    esc,
    parseRecoveryKey,
    query,

    // async backend wrappers
    loadDrives,
    planWarnings,
    commitPassphrase,
    commitRecoveryKey,
    startEncrypt,
    startUnlock,
    dismount,
    cancel,
    pickFolder,
    saveRecoveryPdf,
    listenProgress,
  };
})();
