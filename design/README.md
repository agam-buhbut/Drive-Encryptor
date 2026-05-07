# DriveEncryptor — UI prototype (design branch)

Static HTML/CSS/JS mock of the v0.3 GUI ([../DESIGN.md](../DESIGN.md) §14). No
Rust, no Tauri, no IPC — just three pages you can open in any browser to walk
the visual flow before the real Tauri shell is built.

**Aesthetic:** Windows 95/98 retro chrome (Wizard 97 layout, beveled buttons,
chunked progress bar). Hand-rolled CSS in [css/win9x.css](css/win9x.css); no
external libraries or fonts.

## How to view

```bash
xdg-open design/index.html        # Linux
# or just drag design/index.html into a browser tab
```

The pages are vanilla HTML — `file://` works fine. No build step.

## Pages

| Page | Purpose |
|---|---|
| [index.html](index.html) | Main window: drive list with toolbar (Encrypt / Unlock / Info / Refresh). Clicking a drive selects it; Encrypt/Unlock open the corresponding wizard with the drive path passed as `?path=` |
| [encrypt.html](encrypt.html) | 7-step encrypt wizard: confirm-destruction → mode → plan review → passphrase → progress → recovery-key reveal → done |
| [unlock.html](unlock.html) | 5-step unlock wizard: drive confirm → method (passphrase / recovery key) → secret + mountpoint → mounting → result. Append `?wrong=1` to demo the failure path |

## What's mocked vs. what the real v0.3 will do

| Surface | Prototype | Real v0.3 (Tauri) |
|---|---|---|
| Drive list | Hardcoded `MOCK.drives` in [js/mock-data.js](js/mock-data.js) | `drive_linux::enumerate()` via Tauri IPC |
| Plan warnings | Static array per drive in `MOCK.planWarnings` | `planner::format_and_encrypt(&drive, shred)` warnings |
| Passphrase entry | Webview `<input type=password>` with a yellow "mocked" banner | Native OS dialog (`zenity --password` / `CredUIPromptForWindowsCredentials`) — webview never sees plaintext (DESIGN.md §8.2) |
| Progress events | Timer playback in [js/encrypt-flow.js](js/encrypt-flow.js) | Real `ProgressSink` impl in the Tauri Rust shell, emitting events per [`crates/core/src/progress.rs`](../crates/core/src/progress.rs) |
| Recovery key | Fixed sample value in `MOCK.recoveryKeyGroups` (groups divisible by 11 to match the real codec — `RecoveryKey::decode()` would accept it) | `RecoveryKey::generate()` then `encode_for_display()` |
| Recovery-key parse | `MOCK.parseRecoveryKey` mirrors the liberal parser in [`crates/core/src/recovery_key.rs`](../crates/core/src/recovery_key.rs) | Real `RecoveryKey::decode()` |
| PDF export | `[Save PDF…]` shows an alert | `pdf::export_recovery_pdf()` |
| Folder picker | `[Browse…]` shows an alert | Tauri shell's native folder-picker |

## Promotion path

When v0.3 begins, the HTML/CSS skeleton can be lifted under `crates/gui/ui/`
in the Tauri scaffold; the JS-mocked transitions get replaced with calls to
the IPC commands from DESIGN.md §14. The chrome (`win9x.css` + `app.css`)
and the per-page DOM structure are intended to survive that transition.

## File map

```
design/
├── README.md                 # this file
├── index.html                # drive list (home)
├── encrypt.html              # encrypt wizard (7 steps)
├── unlock.html               # unlock wizard (5 steps)
├── css/
│   ├── win9x.css             # Win9x chrome (windows, buttons, listview, progress, modal)
│   └── app.css               # DriveEncryptor-specific layout (recovery grid, log pane, etc.)
└── js/
    ├── mock-data.js          # fake Drive[], plan warnings, progress script, recovery key
    ├── nav.js                # Wizard step show/hide + footer button state + cancel modal
    └── encrypt-flow.js       # timed playback of ProgressEvent stream → progress UI
```

## Out of scope (deferred)

- Drive **Info** screen (Argon2 params, created_at) and explicit **Lock**
  flow. Both are easy extensions on the same chrome — the toolbar already
  has a disabled Info button to slot one in.
- Real clipboard / PDF / folder-picker plumbing — placeholders only.
- Localization, full ARIA semantics, keyboard-only navigation. The Tauri
  build will tighten these once the visual flow is approved.
- Any changes under `../crates/`.
