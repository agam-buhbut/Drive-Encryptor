# Build Script Design — DriveEncryptor Makefile

## Summary

A `Makefile` at the project root that builds, installs, and uninstalls
DriveEncryptor. The CLI binary becomes accessible from any terminal
(via `~/.local/bin`); the GUI becomes a desktop application with an icon
and launcher entry.

Also adds missing `.gitignore` entries for IDE and secret files.

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make` / `make build` | `cargo build --release` |
| `make install` | Build then install CLI + GUI + desktop entry |
| `make uninstall` | Remove CLI binary, GUI binary, and both desktop files |
| `make clean` | `cargo clean` |

All targets are `.PHONY`.

---

## Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `INSTALL_DIR` | `$(HOME)/.local/bin` | Destination for both binaries |
| `APP_DIR` | `$(HOME)/.local/share/applications` | System app launcher entry |
| `DESKTOP_DIR` | `$(HOME)/Desktop` | Desktop shortcut |
| `ICON` | `$(HOME)/Pictures/Screenshots/Screenshot From 2026-05-24 20-39-46.png` | Desktop icon |
| `CLI_BIN` | `drive-encryptor` | CLI binary name |
| `GUI_BIN` | `drive-encryptor-gui` | GUI binary name |

All path variables are overridable at call time:
`make install INSTALL_DIR=/usr/local/bin`

---

## Install Behavior

1. Runs `cargo build --release`
2. Copies `target/release/drive-encryptor` → `$(INSTALL_DIR)/drive-encryptor`
3. Copies `target/release/drive-encryptor-gui` → `$(INSTALL_DIR)/drive-encryptor-gui`
4. Writes `$(APP_DIR)/DriveEncryptor.desktop` (generated inline)
5. Copies desktop file to `$(DESKTOP_DIR)/DriveEncryptor.desktop`
6. Marks desktop file trusted via `gio set ... metadata::trusted true`
7. Runs `update-desktop-database $(APP_DIR)`

Idempotent — re-running overwrites without error.

---

## Uninstall Behavior

Removes with `-f` (no error if already gone):
- `$(INSTALL_DIR)/$(CLI_BIN)`
- `$(INSTALL_DIR)/$(GUI_BIN)`
- `$(APP_DIR)/DriveEncryptor.desktop`
- `$(DESKTOP_DIR)/DriveEncryptor.desktop`

Runs `update-desktop-database $(APP_DIR)` after removal.

---

## Desktop Entry

Generated inline during `make install`:

```ini
[Desktop Entry]
Version=1.0
Type=Application
Name=DriveEncryptor
Comment=Encrypt and manage drives
Exec=$(INSTALL_DIR)/drive-encryptor-gui
Icon=$(ICON)
Terminal=false
Categories=Utility;Security;
StartupNotify=true
```

---

## .gitignore Additions

Three lines added to existing `.gitignore`:

```
.vscode/
.idea/
.env
```

---

## Files Changed

- `Makefile` — created at project root
- `.gitignore` — three lines added
