<<<<<<< HEAD
# Drive-Encryptor
=======
# DriveEncryptor

Cross-platform GUI tool to encrypt external and secondary internal drives with **AES-256-XTS**. Drives encrypted on Windows open cleanly on Linux and vice versa, with stock CLI tools as a fallback. Every encrypted drive comes with a printable 256-bit recovery key.

> **Status: v0.3 in progress.** Linux CLI is fully shippable (v0.2). The Tauri GUI for the encrypt flow is scaffolded; system Tauri deps + a manual smoke test on real hardware are the remaining gates before declaring v0.3 done. Windows port (v0.4) and self-contained binary (v0.5) still ahead. Wire format is locked in.

---

## What it does

1. Detects every drive attached to your machine that isn't your system drive.
2. You pick one. **All data on it will be destroyed** — back it up first if you want to keep it.
3. You choose whether to pre-shred:
   - **Encrypt** (default) — lay out the encrypted volume directly. Fast.
   - **Shred + encrypt** (`--shred`) — overwrite the entire drive with random bytes first, *then* encrypt. Slower (one full-drive write pass), but defeats forensic recovery of any pre-existing data and makes the unused regions of the encrypted volume indistinguishable from real ciphertext.
4. You enter a passphrase.
5. The app generates a 256-bit recovery key, displays it, and saves a printable PDF.
6. The drive is encrypted. Either the passphrase **or** the recovery key will unlock it.

**Backing up existing data is on you.** Earlier versions had a "copy off / wipe / restore" mode — it was removed because it added more failure modes than it solved. If you have files you want to keep, copy them off the drive yourself first, then run this.

---

## Supported platforms

| OS | Status | Install |
|---|---|---|
| Windows 10/11 (x64) | Planned | Signed `.msi` installer, ~15 MB |
| Linux (x64) | Planned | AppImage (no apt/dnf needed) or `.deb` / `.rpm` |
| macOS | Out of scope for v1 | — |

The app bundles its dependencies. You do not install Python, Node, or VeraCrypt separately.

**Admin / root is required** to run encryption operations — this is unavoidable, since encrypting a block device needs raw disk access.

---

## Cross-platform interoperability

A drive encrypted on Linux opens on Windows and vice versa, with no special drivers. The drive is laid out as:

| Partition | Size | Filesystem | Purpose |
|---|---|---|---|
| 1 | 10 MB | FAT32 (unencrypted) | Holds `recovery.bin` — the wrapped master key |
| 2 | Rest of drive | VeraCrypt AES-256-XTS, exFAT inside | Your data |

The recovery file in P1 is two encrypted blobs (one wrapped with your passphrase, one with your recovery key). It contains nothing useful to an attacker.

---

## Stock-CLI fallback

You don't need this app to recover your data. With **only** stock VeraCrypt and the recovery key (or passphrase), you can open the drive on any machine using a small published script:

```bash
# Step 1: P1 mounts as a normal drive — read recovery.bin off it
# Step 2: Unwrap the master keyfile
denc-unwrap recovery.bin --recovery-key 123456-234567-... > master.key
# Step 3: Mount the encrypted partition with stock VeraCrypt
veracrypt -t -k master.key --pim=0 /dev/sdX2 /mnt/secure         # Linux
"VeraCrypt.exe" /v \\Device\\HarddiskN\\Partition2 /k master.key /l X /q   # Windows
```

The `denc-unwrap` utility is a single small script (Rust binary or Python equivalent) published in this repository. Its source is the entire spec — anyone can read it, audit it, or reimplement it.

This means: **even if this project disappears, your drives are still recoverable** as long as VeraCrypt exists.

---

## CLI usage

```bash
# List candidate drives (system drive filtered out automatically)
drive-encryptor list

# Show drive details + DriveEncryptor metadata if encrypted
drive-encryptor info /dev/sdX

# Format and encrypt (DESTROYS ALL DATA on the drive)
drive-encryptor encrypt /dev/sdX

# Same, but overwrite the drive with random bytes first (slow but stronger
# privacy guarantees — see "What it does" above)
drive-encryptor encrypt /dev/sdX --shred

# Save the recovery-key PDF to a specific path (defaults to ./recovery-<dev>-<ts>.pdf)
drive-encryptor encrypt /dev/sdX --save-recovery-pdf=/home/me/recovery-USB1.pdf

# Unlock with passphrase
drive-encryptor unlock /dev/sdX --mountpoint /mnt/usb

# Unlock with the printed recovery key
drive-encryptor unlock /dev/sdX --mountpoint /mnt/usb --with-recovery-key

# Lock (dismount)
drive-encryptor lock /mnt/usb
```

Each `encrypt` run prints the recovery key on stdout AND saves a PDF. Save the PDF — without it, if you forget your passphrase, your data is unrecoverable.

`info /dev/sdX` reports the Argon2id parameters baked into the drive's `recovery.bin` and the creation timestamp — useful for audits.

---

## Recovery key

- **256 bits** of cryptographically random entropy.
- **96-digit format**, BitLocker-style: 16 groups of 6 decimal digits, each group divisible by 11 (single-digit error detection).
- **Displayed once** as 4 rows of 4 groups, then exported to a PDF at a location you choose.
- **Never persisted by the app** anywhere else. If you lose both the passphrase and the recovery PDF, your data is unrecoverable. There is no backdoor.

The PDF includes the key, the drive label, and the date created. Print it. Put it somewhere safe.

---

## Security model — at a glance

**Protects against:**
- Drive lost or stolen — attacker has the drive but not your passphrase or recovery key.
- Casual snooping on the unencrypted P1 partition — it contains only encrypted blobs.
- Argv leakage — passphrases never appear in process listings.

**Does NOT protect against:**
- A compromised host computer — keyloggers, malware with admin rights, or anything else with access to your RAM during encryption.
- The "staged copy" mode temporarily exposes your files unencrypted on your host disk. The app warns you about this and refuses to proceed without an explicit acknowledgment.
- Cold boot / RAM scraping attacks. We zeroize secrets after use, but RAM persistence is OS-dependent.
- An attacker who replaces the app binary itself (evil maid). We hash-check the bundled VeraCrypt binary at startup, but you must trust the app you installed.

For the full threat model and crypto design, see [DESIGN.md § 8](DESIGN.md#8-security-boundaries--threat-model).

---

## How it works (one paragraph)

The app uses **VeraCrypt** under the hood for the actual encryption — VeraCrypt is mature, audited, and the only AES-256-XTS implementation with mainstream tooling on both Windows and Linux. VeraCrypt itself only supports a single unlock secret per volume, so we add a thin escrow layer on top: a 64-byte random "master keyfile" is what VeraCrypt actually sees, and that master is wrapped twice (once with your passphrase, once with the recovery key) using Argon2id + AES-256-GCM. Both wraps live in `recovery.bin` on the unencrypted P1 partition. To unlock, the app asks you for either secret, derives the wrap key, decrypts the master, hands it to VeraCrypt, and mounts the volume. The full format is documented in [DESIGN.md § 5](DESIGN.md#5-recovery-key--escrow).

---

## Roadmap

- [x] **v0.1** — Linux CLI, format-and-encrypt, `recovery.bin` v1, `denc-unwrap` utility, fixture-pinned wire format.
- [x] **v0.2** — Argon2id auto-tune, optional pre-shred (`--shred`), mlock'd `SecretBytes`, PDF recovery key export, richer `info` subcommand. *No wire format changes.*
- [~] **v0.3** — Tauri 2 GUI ([DESIGN.md §14](DESIGN.md)). Drive picker wizard, native passphrase dialog (zenity), typed `ProgressEvent` IPC channel, single-use TTL-bounded secret-token store. **Encrypt flow** is the v0.3 scope; unlock/lock/info GUI is v0.3.1. Currently in progress.
- [ ] **v0.4** — Self-contained binary ([DESIGN.md §15](DESIGN.md)). Replace `sgdisk` with the `gpt` crate, `mkfs.fat` with `fatfs`; embed VeraCrypt CLI AppImage via `include_bytes!` extracted to `~/.cache/drive-encryptor/` on first run. One signed installer per OS, ~15 MB, **zero external tool dependencies**.
- [ ] **v0.5** — Windows port (`drive_windows.rs` via WMI), security-crypto audit pass, signed public releases.

### Removed from the roadmap

- ~~Staged-copy / data-preservation mode~~ — implemented in v0.2 then removed: too many failure modes for too little benefit. Manual backup is simpler and safer.
- ~~In-place encryption (Windows + NTFS)~~ — substitutable by manual backup + format-and-encrypt; removed from scope permanently.

## Building from source (developers)

Two scripts handle the whole workflow. Both are idempotent — re-run them anytime.

```bash
./setup.sh        # one-shot: installs all deps + builds + runs unit tests
./test-e2e.sh     # privileged loop-device tests; wraps the sudo + PATH dance
```

`setup.sh` will:
1. Install `gdisk` (provides `sgdisk`) via apt.
2. Install Tauri's Linux build deps — `pkg-config`, `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `libsoup-3.0-dev`, plus `zenity` (the GUI's native passphrase dialog).
3. Install VeraCrypt — first via apt, falling back to enabling the Debian `contrib` repo, falling back to downloading the official `.deb` from launchpad. If all three fail it tells you exactly what to do.
4. `cargo build --workspace` (CLI + core + GUI).
5. `cargo test --workspace` (60 unit tests).

### GUI dev mode

```bash
cargo run -p drive-encryptor-gui     # opens the wizard window
sudo cargo run -p drive-encryptor-gui  # required when actually encrypting
```

For bundled artefacts (.deb / AppImage), use Tauri's CLI:

```bash
cargo install tauri-cli --version '^2'
cd crates/gui && cargo tauri build
```

`test-e2e.sh` runs two `#[ignore]` tests:
- **full pipeline**: 256 MiB loop image → encrypt → unlock-with-passphrase → write file → unlock-with-recovery-key → read file back.
- **cross-tool fallback**: same encrypt step, then `denc-unwrap` extracts the master and **stock VeraCrypt** mounts the partition. This is the load-bearing proof that the design's "recoverable without our app" guarantee holds.

---

## License

TBD. Will be MIT or Apache-2.0 for our code; bundled VeraCrypt retains its dual Apache 2.0 / TrueCrypt License 3.0.

## Acknowledgments

- [VeraCrypt](https://veracrypt.fr) — does the actual encryption work.
- [Tauri](https://tauri.app) — cross-platform app shell.
>>>>>>> recover
