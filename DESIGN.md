# DriveEncryptor — Design

**Status:** Proposed (pre-implementation)
**Scope:** Cross-platform GUI + CLI tool to encrypt external and secondary internal drives with AES-256-XTS, with passphrase + 256-bit recovery key.

---

## 1. Context & Constraints

| Constraint | Impact on design |
|---|---|
| Drives encrypted on one OS must open cleanly on the other | Forces interoperable on-disk format. Rules out LUKS-only and BitLocker-only. |
| Must be openable with stock CLI on both OSes | Forces a format that ships with a mainstream CLI tool on both Windows and Linux. |
| AES-256-XTS, 256-bit recovery key | Constrains crypto primitives. |
| GUI, near-zero install friction | Single signed installer per OS, no separate runtime install. |
| External + secondary internal drives only | No pre-boot environment, no bootloader integration. System drive is explicitly refused. |
| Two unlock paths: passphrase OR recovery key | Backend (VeraCrypt) only natively supports one. We must layer escrow ourselves. |

---

## 2. ADR — Crypto Backend

**Status:** Proposed
**Decision:** Use **VeraCrypt** as the underlying encryption engine, invoked via its CLI.

### Options considered

1. **Native per-OS (BitLocker on Windows, LUKS2/dm-crypt on Linux)**
   - ✅ Best per-OS integration, FIPS-validated, kernel-resident
   - ❌ Drives are not portable between OSes without third-party drivers
   - ❌ Rejected by the cross-OS interop requirement
2. **VeraCrypt (chosen)**
   - ✅ Same on-disk format, stock CLI on both OSes (`veracrypt` package on Linux, bundled CLI in Windows installer)
   - ✅ AES-256-XTS is the default mode
   - ✅ Mature, audited (OSTIF audit 2016), open source
   - ✅ KDF is PBKDF2 with SHA-512 — accepted as-is for the data volume; our escrow layer (§ 5) sits on top and uses Argon2id independently
   - ℹ️ Mixed Apache 2.0 / TrueCrypt License 3.0 — accepted; this is a personal-use project, no redistribution legal review needed
3. **Custom AES-256-XTS implementation over raw block I/O**
   - ❌ Header format, sector mapping, atomic header writes, KDF — every one of these is a footgun
   - ❌ Would require a full crypto audit budget before any user touches it
   - **Rejected.**

### Consequences

- **Easier:** Cross-OS interop is solved by the backend. We focus on UX, drive enumeration, and the recovery-key escrow layer.
- **Harder:** We do not control the KDF or volume header format directly. Forward-compatibility depends on VeraCrypt project survival.
- **Locked in:** The VeraCrypt volume format is now part of our wire contract. Migration to a different backend later would be a one-way migration of every existing drive.

---

## 3. Architecture Overview

```
┌───────────────────────────────────────────────────────────┐
│  GUI (Tauri webview, HTML+JS — display only)              │
│   • Drive list, wizard, progress, recovery-key display    │
└──────────────────────────┬────────────────────────────────┘
                           │ Tauri IPC (in-process)
┌──────────────────────────▼────────────────────────────────┐
│  Core (Rust, runs elevated)                               │
│   ├─ DriveEnumerator   (per-OS implementations)           │
│   ├─ EncryptionPlanner (mode + safety checks)             │
│   ├─ EscrowCodec       (recovery.bin format)              │
│   ├─ VeraCryptDriver   (subprocess wrapper)               │
│   ├─ KeyMaterial       (zeroizing buffers)                │
│   └─ PdfExporter       (recovery key → PDF)               │
└──────────────────────────┬────────────────────────────────┘
                           │ subprocess (keyfile path only — no secret on argv)
┌──────────────────────────▼────────────────────────────────┐
│  Bundled VeraCrypt CLI (per-platform binary in app bundle)│
└───────────────────────────────────────────────────────────┘
```

### Component responsibilities

| Component | Owns | Boundary |
|---|---|---|
| GUI | Display, user input flow, prompts | Never holds long-lived secret material. Design goal: passphrases entered via a native OS prompt invoked from Rust. Current wizard: typed into the webview (see § 14 status) |
| DriveEnumerator | Listing candidate drives, classifying as system/data/removable | OS-specific impls behind a single trait |
| EncryptionPlanner | Selecting mode, validating preconditions (free space, FS type, etc.), refusing system drive | All destructive go/no-go decisions land here |
| EscrowCodec | `recovery.bin` read/write, KDF, AEAD wrap/unwrap, zeroization | Pure function, no I/O outside the file handle |
| VeraCryptDriver | Subprocess lifecycle, keyfile hand-off via an in-memory file (memfd) | Single point of contact with the VeraCrypt binary |
| KeyMaterial | `Zeroize`-on-drop buffers, locked-memory allocation where supported | Used by every layer that touches secrets |
| PdfExporter | Generates a printable PDF of the recovery key + drive identifier + creation date | Writes to user-chosen path only, never a temp dir |

### Why Tauri (not Electron, not Qt, not native-per-OS)

- **Single signed installer per OS** with bundled webview is achievable and small (~15 MB)
- **Rust core** = real types, real `Zeroize`, real subprocess control — important for a security-sensitive tool
- **No Python/Node runtime** for the user to install — meets the "near idiot-proof" install bar
- Trade-off: Webview means there's still a JS runtime in-process, so we deliberately **never let plaintext secrets live in JS** (see § 8)

---

## 4. Encryption Mode

There is **one** encryption mode: format-and-encrypt. It is destructive — it
wipes the drive and creates a fresh encrypted volume. If the user wants to
preserve the drive's existing contents, they must back them up themselves
before running the tool. We intentionally do **not** ship a "copy off, wipe,
restore" mode (we did briefly in v0.2 but removed it — it doubles the failure
surface, leaves plaintext on the host disk during a wide window, and is fully
substitutable by a one-line `cp -a` the user runs themselves).

The user can opt into an additional **pre-shred** step (§ 4.2) for stronger
privacy guarantees on previously-used drives.

### 4.1 Format-and-encrypt (default)

1. Confirm destruction with typed confirmation (user types the drive's serial number).
2. Generate 64-byte master keyfile + 256-bit recovery key (CSPRNG).
3. Generate user passphrase wrap + recovery key wrap → `recovery.bin` bytes (in memory).
4. Wipe partition table.
5. Create new GPT with P1 (10 MB FAT32) + P2 (rest, raw).
6. mkfs.fat on P1.
7. Mount P1 rw, write `recovery.bin`, unmount.
8. `veracrypt --create P2 --keyfiles=<master> --encryption=AES --hash=sha-512 --filesystem=exfat --quick=no`.
9. Zeroize master in memory.

**Properties:** Simplest, no plaintext intermediary at any point on the host
disk. Total time dominated by VeraCrypt's volume-fill pass (a few minutes per
GiB on USB 3.0).

### 4.2 Optional pre-shred (`--shred` flag)

When `--shred` is set, immediately after the master/recovery key generation
and **before** the GPT layout, we overwrite the entire drive with
cryptographically-random bytes (1 MiB chunks, single pass). This:

- Defeats forensic recovery of any pre-existing data (especially relevant
  if the drive was previously used to hold sensitive files).
- Fills the unused regions of the future encrypted volume with random bytes,
  making "is this a freshly-created VeraCrypt volume?" fingerprinting harder
  (a fresh volume's unused regions normally read as zeros under XTS until
  written; with pre-shred they look like real ciphertext).
- Adds one full-drive write — slow on large drives (hours on multi-TiB
  spinning disks). The planner emits an extra warning when `--shred` is
  combined with a drive ≥ 2 TiB.

**Honest threat model:** on SSD/NVMe a single overwrite cannot guarantee that
*every physical cell* is overwritten — wear-levelling and the FTL can keep
copies of old data in retired blocks. What pre-shred guarantees is that the
*logical* drive contents are all random, which defeats every standard
file-carving recovery tool. For "I'm decommissioning a drive that held
classified data" the only defensible answer is hardware secure-erase or
physical destruction, neither of which is in scope.

### What's deliberately not here

- **In-place encryption (modify-in-place without wiping)** — was sketched in
  earlier design drafts (Windows + NTFS via VeraCrypt's `/encrypt` mode) but
  removed. It's the highest-risk code path of the original design (VeraCrypt
  itself only supports it on one OS and one filesystem), it can't preserve
  the GPT layout this tool needs, and it's substitutable by "back up
  manually + format-and-encrypt." Out of scope permanently.
- **Staged copy (copy off / wipe / restore)** — was implemented in v0.2 then
  removed. The plaintext-on-host exposure window, the partition-rescan races
  with the source drive, and the "what if our copy is incomplete" failure
  modes added more risk than they removed. Manual backup is simpler, safer,
  and gives the user explicit control.

---

## 5. Recovery Key & Escrow

### 5.1 Why we need a custom escrow layer

VeraCrypt natively supports exactly one unlock secret per volume (password and/or keyfile combined into one KDF input). The requirement for **passphrase OR recovery key** as independent unlock paths cannot be expressed in the VeraCrypt header. We add an escrow layer above it.

### 5.2 The `recovery.bin` format (wire contract — irreversible once shipped)

Stored as a single file in the FAT32 partition (P1) of the drive. Little-endian throughout.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | Magic | `DENC0001` ASCII |
| 8 | 4 | Format version | `1` |
| 12 | 4 | KDF algorithm | `1` = Argon2id |
| 16 | 4 | AEAD algorithm | `1` = AES-256-GCM |
| 20 | 4 | Argon2id memory (KiB) | Auto-tuned at creation (target ≈ 1 s on creating machine, floor 64 MiB), recorded here for unlock |
| 24 | 4 | Argon2id iterations | Auto-tuned, floor `t=2` |
| 28 | 4 | Argon2id parallelism | Auto-tuned, floor `p=1` |
| 32 | 16 | Salt — passphrase wrap | |
| 48 | 16 | Salt — recovery wrap | |
| 64 | 12 | Nonce — passphrase wrap | |
| 76 | 64 | Ciphertext — wrapped master keyfile (passphrase) | |
| 140 | 16 | GCM tag — passphrase wrap | |
| 156 | 12 | Nonce — recovery wrap | |
| 168 | 64 | Ciphertext — wrapped master keyfile (recovery key) | |
| 232 | 16 | GCM tag — recovery wrap | |
| 248 | 32 | Drive label hash | SHA-256 of "DriveEncryptor:" + the device path at creation (e.g. `/dev/sdb`) — informational, never checked |
| 280 | 8 | Created-at | Unix seconds |
| 288 | 32 | Header HMAC | HMAC-SHA256 over bytes 0..288, key = SHA-256("recovery.bin v1 hmac") — integrity only, not authentication |

**Total: 320 bytes.** The file is exactly these 320 bytes (readers accept trailing bytes).

**Accepted KDF range on read:** memory ≤ 256 MiB, iterations ≤ 32, parallelism ≤ 8. The HMAC key is public, so the header is attacker-controllable; without caps a crafted drive could make unlock hang or exhaust RAM. Writers stay far below (64 MiB, t ≤ 10, p = 1).

**The "master" inside both wraps is the same 64-byte VeraCrypt keyfile.** Both unlock paths recover the same VeraCrypt master, which then unlocks the actual data volume.

### 5.3 Unlock flow

```
read recovery.bin from P1
prompt user: passphrase or recovery key?
  passphrase path:  master = AES-GCM-Decrypt(wrap_pass,   key=Argon2id(passphrase,    salt_pass))
  recovery path:    master = AES-GCM-Decrypt(wrap_recov,  key=Argon2id(recovery_key,  salt_recov))
put master in an anonymous memfd (Linux; never linked into any filesystem)
veracrypt --keyfiles=/proc/<pid>/fd/<n> --password= --pim=0 P2 <mountpoint>
scrub and close the memfd (the kernel frees it even if we are killed)
zeroize all in-memory copies
```

### 5.4 "Open with stock CLI alone" — the manual path

We publish a small standalone unwrap utility (single-file Rust binary, `crates/unwrap`, independent of the core crate; a Python port is not written yet) in the project repo. A power user with only stock VeraCrypt can:

```
# 1. Mount P1 (FAT32) — appears as a drive on either OS
# 2. Run our published unwrap tool (prompts for the recovery key):
denc-unwrap recovery.bin --recovery-key > master.key
# 3. Mount the encrypted partition:
veracrypt --text --non-interactive --keyfiles=master.key --pim=0 --password= --protect-hidden=no /dev/sdX2 /mnt/secure   # Linux
"VeraCrypt.exe" /v \\Device\\HarddiskN\\Partition2 /k master.key /l X /q   # Windows
```

The unwrap script is the entire spec — § 5.2 plus a few crypto calls. This guarantees the tool is not a single point of failure: anyone with the recovery key, the drive, and stock VeraCrypt can recover.

### 5.5 Recovery key encoding

- **256 bits** of `getrandom()` / `BCryptGenRandom()` entropy.
- **Encoding**: BitLocker-style — **16 groups of 6 decimal digits**. Each group encodes a 16-bit value `v` as the 6-digit decimal `v × 11`. Every group is therefore divisible by 11, which catches every single-digit typo within a group (changing one digit by d shifts the value by d·10^k ≡ ±d mod 11, never 0). 16 groups × 16 bits = exactly 256 bits, no wasted entropy.
- **Canonical form**: `XXXXXX-XXXXXX-...-XXXXXX` (16 groups joined by `-`).
- **Display**: 4 rows of 4 groups, monospace, with copy button.
- **Liberal parsing on input**: strip whitespace, dashes, dots; case-insensitive (no letters present anyway).
- **Export**: PDF at user-chosen path. PDF contains the key, drive label, creation date, and a one-paragraph "what this is" explainer.
- **Never persisted by us** anywhere else. The key is generated, displayed, exported, then zeroized.

---

## 6. Drive Enumeration & Safety

### 6.1 Per-OS implementations

| OS | Enumeration | System-drive detection |
|---|---|---|
| Linux | `lsblk -J -b -o NAME,PATH,TYPE,SIZE,MOUNTPOINT,MOUNTPOINTS,FSTYPE,SERIAL,RM,RO,VENDOR,MODEL` | Walk the whole lsblk tree under each disk (partitions and anything stacked on them: LUKS, LVM, RAID). System drive = anything in that tree mounted at `/`, `/boot`, `/boot/efi`, `/usr`, `/var`, or used as swap |
| Windows | WMI: `Win32_DiskDrive`, `Win32_DiskPartition`, `Win32_LogicalDisk` | `Win32_OperatingSystem.SystemDrive` → physical disk via partition map |

### 6.2 Hard refusal rules

The planner refuses the operation (no override) when:
- The selected drive contains the running OS (§ 6.1 — including through LUKS/LVM and btrfs subvolumes).
- The drive has active device-mapper / RAID volumes on it (LVM, LUKS, an open VeraCrypt volume, md). They can't be safely torn down by us.
- The drive is read-only, or smaller than 100 MiB.
- The CLI/GUI is given a partition path instead of a whole disk.

Mounted partitions are unmounted before any write; if `umount` fails (busy), the operation stops — no lazy unmount.

Not implemented yet: detecting in-flight writes by other processes (`lsof`), and the "only non-system internal disk" heuristic. Non-removable drives get a soft warning instead.

### 6.3 Soft warnings (override possible with explicit confirmation)

- Drive size > 2 TB (long operation).
- Drive is currently mounted (we will unmount, but warn first).
- Drive contains an existing VeraCrypt volume (re-encrypt would destroy old key).

---

## 7. Cross-Platform CLI Compatibility

The user has two CLI surfaces:

### 7.1 Our app's CLI mode

```
drive-encryptor list
drive-encryptor encrypt /dev/sdX [--shred] [--passphrase-stdin] [--save-recovery-pdf PATH] [--yes]
drive-encryptor unlock  /dev/sdX --mountpoint /mnt/foo [--with-recovery-key] [--secret-stdin]
drive-encryptor lock    /mnt/foo
drive-encryptor info    /dev/sdX
```

Same Rust core, no GUI required. Works headless (servers, SSH).

### 7.2 Stock-tool fallback

Anyone with stock VeraCrypt + our published `denc-unwrap` tool can recover any drive — see § 5.4. This is a **non-negotiable property** of the design and a permanent commitment.

---

## 8. Security Boundaries & Threat Model

### 8.1 Trust zones

| Zone | Trust level | Crosses to |
|---|---|---|
| Webview (JS, HTML) | Untrusted-ish (in-process but executes vendor JS) | Tauri IPC → Core |
| Core (Rust) | Trusted | Subprocess → VeraCrypt CLI; FS → recovery.bin |
| VeraCrypt subprocess | Trusted | Block device |
| VeraCrypt binary on disk | Today: system install found on `PATH`; SHA-256 logged, not checked. Planned (v0.4): bundled and hash-pinned | — |

### 8.2 Secret material lifecycle

| Secret | Origin | Lives in | Zeroized when |
|---|---|---|---|
| User passphrase | CLI: tty / stdin. GUI: webview `<input>` (deviation, see § 14 status) | `SecretBytes` (zeroized, mlock'd where allowed) | After KDF derivation |
| Recovery key (entry) | CLI: tty / stdin. GUI: webview `<input>` | Same as above | After KDF derivation |
| Recovery key (generated) | CSPRNG | Rust buffer; GUI keeps a token for 30 min so the PDF can be saved; the display string is sent to the webview | After PDF write + display dismissed |
| Master keyfile (transient) | CSPRNG | Rust buffer + anonymous memfd | After VeraCrypt mount completes |
| Argon2id-derived KEKs | KDF | Rust buffer | After AEAD operation completes |

**Design goal: webview JS never sees plaintext secrets** (native dialog spawned from Rust; the webview only sees opaque tokens). **Current GUI does not meet it:** passphrases and recovery keys are typed into the webview, and the generated recovery key is displayed there. `request_passphrase` (zenity) exists for a future hardened mode.

### 8.3 Subprocess argv hygiene

VeraCrypt accepts `--password` on the command line. We **never** put a secret there — that exposes it via `/proc/<pid>/cmdline` (Linux) and Process Explorer (Windows). Volumes are keyfile-only: we pass `--password=` (empty) and `--keyfiles=/proc/<our pid>/fd/<n>`, where the fd is an anonymous memfd holding the 64-byte master. The path is not secret, and nothing is left on disk if the process dies.

### 8.4 Threat model: what we do and don't protect against

| Threat | Protected? | Notes |
|---|---|---|
| Drive lost/stolen, attacker has only the drive | **Yes** | Both unlock paths require a secret not on the drive |
| Attacker observes recovery.bin on the drive | **Yes** | Encrypted blobs, indistinguishable from random with KDF protection |
| Evil maid: attacker modifies the bundled VeraCrypt binary | **Partially** | We hash-check at startup, but if attacker replaces our app entirely they win. This is unavoidable for any user-space tool. |
| Cold boot / RAM scraping during operation | **No** | Out of scope; mitigated by zeroize but RAM persistence is OS-dependent |
| Keylogger on host | **No** | Out of scope |
| Quantum adversary | **No** | AES-256 + XTS gives 128-bit post-quantum strength; acceptable for current threat models |

---

## 9. Failure Modes

| Failure | Detection | Response |
|---|---|---|
| Power loss during § 4.1 format | Magic absent on next mount | Drive is unrecoverable — same as any failed format. User informed pre-flight. |
| Power loss during § 4.2 pre-shred | New random bytes overwrote some/all of the old contents; drive looks like noise | Drive is unrecoverable. Same prior-state outcome as above (the user agreed to destroy contents anyway). |
| recovery.bin corruption (P1 damaged) | HMAC check fails | Drive is recoverable only if the user kept an external copy of `recovery.bin`. We do not currently expose an "export master keyfile" backup; the recovery PDF is the user's protection. |
| VeraCrypt subprocess crash | Exit code, stderr | Surface stderr to user, abort transaction, don't touch P2. |
| User cancels mid-encryption | UI cancel button | If pre-write-to-disk: trivial abort. If mid-VeraCrypt-create: partial encrypted volume; treat drive as destroyed (warned). |

---

## 10. Decisions & Remaining Questions

### Locked in

- **Bundle VeraCrypt** in the installer. Personal-use project, no redistribution licensing concerns.
- **Argon2id parameters: auto-tuned** at creation time, targeting ≈1 second on the creating machine, with floors of 64 MiB / t=2 / p=1. Parameters are recorded in `recovery.bin` so any future machine can replay the KDF regardless of its own speed.
- **One recovery key only.** No "export the raw master keyfile" advanced option. Keeps the secret-management story simple: passphrase + one printed PDF.
- **VeraCrypt's PBKDF2-SHA-512 for the data volume is accepted as-is.** Argon2id sits in our escrow layer above it, which is the layer the user-supplied secrets actually touch.

### Still open (minor, non-blocking)

1. **Distributed-build attribution** — VeraCrypt's mixed Apache 2.0 / TrueCrypt License 3.0 requires an attribution screen on first launch when bundled for redistribution. For the current personal-use scope (no public distribution), accepted. When the project ships publicly, add a one-time attribution dialog before the first encrypt and acknowledge the licenses in the installer.

### Resolved during v0.2

- **PDF generation library** — `printpdf` (pure Rust). Implemented in `core::pdf`. No external binary needed.
- **Filesystem inside the encrypted volume** — exFAT default; NTFS is an open option for v0.3 once we expose a `--inner-fs` flag.

---

## 11. Irreversible Decisions (call out before commitment)

These are wire-format / protocol commitments. Changing them later means migrating every existing drive.

1. **VeraCrypt as the data-volume format.** Switching backends = re-encrypting every drive.
2. **`recovery.bin` v1 format** (§ 5.2). New versions can coexist via the version field, but v1 must remain readable forever or we strand users.
3. **GPT layout: P1 = 10 MB FAT32 escrow, P2 = VeraCrypt data.** Changing the layout means existing drives need migration.
4. **Recovery key encoding** (16 groups of 6 decimal digits, each group = 16-bit value × 11, divisible-by-11 check). Printed PDFs from v1 must remain decodable forever.
5. **The "stock CLI fallback" guarantee** (§ 5.4 / § 7.2). Once published, users will rely on it. Format changes that break it are user-hostile.

---

## 12. Out of Scope

- System/boot drive encryption (use BitLocker or LUKS native)
- Encrypted file containers (use VeraCrypt directly)
- Network-attached storage
- Hidden volumes / plausible deniability
- Hardware-key (YubiKey, etc.) integration — possible v2
- Multi-user shared drives with per-user keys — possible v2
- **In-place encryption (modify-without-wipe).** Removed permanently — see § 4.
- **Staged-copy / data preservation.** Removed in v0.2. The user backs up manually.
- **Anti-forensic erasure on SSD/NVMe.** `--shred` defeats logical recovery only; physical-cell-level guarantees would require hardware secure-erase, which is out of scope.
- macOS support — possible v2 (VeraCrypt supports it; we'd need to add the Tauri target and per-OS drive enumeration)

---

## 13. → security-crypto audit recommended

Before any release, audit:
- The `recovery.bin` format and KDF parameter choices (§ 5.2)
- The key zeroization story across the GUI / IPC / subprocess boundary (§ 8.2)
- The pre-shred CSPRNG source and end-of-device handling (§ 4.2)
- Subprocess argv handling for any VeraCrypt invocation (§ 8.3)
- The published `denc-unwrap` tool (it is part of the trust boundary for recovery)

---

## 14. v0.3 — Tauri GUI architecture

**Status:** the encrypt and unlock wizards are implemented (`crates/gui`). Deviations from the plan below:
- Passphrases are typed into the webview and sent over IPC (`commit_passphrase`), not taken from a native dialog. `request_passphrase` (zenity) is kept but unused.
- `inspect_drive` is not implemented; `plan_encrypt(path, shred)` and `start_encrypt(drive_path, shred, passphrase_token)` take the drive path, not a plan object.
- The whole GUI process, including the webview, runs as root. A privileged helper with an unprivileged UI would shrink that.
- Only one encrypt/unlock runs at a time; the wizard can't go back once encryption has started.

**Goal:** the GUI sits on top of the v0.2 CLI core. No core refactor; the GUI is a new crate that links `denc_core` and exposes Tauri commands matching the CLI subcommands.

### Component layout

```
┌─────────────────────────────────────────────────┐
│  Webview (HTML/JS/CSS — display only)           │
│   • Drive list, wizard, recovery-key display    │
│   • Zero plaintext secrets ever live in JS      │
└──────────────────┬──────────────────────────────┘
                   │ Tauri IPC commands (typed)
┌──────────────────▼──────────────────────────────┐
│  Tauri Rust shell (`crates/gui/`)               │
│   • IPC handlers → call denc_core directly      │
│   • Native passphrase dialog (OS dialog,        │
│     spawned by Rust, bypasses webview entirely) │
│   • `tracing` subscriber → ProgressEvent stream │
└──────────────────┬──────────────────────────────┘
                   │ Function calls
┌──────────────────▼──────────────────────────────┐
│  denc_core (unchanged)                          │
└─────────────────────────────────────────────────┘
```

### IPC command list

Each Tauri command is the GUI counterpart of one CLI subcommand. All return JSON-serializable values; secrets never cross this boundary.

| Command | Mirrors CLI | Args | Returns |
|---|---|---|---|
| `list_drives` | `list` | — | `Vec<DriveInfo>` |
| `inspect_drive` | `info` | `path: String` | `DriveInfo + Option<EscrowMetadata>` |
| `plan_encrypt` | (internal) | `path, mode, staging_dir?` | `EncryptionPlan` (warnings, mode, etc.) |
| `start_encrypt` | `encrypt` | `plan, secret_token` | `Recovery key + PDF path` |
| `start_unlock` | `unlock` | `path, mountpoint, secret_token, kind` | `MountResult` |
| `dismount` | `lock` | `mountpoint` | `()` |
| `cancel` | (interrupt) | `op_id` | best-effort |

`secret_token` is an opaque handle that the **Rust shell** holds, NOT the JS layer. JS asks the Rust shell to "show a passphrase dialog and remember the answer as token T"; later JS calls `start_encrypt(plan, T)`. The token is consumed and discarded after one use.

### Native passphrase dialog (the security-critical bit)

Webview JS **never** sees passphrase plaintext. The Rust shell spawns:
- **Linux**: `zenity --password` subprocess; output read directly into a `SecretBytes` and stored against a token.
- **Windows**: native credential prompt via `windows-rs` (`CredUIPromptForCredentials` or the newer `CredUIPromptForWindowsCredentials`).
- **macOS** (v2+): `osascript` `display dialog` with the `hidden answer` flag.

References §8.2 (secret material lifecycle) — the trait surface there already accommodates this.

### ProgressEvent schema

The CLI prints log lines via `tracing`. The GUI subscribes to the same events and routes them to the webview as typed updates.

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgressEvent {
    PlanReady { warnings: Vec<String> },
    PreShredding { bytes_done: u64, bytes_total: u64 }, // emitted ≤ 10 Hz
    GptCreated,
    P1Formatted,
    RecoveryWritten,
    VolumeCreating { bytes_written: u64, bytes_total: u64 }, // see note
    Verified,
    Done { recovery_key_pdf: Option<PathBuf> },
    Aborted { reason: String },
}
```

**Note on `VolumeCreating`:** VeraCrypt's `--create` does not expose a
programmatic progress hook, so we emit a single before/after pair — `bytes_total = 0`
means "indeterminate" and the GUI shows a spinner during this window.
v0.5 (self-contained binary, § 15) replaces VeraCrypt invocation with our
own AES-XTS write loop; that milestone gets real per-MiB progress.

### Drive picker UX

Single-page wizard:
1. Drive list (filtered by `drive_linux::enumerate`, system drive grayed out and unselectable).
2. Mode chooser — **Format only** vs **Format + Shred**. The shred radio reveals an extra warning about wall-clock time on large drives.
3. Plan review — warnings shown explicitly with one "I understand all data on this drive will be destroyed" checkbox.
4. Native passphrase dialog spawn (Rust shell side; webview never sees plaintext).
5. Progress page consuming `ProgressEvent`s. Pre-shred phase shows a real progress bar; volume-creating phase shows an indeterminate spinner.
6. Recovery key reveal — copy button, "save PDF" button (defaults to user's Documents folder), plain-language "to unlock later, run …" CLI hint.

### What v0.3 reuses from v0.2 unchanged

- `denc_core::operations::*` — every workflow is already a single function call.
- `denc_core::planner::*` — already returns `warnings: Vec<String>` ready to display.
- `denc_core::pdf::export_recovery_pdf` — call from a "Save PDF" button handler.
- `tracing` events — install a Tauri-aware subscriber instead of the CLI's `fmt`.

### What v0.3 needs that v0.2 doesn't have

- A new crate `crates/gui/` (Tauri scaffold).
- Native passphrase prompt impls (one per OS).
- Webview UI (HTML+JS).
- Bundled installer per OS (Tauri produces these natively).

---

## 15. v0.4 — Self-contained binary roadmap (planned, not yet implemented)

**Goal:** kill all external-tool installation friction. The user runs **one** signed binary; everything works.

### Replacements

| External tool today | Replacement | Why |
|---|---|---|
| `sgdisk` (gptfdisk pkg) | [`gpt`](https://crates.io/crates/gpt) crate (pure Rust GPT read/write) | We only need GPT layout writes — fully covered. |
| `mkfs.fat` (dosfstools pkg) | [`fatfs`](https://crates.io/crates/fatfs) crate (pure Rust FAT12/16/32 read+write) | Bonus: with `fatfs`, we can write `recovery.bin` directly into the in-memory FAT image and dd it to P1 — no `mount` syscall needed at all for the escrow partition. |
| `mount`/`umount` (P1 access) | direct `fatfs` I/O on the partition device | See above. We still need `mount`/`umount` for the source-data partition during staged-copy (foreign filesystems we don't reimplement); v0.4 keeps those calls but makes them best-effort and gracefully skips if `mount` is unavailable. |
| `blkid` (util-linux pkg) | Inline magic-byte detection in our staging helper | Recognize FAT/NTFS/ext4 by their well-known signatures. v0.4 supports the same set as v0.2. |
| `veracrypt` (separate pkg) | Embedded **VeraCrypt CLI AppImage** via `include_bytes!` → extracted to `~/.cache/drive-encryptor/veracrypt-<sha256>/` on first run, hash-verified, exec'd from there | One install command (`apt install` or `.deb`/`.msi`/AppImage installer) brings everything along. |

### Build process

- `build.rs` downloads the pinned VeraCrypt AppImage from the official URL **at build time only**, hash-verifies, embeds via `include_bytes!`. Reproducible because the URL + SHA-256 are pinned.
- For air-gapped builds: a `vendor/` directory checked into the repo (gitignored by default; populated by `setup.sh` for distribution builds).
- Final binary size: ≈ 15 MB (Rust core ~2 MB + VeraCrypt AppImage ~12 MB + AppImage runtime ~1 MB).

### First-run extraction

```rust
fn ensure_veracrypt_extracted() -> PathBuf {
    const EMBEDDED: &[u8] = include_bytes!("../vendor/veracrypt.AppImage");
    const SHA256: &str = "<pinned-at-build>";
    let target = directories::ProjectDirs::from("", "", "drive-encryptor")?
        .cache_dir()
        .join(format!("veracrypt-{}", SHA256));
    if !target.is_file() {
        // Verify embedded matches pinned SHA-256 (defense in depth).
        let actual = sha2::Sha256::digest(EMBEDDED);
        assert_eq!(hex::encode(actual), SHA256);
        std::fs::write(&target, EMBEDDED)?;
        std::fs::set_permissions(&target, Permissions::from_mode(0o755))?;
    }
    target
}
```

`VeraCryptDriver::detect()` learns this path first, then falls back to `which veracrypt` for development overrides.

### Trust boundary update

§ 8.1 already lists "bundled VeraCrypt binary on disk → tamper-checked at startup via embedded SHA-256." v0.4 makes this real:
1. Embedded blob has a known SHA-256 from build time.
2. On extract, verify the blob hash matches.
3. The extracted file lives in a per-user cache directory (mode 0700) — only the owner can mutate it.
4. Re-verify hash on each launch; re-extract on mismatch.

### Trade-offs

- **Pro:** zero runtime install steps. User downloads `drive-encryptor.AppImage` (or `.msi`); double-click; works.
- **Pro:** removes 5 external-tool dependencies, simplifying the failure-mode matrix.
- **Con:** binary is ~15 MB instead of ~2 MB.
- **Con:** updating VeraCrypt requires a re-release of our app. Acceptable cadence: VeraCrypt has historically released once or twice a year.
- **Con:** licensing concerns when **distributing** the bundled AppImage publicly (resolved per §10 — attribution screen on first launch).

### What v0.4 leaves untouched

The wire format (`recovery.bin` v1, GPT layout, recovery key encoding) does not change. Existing drives encrypted with v0.1/v0.2/v0.3 unlock identically with v0.4 binaries. This is purely a packaging milestone.
