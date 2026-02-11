# ShredOS Vault — Comprehensive Usage Guide

ShredOS Vault is a self-destructing secure vault system. It adds an authentication
gate with a dead man's switch: authenticate to proceed, or fail too many times and
the drive encrypts itself with a random key and wipes itself.

ShredOS Vault runs from a **unified codebase** that supports three deployment modes:

1. **ShredOS Boot (USB)** — boots from USB, runs as the system init, protects a
   LUKS-encrypted volume with password/fingerprint/voice authentication.
2. **Persistent Install** — installs on the host machine's boot partition
   (Linux/macOS/Windows). Runs every boot before OS login. On auth failure,
   encrypts the entire drive with a random key and wipes it.
3. **secure_wipe (macOS)** — standalone CLI tool for direct low-level disk wiping
   with IOKit, SecRandomCopyBytes, and per-pass verification.

---

## Table of Contents

- [Quick Start — Linux (ShredOS Boot)](#quick-start--linux-shredos-boot)
- [Quick Start — macOS (secure_wipe)](#quick-start--macos-secure_wipe)
- [Persistent Install](#persistent-install)
  - [How It Works](#how-it-works)
  - [Building](#building-persistent-install)
  - [Linux Install](#linux-install)
  - [macOS Install](#macos-install)
  - [Windows Install](#windows-install)
- [Building (USB Image)](#building-usb-image)
- [GRUB Boot Menu](#grub-boot-menu)
- [First-Run Setup Wizard](#first-run-setup-wizard)
- [Normal Boot Flow](#normal-boot-flow)
- [Dead Man's Switch](#dead-mans-switch)
- [Authentication Methods](#authentication-methods)
- [Wipe Algorithms](#wipe-algorithms)
- [Configuration Reference](#configuration-reference)
- [Command-Line Reference — shredos-vault](#command-line-reference--shredos-vault)
- [Kernel Command-Line Parameters](#kernel-command-line-parameters)
- [Command-Line Reference — secure_wipe (macOS)](#command-line-reference--secure_wipe-macos)
- [LUKS Encryption Details](#luks-encryption-details)
- [SSD Limitations](#ssd-limitations)
- [Security Design](#security-design)
- [Troubleshooting](#troubleshooting)

---

## Quick Start — Linux (ShredOS Boot)

```
1. Build the image:
   make shredos_defconfig
   make

2. Write to USB:
   sudo dd if=output/images/shredos-*.img of=/dev/sdX bs=4M status=progress

3. Boot from USB. Select "ShredOS Vault Setup" from the GRUB menu.

4. Follow the setup wizard:
   - Select a target drive to protect
   - Set a password
   - Set the failure threshold (default: 3)
   - Choose a wipe algorithm (default: Gutmann 35-pass)
   - Confirm to format the drive as LUKS encrypted

5. Reboot. Select "ShredOS Vault" from GRUB.

6. Enter your password. On success, the encrypted volume mounts at /vault.
   On 3 consecutive failures, the dead man's switch activates.
```

## Quick Start — macOS (secure_wipe)

```
1. Build:
   cd package/shredos-vault/src/macos
   make

2. View drive info:
   sudo ./secure_wipe --device /dev/disk4 --info

3. Wipe a drive:
   sudo ./secure_wipe --device /dev/disk4 --algorithm gutmann --verify

4. Type YES to confirm when prompted.
```

---

## Persistent Install

ShredOS Vault can be installed directly onto a machine's boot partition so the
authentication gate runs **every time the machine starts** — no USB required.
If authentication fails past the threshold, the **entire drive** is encrypted
with a random key and wiped.

This uses the same full-featured codebase as the USB boot version: all 6 wipe
algorithms, nwipe with direct I/O fallback, ncurses or VT100 TUI, and the
complete dead man's switch with encrypt-before-wipe.

### How It Works

| Platform | Integration Point | Runs Before | TUI |
|----------|-------------------|-------------|-----|
| **Linux** | initramfs hook | Root filesystem mount | ncurses (VT100 fallback) |
| **macOS** | LaunchDaemon | Login window | VT100 on /dev/console |
| **Windows** | Credential Provider + Service | Windows login | Win32 console |

### Building (Persistent Install)

```bash
cd package/shredos-vault/src/vault-gate

# Auto-detect platform and available libraries:
make

# Or specify platform:
make linux    # Dynamically linked, auto-detects ncurses/libconfig/cryptsetup
make macos    # VT100 TUI + IOKit/Security frameworks

# See what libraries were detected:
make detect-libs
```

The Makefile auto-detects available libraries via `pkg-config`:
- **ncurses** — ncurses TUI (falls back to VT100 if not found)
- **libconfig** — libconfig parser (falls back to built-in INI parser)
- **libcryptsetup** — LUKS encryption support
- **libcrypt** — POSIX crypt() for SHA-512 hashing
- **libfprint** — fingerprint authentication (optional)
- **pocketsphinx + portaudio** — voice authentication (optional)

---

### Linux Install

**Boot flow:**
```
GRUB -> kernel -> initramfs -> shredos-vault (password prompt)
                                    |
                              +-----+------+
                            SUCCESS      THRESHOLD
                              |          EXCEEDED
                         cryptsetup       |
                         luksOpen     Encrypt /dev/sda
                         root drive   with random key,
                              |       wipe with Gutmann,
                         Continue     power off
                         normal boot
```

ShredOS Vault runs inside the initramfs — the earliest userspace code after the
kernel. At this point, the root filesystem is NOT mounted, so the vault gate
has raw access to the entire disk.

**Prerequisites:**
- Root/sudo access
- LUKS-encrypted root partition (recommended)
- GCC or Clang

**Installation:**

```bash
cd package/shredos-vault/src/vault-gate

# Use the installer script (recommended — installs deps, builds, configures initramfs):
sudo bash linux/install.sh

# First-time setup:
sudo shredos-vault --setup

# Test interactively (without initramfs mode):
sudo shredos-vault
```

The installer auto-detects your initramfs system:

| System | Distros | What gets installed |
|--------|---------|---------------------|
| **initramfs-tools** | Ubuntu, Debian, Mint | Hook + local-top script |
| **dracut** | Fedora, RHEL, Arch, openSUSE | Module + systemd service |

After install, the initramfs is rebuilt automatically. `copy_exec`/`inst_binary`
auto-copies all shared library dependencies (.so files) into the initramfs.

**File locations:**

| File | Purpose |
|------|---------|
| `/usr/sbin/shredos-vault` | Binary |
| `/etc/shredos-vault/vault.conf` | Configuration |
| `/etc/initramfs-tools/hooks/shredos-vault` | initramfs-tools hook |
| `/etc/initramfs-tools/scripts/local-top/shredos-vault` | initramfs-tools boot script |
| `/usr/lib/dracut/modules.d/90shredos-vault/` | Dracut module directory |

**Uninstallation:**

```bash
sudo bash linux/uninstall.sh
```

---

### macOS Install

**Boot flow:**
```
EFI -> macOS kernel -> loginwindow -> shredos-vault (LaunchDaemon)
                                           |
                                     +-----+------+
                                   SUCCESS      THRESHOLD
                                     |          EXCEEDED
                                Dismiss,      Wipe /dev/rdisk0
                                allow         via raw I/O,
                                login         shutdown
```

ShredOS Vault runs as a LaunchDaemon at boot, presenting a VT100 password prompt
on `/dev/console`. On success, it exits and the normal login window appears. On
failure, it wipes the raw disk.

**Prerequisites:**
- macOS 10.15+
- Root/sudo access
- Xcode Command Line Tools (`xcode-select --install`)

**Recommended:** Enable FileVault for full-disk encryption. ShredOS Vault adds
the dead man's switch layer on top.

**Installation:**

```bash
cd package/shredos-vault/src/vault-gate

# Use the installer:
sudo bash macos/install.sh

# Run setup:
sudo shredos-vault --setup

# Activate:
sudo launchctl load /Library/LaunchDaemons/com.shredos.vault-gate.plist
```

**File locations:**

| File | Purpose |
|------|---------|
| `/usr/local/sbin/shredos-vault` | Binary |
| `/Library/Application Support/ShredOS-Vault/vault.conf` | Configuration |
| `/Library/LaunchDaemons/com.shredos.vault-gate.plist` | LaunchDaemon |
| `/var/log/shredos-vault.log` | Error log |

**SIP Note:** The current implementation uses a LaunchDaemon which does NOT
require disabling System Integrity Protection.

**Uninstallation:**

```bash
sudo bash macos/uninstall.sh
```

---

### Windows Install

**Boot flow:**
```
UEFI -> Windows Boot Manager -> logonui.exe -> ShredOS Vault Credential Provider
                                                      |
                                                +-----+------+
                                              SUCCESS      THRESHOLD
                                                |          EXCEEDED
                                           Allow normal  ShredOS Vault service
                                           Windows       wipes \\.\PhysicalDrive0,
                                           login         shuts down
```

ShredOS Vault uses the Windows Credential Provider mechanism to add a custom
authentication tile to the Windows login screen. A companion Windows service
runs as SYSTEM and handles the wipe operation using the unified wipe engine.

**Prerequisites:**
- Windows 10/11
- Administrator privileges
- Visual Studio (for building) or pre-built binaries

**Recommended:** Enable BitLocker for full-disk encryption. ShredOS Vault adds
the dead man's switch layer on top.

**Building (from Visual Studio Developer Command Prompt):**

```cmd
REM Build the service:
cl /O2 /W4 /DVAULT_PLATFORM_WINDOWS ^
   windows\vault-gate-service.c ..\..\platform.c ..\..\config.c ^
   ..\..\auth_password.c ..\..\wipe.c ..\..\deadman.c ^
   advapi32.lib crypt32.lib /Fe:shredos-vault-service.exe

REM Build the Credential Provider:
cl /EHsc /LD /DUNICODE /D_UNICODE /DVAULT_PLATFORM_WINDOWS ^
   windows\VaultGateProvider.cpp ..\..\auth_password.c ..\..\config.c ^
   ..\..\platform.c ^
   /link ole32.lib advapi32.lib shlwapi.lib crypt32.lib ^
   /OUT:VaultGateProvider.dll
```

**Installation:**

Run `install.bat` as Administrator. This:
1. Copies files to `C:\Program Files\ShredOS-Vault\`
2. Registers the Credential Provider via registry
3. Creates and starts the ShredOS Vault Windows service

**File locations:**

| File | Purpose |
|------|---------|
| `C:\Windows\System32\VaultGateProvider.dll` | Credential Provider DLL |
| `C:\Program Files\ShredOS-Vault\shredos-vault-service.exe` | Wipe service |
| `C:\ProgramData\ShredOS-Vault\vault.conf` | Configuration |
| `C:\ProgramData\ShredOS-Vault\shredos-vault.log` | Service log |

**Testing:**

```cmd
REM Run the service in console mode (for testing):
shredos-vault-service.exe --console
```

**Uninstallation:**

Run `uninstall.bat` as Administrator.

---

## Building (USB Image)

### Linux (ShredOS Bootable Image)

Requires a Buildroot cross-compilation environment.

```bash
# Standard build (password authentication only):
make shredos_defconfig
make

# Enable fingerprint support:
make menuconfig
# Navigate to: Target packages -> shredos-vault -> fingerprint authentication support
make

# Enable voice passphrase support:
make menuconfig
# Navigate to: Target packages -> shredos-vault -> voice passphrase authentication support
make
```

Output images are placed in `output/images/`:
- `shredos-*.img` — USB bootable image
- `shredos-*.iso` — Hybrid ISO (USB/CD)

### macOS (secure_wipe Standalone Tool)

```bash
cd package/shredos-vault/src/macos

# Build:
make

# Or manually:
cc -O2 -Wall -Wextra -Wpedantic -std=c11 \
   -framework Security -framework IOKit -framework CoreFoundation \
   secure_wipe.c -o secure_wipe

# Install system-wide:
sudo make install    # installs to /usr/local/bin/secure_wipe
```

---

## GRUB Boot Menu

When booting from the ShredOS USB, GRUB presents four options (5-second timeout):

| Entry | Description |
|-------|-------------|
| **ShredOS Vault** | Normal operation — authenticate to unlock your volume |
| **ShredOS Vault Setup** | First-run setup wizard (or re-configure) |
| **ShredOS Vault (nomodeset)** | Same as Vault, with GPU compatibility mode |
| **ShredOS Classic (nwipe only)** | Original ShredOS behavior (direct nwipe, no auth) |

---

## First-Run Setup Wizard

Triggered automatically on first boot (no config file found), or manually via:
- GRUB menu: "ShredOS Vault Setup"
- Kernel parameter: `vault_setup`
- Command line: `shredos-vault --setup`

### Setup Steps

**Step 1 — Select Target Device**
- Scans `/sys/block/` for all block devices (Linux) or `diskutil list` (macOS)
- Displays device name and size (e.g., `/dev/sda  500.0 GB`)
- Use arrow keys to select, Enter to confirm
- Loop devices and RAM disks are filtered out

**Step 2 — Set Password**
- Enter a password (masked with `*`)
- Confirm by entering it again
- Passwords must match and cannot be empty
- Linux/macOS: Stored as SHA-512 hash with random 16-byte salt (`$6$` crypt format)
- Windows: Stored as SHA-512 hash (`$vg$sha512$` format via CryptoAPI)

**Step 3 — Set Failure Threshold**
- How many failed authentication attempts before auto-wipe
- Default: 3. Range: 1 to 99
- Use up/down arrows to adjust, Enter to confirm

**Step 4 — Select Wipe Algorithm**
- Choose the algorithm for the dead man's switch
- Options listed with pass count and description
- Default: Gutmann (35-pass) — most thorough

**Step 5 — Format LUKS Volume** (Linux with libcryptsetup only)
- Displays a WARNING that all data will be destroyed
- Must press `Y` to confirm
- Formats the selected device as LUKS2 encrypted volume
- Creates an ext4 filesystem inside the encrypted container
- Saves configuration
- Reboots automatically

---

## Normal Boot Flow

### USB Boot (Linux)

```
Power On
  +- GRUB -> "ShredOS Vault"
       +- Linux kernel boots
            +- inittab -> shredos-vault on tty1
                 +- Load /etc/shredos-vault/vault.conf
                      +- Authentication Screen
                           |
                      +----+----+
                   Correct    Wrong
                   password   password
                      |         |
                      |    Increment counter
                      |    "N attempts remaining"
                      |         |
                      |    Counter < threshold?
                      |    +- Yes -> Retry
                      |    +- No  -> DEAD MAN'S SWITCH
                      |
                 Unlock LUKS volume
                 Mount at /vault
                 Success screen
                      |
                 Press 'q' -> unmount, lock, shutdown
                 Press 's' -> drop to bash shell
```

### Persistent Install (Linux initramfs)

```
Power On
  +- GRUB -> normal OS kernel
       +- initramfs loads
            +- shredos-vault --initramfs
                 +- Authentication Screen
                      |
                 +----+----+
              Correct    Wrong -> DEAD MAN'S SWITCH
              password
                 |
            cryptsetup luksOpen (unlock root volume)
            Exit 0 -> init/systemd continues boot
                 |
            Normal OS login screen
```

### Persistent Install (macOS)

```
Power On
  +- EFI -> macOS kernel
       +- LaunchDaemon: shredos-vault
            +- VT100 password prompt on /dev/console
                 |
            +----+----+
         Correct    Wrong -> DEAD MAN'S SWITCH
         password
            |
       Exit 0 -> login window appears
            |
       Normal macOS login
```

---

## Dead Man's Switch

Activated when failed authentication attempts reach the configured threshold.

**THIS SEQUENCE CANNOT BE STOPPED ONCE TRIGGERED.**

### Sequence

1. **All signals blocked** — SIGINT, SIGTERM, SIGQUIT, SIGTSTP, SIGHUP are
   all ignored. Ctrl+C, Ctrl+Z, kill signals have no effect. On Windows,
   console control handler is set to ignore all events.

2. **5-second countdown** — Full-screen red warning:
   ```
   !!! DEAD MAN'S SWITCH ACTIVATED !!!
   MAXIMUM AUTHENTICATION ATTEMPTS EXCEEDED
   Target drive will be ENCRYPTED and WIPED
   THIS CANNOT BE STOPPED OR REVERSED
   Starting in 5 seconds...
   ```

3. **LUKS volume closed** — Any mounted volume is unmounted and locked.
   On macOS, `diskutil unmountDisk force` is used.

4. **Encrypt with random key** (if `encrypt_before_wipe = true` and LUKS available):
   - Generates 512-bit random key using platform-specific CSPRNG
   - Formats the device with `LUKS2 AES-XTS-plain64`
   - Uses a random passphrase that is never stored
   - This destroys the original LUKS header — existing data is now
     permanently unrecoverable even before the wipe begins.

5. **Wipe the drive**:
   - **Linux**: Calls nwipe with the configured algorithm. Falls back to
     direct I/O engine if nwipe is not available.
   - **macOS**: Direct I/O via raw device (`/dev/rdiskN`), `F_FULLFSYNC`
     for guaranteed write-through.
   - **Windows**: Direct I/O via `FILE_FLAG_NO_BUFFERING` on
     `\\.\PhysicalDriveN`.

6. **Sync and power off** — Flushes all writes, then powers off the system.

---

## Authentication Methods

### Password (always available)

- Linux/macOS: Hashed with SHA-512 and a random 16-byte salt (`$6$` crypt format)
- Windows: Hashed with SHA-512 via CryptoAPI (`$vg$sha512$` format, 10000 iterations)
- Hash format is auto-detected during verification
- Constant-time comparison prevents timing side-channel attacks
- Password is wiped from memory immediately after verification

### Fingerprint (optional, Linux only)

- Uses libfprint with compatible USB fingerprint readers
- Enrollment requires 5 successful scans during setup
- Enrolled fingerprint stored at `/etc/shredos-vault/fingerprints/enrolled.dat`
- Verification via `fp_device_verify_sync()` with 15-second timeout

**Enable at build time:**
```
BR2_PACKAGE_SHREDOS_VAULT_FINGERPRINT=y
```

**Supported readers:** All devices supported by libfprint 1.94.x (see
https://fprint.freedesktop.org/supported-devices.html)

### Voice Passphrase (optional, Linux only)

- Records 5 seconds of audio at 16kHz mono via PortAudio
- Runs offline speech-to-text via PocketSphinx (English model)
- Compares recognized text against stored passphrase
- Fuzzy matching: 60% similarity threshold (Levenshtein distance)
- Requires a microphone (USB or built-in HDA)

**Enable at build time:**
```
BR2_PACKAGE_SHREDOS_VAULT_VOICE=y
```

**Important limitation:** This is passphrase *recognition* (speech-to-text),
NOT speaker *identification* (voiceprint). Anyone who knows the passphrase
and speaks clearly can authenticate.

---

## Wipe Algorithms

All algorithms are implemented with direct low-level I/O (sector-by-sector
writes). On Linux, nwipe is used when available; the built-in direct I/O engine
is used as fallback. On macOS and Windows, the built-in engine is always used.

| Algorithm | Passes | Details | Use Case |
|-----------|--------|---------|----------|
| **Gutmann** | 35 | 4 random + 27 specific byte patterns + 4 random | Maximum thoroughness for magnetic HDDs |
| **DoD 5220.22-M** | 7 | 0x00, 0xFF, random, 0x00, 0xFF, random, random | US Government standard |
| **Bruce Schneier** | 3 | 3 passes of cryptographic random data | Schneier's Applied Cryptography method |
| **Random** | 1 | Single pass of cryptographic random | Quick single-pass wipe |
| **Zero Fill** | 1 | Single pass of 0x00 bytes | Fastest; verifiable |

### Gutmann 35-Pass Detail

| Passes | Data |
|--------|------|
| 1-4 | Random |
| 5 | 0x55 |
| 6 | 0xAA |
| 7 | 0x92 0x49 0x24 |
| 8 | 0x49 0x24 0x92 |
| 9 | 0x24 0x92 0x49 |
| 10-14 | 0x00, 0x11, 0x22, 0x33, 0x44 |
| 15-19 | 0x55, 0x66, 0x77, 0x88, 0x99 |
| 20-24 | 0xAA, 0xBB, 0xCC, 0xDD, 0xEE |
| 25 | 0xFF |
| 26-28 | 0x92 0x49 0x24 / 0x49 0x24 0x92 / 0x24 0x92 0x49 |
| 29-31 | 0x6D 0xB6 0xDB / 0xB6 0xDB 0x6D / 0xDB 0x6D 0xB6 |
| 32-35 | Random |

---

## Configuration Reference

**Linux USB:** `/etc/shredos-vault/vault.conf` — libconfig format
**Linux persistent:** `/etc/shredos-vault/vault.conf` — INI or libconfig format (auto-detected)
**macOS persistent:** `/Library/Application Support/ShredOS-Vault/vault.conf` — INI format
**Windows persistent:** `C:\ProgramData\ShredOS-Vault\vault.conf` — INI format
**Permissions:** 0600

### INI Format (persistent install)

```
# Authentication methods (comma-separated)
# Available: password, fingerprint, voice
auth_methods = password

# Max failed attempts before dead man's switch activates (1-99)
max_attempts = 3

# SHA-512 password hash (set during setup, do not edit manually)
# password_hash = ""

# Voice passphrase text (for voice auth, case-insensitive)
# voice_passphrase = ""

# Target device (WHOLE DISK)
target_device = /dev/sda

# Mount point for unlocked LUKS volume (Linux only)
mount_point = /mnt/vault

# Wipe algorithm: gutmann, dod522022m, schneier, random, zero
wipe_algorithm = gutmann

# Encrypt drive with random key before wiping (recommended)
encrypt_before_wipe = true

# Verify data after each wipe pass
verify_passes = false
```

### libconfig Format (USB boot with libconfig available)

```
auth_methods = ["password"];
max_attempts = 3;
password_hash = "$6$aBcDeFgHiJkLmNoP$...";
voice_passphrase = "open sesame vault";
target_device = "/dev/sda2";
mount_point = "/vault";
wipe_algorithm = "gutmann";
encrypt_before_wipe = true;
```

---

## Command-Line Reference — shredos-vault

```
shredos-vault [OPTIONS]

Options:
  --setup          Run first-time setup wizard
  --config PATH    Use alternate config file
  --initramfs      Linux only: run in initramfs mode (unlock LUKS on success,
                   exit 0 for init to continue boot)
  --help           Show help and exit
```

**Exit Codes:**

| Code | Meaning |
|------|---------|
| 0 | Success (setup complete, or user locked and shut down normally) |
| 1 | Error (config missing, TUI failure, auth failure, LUKS error) |

---

## Kernel Command-Line Parameters

Add these to the GRUB `linux` line or edit `grub.cfg` on the USB:

| Parameter | Example | Description |
|-----------|---------|-------------|
| `vault_setup` | `vault_setup` | Boot into setup wizard |
| `vault_device=` | `vault_device=/dev/sda2` | Override target device |
| `vault_threshold=` | `vault_threshold=5` | Override failure threshold |
| `vault_wipe=` | `vault_wipe=gutmann` | Override wipe algorithm |

**Example GRUB entry with custom parameters:**
```
menuentry "ShredOS Vault (custom)" {
    linux /boot/bzImage console=tty3 loglevel=3 vault_threshold=5 vault_wipe=dod
}
```

---

## Command-Line Reference — secure_wipe (macOS)

```
sudo secure_wipe --device <path> --algorithm <alg> [OPTIONS]

Required:
  --device <path>       Device to wipe (/dev/disk4 or /dev/rdisk4)
  --algorithm <alg>     Wipe algorithm (see below)

Options:
  --verify              Read-back verification after each pass
  --force               Skip interactive "YES" confirmation
  --info                Show drive info (type, size) and exit
  --help                Show usage

Algorithms:
  gutmann               Gutmann 35-pass
  dod                   DoD 5220.22-M 7-pass
  schneier              Bruce Schneier 3-pass random
  random                Single-pass cryptographic random
  zero                  Single-pass zero fill
```

### Examples

```bash
# Show drive information (no wipe):
sudo ./secure_wipe --device /dev/disk4 --info

# Wipe with Gutmann and verify each pass:
sudo ./secure_wipe --device /dev/disk4 --algorithm gutmann --verify

# Quick wipe without confirmation:
sudo ./secure_wipe --device /dev/rdisk4 --algorithm schneier --force

# Zero-fill with verification:
sudo ./secure_wipe --device /dev/disk4 --algorithm zero --verify
```

### Progress Output

```
  Pass 7/35: Pattern 0x924924  42.3%  185.2 MB/s  ETA 03:22
```

Shows: pass number, pattern description, percentage, write speed, estimated time.

### Wipe Report

After completion, a summary is printed:

```
  ============= WIPE REPORT =============
  Device:               /dev/rdisk4
  Drive Type:           SSD (Solid State)
  Algorithm:            Gutmann (35-pass)
  Passes Completed:     35 / 35
  Total Data Written:   17500.00 GB
  Time Elapsed:         28847.3 seconds
  Verification Errors:  0
  Status:               COMPLETED
  =========================================
```

### Drive Type Detection

The macOS tool uses IOKit to detect:
- **HDD** — Rotational magnetic drives
- **SSD** — SATA/AHCI solid state drives
- **NVMe** — NVMe solid state drives

Detection traverses the IORegistry tree checking `Device Characteristics`
(Medium Type) and `Solid State` boolean properties.

---

## LUKS Encryption Details

| Parameter | Value |
|-----------|-------|
| Format | LUKS2 (LUKS1 fallback for unlock) |
| Cipher | `aes-xts-plain64` |
| Key Size | 512 bits |
| Hash | SHA-256 |
| Sector Size | 512 bytes |
| DM Name | `vault_crypt` (mapped to `/dev/mapper/vault_crypt`) |

**Supported inner filesystems** (tried in order during mount):
ext4, ext3, ext2, xfs, btrfs

LUKS is only available on Linux when libcryptsetup is installed. On macOS and
Windows, the encrypt-before-wipe step is skipped (use FileVault/BitLocker for
full-disk encryption).

---

## SSD Limitations

Software-based disk wiping has inherent limitations on solid state drives:

1. **Wear-leveling** — SSDs transparently remap sectors. Old data may persist
   in unmapped blocks that software cannot access.

2. **Over-provisioning** — SSDs reserve hidden capacity (typically 7-28%)
   that is invisible to the operating system.

3. **TRIM/DISCARD** — The SSD controller may not physically erase trimmed
   blocks immediately.

**Recommendations for SSDs:**

- Encrypt the drive BEFORE storing sensitive data (the `encrypt_before_wipe`
  option provides this at wipe time, but ideally use full-disk encryption
  from the start — LUKS on Linux, FileVault on macOS, BitLocker on Windows)
- Use **ATA Secure Erase** via `hdparm --security-erase` (SATA drives)
- Use **NVMe Format** with Crypto Erase: `nvme format --ses=2 /dev/nvmeXnY`
- Consider manufacturer-provided secure erase tools

ShredOS Vault provides SSD detection and prints a warning. The
`encrypt_before_wipe = true` option (default) adds a layer of defense by
destroying the LUKS header with a random key before wiping, making key
recovery impossible even if some sectors survive the wipe.

---

## Security Design

### Memory Protection
- `mlockall(MCL_CURRENT | MCL_FUTURE)` on Linux/macOS prevents sensitive data
  from being written to swap. Windows uses `VirtualLock()`.
- All passwords are wiped from memory using volatile writes immediately
  after use (`vault_secure_memzero()`)
- Random keys for the dead man's switch are zeroed after LUKS format

### Signal Handling
- SIGINT (Ctrl+C), SIGTSTP (Ctrl+Z), and SIGQUIT are blocked during
  the authentication screen
- The dead man's switch blocks ALL signals — it cannot be interrupted
  once triggered
- On Windows, `SetConsoleCtrlHandler(NULL, TRUE)` ignores all console events

### TTY Lockdown (USB Boot)
- tty1 runs `shredos-vault` directly (no login shell)
- tty2 shell access is disabled by default (commented out in inittab)

### Password Storage
- Linux/macOS: SHA-512 with 16-byte random salt (`$6$` crypt format)
- Windows: SHA-512 via CryptoAPI with random salt (`$vg$sha512$` format)
- Constant-time comparison prevents timing attacks

### Cryptographic Randomness
- Linux: `/dev/urandom` (kernel CSPRNG)
- macOS: `SecRandomCopyBytes()` (Security.framework)
- Windows: `CryptGenRandom()` (CryptoAPI)

---

## Troubleshooting

### "No configuration found" at boot
Run setup: Select "ShredOS Vault Setup" from GRUB, or boot with
`vault_setup` kernel parameter, or run `sudo shredos-vault --setup`.

### "Failed to unlock LUKS volume"
- Wrong password (this counts as a failed attempt)
- Corrupted LUKS header (drive may need re-setup)
- Wrong device in config (edit `vault.conf` or re-run setup)

### "No block devices found" in setup
- Wait for USB/SATA initialization (ShredOS waits up to 30 seconds)
- Check that your drive is connected and powered
- Try the `nomodeset` GRUB option if display issues

### "Cannot open /dev/... for writing: Permission denied"
- macOS `secure_wipe` requires `sudo`
- Linux: `shredos-vault` must run as root (it does when launched from inittab)
- Persistent install: the installer runs with `sudo` and sets correct permissions

### Fingerprint reader not detected
- Check USB connection
- Verify reader is in libfprint's supported device list
- Ensure `BR2_PACKAGE_SHREDOS_VAULT_FINGERPRINT=y` was set at build time
- Fingerprint auth is currently Linux-only

### Voice recognition not matching
- Speak clearly and at normal volume
- Ensure microphone is connected (check `arecord -l` from tty2)
- The 60% similarity threshold is intentionally lenient — if it still
  fails, your microphone may not be working
- Voice auth recognizes the passphrase text, not your voice — anyone
  who knows the phrase can authenticate

### macOS: "Cannot determine disk size"
- Use whole-disk path (`/dev/disk4`), not partition (`/dev/disk4s1`)
- Verify the disk exists: `diskutil list`
- The tool auto-converts to raw path (`/dev/rdisk4`) internally

### macOS: Drive still shows data after wipe
- If SSD: wear-leveled blocks may retain data (see SSD Limitations)
- Verify the wipe report shows all passes completed with 0 verification errors
- Re-run with `--verify` to confirm sector-level erasure

### Windows: Credential Provider not showing
- Verify `VaultGateProvider.dll` is registered: check registry key
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`
- Run `regsvr32 VaultGateProvider.dll` as Administrator
- Check Event Viewer for COM registration errors

### LUKS functions return "not available"
- libcryptsetup was not found at build time
- Re-run `make detect-libs` to verify
- Install `libcryptsetup-dev` (Debian) or `cryptsetup-devel` (Fedora)
- LUKS is Linux-only; macOS/Windows use FileVault/BitLocker instead

---

## File Locations

### ShredOS Vault (USB Boot)

| File | Purpose |
|------|---------|
| `/etc/shredos-vault/vault.conf` | Main configuration |
| `/etc/shredos-vault/fingerprints/enrolled.dat` | Enrolled fingerprint data |
| `/vault` | Default mount point for unlocked volume |
| `/dev/mapper/vault_crypt` | LUKS device mapper name |
| `/proc/cmdline` | Kernel parameters (read at boot) |

### Persistent Install — Linux

| File | Purpose |
|------|---------|
| `/usr/sbin/shredos-vault` | Binary |
| `/etc/shredos-vault/vault.conf` | Configuration |
| `/etc/initramfs-tools/hooks/shredos-vault` | initramfs-tools hook |
| `/etc/initramfs-tools/scripts/local-top/shredos-vault` | initramfs-tools boot script |
| `/usr/lib/dracut/modules.d/90shredos-vault/` | Dracut module directory |

### Persistent Install — macOS

| File | Purpose |
|------|---------|
| `/usr/local/sbin/shredos-vault` | Binary |
| `/Library/Application Support/ShredOS-Vault/vault.conf` | Configuration |
| `/Library/LaunchDaemons/com.shredos.vault-gate.plist` | LaunchDaemon |
| `/var/log/shredos-vault.log` | Error log |

### Persistent Install — Windows

| File | Purpose |
|------|---------|
| `C:\Windows\System32\VaultGateProvider.dll` | Credential Provider DLL |
| `C:\Program Files\ShredOS-Vault\shredos-vault-service.exe` | Wipe service |
| `C:\ProgramData\ShredOS-Vault\vault.conf` | Configuration |
| `C:\ProgramData\ShredOS-Vault\shredos-vault.log` | Service log |
