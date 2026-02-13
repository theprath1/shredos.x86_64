# ShredOS Vault

A pre-boot authentication gate with a dead man's switch. ShredOS Vault sits between power-on and your operating system — if someone can't provide the correct password within a set number of attempts, the drive is encrypted with a random key and wiped. No data survives.

ShredOS Vault runs on **Linux**, **macOS**, and **Windows**. It can be booted from a ShredOS USB stick or installed persistently onto a host machine's boot sequence.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Boot Menu Options](#boot-menu-options)
- [Installation](#installation)
  - [From ShredOS USB (Install Wizard)](#from-shredos-usb-install-wizard)
  - [Standalone Linux Install](#standalone-linux-install)
  - [Standalone macOS Install](#standalone-macos-install)
  - [Standalone Windows Install](#standalone-windows-install)
- [Setup](#setup)
- [Configuration](#configuration)
- [Wipe Algorithms](#wipe-algorithms)
- [Dead Man's Switch](#dead-mans-switch)
- [LUKS Integration](#luks-integration)
- [Platform Details](#platform-details)
- [Uninstallation](#uninstallation)
- [Building from Source](#building-from-source)
- [Architecture](#architecture)
- [FAQ](#faq)

---

## How It Works

```
Power On
   │
   ▼
┌──────────────────┐
│   Boot Loader    │
│  (GRUB/ISOLINUX) │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Initramfs/Boot  │
│   Hook Runs      │
│  shredos-vault   │
└────────┬─────────┘
         │
    ┌────┴────┐
    │ Password │
    │  Prompt  │
    └────┬────┘
         │
    ┌────┴────────────┐
    │                 │
 Correct           Wrong
    │                 │
    ▼                 ▼
┌─────────┐   ┌─────────────┐
│  Boot   │   │ Attempts    │
│ Continues│   │ Remaining?  │
└─────────┘   └──────┬──────┘
                     │
                ┌────┴────┐
                │         │
              Yes        No
                │         │
                ▼         ▼
           ┌────────┐ ┌──────────────────┐
           │ Retry  │ │ DEAD MAN'S SWITCH│
           └────────┘ │                  │
                      │ 1. Block signals │
                      │ 2. 5s countdown  │
                      │ 3. Encrypt drive │
                      │    (random key)  │
                      │ 4. Wipe drive    │
                      │ 5. Power off     │
                      └──────────────────┘
```

1. **Boot loader** starts the kernel with ShredOS Vault embedded in the initramfs.
2. **Before the root filesystem mounts**, the vault binary runs and presents a password prompt.
3. **Correct password** — boot continues normally. If LUKS is configured, the encrypted volume is unlocked and mounted.
4. **Too many wrong passwords** — the dead man's switch activates. The drive is encrypted with a random key (making existing data unrecoverable), then overwritten with the selected wipe algorithm, then the machine powers off.

The vault runs inside the initramfs, before the OS even loads. There is no shell to escape to, no Ctrl+C to interrupt, no way to bypass it.

---

## Features

### Security
- **Pre-boot authentication** — runs before the OS loads, inside the initramfs
- **Dead man's switch** — configurable failure threshold (1–99 attempts)
- **Encrypt-before-wipe** — encrypts the drive with a random LUKS key before wiping, making recovery impossible even if the wipe is interrupted
- **Non-interruptible wipe** — all signals are blocked during the wipe sequence (SIGINT, SIGTERM, SIGKILL, SIGTSTP, etc.)
- **Memory locking** — all sensitive data is locked in RAM via `mlockall()` to prevent it from being swapped to disk
- **Secure memory zeroing** — passwords and keys are overwritten with volatile memzero operations before being freed
- **CSPRNG** — cryptographically secure random number generation on all platforms

### Wipe Engine
- **5 wipe algorithms** — Gutmann 35-pass, DoD 5220.22-M 7-pass, DoD Short 3-pass, random, and zero fill
- **nwipe integration** — uses nwipe when available on Linux for hardware-optimized wiping
- **Direct I/O fallback** — falls back to direct disk writes if nwipe is unavailable
- **Cross-platform disk I/O** — native unbuffered writes on Linux, macOS, and Windows
- **SSD detection** — identifies solid-state drives via sysfs

### User Interface
- **ncurses TUI** — full-color terminal interface with box drawing, menus, and ASCII art banner
- **VT100 fallback** — works in minimal environments without ncurses (raw escape codes)
- **Windows Console** — native Win32 console API for Windows builds
- **Installer wizard** — guided installation from ShredOS USB to any detected OS

### Platform Support
- **Linux** — initramfs-tools and dracut boot hooks
- **macOS** — LaunchDaemon integration
- **Windows** — Credential Provider DLL and Windows Service

### Authentication Methods
- **Password** — SHA-512 hashing via POSIX `crypt()` with random salt
- **Fingerprint** — optional, via libfprint (Linux only, compile-time flag)
- **Voice passphrase** — optional, via PocketSphinx + PortAudio (compile-time flag)

---

## Boot Menu Options

When booting from a ShredOS USB stick, the following menu entries are available:

| Menu Entry | Description |
|---|---|
| **ShredOS Vault** | Boot into vault authentication mode (default) |
| **ShredOS Vault Setup** | Run the first-time setup wizard to set your password, target device, wipe algorithm, and failure threshold |
| **Install ShredOS Vault to Hard Drive** | Launch the installer wizard to deploy vault onto a host machine's boot sequence |
| **ShredOS Vault (nomodeset)** | Same as default, with `nomodeset` for display compatibility |
| **ShredOS Classic (nwipe only)** | Boot directly into nwipe without vault authentication |
| **Memtest86+** | Memory testing (multiple variants for different keyboard/display configurations) |

---

## Installation

### From ShredOS USB (Install Wizard)

This is the recommended method. Boot from a ShredOS USB stick and select **"Install ShredOS Vault to Hard Drive"** from the boot menu.

The wizard will:

1. **Scan all connected drives** — identifies block devices, their sizes, SSD/HDD type, and filters out the ShredOS USB itself
2. **Detect the operating system** on each drive — mounts partitions read-only and probes for Linux (`/etc/os-release`), macOS (`SystemVersion.plist`), or Windows (`ntoskrnl.exe`)
3. **Present a drive selection menu** — shows each drive with its detected OS
4. **Prompt for a password** — with confirmation. This is the password you'll enter on every boot.
5. **Set the failure threshold** — how many wrong attempts before the dead man's switch triggers (default: 3)
6. **Select a wipe algorithm** — choose what happens to the drive when the switch triggers
7. **Confirm and install** — the wizard handles everything:

**For Linux targets:**
- Copies the vault binary to `/usr/sbin/shredos-vault`
- Writes the config to `/etc/shredos-vault/vault.conf`
- Installs initramfs hooks (auto-detects initramfs-tools or dracut)
- Rebuilds the initramfs via chroot (`update-initramfs -u` or `dracut --force`)

**For macOS targets:**
- Copies the vault binary to `/usr/local/sbin/shredos-vault`
- Writes the config to `/Library/Application Support/ShredOS-Vault/`
- Installs a LaunchDaemon plist for boot-time execution

**For Windows targets (requires ntfs-3g):**
- Copies config files and install scripts to `C:\ProgramData\ShredOS-Vault\`
- Creates a `COMPLETE_SETUP.txt` with instructions
- The user must run `install.bat` as Administrator on the next Windows boot to register the Credential Provider and Windows Service

### Standalone Linux Install

If you're already on a Linux machine and want to install vault directly:

```bash
cd package/shredos-vault/src/vault-gate/linux
sudo bash install.sh
```

The script will:
1. Detect your distro (Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE)
2. Install build dependencies via the appropriate package manager
3. Compile the vault binary
4. Copy it to `/usr/sbin/shredos-vault`
5. Install a default config to `/etc/shredos-vault/vault.conf`
6. Install the appropriate initramfs hook (initramfs-tools or dracut)
7. Rebuild the initramfs

After installation, run setup:

```bash
sudo shredos-vault --setup
```

### Standalone macOS Install

```bash
cd package/shredos-vault/src/vault-gate/macos
sudo bash install.sh
```

This compiles the vault binary, installs it to `/usr/local/sbin/`, copies the config, and loads a LaunchDaemon.

Run setup afterward:

```bash
sudo shredos-vault --setup
```

### Standalone Windows Install

Build with MSVC first (see [Building from Source](#building-from-source)), then:

1. Right-click `install.bat` → **Run as administrator**
2. The script creates a Windows Service (`ShredOSVault`) and registers a Credential Provider DLL
3. Run setup: `"C:\Program Files\ShredOS-Vault\shredos-vault-service.exe" --setup`

---

## Setup

Setup configures your vault password, target device, failure threshold, and wipe algorithm. You can run setup in two ways:

**From the boot menu:**
Select "ShredOS Vault Setup" at boot, or add `vault_setup` to the kernel command line.

**From the command line:**
```bash
sudo shredos-vault --setup
```

The setup wizard will prompt you to:

1. **Set a password** — enter and confirm. Stored as a SHA-512 hash with a random 16-byte salt. The plaintext is never saved.
2. **Select the target device** — the drive to protect (and wipe on failure).
3. **Set the failure threshold** — number of wrong passwords before the dead man's switch triggers (1–99, default 3).
4. **Choose a wipe algorithm** — see [Wipe Algorithms](#wipe-algorithms).

The configuration is saved to:
- Linux: `/etc/shredos-vault/vault.conf`
- macOS: `/Library/Application Support/ShredOS-Vault/vault.conf`
- Windows: `C:\ProgramData\ShredOS-Vault\vault.conf`

---

## Configuration

The config file (`vault.conf`) supports two formats:
- **libconfig format** — used in Buildroot builds (semicolons, brackets for arrays)
- **INI format** — used in persistent installs (simple `key = value`)

Both formats are auto-detected at load time.

### Configuration Options

```ini
# Authentication method(s) — password, fingerprint, voice
auth_methods = ["password"]

# Max failed attempts before dead man's switch (1-99)
max_attempts = 3

# SHA-512 password hash (set by --setup, do not edit manually)
password_hash = "$6$randomsalt$longhash..."

# Target device to wipe on auth failure
target_device = "/dev/sda"

# Mount point for LUKS-unlocked volume
mount_point = "/vault"

# Wipe algorithm (see Wipe Algorithms section)
wipe_algorithm = "gutmann"

# Encrypt with random key before wiping
encrypt_before_wipe = true
```

### Kernel Command Line Overrides

These override config file values when passed as kernel parameters:

| Parameter | Description | Example |
|---|---|---|
| `vault_setup` | Enter setup mode | — |
| `vault_install` | Enter install wizard mode | — |
| `vault_device=X` | Override target device | `vault_device=/dev/sda` |
| `vault_threshold=N` | Override failure threshold | `vault_threshold=5` |
| `vault_wipe=ALG` | Override wipe algorithm | `vault_wipe=dod` |

Valid `vault_wipe` values: `gutmann`, `dod`, `dodshort`, `random`, `zero`

### Command Line Flags

```
shredos-vault [options]

Options:
  --setup              Run first-time setup wizard
  --install-wizard     Launch USB-to-host install wizard
  --config PATH        Use alternate config file
  --initramfs          Running from initramfs (set automatically by boot hooks)
  --help               Show help message
```

---

## Wipe Algorithms

| Algorithm | Passes | Speed | Description |
|---|---|---|---|
| **Gutmann** | 35 | Slowest | 4 random passes + 27 specific MFM encoding patterns + 4 random passes. The most thorough algorithm, designed to defeat magnetic force microscopy. |
| **DoD 5220.22-M** | 7 | Slow | US Department of Defense standard. Alternates between 0x00, 0xFF, and random data across 7 passes. |
| **DoD Short** | 3 | Moderate | Three passes of cryptographic random data. Good balance of speed and security. |
| **Random** | 1 | Fast | Single pass of CSPRNG data. Sufficient for most threat models when combined with encrypt-before-wipe. |
| **Zero Fill** | 1 | Fastest | Single pass of 0x00 bytes. Minimal security but fast. Best combined with encrypt-before-wipe. |

### Encrypt-Before-Wipe

When `encrypt_before_wipe = true` (default and recommended), the vault encrypts the entire drive with a randomly generated key **before** running the wipe algorithm. The key is immediately discarded — it exists only in locked memory for the duration of the LUKS format operation.

This means:
- Even if the wipe is interrupted (power loss, hardware failure), the data is already encrypted with a key that no longer exists
- The subsequent wipe destroys even the encrypted ciphertext
- Data recovery is virtually impossible regardless of the wipe algorithm chosen

### nwipe Integration

On Linux, the vault automatically checks for nwipe and uses it when available. nwipe provides hardware-optimized secure erasure and is the same engine used by ShredOS Classic. If nwipe is unavailable or fails, the vault falls back to its built-in direct I/O wipe engine.

---

## Dead Man's Switch

The dead man's switch is the core security mechanism. When the failure threshold is exceeded, the following sequence executes:

1. **Signal blocking** — `sigfillset()` + `sigprocmask(SIG_BLOCK)` blocks every signal. Individual handlers are set to `SIG_IGN` for SIGINT, SIGTERM, SIGQUIT, SIGTSTP, and SIGHUP. On Windows, `SetConsoleCtrlHandler(NULL, TRUE)` disables Ctrl+C. **The process cannot be killed.**

2. **5-second warning countdown** — a full-screen red warning is displayed. This is informational only — there is no way to cancel.

3. **Cleanup** — any mounted LUKS volumes are unmounted and closed.

4. **Encryption** — if `encrypt_before_wipe` is enabled and LUKS is available, the target device is formatted as LUKS2 with AES-XTS-plain64 using a randomly generated 512-bit key. The key is immediately discarded.

5. **Wipe** — the configured wipe algorithm runs against the target device. If the primary wipe fails, it falls back to a single random pass.

6. **Power off** — the system calls `sync()` and powers off.

**This sequence is a point of no return.** Once the threshold is exceeded, the drive will be destroyed and the machine will shut down. There is no abort mechanism by design.

---

## LUKS Integration

ShredOS Vault integrates with LUKS (Linux Unified Key Setup) for two purposes:

### 1. Volume Unlocking (Normal Boot)

If your target device is a LUKS-encrypted partition, successful authentication will:
- Open the LUKS volume as `/dev/mapper/vault_crypt`
- Mount it at the configured mount point (default: `/vault`)
- Boot continues with the decrypted volume accessible

On shutdown or if the vault exits, the volume is unmounted and closed.

### 2. Encrypt-Before-Wipe (Dead Man's Switch)

When the dead man's switch triggers with `encrypt_before_wipe = true`:
- The drive is formatted as LUKS2 with a random 64-byte key
- AES-XTS-plain64 cipher with 512-byte sectors
- The key is generated from the platform CSPRNG and immediately zeroed after formatting
- This destroys the existing LUKS header and partition table
- The drive is then wiped with the configured algorithm on top of the encryption

LUKS support requires `libcryptsetup`. If unavailable, the vault skips the encryption step and proceeds directly to wiping.

---

## Platform Details

### Linux

| Component | Details |
|---|---|
| **Boot hook** | initramfs-tools (`/etc/initramfs-tools/hooks/` + `/scripts/local-top/`) or dracut module (`/usr/lib/dracut/modules.d/90vault-gate/`) |
| **Binary location** | `/usr/sbin/shredos-vault` |
| **Config location** | `/etc/shredos-vault/vault.conf` |
| **TUI backend** | ncurses (with VT100 fallback) |
| **Disk I/O** | Direct writes to `/dev/sdX` with `O_SYNC` + `fsync()` |
| **CSPRNG** | `/dev/urandom` |
| **SSD detection** | `/sys/block/*/queue/rotational` (0 = SSD) |
| **Shutdown** | `poweroff -f` |

### macOS

| Component | Details |
|---|---|
| **Boot hook** | LaunchDaemon plist (`/Library/LaunchDaemons/com.shredos.vault-gate.plist`) |
| **Binary location** | `/usr/local/sbin/shredos-vault` |
| **Config location** | `/Library/Application Support/ShredOS-Vault/vault.conf` |
| **TUI backend** | VT100 escape codes |
| **Disk I/O** | Raw device `/dev/rdiskN` with `F_FULLFSYNC` |
| **CSPRNG** | `SecRandomCopyBytes()` |
| **Encryption** | `diskutil apfs encryptVolume` via `system()` |
| **Shutdown** | `shutdown -h now` |

### Windows

| Component | Details |
|---|---|
| **Boot hook** | Credential Provider DLL + Windows Service |
| **Binary location** | `C:\Program Files\ShredOS-Vault\shredos-vault-service.exe` |
| **Config location** | `C:\ProgramData\ShredOS-Vault\vault.conf` |
| **TUI backend** | Windows Console API |
| **Disk I/O** | `\\.\PhysicalDriveN` with `FILE_FLAG_NO_BUFFERING` |
| **CSPRNG** | `CryptGenRandom()` |
| **Encryption** | BitLocker (`manage-bde`) via install scripts |
| **Shutdown** | `ExitWindowsEx(EWX_POWEROFF \| EWX_FORCE)` |

---

## Uninstallation

### Linux

**If installed via the install wizard or install.sh:**

```bash
cd package/shredos-vault/src/vault-gate/linux
sudo bash uninstall.sh
```

This removes the binary, config directory, initramfs hooks, and rebuilds the initramfs.

**Manual removal:**

```bash
sudo rm /usr/sbin/shredos-vault
sudo rm -rf /etc/shredos-vault
sudo rm /etc/initramfs-tools/hooks/vault-gate
sudo rm /etc/initramfs-tools/scripts/local-top/vault-gate
sudo update-initramfs -u
# Or for dracut:
sudo rm -rf /usr/lib/dracut/modules.d/90vault-gate
sudo dracut --force
```

### macOS

```bash
cd package/shredos-vault/src/vault-gate/macos
sudo bash uninstall.sh
```

Or manually:

```bash
sudo launchctl unload /Library/LaunchDaemons/com.shredos.vault-gate.plist
sudo rm /Library/LaunchDaemons/com.shredos.vault-gate.plist
sudo rm /usr/local/sbin/shredos-vault
sudo rm -rf "/Library/Application Support/ShredOS-Vault"
```

### Windows

Right-click `uninstall.bat` → **Run as administrator**

This stops and removes the Windows Service, removes the Credential Provider registry keys, and deletes program files.

Or manually (as Administrator):

```
sc stop ShredOSVault
sc delete ShredOSVault
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" /f
rmdir /s /q "C:\Program Files\ShredOS-Vault"
rmdir /s /q "C:\ProgramData\ShredOS-Vault"
```

---

## Building from Source

### As Part of ShredOS (Buildroot)

ShredOS Vault is a Buildroot package. To include it in a ShredOS build:

1. Enable it in your defconfig or via `make menuconfig`:
   ```
   Target packages → ShredOS Vault
   ```
2. Optional sub-packages:
   - `BR2_PACKAGE_SHREDOS_VAULT_FINGERPRINT` — fingerprint auth via libfprint
   - `BR2_PACKAGE_SHREDOS_VAULT_VOICE` — voice passphrase via PocketSphinx
   - `BR2_PACKAGE_SHREDOS_VAULT_NTFS` — NTFS support for Windows drive installation
3. Build: `make`

### Standalone Build (Linux)

```bash
cd package/shredos-vault/src/vault-gate
make
```

The Makefile auto-detects available libraries via pkg-config:
- **ncurses** — full TUI (falls back to VT100 without it)
- **libconfig** — config file parsing (falls back to INI parser without it)
- **libcryptsetup** — LUKS support (disabled without it)
- **libcrypt** — SHA-512 password hashing

Check what was detected:
```bash
make detect-libs
```

### Standalone Build (macOS)

```bash
cd package/shredos-vault/src/vault-gate
make macos
```

Uses VT100 TUI backend and IOKit/Security/CoreFoundation frameworks.

### Windows Build (MSVC)

Build the Credential Provider DLL:
```
cl /EHsc /LD /DUNICODE /D_UNICODE /DVAULT_PLATFORM_WINDOWS
   VaultGateProvider.cpp ..\auth_password.c ..\config.c ..\platform.c
   /link ole32.lib advapi32.lib shlwapi.lib crypt32.lib
   /OUT:VaultGateProvider.dll
```

Build the service:
```
cl /DUNICODE /D_UNICODE /DVAULT_PLATFORM_WINDOWS
   vault-gate-service.c ..\main.c ..\platform.c ..\config.c
   ..\auth.c ..\auth_password.c ..\wipe.c ..\deadman.c
   ..\tui_win32.c
   /link advapi32.lib crypt32.lib
   /OUT:shredos-vault-service.exe
```

### Autotools Build

```bash
cd package/shredos-vault/src
autoreconf -i
./configure
make
sudo make install
```

Optional configure flags:
- `--enable-fingerprint` — build with libfprint support
- `--enable-voice` — build with PocketSphinx/PortAudio support

---

## Architecture

### Source Tree

```
package/shredos-vault/
├── Config.in                      # Buildroot package config
├── shredos-vault.mk               # Buildroot package makefile
├── README.md                      # This file
└── src/
    ├── configure.ac                # Autotools configure
    ├── Makefile.am                 # Autotools makefile
    │
    ├── main.c                     # Entry point, arg parsing, mode routing
    ├── platform.h / platform.c    # Platform detection, CSPRNG, memory lock, shutdown
    ├── config.h / config.c        # Config load/save (libconfig + INI backends)
    ├── auth.h / auth.c            # Auth dispatcher, attempt loop
    ├── auth_password.h / .c       # SHA-512 password hashing
    ├── wipe.h / wipe.c            # Cross-platform wipe engine (5 algorithms)
    ├── luks.h / luks.c            # LUKS encryption wrapper
    ├── deadman.h / deadman.c      # Dead man's switch
    ├── installer.h / installer.c  # OS detection, drive scanning, install wizard
    │
    ├── tui.h                      # TUI interface contract
    ├── tui_ncurses.c              # ncurses backend
    ├── tui_vt100.c                # VT100 fallback backend
    ├── tui_win32.c                # Windows console backend
    │
    └── vault-gate/                # Boot integration files
        ├── vault-gate.conf        # Default config template
        ├── Makefile               # Standalone build system
        ├── linux/
        │   ├── install.sh
        │   ├── uninstall.sh
        │   ├── initramfs-hook.sh
        │   ├── initramfs-script.sh
        │   └── dracut-module/
        │       ├── module-setup.sh
        │       ├── vault-gate-hook.sh
        │       └── vault-gate.service
        ├── macos/
        │   ├── install.sh
        │   ├── uninstall.sh
        │   └── com.shredos.vault-gate.plist
        └── windows/
            ├── VaultGateProvider.cpp / .h
            ├── vault-gate-service.c
            ├── install.bat
            └── uninstall.bat
```

### Design Principles

- **Single binary, multiple modes** — one `shredos-vault` binary handles authentication, setup, and installation. No separate programs.
- **Compile-time feature detection** — libraries are optional. The binary gracefully degrades when ncurses, libcryptsetup, or libconfig are unavailable.
- **Config format auto-detection** — reads both libconfig (`;`-terminated, bracketed arrays) and plain INI (`key = value`) formats transparently.
- **Platform abstraction** — all platform-specific code is behind `#ifdef` guards in `platform.c`. The rest of the codebase is platform-independent C11.

---

## FAQ

**Q: What happens if I forget my password?**
The dead man's switch triggers after the configured number of failed attempts. Your drive will be encrypted with a random key and wiped. **There is no recovery mechanism.** This is by design.

**Q: Can someone bypass the vault by booting from a different USB?**
If the vault is installed persistently into the initramfs, the authentication gate runs before the root filesystem is mounted. However, if an attacker has physical access and can boot from their own media, they could mount the drive directly. To protect against this, use full-disk encryption (LUKS) and ensure `encrypt_before_wipe` is enabled so the dead man's switch makes recovery impossible even if bypassed.

**Q: Does it work with full-disk encryption (LUKS)?**
Yes. If your target device is a LUKS partition, the vault will unlock it on successful authentication and mount it at the configured mount point. On auth failure, the dead man's switch re-encrypts the drive with a random key before wiping.

**Q: Which wipe algorithm should I use?**
For most users, **DoD Short** (3 random passes) with `encrypt_before_wipe = true` provides excellent security with reasonable speed. **Gutmann** is the most thorough but takes significantly longer. **Random** (single pass) with encryption is sufficient against all non-state-level adversaries.

**Q: Can the wipe be interrupted?**
No. Once the dead man's switch triggers, all signals are blocked. The process cannot be killed by any signal, including SIGKILL on most configurations (since it runs in the initramfs before the OS is fully loaded). Even if power is cut, the encrypt-before-wipe step has already destroyed the encryption header, making the data unrecoverable.

**Q: Does the vault work on SSDs?**
Yes. The vault detects SSDs via `/sys/block/*/queue/rotational` on Linux. Note that secure erasure on SSDs is inherently less reliable than on HDDs due to wear leveling and overprovisioning. The encrypt-before-wipe feature is especially important for SSDs — it ensures data is cryptographically destroyed regardless of the SSD controller's behavior.

**Q: How does the Windows installation work?**
Since the ShredOS USB runs Linux, it cannot directly modify the Windows registry or install services. The installer copies the necessary files to the Windows partition and creates a `COMPLETE_SETUP.txt` file with instructions. On the next Windows boot, the user runs `install.bat` as Administrator to register the Credential Provider and Windows Service.

**Q: Can I change my password after installation?**
Yes. Run `shredos-vault --setup` (or boot with the `vault_setup` kernel parameter) to re-run the setup wizard and set a new password.

**Q: What if the vault binary is corrupted or missing from the initramfs?**
The initramfs boot script checks for the binary and config file before execution. If either is missing, the boot continues normally without vault authentication. To ensure integrity, rebuild the initramfs after any updates: `sudo update-initramfs -u` or `sudo dracut --force`.

---

## License

GPL-2.0+
