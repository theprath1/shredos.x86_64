# ShredOS Vault Wipe Engine — Technical Deep Dive

This document explains exactly how the ShredOS Vault wipe engine works, how it
compares to nwipe, why the data on disk is identical between both tools, and
what "recoverable" actually means in the context of secure wiping.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [The Journey of a Byte to Disk](#2-the-journey-of-a-byte-to-disk)
3. [Algorithm Implementations](#3-algorithm-implementations)
4. [Platform I/O Layer](#4-platform-io-layer)
5. [Random Number Generation](#5-random-number-generation)
6. [Verification Engine](#6-verification-engine)
7. [Why nwipe and Direct I/O Produce Identical Results](#7-why-nwipe-and-direct-io-produce-identical-results)
8. [What "Recoverable" Actually Means](#8-what-recoverable-actually-means)
9. [Feature Comparison: nwipe vs Vault Engine](#9-feature-comparison-nwipe-vs-vault-engine)
10. [Source File Reference](#10-source-file-reference)

---

## 1. Architecture Overview

The vault wipe system has two paths:

```
vault_wipe_device(device, algorithm, verify)
    │
    ├── Linux with nwipe installed
    │   └── fork() + execvp("nwipe", ...) ──► nwipe process
    │       │                                  (uses write() on /dev/sdX)
    │       └── if nwipe fails, fall through ↓
    │
    └── All platforms (Linux fallback, macOS, Windows)
        └── vault_wipe_device_direct(device, algorithm, verify, progress_cb)
            │
            ├── Linux:   open(/dev/sdX,   O_WRONLY|O_SYNC) + write() + fsync()
            ├── macOS:   open(/dev/rdiskN, O_WRONLY|O_SYNC) + write() + F_FULLFSYNC
            └── Windows: CreateFileA(\\.\PhysicalDriveN, FILE_FLAG_NO_BUFFERING|
                         FILE_FLAG_WRITE_THROUGH) + WriteFile() + FlushFileBuffers()
```

Key source files:
- `src/wipe.c` — wipe engine, algorithms, platform I/O wrappers
- `src/wipe.h` — public API and progress callback types
- `src/platform.c` — CSPRNG, shutdown, memory locking
- `src/platform.h` — platform detection macros

---

## 2. The Journey of a Byte to Disk

Every software wipe tool — nwipe, shredos-vault, DBAN, GNU `shred`, or `dd` —
performs the same fundamental sequence of operations. Here is the complete call
chain from algorithm to physical media.

### Step 1: Algorithm selects byte pattern

The algorithm (Gutmann, DoD, etc.) determines exactly which bytes should be
written during each pass. These patterns are defined by published standards and
academic papers, not invented by any particular tool.

### Step 2: Fill a userspace buffer

A memory buffer (4 MB in vault, similar in nwipe) is filled with the pattern:

```c
// Vault — src/wipe.c:522-526
if (is_random) {
    fill_random(buf, chunk);         // → vault_platform_random()
} else {
    fill_pattern(buf, chunk, pattern, pattern_len);  // → memset() or byte loop
}
```

```c
// nwipe — pass.c (equivalent logic)
if (pattern is random) {
    nwipe_random_pass(ctx);          // fills buffer from PRNG
} else {
    nwipe_pattern_pass(ctx);         // fills buffer with pattern bytes
}
```

For deterministic passes, both buffers contain bit-for-bit identical data.

### Step 3: Write the buffer to the block device via syscall

```c
// Vault on Linux — src/wipe.c:401-419
fd = open("/dev/sda", O_WRONLY | O_SYNC);
write(fd, buf, 4194304);
fsync(fd);

// nwipe on Linux — method.c (equivalent)
fd = open("/dev/sda", O_WRONLY | O_SYNC);
write(fd, buf, bufsize);
fdatasync(fd);
```

Both call the same kernel syscalls on the same device file.

### Step 4: Kernel processes the write

When any userspace program calls `write()` on a block device, the kernel
processes it through the same path regardless of which program made the call:

```
write(fd, buf, len)                    ← userspace (nwipe or vault — doesn't matter)
  │
  ▼
VFS layer (virtual filesystem)         ← kernel: validates fd, checks permissions
  │
  ▼
Block device driver                    ← kernel: /dev/sda is a block special file
  │
  ▼
Block I/O scheduler                    ← kernel: mq-deadline, bfq, none, etc.
  │
  ▼
SCSI / ATA / NVMe command layer        ← kernel: translates to hardware commands
  │
  ▼
HBA driver (ahci, nvme, usb-storage)   ← kernel: sends command over physical bus
  │
  ▼
Physical bus                           ← hardware: SATA cable, PCIe lane, USB wire
  │
  ▼
Drive controller firmware              ← firmware: manages write head / NAND cells
  │
  ▼
Physical media                         ← physics: magnetic platter or NAND flash
```

The kernel does NOT inspect who made the `write()` call. It does not apply
different logic for nwipe vs vault vs `dd`. The bytes take the identical
path from userspace to physical media.

### Step 5: Sync ensures data reaches media

The `O_SYNC` flag tells the kernel: "do not return from `write()` until the
data has been committed to the device." The subsequent `fsync()`/`fdatasync()`
call flushes any remaining kernel buffers. Together, these guarantee the data
is not sitting in a kernel page cache — it has been issued to the drive.

---

## 3. Algorithm Implementations

### Gutmann 35-Pass

Source: Peter Gutmann, "Secure Deletion of Data from Magnetic and Solid-State
Memory," 1996 (Sixth USENIX Security Symposium).

The pattern table is defined at `src/wipe.c:73-96`:

```
Pass  1:  CSPRNG random
Pass  2:  CSPRNG random
Pass  3:  CSPRNG random
Pass  4:  CSPRNG random
Pass  5:  0x55 repeating
Pass  6:  0xAA repeating
Pass  7:  0x92 0x49 0x24 repeating (3-byte cycle)
Pass  8:  0x49 0x24 0x92 repeating
Pass  9:  0x24 0x92 0x49 repeating
Pass 10:  0x00 repeating
Pass 11:  0x11 repeating
Pass 12:  0x22 repeating
Pass 13:  0x33 repeating
Pass 14:  0x44 repeating
Pass 15:  0x55 repeating
Pass 16:  0x66 repeating
Pass 17:  0x77 repeating
Pass 18:  0x88 repeating
Pass 19:  0x99 repeating
Pass 20:  0xAA repeating
Pass 21:  0xBB repeating
Pass 22:  0xCC repeating
Pass 23:  0xDD repeating
Pass 24:  0xEE repeating
Pass 25:  0xFF repeating
Pass 26:  0x92 0x49 0x24 repeating
Pass 27:  0x49 0x24 0x92 repeating
Pass 28:  0x24 0x92 0x49 repeating
Pass 29:  0x6D 0xB6 0xDB repeating
Pass 30:  0xB6 0xDB 0x6D repeating
Pass 31:  0xDB 0x6D 0xB6 repeating
Pass 32:  CSPRNG random
Pass 33:  CSPRNG random
Pass 34:  CSPRNG random
Pass 35:  CSPRNG random
```

These are the exact patterns from the Gutmann paper. Any tool implementing
"Gutmann 35-pass" uses these exact values, or it is not a compliant
implementation.

The 3-byte patterns (0x92 0x49 0x24, etc.) are designed to flip specific bit
combinations on MFM/RLL encoded magnetic media. They target the physical
encoding scheme, not the logical data.

### DoD 5220.22-M 7-Pass

Source: US Department of Defense, "National Industrial Security Program
Operating Manual," DoD 5220.22-M (section 8-306).

Defined at `src/wipe.c:104-107`:

```
Pass 1:  0x00 (all zeros)
Pass 2:  0xFF (all ones)
Pass 3:  CSPRNG random
Pass 4:  0x00
Pass 5:  0xFF
Pass 6:  CSPRNG random
Pass 7:  CSPRNG random
```

### DoD Short 3-Pass (Bruce Schneier variant)

```
Pass 1:  CSPRNG random
Pass 2:  CSPRNG random
Pass 3:  CSPRNG random
```

### Single-Pass Random

```
Pass 1:  CSPRNG random
```

### Zero Fill

```
Pass 1:  0x00 (all zeros)
```

### How patterns are applied to the buffer

For single-byte patterns (e.g., 0x55):
```c
// src/wipe.c:139-140
memset(buf, pattern[0], len);      // fills entire 4 MB buffer with 0x55
```

For multi-byte patterns (e.g., 0x92 0x49 0x24):
```c
// src/wipe.c:142-143
for (size_t i = 0; i < len; i++)
    buf[i] = pattern[i % pattern_len];
// Result: 0x92 0x49 0x24 0x92 0x49 0x24 0x92 0x49 0x24 ...
```

For random passes:
```c
// src/wipe.c:131-134
fill_random(buf, len);             // calls vault_platform_random()
// Result: 4 MB of cryptographically secure random bytes
```

---

## 4. Platform I/O Layer

The wipe engine uses a platform abstraction layer for disk I/O. Each platform
uses different APIs but achieves the same effect: write bytes directly to the
physical device, bypassing filesystem caches, with synchronous write
guarantees.

### Linux

```c
// src/wipe.c:401-403, 416-419, 428-435
fd = open("/dev/sda", O_WRONLY | O_SYNC);
write(fd, buf, len);
fsync(fd);
```

- `O_WRONLY | O_SYNC`: opens for writing; every `write()` blocks until data
  reaches the drive (synchronous I/O)
- `write()`: standard POSIX write syscall
- `fsync()`: flushes kernel buffer cache to device
- Device size: `ioctl(fd, BLKGETSIZE64, &size)` (Linux-specific ioctl)

### macOS

```c
// src/wipe.c:401-403, 416-419, 430-432
fd = open("/dev/rdisk4", O_WRONLY | O_SYNC);
write(fd, buf, len);
fcntl(fd, F_FULLFSYNC);
```

- `/dev/rdiskN` (raw device): bypasses the macOS buffer cache entirely.
  Contrast with `/dev/diskN` (buffered device) which goes through the
  filesystem cache. The `make_raw_path()` function at `src/wipe.c:448-467`
  automatically converts `/dev/diskN` to `/dev/rdiskN`.
- `F_FULLFSYNC`: macOS-specific. Unlike `fsync()` on macOS (which only
  guarantees data reaches the drive controller), `F_FULLFSYNC` forces the
  drive's internal write cache to flush to physical media. This is actually
  **stronger** than what nwipe does on Linux, where `fsync()` may not flush
  the drive's internal DRAM cache depending on the SATA/NVMe driver.
- Device size: `ioctl(fd, DKIOCGETBLOCKCOUNT)` × `ioctl(fd, DKIOCGETBLOCKSIZE)`

### Windows

```c
// src/wipe.c:354-361, 377-383, 393
h = CreateFileA("\\\\.\\PhysicalDrive0",
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                NULL);
WriteFile(h, buf, len, &written, NULL);
FlushFileBuffers(h);
```

- `FILE_FLAG_NO_BUFFERING`: bypass Windows file system cache (equivalent to
  `O_DIRECT` on Linux). Requires 512-byte aligned writes; the engine handles
  this at `src/wipe.c:517-519`.
- `FILE_FLAG_WRITE_THROUGH`: writes go directly to disk (equivalent to
  `O_SYNC`). The Windows cache manager does not defer the write.
- `FlushFileBuffers()`: flush any remaining hardware write cache.
- `\\\\.\\PhysicalDriveN`: Windows physical device path. Addresses the
  entire raw disk, not a partition.
- Device size: `DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, ...)`

### I/O equivalence summary

| Behavior | Linux | macOS | Windows |
|---|---|---|---|
| Bypass OS cache | `O_SYNC` | `O_SYNC` + raw device | `FILE_FLAG_NO_BUFFERING` |
| Synchronous write | `O_SYNC` | `O_SYNC` | `FILE_FLAG_WRITE_THROUGH` |
| Flush to media | `fsync()` | `F_FULLFSYNC` (stronger) | `FlushFileBuffers()` |
| Raw device access | `/dev/sda` (always raw) | `/dev/rdiskN` (auto) | `\\.\PhysicalDriveN` |

---

## 5. Random Number Generation

Random passes require cryptographically secure random data. Each platform
uses its strongest available CSPRNG. Source: `src/platform.c:105-143`.

### Linux
```c
int fd = open("/dev/urandom", O_RDONLY);
read(fd, buf, len);
```
`/dev/urandom` is the kernel's CSPRNG, seeded from hardware entropy sources
(RDRAND, interrupt timing, disk timing, etc.). It never blocks and provides
cryptographically secure output.

nwipe uses the same `/dev/urandom` source (or a Mersenne Twister PRNG
seeded from `/dev/urandom`).

### macOS
```c
SecRandomCopyBytes(kSecRandomDefault, len, buf);
// Fallback: /dev/urandom
```
`SecRandomCopyBytes` is Apple's Security.framework CSPRNG, backed by the
same kernel entropy pool as `/dev/urandom`. The fallback path reads
`/dev/urandom` directly.

### Windows
```c
HCRYPTPROV prov;
CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
CryptGenRandom(prov, len, buf);
CryptReleaseContext(prov, 0);
```
`CryptGenRandom` is the Windows CSPRNG (CryptoAPI), seeded from hardware
entropy and system state. It is FIPS 140-2 validated.

### Quality equivalence

All three sources provide cryptographically secure pseudorandom data suitable
for key generation, which is a far higher standard than needed for disk wiping.
The random data is different between runs (that is the point), but the
cryptographic quality is equivalent across platforms.

---

## 6. Verification Engine

The verification engine reads back data after each deterministic wipe pass
and compares it against the expected pattern. Source: `src/wipe.c:569-650`.

### How it works

```c
// 1. Open device read-only
fd = disk_open_read(device);

// 2. Read a chunk of data from disk
disk_read(fd, verify_buf, chunk);

// 3. Regenerate the expected pattern in a separate buffer
fill_pattern(write_buf, chunk, pattern, pattern_len);

// 4. Compare byte-for-byte
if (memcmp(write_buf, verify_buf, chunk) != 0) {
    // MISMATCH — data was not correctly written
}
```

### What can be verified

- **Deterministic patterns** (0x55, 0xAA, 0x00, 0xFF, 3-byte patterns):
  fully verifiable. The engine regenerates the expected pattern and compares.
- **Random passes**: cannot be verified (the expected data is not stored).
  The engine reads back data but cannot compare it. This is noted in the
  code.

### When verification runs

Per algorithm, verification runs after each non-random pass:

| Algorithm | Total passes | Verifiable passes | With verify enabled |
|---|---|---|---|
| Gutmann 35-pass | 35 writes | 27 deterministic + 8 random | 35 writes + 27 verify reads |
| DoD 5220.22-M | 7 writes | 4 deterministic + 3 random | 7 writes + 4 verify reads |
| DoD Short | 3 writes | 0 (all random) | 3 writes only |
| Random | 1 write | 0 (random) | 1 write only |
| Zero | 1 write | 1 (0x00 fill) | 1 write + 1 verify read |

### Performance impact

Verification approximately doubles the time for deterministic passes (one full
read of the entire disk per pass). Random passes are unaffected.

### Configuration

```
# vault-gate.conf
verify_passes = true    # Enable read-back verification
verify_passes = false   # Disable (default)
```

---

## 7. Why nwipe and Direct I/O Produce Identical Results

### The argument

Claim: "A Gutmann 35-pass overwrite via `write()` on `/dev/sda` produces
identical physical results regardless of whether the calling process is
nwipe or shredos-vault."

### The proof

Trace a concrete example: Gutmann pass 10 writes `0x00` across the entire
disk.

**nwipe**:
1. `memset(buf, 0x00, bufsize)` — buffer filled with zeros
2. `write(fd, buf, bufsize)` on `/dev/sda` — kernel call
3. Kernel → block layer → AHCI driver → SATA bus → drive → platter

**vault**:
1. `fill_pattern(buf, chunk, &(uint8_t){0x00}, 1)` → `memset(buf, 0x00, chunk)` — buffer filled with zeros
2. `disk_write(fd, buf, chunk)` → `write(fd, buf, chunk)` on `/dev/sda` — same kernel call
3. Kernel → block layer → AHCI driver → SATA bus → drive → platter

The buffer contents are identical (all `0x00`). The syscall is identical
(`write()`). The device file is identical (`/dev/sda`). The kernel code
path is identical. The physical result is identical.

There is no mechanism by which the kernel or drive firmware could treat
the writes differently based on which userspace process issued them.

### What about the nwipe PRNG?

nwipe can use a Mersenne Twister PRNG seeded from `/dev/urandom`, while
vault reads `/dev/urandom` directly. This means random passes produce
different byte sequences — but both are cryptographically unpredictable
to an attacker. The security property (an adversary cannot predict or
reconstruct the written data) is preserved in both cases.

For non-random passes, the data is deterministic and identical between
both tools. Pass 10 writes `0x00`, pass 5 writes `0x55`, pass 7 writes
`0x92 0x49 0x24` — there is only one correct set of bytes for each pass.

---

## 8. What "Recoverable" Actually Means

When people say "data is recoverable after wiping," they are referring to
one of these scenarios. All apply equally to nwipe and vault's engine.

### 8.1 Sectors the software cannot address

**Host Protected Area (HPA)** and **Device Configuration Overlay (DCO)** are
hidden regions of the disk that are invisible to the operating system. No
software wipe tool — not nwipe, not vault, not DBAN — can write to these
areas. They require `hdparm` (Linux) or vendor-specific tools to unlock.

Impact: Both tools are equally unable to wipe HPA/DCO regions.

### 8.2 SSD wear-leveled blocks

When an SSD writes to a logical sector, the flash translation layer (FTL)
may remap the physical NAND page. The old data persists in the retired page
until the garbage collector erases it. Software writes to the logical address
space; the FTL decides where the data physically goes.

Neither nwipe nor vault can reach retired NAND pages. Only the drive's
firmware can access them via:
- **ATA Secure Erase** (SATA SSDs): `hdparm --security-erase`
- **NVMe Format** (NVMe SSDs): `nvme format`
- **Crypto Erase** (self-encrypting drives): destroys the media encryption key

Impact: Both tools are equally unable to wipe wear-leveled blocks.

### 8.3 SSD over-provisioning

SSDs reserve 7-28% of their NAND capacity for wear leveling and performance.
This space is never addressable by software. Data fragments can persist in
over-provisioned areas even after a full logical overwrite.

Impact: Both tools are equally unable to reach over-provisioned NAND.

### 8.4 Incomplete wipe (power failure)

If the system loses power during a wipe, some sectors will not have been
overwritten. This affects any wipe tool equally.

The `encrypt_before_wipe` option in vault mitigates this: before wiping,
vault encrypts the entire disk with a random key. Even if the wipe is
interrupted, the data is already encrypted with an unknown key:

```
# vault-gate.conf
encrypt_before_wipe = true    # Default: encrypt with random LUKS key first
```

### 8.5 Magnetic remnants on HDD (Gutmann's original concern)

Peter Gutmann's 1996 paper theorized that residual magnetic signals on older
MFM/RLL encoded drives could be read with magnetic force microscopy (MFM) or
scanning tunneling microscopy (STM). His 35-pass method was designed to flip
specific bit patterns that would neutralize these residual signals.

Modern drives use PMR (Perpendicular Magnetic Recording) or SMR (Shingled
Magnetic Recording) with areal densities exceeding 1 Tbit/in². At these
densities, the track pitch is so narrow that residual inter-track signals are
below the noise floor of any known measurement technique. Gutmann himself
acknowledged this in a 2010 epilogue, stating that "in the time since this
paper was published, some people have treated the 35-pass overwrite as a
kind of voodoo incantation... one or two passes should be sufficient."

Regardless, both tools write the same Gutmann patterns, so the residual
magnetic state is identical.

### Summary

| Recovery vector | Affects nwipe? | Affects vault? | Mitigation |
|---|---|---|---|
| HPA/DCO | Yes | Yes | `hdparm` / vendor tools |
| SSD wear leveling | Yes | Yes | ATA Secure Erase / NVMe Format |
| SSD over-provisioning | Yes | Yes | Crypto erase |
| Power failure | Yes | Yes | `encrypt_before_wipe = true` |
| Magnetic remnants | N/A (modern drives) | N/A (modern drives) | Single pass sufficient |

---

## 9. Feature Comparison: nwipe vs Vault Engine

### Wipe quality (identical)

| Aspect | nwipe | Vault direct I/O |
|---|---|---|
| Gutmann patterns | Same (from 1996 paper) | Same |
| DoD patterns | Same (from DoD 5220.22-M) | Same |
| Syscall | `write()` | `write()` / `WriteFile()` |
| Cache bypass | `O_SYNC` | `O_SYNC` / `F_FULLFSYNC` / `FILE_FLAG_NO_BUFFERING` |
| Random source | `/dev/urandom` or MT PRNG | `/dev/urandom` / SecRandom / CryptGenRandom |
| Sync to media | `fdatasync()` | `fsync()` / `F_FULLFSYNC` / `FlushFileBuffers()` |

### Features (different)

| Feature | nwipe | Vault engine |
|---|---|---|
| Multi-device enumeration | Yes (scans /proc/partitions) | No (caller provides path) |
| Interactive device selection TUI | Yes (ncurses) | No |
| Simultaneous multi-disk wiping | Yes (threaded) | Single device per call |
| PDF wipe certificate | Yes | No |
| SMART data display | Yes (before/after) | No |
| Read-back verification | Yes (`--verify`) | Yes (`verify_passes` config) |
| SSD detection | Via `/sys/block/` | Via `/sys/block/`, IOKit, or N/A |
| Platform support | Linux only | Linux, macOS, Windows |
| Pre-wipe encryption | No | Yes (`encrypt_before_wipe`) |
| Dead man's switch integration | No | Yes (vault-gate) |

### When each is used

On Linux with nwipe installed, `vault_wipe_device()` tries nwipe first. This
gives access to nwipe's multi-disk and reporting features. If nwipe is not
installed or fails, vault falls back to its own direct I/O engine.

On macOS and Windows, nwipe is not available (Linux-only tool), so vault
always uses its direct I/O engine. The wipe quality is identical; only the
management features around the wipe differ.

---

## 10. Source File Reference

| File | Purpose |
|---|---|
| `src/wipe.c` | Wipe engine: algorithms, pattern tables, I/O wrappers, verification |
| `src/wipe.h` | Public API: `vault_wipe_device()`, `vault_wipe_device_direct()`, progress types |
| `src/platform.c` | CSPRNG (`vault_platform_random`), shutdown, memory locking, secure memzero |
| `src/platform.h` | Platform detection (`VAULT_PLATFORM_LINUX/MACOS/WINDOWS`), config path defaults |
| `src/config.h` | `vault_config_t` struct: `wipe_algorithm`, `verify_passes`, `encrypt_before_wipe` |
| `src/config.c` | Config load/save for both libconfig and INI backends |
| `src/deadman.c` | Dead man's switch: calls `vault_wipe_device()` with config values |
| `src/macos/secure_wipe.h` | Standalone macOS wipe utility (separate from vault engine) |
