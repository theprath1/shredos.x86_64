/*
 * wipe.c — Unified Cross-Platform Secure Wipe Engine
 *
 * Merges Linux (nwipe + direct I/O), macOS (IOKit + SecRandom + F_FULLFSYNC),
 * and Windows (CryptGenRandom + IOCTL + FILE_FLAG_NO_BUFFERING) wipe paths
 * into a single file with compile-time platform selection via platform.h.
 *
 * Algorithms (defined ONCE):
 *   - Gutmann 35-pass: specific byte patterns per Gutmann paper
 *   - DoD 5220.22-M 7-pass: 0x00, 0xFF, random, repeat, final random
 *   - Bruce Schneier 3-pass: three rounds of cryptographic random
 *   - Cryptographic Random: single-pass CSPRNG
 *   - Zero Fill: single-pass 0x00
 *   - Verify Only: read-back verification
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "wipe.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/*  Platform includes                                                  */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_WINDOWS)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <winioctl.h>
#elif defined(VAULT_PLATFORM_MACOS)
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <sys/ioctl.h>
  #include <sys/disk.h>
  #include <sys/time.h>
  #ifdef HAVE_IOKIT
    #include <IOKit/IOKitLib.h>
    #include <IOKit/storage/IOMedia.h>
    #include <IOKit/storage/IOBlockStorageDevice.h>
    #include <IOKit/IOBSD.h>
    #include <CoreFoundation/CoreFoundation.h>
  #endif
#else /* Linux */
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <sys/ioctl.h>
  #include <sys/time.h>
  #include <sys/wait.h>
  #ifdef __linux__
    #include <linux/fs.h>  /* BLKGETSIZE64 */
  #endif
#endif

#define WIPE_BUF_SIZE (4 * 1024 * 1024) /* 4 MB I/O buffer */

/* ------------------------------------------------------------------ */
/*  Gutmann 35-pass patterns (defined ONCE)                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int     is_random;
    size_t  pattern_len;
    uint8_t pattern[3];
} gutmann_pass_t;

static const gutmann_pass_t gutmann_passes[35] = {
    /* 1-4: random */
    {1,0,{0}}, {1,0,{0}}, {1,0,{0}}, {1,0,{0}},
    /* 5-9 */
    {0,1,{0x55}}, {0,1,{0xAA}}, {0,3,{0x92,0x49,0x24}},
    {0,3,{0x49,0x24,0x92}}, {0,3,{0x24,0x92,0x49}},
    /* 10-14 */
    {0,1,{0x00}}, {0,1,{0x11}}, {0,1,{0x22}},
    {0,1,{0x33}}, {0,1,{0x44}},
    /* 15-19 */
    {0,1,{0x55}}, {0,1,{0x66}}, {0,1,{0x77}},
    {0,1,{0x88}}, {0,1,{0x99}},
    /* 20-24 */
    {0,1,{0xAA}}, {0,1,{0xBB}}, {0,1,{0xCC}},
    {0,1,{0xDD}}, {0,1,{0xEE}},
    /* 25-27 */
    {0,1,{0xFF}}, {0,3,{0x92,0x49,0x24}},
    {0,3,{0x49,0x24,0x92}},
    /* 28-31 */
    {0,3,{0x24,0x92,0x49}}, {0,3,{0x6D,0xB6,0xDB}},
    {0,3,{0xB6,0xDB,0x6D}}, {0,3,{0xDB,0x6D,0xB6}},
    /* 32-35: random */
    {1,0,{0}}, {1,0,{0}}, {1,0,{0}}, {1,0,{0}}
};

/* DoD 5220.22-M 7-pass */
typedef struct {
    int     is_random;
    uint8_t byte;
} dod_pass_t;

static const dod_pass_t dod_passes[7] = {
    {0, 0x00}, {0, 0xFF}, {1, 0},
    {0, 0x00}, {0, 0xFF}, {1, 0}, {1, 0}
};

/* ------------------------------------------------------------------ */
/*  Timing helper                                                      */
/* ------------------------------------------------------------------ */

static double now_secs(void)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (double)cnt.QuadPart / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
#endif
}

/* ------------------------------------------------------------------ */
/*  Fill buffer with random or repeating pattern                       */
/* ------------------------------------------------------------------ */

static int fill_random(uint8_t *buf, size_t len)
{
    return vault_platform_random(buf, len);
}

static void fill_pattern(uint8_t *buf, size_t len,
                          const uint8_t *pattern, size_t pattern_len)
{
    if (pattern_len == 1) {
        memset(buf, pattern[0], len);
    } else {
        for (size_t i = 0; i < len; i++)
            buf[i] = pattern[i % pattern_len];
    }
}

/* ------------------------------------------------------------------ */
/*  Get device size (platform-specific)                                */
/* ------------------------------------------------------------------ */

uint64_t vault_wipe_get_device_size(const char *device)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    HANDLE h = CreateFileA(device, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;

    GET_LENGTH_INFORMATION li;
    DWORD out;
    BOOL ok = DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO,
                              NULL, 0, &li, sizeof(li), &out, NULL);
    CloseHandle(h);
    return ok ? (uint64_t)li.Length.QuadPart : 0;

#elif defined(VAULT_PLATFORM_MACOS)
    int fd = open(device, O_RDONLY);
    if (fd < 0) return 0;

    uint64_t block_count = 0;
    uint32_t block_size = 0;
    if (ioctl(fd, DKIOCGETBLOCKCOUNT, &block_count) < 0 ||
        ioctl(fd, DKIOCGETBLOCKSIZE, &block_size) < 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return block_count * (uint64_t)block_size;

#else /* Linux */
    int fd = open(device, O_RDONLY);
    if (fd < 0) return 0;
    uint64_t size = 0;
  #ifdef BLKGETSIZE64
    if (ioctl(fd, BLKGETSIZE64, &size) < 0) size = 0;
  #endif
    close(fd);
    return size;
#endif
}

/* ------------------------------------------------------------------ */
/*  SSD detection (platform-specific)                                  */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_MACOS) && defined(HAVE_IOKIT)

static const char *extract_bsd_name(const char *device_path)
{
    const char *p = strrchr(device_path, '/');
    if (!p) p = device_path;
    else p++;

    /* Skip leading 'r' for raw devices */
    if (*p == 'r' && strncmp(p + 1, "disk", 4) == 0)
        p++;

    return p;
}

int vault_wipe_is_ssd(const char *device)
{
    const char *bsd_name = extract_bsd_name(device);

    CFMutableDictionaryRef match = IOBSDNameMatching(kIOMainPortDefault,
                                                      0, bsd_name);
    if (!match)
        return -1;

    io_service_t media = IOServiceGetMatchingService(kIOMainPortDefault,
                                                      match);
    /* match is consumed by IOServiceGetMatchingService */
    if (!media)
        return -1;

    int result = -1;
    io_service_t current = media;

    for (int depth = 0; depth < 20; depth++) {
        /* Check for NVMe */
        if (IOObjectConformsTo(current, "IONVMeBlockStorageDevice") ||
            IOObjectConformsTo(current, "IONVMeController")) {
            result = 1;
            break;
        }

        /* Check via Device Characteristics dictionary */
        CFTypeRef prop = IORegistryEntrySearchCFProperty(
            current, kIOServicePlane,
            CFSTR("Device Characteristics"),
            kCFAllocatorDefault,
            kIORegistryIterateRecursively | kIORegistryIterateParents);

        if (prop && CFGetTypeID(prop) == CFDictionaryGetTypeID()) {
            CFDictionaryRef chars = (CFDictionaryRef)prop;
            CFStringRef medium = CFDictionaryGetValue(chars,
                                     CFSTR("Medium Type"));
            if (medium) {
                char buf[64] = {0};
                CFStringGetCString(medium, buf, sizeof(buf),
                                   kCFStringEncodingUTF8);
                if (strcasecmp(buf, "Solid State") == 0 ||
                    strcasecmp(buf, "SSD") == 0) {
                    result = 1;
                } else if (strcasecmp(buf, "Rotational") == 0) {
                    result = 0;
                }
                CFRelease(prop);
                break;
            }
            CFRelease(prop);
        }

        /* Check "Solid State" boolean property */
        CFTypeRef ssd_prop = IORegistryEntrySearchCFProperty(
            current, kIOServicePlane,
            CFSTR("Solid State"),
            kCFAllocatorDefault,
            kIORegistryIterateRecursively | kIORegistryIterateParents);

        if (ssd_prop) {
            if (CFGetTypeID(ssd_prop) == CFBooleanGetTypeID()) {
                result = CFBooleanGetValue(ssd_prop) ? 1 : 0;
                CFRelease(ssd_prop);
                break;
            }
            CFRelease(ssd_prop);
        }

        /* Move to parent */
        io_service_t parent;
        kern_return_t kr = IORegistryEntryGetParentEntry(current,
                                                          kIOServicePlane,
                                                          &parent);
        if (current != media)
            IOObjectRelease(current);
        if (kr != KERN_SUCCESS)
            break;
        current = parent;
    }

    if (current != media)
        IOObjectRelease(current);
    IOObjectRelease(media);

    return result;
}

#elif defined(VAULT_PLATFORM_LINUX)

int vault_wipe_is_ssd(const char *device)
{
    /* Extract device name: /dev/sda → sda, /dev/nvme0n1 → nvme0n1 */
    const char *name = strrchr(device, '/');
    name = name ? name + 1 : device;

    /* Strip partition number (sda2 → sda) */
    char base[64];
    strncpy(base, name, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';
    size_t len = strlen(base);
    while (len > 0 && base[len-1] >= '0' && base[len-1] <= '9') {
        /* Don't strip digits from nvme0n1 type names */
        if (len >= 2 && base[len-2] == 'n') break;
        base[--len] = '\0';
    }

    /* NVMe is always SSD */
    if (strncmp(base, "nvme", 4) == 0) return 1;

    char path[256];
    snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", base);

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    int val = -1;
    if (fscanf(fp, "%d", &val) != 1) val = -1;
    fclose(fp);

    /* rotational: 0 = SSD, 1 = HDD */
    return (val == 0) ? 1 : 0;
}

#else /* Windows or macOS without IOKit */

int vault_wipe_is_ssd(const char *device)
{
    (void)device;
    return -1;
}

#endif

/* ------------------------------------------------------------------ */
/*  Platform-specific disk I/O wrappers                                */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_WINDOWS)

typedef HANDLE disk_handle_t;
#define INVALID_DISK_HANDLE INVALID_HANDLE_VALUE

static disk_handle_t disk_open_write(const char *path)
{
    return CreateFileA(path, GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING,
                       FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                       NULL);
}

static disk_handle_t disk_open_read(const char *path)
{
    return CreateFileA(path, GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
}

static int disk_seek_begin(disk_handle_t h)
{
    LARGE_INTEGER li;
    li.QuadPart = 0;
    return SetFilePointerEx(h, li, NULL, FILE_BEGIN) ? 0 : -1;
}

static int disk_write(disk_handle_t h, const uint8_t *buf, size_t len)
{
    DWORD written;
    if (!WriteFile(h, buf, (DWORD)len, &written, NULL))
        return -1;
    return (int)written;
}

static int disk_read(disk_handle_t h, uint8_t *buf, size_t len)
{
    DWORD nread;
    if (!ReadFile(h, buf, (DWORD)len, &nread, NULL))
        return -1;
    return (int)nread;
}

static void disk_sync(disk_handle_t h) { FlushFileBuffers(h); }
static void disk_close(disk_handle_t h) { CloseHandle(h); }

#else /* POSIX (Linux + macOS) */

typedef int disk_handle_t;
#define INVALID_DISK_HANDLE (-1)

static disk_handle_t disk_open_write(const char *path)
{
    return open(path, O_WRONLY | O_SYNC);
}

static disk_handle_t disk_open_read(const char *path)
{
    return open(path, O_RDONLY);
}

static int disk_seek_begin(disk_handle_t h)
{
    return (lseek(h, 0, SEEK_SET) == 0) ? 0 : -1;
}

static int disk_write(disk_handle_t h, const uint8_t *buf, size_t len)
{
    ssize_t wr = write(h, buf, len);
    return (int)wr;
}

static int disk_read(disk_handle_t h, uint8_t *buf, size_t len)
{
    ssize_t rd = read(h, buf, len);
    return (int)rd;
}

static void disk_sync(disk_handle_t h)
{
#if defined(VAULT_PLATFORM_MACOS)
    if (fcntl(h, F_FULLFSYNC) != 0)
        fsync(h);
#else
    fsync(h);
#endif
}

static void disk_close(disk_handle_t h) { close(h); }

#endif /* Platform I/O */

/* ------------------------------------------------------------------ */
/*  macOS: Convert /dev/diskN to /dev/rdiskN for raw access            */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_MACOS)

static void make_raw_path(const char *device_path, char *raw_path, size_t size)
{
    const char *last_slash = strrchr(device_path, '/');
    if (!last_slash) {
        snprintf(raw_path, size, "/dev/r%s", device_path);
        return;
    }

    /* Already raw? */
    if (last_slash[1] == 'r' && strncmp(last_slash + 2, "disk", 4) == 0) {
        strncpy(raw_path, device_path, size - 1);
        raw_path[size - 1] = '\0';
        return;
    }

    /* Convert /dev/diskN → /dev/rdiskN */
    size_t prefix_len = (size_t)(last_slash - device_path + 1);
    snprintf(raw_path, size, "%.*sr%s",
             (int)prefix_len, device_path, last_slash + 1);
}

#endif

/* ------------------------------------------------------------------ */
/*  nwipe availability (Linux only)                                    */
/* ------------------------------------------------------------------ */

int vault_wipe_nwipe_available(void)
{
#if defined(VAULT_PLATFORM_LINUX)
    return access("/usr/bin/nwipe", X_OK) == 0 ||
           access("/usr/sbin/nwipe", X_OK) == 0;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/*  Single write pass                                                  */
/* ------------------------------------------------------------------ */

static int do_direct_pass(disk_handle_t fd, uint64_t disk_size, uint8_t *buf,
                           size_t buf_size, int is_random,
                           const uint8_t *pattern, size_t pattern_len,
                           int pass_num, int total_passes,
                           const char *desc,
                           vault_wipe_progress_cb progress_cb)
{
    if (!is_random && (!pattern || pattern_len == 0)) {
        fprintf(stderr, "vault: invalid wipe pattern for pass %d\n", pass_num);
        return -1;
    }

    double start = now_secs();
    double last_report = start;
    uint64_t written = 0;

    if (disk_seek_begin(fd) != 0) {
        fprintf(stderr, "vault: pass %d seek failed\n", pass_num);
        return -1;
    }

    while (written < disk_size) {
        size_t chunk = buf_size;
        if (written + chunk > disk_size)
            chunk = (size_t)(disk_size - written);

#if defined(VAULT_PLATFORM_WINDOWS)
        /* Align chunk to 512 for FILE_FLAG_NO_BUFFERING */
        if (chunk % 512 != 0)
            chunk = (chunk / 512) * 512;
        if (chunk == 0) break;
#endif

        if (is_random) {
            if (fill_random(buf, chunk) != 0) return -1;
        } else {
            fill_pattern(buf, chunk, pattern, pattern_len);
        }

        int wr = disk_write(fd, buf, chunk);
        if (wr < 0) {
#if !defined(VAULT_PLATFORM_WINDOWS)
            if (errno == EINTR) continue;
#endif
            fprintf(stderr, "vault: pass %d write error at %llu\n",
                    pass_num, (unsigned long long)written);
            return -1;
        }
        written += (uint64_t)wr;

        /* Progress reporting */
        double now = now_secs();
        if (progress_cb && (now - last_report > 0.5)) {
            double elapsed = now - start;
            double speed = (elapsed > 0) ? ((double)written / elapsed) : 0;

            vault_wipe_progress_t prog;
            memset(&prog, 0, sizeof(prog));
            prog.current_pass     = pass_num;
            prog.total_passes     = total_passes;
            prog.bytes_written    = written;
            prog.bytes_total      = disk_size;
            prog.speed_mbps       = speed / (1024.0 * 1024.0);
            prog.eta_secs         = (speed > 0) ?
                ((double)(disk_size - written) / speed) : 0;
            prog.pass_description = desc;
            prog.verifying        = 0;
            progress_cb(&prog);
            last_report = now;
        }
    }

    disk_sync(fd);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Single verify pass                                                 */
/* ------------------------------------------------------------------ */

static int do_direct_verify(const char *device, uint64_t disk_size,
                              uint8_t *write_buf, uint8_t *verify_buf,
                              size_t buf_size, int is_random,
                              const uint8_t *pattern, size_t pattern_len,
                              int pass_num, int total_passes,
                              vault_wipe_progress_cb progress_cb)
{
    if (!is_random && (!pattern || pattern_len == 0)) {
        fprintf(stderr, "vault: invalid verify pattern for pass %d\n", pass_num);
        return -1;
    }

    disk_handle_t fd = disk_open_read(device);
    if (fd == INVALID_DISK_HANDLE) {
        fprintf(stderr, "vault: verify open failed\n");
        return -1;
    }

    double start = now_secs();
    double last_report = start;
    uint64_t verified = 0;
    int ret = 0;

    while (verified < disk_size) {
        size_t chunk = buf_size;
        if (verified + chunk > disk_size)
            chunk = (size_t)(disk_size - verified);

#if defined(VAULT_PLATFORM_WINDOWS)
        if (chunk % 512 != 0)
            chunk = (chunk / 512) * 512;
        if (chunk == 0) break;
#endif

        int rd = disk_read(fd, verify_buf, chunk);
        if (rd < 0) {
#if !defined(VAULT_PLATFORM_WINDOWS)
            if (errno == EINTR) continue;
#endif
            fprintf(stderr, "vault: verify read error at %llu\n",
                    (unsigned long long)verified);
            ret = -1;
            break;
        }

        /* For deterministic patterns, verify exact data */
        if (!is_random) {
            fill_pattern(write_buf, chunk, pattern, pattern_len);
            if (memcmp(write_buf, verify_buf, chunk) != 0) {
                fprintf(stderr, "vault: verify MISMATCH at offset %llu\n",
                        (unsigned long long)verified);
                ret = -1;
                break;
            }
        }

        verified += (uint64_t)rd;

        double now = now_secs();
        if (progress_cb && (now - last_report > 0.5)) {
            double elapsed = now - start;
            double speed = (elapsed > 0) ? ((double)verified / elapsed) : 0;

            vault_wipe_progress_t prog;
            memset(&prog, 0, sizeof(prog));
            prog.current_pass     = pass_num;
            prog.total_passes     = total_passes;
            prog.bytes_written    = verified;
            prog.bytes_total      = disk_size;
            prog.speed_mbps       = speed / (1024.0 * 1024.0);
            prog.eta_secs         = (speed > 0) ?
                ((double)(disk_size - verified) / speed) : 0;
            prog.pass_description = "Verifying";
            prog.verifying        = 1;
            progress_cb(&prog);
            last_report = now;
        }
    }

    disk_close(fd);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Resolve device path for the platform                               */
/* ------------------------------------------------------------------ */

static const char *resolve_device_path(const char *device,
                                        char *resolved, size_t resolved_size)
{
#if defined(VAULT_PLATFORM_MACOS)
    /* Convert /dev/diskN → /dev/rdiskN for raw access */
    make_raw_path(device, resolved, resolved_size);
    return resolved;
#else
    (void)resolved;
    (void)resolved_size;
    return device;
#endif
}

/* ------------------------------------------------------------------ */
/*  vault_wipe_device — top-level wipe dispatcher                      */
/* ------------------------------------------------------------------ */

int vault_wipe_device(const char *device, wipe_algorithm_t algorithm,
                       int verify)
{
#if defined(VAULT_PLATFORM_LINUX)
    const char *method_flag = vault_wipe_algorithm_nwipe_flag(algorithm);

    if (!vault_wipe_nwipe_available()) {
        fprintf(stderr, "vault: nwipe not found, falling back to direct wipe\n");
        return vault_wipe_device_direct(device, algorithm, verify, NULL);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("vault: fork");
        return -1;
    }

    if (pid == 0) {
        const char *argv[9];
        int argc = 0;
        argv[argc++] = "nwipe";
        argv[argc++] = "--autonuke";
        argv[argc++] = "--nowait";
        argv[argc++] = "--nogui";
        if (verify)
            argv[argc++] = "--verify=all";
        argv[argc++] = method_flag;
        argv[argc++] = device;
        argv[argc] = NULL;
        execvp("nwipe", (char *const *)argv);
        perror("vault: execvp nwipe");
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        perror("vault: waitpid");
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;

    fprintf(stderr, "vault: nwipe failed (status %d), retrying with direct wipe\n",
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return vault_wipe_device_direct(device, algorithm, verify, NULL);

#else
    /* macOS and Windows: direct I/O only */
    return vault_wipe_device_direct(device, algorithm, verify, NULL);
#endif
}

/* ------------------------------------------------------------------ */
/*  vault_wipe_device_direct — full direct I/O wipe engine             */
/* ------------------------------------------------------------------ */

int vault_wipe_device_direct(const char *device, wipe_algorithm_t algorithm,
                              int verify, vault_wipe_progress_cb progress_cb)
{
    /* Resolve platform-specific device path */
    char resolved_path[256];
    const char *dev_path = resolve_device_path(device, resolved_path,
                                                sizeof(resolved_path));

    /* SSD warning */
    int ssd = vault_wipe_is_ssd(device);
    if (ssd == 1) {
        fprintf(stderr,
            "WARNING: %s is an SSD. Software wiping cannot guarantee complete\n"
            "erasure due to wear-leveling. Consider ATA Secure Erase or\n"
            "full-disk encryption before storing sensitive data.\n", device);
    }

#if defined(VAULT_PLATFORM_MACOS)
    /* Unmount all volumes before wiping */
    char umount_cmd[512];
    snprintf(umount_cmd, sizeof(umount_cmd),
             "diskutil unmountDisk %s 2>/dev/null", device);
    system(umount_cmd);
#endif

    uint64_t disk_size = vault_wipe_get_device_size(dev_path);
    if (disk_size == 0) {
        fprintf(stderr, "vault: cannot determine size of %s\n", dev_path);
        return -1;
    }

    disk_handle_t fd = disk_open_write(dev_path);
    if (fd == INVALID_DISK_HANDLE) {
        fprintf(stderr, "vault: cannot open %s for writing\n", dev_path);
        return -1;
    }

    uint8_t *write_buf = (uint8_t *)malloc(WIPE_BUF_SIZE);
    uint8_t *verify_buf = verify ? (uint8_t *)malloc(WIPE_BUF_SIZE) : NULL;
    if (!write_buf || (verify && !verify_buf)) {
        free(write_buf);
        free(verify_buf);
        disk_close(fd);
        return -1;
    }

    int ret = 0;
    int total_passes;
    char desc[128];

    switch (algorithm) {
    case WIPE_GUTMANN:
        total_passes = 35;
        for (int p = 0; p < 35 && ret == 0; p++) {
            const gutmann_pass_t *gp = &gutmann_passes[p];
            if (gp->is_random) {
                snprintf(desc, sizeof(desc), "Pass %d/35: random", p + 1);
            } else if (gp->pattern_len == 1) {
                snprintf(desc, sizeof(desc), "Pass %d/35: 0x%02X",
                         p + 1, gp->pattern[0]);
            } else {
                snprintf(desc, sizeof(desc),
                         "Pass %d/35: 0x%02X%02X%02X", p + 1,
                         gp->pattern[0], gp->pattern[1], gp->pattern[2]);
            }
            ret = do_direct_pass(fd, disk_size, write_buf, WIPE_BUF_SIZE,
                                  gp->is_random, gp->pattern,
                                  gp->pattern_len, p + 1, total_passes,
                                  desc, progress_cb);
            if (ret == 0 && verify && !gp->is_random)
                ret = do_direct_verify(dev_path, disk_size, write_buf,
                                        verify_buf, WIPE_BUF_SIZE,
                                        gp->is_random, gp->pattern,
                                        gp->pattern_len, p + 1,
                                        total_passes, progress_cb);
        }
        break;

    case WIPE_DOD_522022:
        total_passes = 7;
        for (int p = 0; p < 7 && ret == 0; p++) {
            const dod_pass_t *dp = &dod_passes[p];
            uint8_t pat[1] = { dp->byte };
            snprintf(desc, sizeof(desc), "Pass %d/7: %s", p + 1,
                     dp->is_random ? "random" : "pattern");
            ret = do_direct_pass(fd, disk_size, write_buf, WIPE_BUF_SIZE,
                                  dp->is_random, pat, 1, p + 1,
                                  total_passes, desc, progress_cb);
            if (ret == 0 && verify && !dp->is_random)
                ret = do_direct_verify(dev_path, disk_size, write_buf,
                                        verify_buf, WIPE_BUF_SIZE,
                                        dp->is_random, pat, 1, p + 1,
                                        total_passes, progress_cb);
        }
        break;

    case WIPE_DOD_SHORT:
        total_passes = 3;
        for (int p = 0; p < 3 && ret == 0; p++) {
            snprintf(desc, sizeof(desc), "Pass %d/3: random", p + 1);
            ret = do_direct_pass(fd, disk_size, write_buf, WIPE_BUF_SIZE,
                                  1, NULL, 0, p + 1, total_passes,
                                  desc, progress_cb);
        }
        break;

    case WIPE_RANDOM:
        total_passes = 1;
        ret = do_direct_pass(fd, disk_size, write_buf, WIPE_BUF_SIZE,
                              1, NULL, 0, 1, 1,
                              "Pass 1/1: random", progress_cb);
        break;

    case WIPE_ZERO: {
        total_passes = 1;
        uint8_t zero = 0x00;
        ret = do_direct_pass(fd, disk_size, write_buf, WIPE_BUF_SIZE,
                              0, &zero, 1, 1, 1,
                              "Pass 1/1: zero", progress_cb);
        if (ret == 0 && verify)
            ret = do_direct_verify(dev_path, disk_size, write_buf,
                                    verify_buf, WIPE_BUF_SIZE,
                                    0, &zero, 1, 1, 1, progress_cb);
        break;
    }

    default:
        ret = -1;
    }

    free(write_buf);
    free(verify_buf);
    disk_close(fd);
    return ret;
}
