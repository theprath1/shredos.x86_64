/*
 * wipe.c -- Unified Cross-Platform Secure Wipe Engine
 *
 * Algorithms:
 *   Gutmann 35-pass, DoD 5220.22-M 7-pass, DoD Short 3-pass,
 *   Cryptographic Random 1-pass, Zero Fill 1-pass.
 *
 * Platform I/O:
 *   Linux:   direct /dev/sdX with O_SYNC + fsync()
 *   macOS:   /dev/rdiskN with F_FULLFSYNC
 *   Windows: \\.\PhysicalDriveN with FILE_FLAG_NO_BUFFERING
 *
 * Copyright 2025 -- GPL-2.0+
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
#else /* Linux */
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  #include <sys/ioctl.h>
  #include <sys/time.h>
  #include <sys/wait.h>
  #ifdef __linux__
    #include <linux/fs.h>
  #endif
#endif

#define WIPE_BUF_SIZE (4 * 1024 * 1024) /* 4 MB */

/* ------------------------------------------------------------------ */
/*  Gutmann 35-pass patterns                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    int     is_random;
    size_t  pattern_len;
    uint8_t pattern[3];
} gutmann_pass_t;

static const gutmann_pass_t gutmann_passes[35] = {
    {1,0,{0}}, {1,0,{0}}, {1,0,{0}}, {1,0,{0}},
    {0,1,{0x55}}, {0,1,{0xAA}}, {0,3,{0x92,0x49,0x24}},
    {0,3,{0x49,0x24,0x92}}, {0,3,{0x24,0x92,0x49}},
    {0,1,{0x00}}, {0,1,{0x11}}, {0,1,{0x22}},
    {0,1,{0x33}}, {0,1,{0x44}},
    {0,1,{0x55}}, {0,1,{0x66}}, {0,1,{0x77}},
    {0,1,{0x88}}, {0,1,{0x99}},
    {0,1,{0xAA}}, {0,1,{0xBB}}, {0,1,{0xCC}},
    {0,1,{0xDD}}, {0,1,{0xEE}},
    {0,1,{0xFF}}, {0,3,{0x92,0x49,0x24}},
    {0,3,{0x49,0x24,0x92}},
    {0,3,{0x24,0x92,0x49}}, {0,3,{0x6D,0xB6,0xDB}},
    {0,3,{0xB6,0xDB,0x6D}}, {0,3,{0xDB,0x6D,0xB6}},
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
/*  Timing                                                             */
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
/*  Buffer fill                                                        */
/* ------------------------------------------------------------------ */

static int fill_random(uint8_t *buf, size_t len)
{
    return vault_platform_random(buf, len);
}

static void fill_pattern(uint8_t *buf, size_t len,
                          const uint8_t *pat, size_t pat_len)
{
    if (pat_len == 1) {
        memset(buf, pat[0], len);
    } else {
        for (size_t i = 0; i < len; i++)
            buf[i] = pat[i % pat_len];
    }
}

/* ------------------------------------------------------------------ */
/*  Device size                                                        */
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
    uint64_t bc = 0;
    uint32_t bs = 0;
    if (ioctl(fd, DKIOCGETBLOCKCOUNT, &bc) < 0 ||
        ioctl(fd, DKIOCGETBLOCKSIZE, &bs) < 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return bc * (uint64_t)bs;

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
/*  SSD detection                                                      */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_LINUX)

int vault_wipe_is_ssd(const char *device)
{
    const char *name = strrchr(device, '/');
    name = name ? name + 1 : device;

    /* Strip partition number */
    char base[64];
    strncpy(base, name, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';
    size_t len = strlen(base);
    while (len > 0 && base[len - 1] >= '0' && base[len - 1] <= '9') {
        if (len >= 2 && base[len - 2] == 'n') break;
        base[--len] = '\0';
    }

    if (strncmp(base, "nvme", 4) == 0) return 1;

    char path[256];
    snprintf(path, sizeof(path), "/sys/block/%s/queue/rotational", base);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    int val = -1;
    if (fscanf(fp, "%d", &val) != 1) val = -1;
    fclose(fp);
    return (val == 0) ? 1 : 0;
}

#else

int vault_wipe_is_ssd(const char *device)
{
    (void)device;
    return -1;
}

#endif

/* ------------------------------------------------------------------ */
/*  Platform disk I/O                                                  */
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
    LARGE_INTEGER li; li.QuadPart = 0;
    return SetFilePointerEx(h, li, NULL, FILE_BEGIN) ? 0 : -1;
}

static int disk_write(disk_handle_t h, const uint8_t *buf, size_t len)
{
    DWORD written;
    return WriteFile(h, buf, (DWORD)len, &written, NULL) ? (int)written : -1;
}

static int disk_read(disk_handle_t h, uint8_t *buf, size_t len)
{
    DWORD nread;
    return ReadFile(h, buf, (DWORD)len, &nread, NULL) ? (int)nread : -1;
}

static void disk_sync(disk_handle_t h) { FlushFileBuffers(h); }
static void disk_close(disk_handle_t h) { CloseHandle(h); }

#else /* POSIX */

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
    return (int)write(h, buf, len);
}

static int disk_read(disk_handle_t h, uint8_t *buf, size_t len)
{
    return (int)read(h, buf, len);
}

static void disk_sync(disk_handle_t h)
{
#if defined(VAULT_PLATFORM_MACOS)
    if (fcntl(h, F_FULLFSYNC) != 0) fsync(h);
#else
    fsync(h);
#endif
}

static void disk_close(disk_handle_t h) { close(h); }

#endif

/* ------------------------------------------------------------------ */
/*  macOS raw device path                                              */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_MACOS)
static void make_raw_path(const char *dev, char *raw, size_t size)
{
    const char *sl = strrchr(dev, '/');
    if (!sl) { snprintf(raw, size, "/dev/r%s", dev); return; }
    if (sl[1] == 'r' && strncmp(sl + 2, "disk", 4) == 0) {
        strncpy(raw, dev, size - 1);
        raw[size - 1] = '\0';
        return;
    }
    size_t plen = (size_t)(sl - dev + 1);
    snprintf(raw, size, "%.*sr%s", (int)plen, dev, sl + 1);
}
#endif

static const char *resolve_device_path(const char *device,
                                        char *resolved, size_t size)
{
#if defined(VAULT_PLATFORM_MACOS)
    make_raw_path(device, resolved, size);
    return resolved;
#else
    (void)resolved; (void)size;
    return device;
#endif
}

/* ------------------------------------------------------------------ */
/*  nwipe availability                                                 */
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
                           const uint8_t *pat, size_t pat_len,
                           int pass_num, int total_passes,
                           const char *desc,
                           vault_wipe_progress_cb progress_cb)
{
    if (!is_random && (!pat || pat_len == 0)) return -1;

    double start = now_secs();
    double last_report = start;
    uint64_t written = 0;

    if (disk_seek_begin(fd) != 0) return -1;

    while (written < disk_size) {
        size_t chunk = buf_size;
        if (written + chunk > disk_size)
            chunk = (size_t)(disk_size - written);

#if defined(VAULT_PLATFORM_WINDOWS)
        if (chunk % 512 != 0) chunk = (chunk / 512) * 512;
        if (chunk == 0) break;
#endif

        if (is_random) {
            if (fill_random(buf, chunk) != 0) return -1;
        } else {
            fill_pattern(buf, chunk, pat, pat_len);
        }

        int wr = disk_write(fd, buf, chunk);
        if (wr < 0) {
#if !defined(VAULT_PLATFORM_WINDOWS)
            if (errno == EINTR) continue;
#endif
            return -1;
        }
        written += (uint64_t)wr;

        double now = now_secs();
        if (progress_cb && (now - last_report > 0.5)) {
            double elapsed = now - start;
            double speed = (elapsed > 0) ? ((double)written / elapsed) : 0;
            vault_wipe_progress_t prog = {
                .current_pass = pass_num,
                .total_passes = total_passes,
                .bytes_written = written,
                .bytes_total = disk_size,
                .speed_mbps = speed / (1024.0 * 1024.0),
                .eta_secs = (speed > 0) ? ((double)(disk_size - written) / speed) : 0,
                .pass_description = desc,
                .verifying = 0
            };
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
                              uint8_t *wbuf, uint8_t *vbuf,
                              size_t buf_size, int is_random,
                              const uint8_t *pat, size_t pat_len,
                              int pass_num, int total_passes,
                              vault_wipe_progress_cb progress_cb)
{
    if (!is_random && (!pat || pat_len == 0)) return -1;

    disk_handle_t fd = disk_open_read(device);
    if (fd == INVALID_DISK_HANDLE) return -1;

    double start = now_secs();
    double last_report = start;
    uint64_t verified = 0;
    int ret = 0;

    while (verified < disk_size) {
        size_t chunk = buf_size;
        if (verified + chunk > disk_size)
            chunk = (size_t)(disk_size - verified);

#if defined(VAULT_PLATFORM_WINDOWS)
        if (chunk % 512 != 0) chunk = (chunk / 512) * 512;
        if (chunk == 0) break;
#endif

        int rd = disk_read(fd, vbuf, chunk);
        if (rd < 0) { ret = -1; break; }

        if (!is_random) {
            fill_pattern(wbuf, chunk, pat, pat_len);
            if (memcmp(wbuf, vbuf, chunk) != 0) { ret = -1; break; }
        }

        verified += (uint64_t)rd;

        double now = now_secs();
        if (progress_cb && (now - last_report > 0.5)) {
            double elapsed = now - start;
            double speed = (elapsed > 0) ? ((double)verified / elapsed) : 0;
            vault_wipe_progress_t prog = {
                .current_pass = pass_num,
                .total_passes = total_passes,
                .bytes_written = verified,
                .bytes_total = disk_size,
                .speed_mbps = speed / (1024.0 * 1024.0),
                .eta_secs = (speed > 0) ? ((double)(disk_size - verified) / speed) : 0,
                .pass_description = "Verifying",
                .verifying = 1
            };
            progress_cb(&prog);
            last_report = now;
        }
    }

    disk_close(fd);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  vault_wipe_device -- top-level dispatcher                          */
/* ------------------------------------------------------------------ */

int vault_wipe_device(const char *device, wipe_algorithm_t algorithm,
                       int verify)
{
#if defined(VAULT_PLATFORM_LINUX)
    if (!vault_wipe_nwipe_available())
        return vault_wipe_device_direct(device, algorithm, verify, NULL);

    const char *mflag = vault_wipe_algorithm_nwipe_flag(algorithm);

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        const char *argv[9];
        int ac = 0;
        argv[ac++] = "nwipe";
        argv[ac++] = "--autonuke";
        argv[ac++] = "--nowait";
        argv[ac++] = "--nogui";
        if (verify) argv[ac++] = "--verify=all";
        argv[ac++] = mflag;
        argv[ac++] = device;
        argv[ac] = NULL;
        execvp("nwipe", (char *const *)argv);
        _exit(127);
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;

    return vault_wipe_device_direct(device, algorithm, verify, NULL);
#else
    return vault_wipe_device_direct(device, algorithm, verify, NULL);
#endif
}

/* ------------------------------------------------------------------ */
/*  vault_wipe_device_direct -- full direct I/O wipe                   */
/* ------------------------------------------------------------------ */

int vault_wipe_device_direct(const char *device, wipe_algorithm_t algorithm,
                              int verify, vault_wipe_progress_cb progress_cb)
{
    char resolved_path[256];
    const char *dev = resolve_device_path(device, resolved_path,
                                           sizeof(resolved_path));

    int ssd = vault_wipe_is_ssd(device);
    if (ssd == 1) {
        fprintf(stderr,
            "WARNING: %s is SSD. Software wiping cannot guarantee\n"
            "complete erasure due to wear-levelling.\n", device);
    }

#if defined(VAULT_PLATFORM_MACOS)
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "diskutil unmountDisk %s 2>/dev/null", device);
    system(cmd);
#endif

    uint64_t disk_size = vault_wipe_get_device_size(dev);
    if (disk_size == 0) return -1;

    disk_handle_t fd = disk_open_write(dev);
    if (fd == INVALID_DISK_HANDLE) return -1;

    uint8_t *wbuf = (uint8_t *)malloc(WIPE_BUF_SIZE);
    uint8_t *vbuf = verify ? (uint8_t *)malloc(WIPE_BUF_SIZE) : NULL;
    if (!wbuf || (verify && !vbuf)) {
        free(wbuf); free(vbuf);
        disk_close(fd);
        return -1;
    }

    int ret = 0;
    int total;
    char desc[128];

    switch (algorithm) {
    case WIPE_GUTMANN:
        total = 35;
        for (int p = 0; p < 35 && ret == 0; p++) {
            const gutmann_pass_t *gp = &gutmann_passes[p];
            if (gp->is_random)
                snprintf(desc, sizeof(desc), "Pass %d/35: random", p + 1);
            else if (gp->pattern_len == 1)
                snprintf(desc, sizeof(desc), "Pass %d/35: 0x%02X", p + 1, gp->pattern[0]);
            else
                snprintf(desc, sizeof(desc), "Pass %d/35: 0x%02X%02X%02X",
                         p + 1, gp->pattern[0], gp->pattern[1], gp->pattern[2]);

            ret = do_direct_pass(fd, disk_size, wbuf, WIPE_BUF_SIZE,
                                  gp->is_random, gp->pattern, gp->pattern_len,
                                  p + 1, total, desc, progress_cb);
            if (ret == 0 && verify && !gp->is_random)
                ret = do_direct_verify(dev, disk_size, wbuf, vbuf,
                                        WIPE_BUF_SIZE, gp->is_random,
                                        gp->pattern, gp->pattern_len,
                                        p + 1, total, progress_cb);
        }
        break;

    case WIPE_DOD_522022:
        total = 7;
        for (int p = 0; p < 7 && ret == 0; p++) {
            const dod_pass_t *dp = &dod_passes[p];
            uint8_t pat[1] = { dp->byte };
            snprintf(desc, sizeof(desc), "Pass %d/7: %s",
                     p + 1, dp->is_random ? "random" : "pattern");
            ret = do_direct_pass(fd, disk_size, wbuf, WIPE_BUF_SIZE,
                                  dp->is_random, pat, 1,
                                  p + 1, total, desc, progress_cb);
            if (ret == 0 && verify && !dp->is_random)
                ret = do_direct_verify(dev, disk_size, wbuf, vbuf,
                                        WIPE_BUF_SIZE, dp->is_random,
                                        pat, 1, p + 1, total, progress_cb);
        }
        break;

    case WIPE_DOD_SHORT:
        total = 3;
        for (int p = 0; p < 3 && ret == 0; p++) {
            snprintf(desc, sizeof(desc), "Pass %d/3: random", p + 1);
            ret = do_direct_pass(fd, disk_size, wbuf, WIPE_BUF_SIZE,
                                  1, NULL, 0, p + 1, total, desc, progress_cb);
        }
        break;

    case WIPE_RANDOM:
        total = 1;
        ret = do_direct_pass(fd, disk_size, wbuf, WIPE_BUF_SIZE,
                              1, NULL, 0, 1, 1, "Pass 1/1: random", progress_cb);
        break;

    case WIPE_ZERO: {
        total = 1;
        uint8_t zero = 0x00;
        ret = do_direct_pass(fd, disk_size, wbuf, WIPE_BUF_SIZE,
                              0, &zero, 1, 1, 1, "Pass 1/1: zero", progress_cb);
        if (ret == 0 && verify)
            ret = do_direct_verify(dev, disk_size, wbuf, vbuf,
                                    WIPE_BUF_SIZE, 0, &zero, 1, 1, 1,
                                    progress_cb);
        break;
    }

    default:
        ret = -1;
    }

    free(wbuf);
    free(vbuf);
    disk_close(fd);
    return ret;
}
