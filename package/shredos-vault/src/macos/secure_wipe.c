/*
 * secure_wipe.c — macOS Secure Drive Wiper
 *
 * Low-level disk wipe utility using direct raw device I/O.
 * Uses SecRandomCopyBytes for cryptographically secure randomness.
 * Detects HDD vs SSD via IOKit and applies appropriate strategy.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -framework Security -framework IOKit \
 *      -framework CoreFoundation secure_wipe.c -o secure_wipe
 *
 * Usage:
 *   sudo ./secure_wipe --device /dev/rdisk4 --algorithm gutmann --verify
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "secure_wipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/time.h>

/* macOS frameworks */
#include <Security/Security.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/IOBSD.h>
#include <CoreFoundation/CoreFoundation.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define BUFFER_SIZE       (4 * 1024 * 1024)  /* 4 MB I/O buffer */
#define VERIFY_BLOCK_SIZE (1 * 1024 * 1024)  /* 1 MB verify reads */
#define PROGRESS_INTERVAL 500000             /* report every 500ms (usec) */

/* ------------------------------------------------------------------ */
/*  Gutmann 35-pass patterns                                           */
/*  Passes 1-4 and 33-35 use random data.                             */
/*  Passes 5-31 use specific byte patterns from the Gutmann paper.    */
/* ------------------------------------------------------------------ */

typedef struct {
    bool   is_random;
    size_t pattern_len;          /* 1 or 3 bytes */
    uint8_t pattern[3];
} gutmann_pass_t;

#define GP_RAND { true,  0, {0} }
#define GP1(a)  { false, 1, {(a), 0, 0} }
#define GP3(a,b,c) { false, 3, {(a),(b),(c)} }

static const gutmann_pass_t gutmann_passes[35] = {
    /* 1-4: random */
    GP_RAND, GP_RAND, GP_RAND, GP_RAND,
    /* 5-9 */
    GP1(0x55), GP1(0xAA), GP3(0x92,0x49,0x24), GP3(0x49,0x24,0x92),
    GP3(0x24,0x92,0x49),
    /* 10-14 */
    GP1(0x00), GP1(0x11), GP1(0x22), GP1(0x33), GP1(0x44),
    /* 15-19 */
    GP1(0x55), GP1(0x66), GP1(0x77), GP1(0x88), GP1(0x99),
    /* 20-24 */
    GP1(0xAA), GP1(0xBB), GP1(0xCC), GP1(0xDD), GP1(0xEE),
    /* 25-27 */
    GP1(0xFF), GP3(0x92,0x49,0x24), GP3(0x49,0x24,0x92),
    /* 28-31 */
    GP3(0x24,0x92,0x49), GP3(0x6D,0xB6,0xDB), GP3(0xB6,0xDB,0x6D),
    GP3(0xDB,0x6D,0xB6),
    /* 32-35: random */
    GP_RAND, GP_RAND, GP_RAND
};

/* ------------------------------------------------------------------ */
/*  Algorithm metadata                                                 */
/* ------------------------------------------------------------------ */

static const struct {
    const char *name;
    int passes;
} algorithm_info[ALG_COUNT] = {
    [ALG_GUTMANN]     = { "Gutmann (35-pass)",                35 },
    [ALG_DOD_522022M] = { "DoD 5220.22-M (7-pass)",           7 },
    [ALG_SCHNEIER]    = { "Bruce Schneier (3-pass random)",    3 },
    [ALG_RANDOM]      = { "Cryptographic Random (1-pass)",     1 },
    [ALG_ZERO]        = { "Zero Fill (1-pass)",                1 },
};

const char *wipe_algorithm_name(wipe_algorithm_t alg)
{
    if (alg >= ALG_COUNT) return "Unknown";
    return algorithm_info[alg].name;
}

int wipe_algorithm_passes(wipe_algorithm_t alg)
{
    if (alg >= ALG_COUNT) return 0;
    return algorithm_info[alg].passes;
}

const char *wipe_drive_type_name(drive_type_t type)
{
    switch (type) {
    case DRIVE_HDD:     return "HDD (Rotational)";
    case DRIVE_SSD:     return "SSD (Solid State)";
    case DRIVE_NVME:    return "NVMe SSD";
    case DRIVE_UNKNOWN: return "Unknown";
    }
    return "Unknown";
}

/* ------------------------------------------------------------------ */
/*  Timing helpers                                                     */
/* ------------------------------------------------------------------ */

static double now_secs(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
}

/* ------------------------------------------------------------------ */
/*  Cryptographically secure random fill                               */
/* ------------------------------------------------------------------ */

static int fill_random(uint8_t *buf, size_t len)
{
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) != errSecSuccess) {
        /* Fallback to /dev/urandom */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return -1;
        ssize_t rd = read(fd, buf, len);
        close(fd);
        return (rd == (ssize_t)len) ? 0 : -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Fill buffer with a repeating pattern                               */
/* ------------------------------------------------------------------ */

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
/*  IOKit drive type detection                                         */
/* ------------------------------------------------------------------ */

/*
 * Extract disk number from device path (e.g., "/dev/rdisk4" → "disk4").
 * Handles both /dev/diskN and /dev/rdiskN.
 */
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

drive_type_t wipe_detect_drive_type(const char *device_path)
{
    const char *bsd_name = extract_bsd_name(device_path);

    /* Match IOMedia with this BSD name */
    CFMutableDictionaryRef match = IOBSDNameMatching(kIOMainPortDefault,
                                                      0, bsd_name);
    if (!match)
        return DRIVE_UNKNOWN;

    io_service_t media = IOServiceGetMatchingService(kIOMainPortDefault,
                                                      match);
    /* match is consumed by IOServiceGetMatchingService */
    if (!media)
        return DRIVE_UNKNOWN;

    drive_type_t result = DRIVE_UNKNOWN;

    /* Walk up the IORegistry tree to find the storage device */
    io_service_t parent = media;
    io_service_t current = media;

    for (int depth = 0; depth < 20; depth++) {
        /* Check for NVMe */
        if (IOObjectConformsTo(current, "IONVMeBlockStorageDevice") ||
            IOObjectConformsTo(current, "IONVMeController")) {
            result = DRIVE_NVME;
            break;
        }

        /* Check for SSD vs HDD via device characteristics */
        CFTypeRef prop = IORegistryEntrySearchCFProperty(
            current,
            kIOServicePlane,
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
                    result = DRIVE_SSD;
                } else if (strcasecmp(buf, "Rotational") == 0) {
                    result = DRIVE_HDD;
                }
                CFRelease(prop);
                break;
            }
            CFRelease(prop);
        }

        /* Also check for "Solid State" property directly */
        CFTypeRef ssd_prop = IORegistryEntrySearchCFProperty(
            current,
            kIOServicePlane,
            CFSTR("Solid State"),
            kCFAllocatorDefault,
            kIORegistryIterateRecursively | kIORegistryIterateParents);

        if (ssd_prop) {
            if (CFGetTypeID(ssd_prop) == CFBooleanGetTypeID()) {
                result = CFBooleanGetValue(ssd_prop) ? DRIVE_SSD : DRIVE_HDD;
                CFRelease(ssd_prop);
                break;
            }
            CFRelease(ssd_prop);
        }

        /* Move to parent */
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

/* ------------------------------------------------------------------ */
/*  Get disk size                                                      */
/* ------------------------------------------------------------------ */

uint64_t wipe_get_disk_size(const char *device_path)
{
    int fd = open(device_path, O_RDONLY);
    if (fd < 0)
        return 0;

    uint64_t block_count = 0;
    uint32_t block_size = 0;

    if (ioctl(fd, DKIOCGETBLOCKCOUNT, &block_count) < 0 ||
        ioctl(fd, DKIOCGETBLOCKSIZE, &block_size) < 0) {
        close(fd);
        return 0;
    }

    close(fd);
    return block_count * (uint64_t)block_size;
}

/* ------------------------------------------------------------------ */
/*  Convert /dev/diskN to /dev/rdiskN for raw access                   */
/* ------------------------------------------------------------------ */

static int make_raw_path(const char *device_path, char *raw_path, size_t size)
{
    const char *last_slash = strrchr(device_path, '/');
    if (!last_slash) {
        snprintf(raw_path, size, "/dev/r%s", device_path);
        return 0;
    }

    /* Already raw? */
    if (last_slash[1] == 'r' && strncmp(last_slash + 2, "disk", 4) == 0) {
        strncpy(raw_path, device_path, size - 1);
        raw_path[size - 1] = '\0';
        return 0;
    }

    /* Convert /dev/diskN → /dev/rdiskN */
    size_t prefix_len = (size_t)(last_slash - device_path + 1);
    snprintf(raw_path, size, "%.*sr%s",
             (int)prefix_len, device_path, last_slash + 1);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Single pass: write pattern/random to entire disk                   */
/* ------------------------------------------------------------------ */

static int do_write_pass(int fd, uint64_t disk_size, uint8_t *buf,
                          size_t buf_size, bool is_random,
                          const uint8_t *pattern, size_t pattern_len,
                          int pass_num, int total_passes,
                          const char *pass_desc,
                          const wipe_config_t *config,
                          wipe_result_t *result)
{
    double start = now_secs();
    double last_report = start;
    uint64_t written = 0;

    /* Seek to beginning */
    if (lseek(fd, 0, SEEK_SET) != 0) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Pass %d: lseek failed: %s", pass_num, strerror(errno));
        return -1;
    }

    while (written < disk_size) {
        size_t chunk = buf_size;
        if (written + chunk > disk_size)
            chunk = (size_t)(disk_size - written);

        /* Fill buffer */
        if (is_random) {
            if (fill_random(buf, chunk) != 0) {
                snprintf(result->error_msg, sizeof(result->error_msg),
                         "Pass %d: random generation failed", pass_num);
                return -1;
            }
        } else {
            fill_pattern(buf, chunk, pattern, pattern_len);
        }

        /* Write to disk */
        ssize_t wr = write(fd, buf, chunk);
        if (wr < 0) {
            if (errno == EINTR) continue;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Pass %d: write error at offset %llu: %s",
                     pass_num, (unsigned long long)written, strerror(errno));
            return -1;
        }
        if ((size_t)wr != chunk) {
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Pass %d: short write at offset %llu (%zd/%zu)",
                     pass_num, (unsigned long long)written, wr, chunk);
            return -1;
        }

        written += (uint64_t)wr;
        result->total_bytes_written += (uint64_t)wr;

        /* Progress reporting (throttled) */
        double now = now_secs();
        if (config->progress_cb && (now - last_report > 0.5)) {
            double elapsed = now - start;
            double speed = (elapsed > 0) ? ((double)written / elapsed) : 0;
            double eta = (speed > 0) ?
                ((double)(disk_size - written) / speed) : 0;

            wipe_progress_t prog = {
                .current_pass     = pass_num,
                .total_passes     = total_passes,
                .bytes_written    = written,
                .bytes_total      = disk_size,
                .elapsed_secs     = elapsed,
                .eta_secs         = eta,
                .speed_mbps       = speed / (1024.0 * 1024.0),
                .pass_description = pass_desc,
                .verifying        = false,
            };

            if (config->progress_cb(&prog, config->progress_ctx) != 0) {
                snprintf(result->error_msg, sizeof(result->error_msg),
                         "Aborted by user at pass %d", pass_num);
                return -1;
            }
            last_report = now;
        }
    }

    /* Flush to physical media */
    if (fcntl(fd, F_FULLFSYNC) != 0) {
        /* F_FULLFSYNC is macOS-specific — ensures write to physical media */
        fsync(fd); /* Fallback */
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Single pass: verify (read-back check)                              */
/* ------------------------------------------------------------------ */

static int do_verify_pass(int fd, uint64_t disk_size, uint8_t *buf,
                           uint8_t *verify_buf, size_t buf_size,
                           bool is_random, const uint8_t *pattern,
                           size_t pattern_len, int pass_num,
                           int total_passes, const wipe_config_t *config,
                           wipe_result_t *result)
{
    /*
     * For random passes, we cannot verify the exact data (it was random).
     * We verify that the sectors are readable (no I/O errors).
     * For pattern passes, we verify the exact pattern.
     */

    if (lseek(fd, 0, SEEK_SET) != 0) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Verify pass %d: lseek failed: %s", pass_num,
                 strerror(errno));
        return -1;
    }

    double start = now_secs();
    double last_report = start;
    uint64_t verified = 0;

    while (verified < disk_size) {
        size_t chunk = buf_size;
        if (verified + chunk > disk_size)
            chunk = (size_t)(disk_size - verified);

        ssize_t rd = read(fd, verify_buf, chunk);
        if (rd < 0) {
            if (errno == EINTR) continue;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Verify pass %d: read error at %llu: %s",
                     pass_num, (unsigned long long)verified, strerror(errno));
            result->verification_failures++;
            return -1;
        }
        if ((size_t)rd != chunk) {
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Verify pass %d: short read at %llu",
                     pass_num, (unsigned long long)verified);
            result->verification_failures++;
            return -1;
        }

        /* For deterministic patterns, verify exact data */
        if (!is_random) {
            fill_pattern(buf, chunk, pattern, pattern_len);
            if (memcmp(buf, verify_buf, chunk) != 0) {
                snprintf(result->error_msg, sizeof(result->error_msg),
                         "Verify pass %d: data mismatch at offset %llu",
                         pass_num, (unsigned long long)verified);
                result->verification_failures++;
                return -1;
            }
        }

        verified += (uint64_t)rd;

        /* Progress */
        double now = now_secs();
        if (config->progress_cb && (now - last_report > 0.5)) {
            double elapsed = now - start;
            double speed = (elapsed > 0) ? ((double)verified / elapsed) : 0;
            double eta = (speed > 0) ?
                ((double)(disk_size - verified) / speed) : 0;

            char desc[128];
            snprintf(desc, sizeof(desc), "Verifying pass %d/%d",
                     pass_num, total_passes);

            wipe_progress_t prog = {
                .current_pass     = pass_num,
                .total_passes     = total_passes,
                .bytes_written    = verified,
                .bytes_total      = disk_size,
                .elapsed_secs     = elapsed,
                .eta_secs         = eta,
                .speed_mbps       = speed / (1024.0 * 1024.0),
                .pass_description = desc,
                .verifying        = true,
            };

            if (config->progress_cb(&prog, config->progress_ctx) != 0) {
                snprintf(result->error_msg, sizeof(result->error_msg),
                         "Verify aborted at pass %d", pass_num);
                return -1;
            }
            last_report = now;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  DoD 5220.22-M 7-pass implementation                               */
/*  Pass 1: 0x00                                                       */
/*  Pass 2: 0xFF                                                       */
/*  Pass 3: Random                                                     */
/*  Pass 4: 0x00                                                       */
/*  Pass 5: 0xFF                                                       */
/*  Pass 6: Random                                                     */
/*  Pass 7: Random (verification pass)                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    bool    is_random;
    uint8_t byte;
    const char *description;
} dod_pass_t;

static const dod_pass_t dod_passes[7] = {
    { false, 0x00, "Pass 1/7: Zero fill (0x00)" },
    { false, 0xFF, "Pass 2/7: Ones fill (0xFF)" },
    { true,  0,    "Pass 3/7: Cryptographic random" },
    { false, 0x00, "Pass 4/7: Zero fill (0x00)" },
    { false, 0xFF, "Pass 5/7: Ones fill (0xFF)" },
    { true,  0,    "Pass 6/7: Cryptographic random" },
    { true,  0,    "Pass 7/7: Final random verification pass" },
};

/* ------------------------------------------------------------------ */
/*  Main wipe execution                                                */
/* ------------------------------------------------------------------ */

int wipe_execute(const wipe_config_t *config, wipe_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->total_passes = wipe_algorithm_passes(config->algorithm);

    /* Detect drive type */
    result->detected_drive_type = wipe_detect_drive_type(config->device_path);

    /* Convert to raw device path for direct I/O */
    char raw_path[256];
    make_raw_path(config->device_path, raw_path, sizeof(raw_path));

    /* Get disk size */
    uint64_t disk_size = wipe_get_disk_size(raw_path);
    if (disk_size == 0) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Cannot determine disk size for %s", raw_path);
        return -1;
    }

    /* SSD warning */
    if (result->detected_drive_type == DRIVE_SSD ||
        result->detected_drive_type == DRIVE_NVME) {
        fprintf(stderr,
            "\n"
            "========================================================\n"
            " WARNING: SSD/NVMe DETECTED (%s)\n"
            "========================================================\n"
            " Due to wear-leveling and over-provisioning, software\n"
            " wiping CANNOT guarantee complete data erasure on SSDs.\n"
            "\n"
            " For SSDs, the RECOMMENDED approach is:\n"
            "   1. Full-disk encrypt BEFORE storing sensitive data\n"
            "   2. Use manufacturer's Secure Erase command (ATA SE)\n"
            "   3. Use NVMe Format with Crypto Erase (for NVMe)\n"
            "\n"
            " This software wipe provides a BEST-EFFORT erasure.\n"
            " Inaccessible wear-leveled blocks may retain data.\n"
            "========================================================\n\n",
            wipe_drive_type_name(result->detected_drive_type));
    }

    /* Open raw device for direct I/O */
    int fd = open(raw_path, O_WRONLY | O_SYNC);
    if (fd < 0) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Cannot open %s for writing: %s (are you root?)",
                 raw_path, strerror(errno));
        return -1;
    }

    /* Allocate I/O buffers */
    uint8_t *write_buf = malloc(BUFFER_SIZE);
    uint8_t *verify_buf = config->verify ? malloc(BUFFER_SIZE) : NULL;

    if (!write_buf || (config->verify && !verify_buf)) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Memory allocation failed");
        free(write_buf);
        free(verify_buf);
        close(fd);
        return -1;
    }

    double total_start = now_secs();
    int ret = 0;

    /* === Execute algorithm === */
    switch (config->algorithm) {

    case ALG_GUTMANN: {
        for (int p = 0; p < 35 && ret == 0; p++) {
            char desc[128];
            const gutmann_pass_t *gp = &gutmann_passes[p];

            if (gp->is_random) {
                snprintf(desc, sizeof(desc),
                         "Pass %d/35: Cryptographic random", p + 1);
            } else if (gp->pattern_len == 1) {
                snprintf(desc, sizeof(desc),
                         "Pass %d/35: Pattern 0x%02X", p + 1,
                         gp->pattern[0]);
            } else {
                snprintf(desc, sizeof(desc),
                         "Pass %d/35: Pattern 0x%02X 0x%02X 0x%02X",
                         p + 1, gp->pattern[0], gp->pattern[1],
                         gp->pattern[2]);
            }

            ret = do_write_pass(fd, disk_size, write_buf, BUFFER_SIZE,
                                 gp->is_random, gp->pattern,
                                 gp->pattern_len, p + 1, 35, desc,
                                 config, result);

            if (ret == 0) {
                result->passes_completed++;

                /* Verify if requested and pattern is deterministic */
                if (config->verify && !gp->is_random) {
                    /* Reopen as read for verification */
                    int vfd = open(raw_path, O_RDONLY);
                    if (vfd >= 0) {
                        ret = do_verify_pass(vfd, disk_size, write_buf,
                                              verify_buf, BUFFER_SIZE,
                                              gp->is_random, gp->pattern,
                                              gp->pattern_len, p + 1, 35,
                                              config, result);
                        close(vfd);
                    }
                }
            }
        }
        break;
    }

    case ALG_DOD_522022M: {
        for (int p = 0; p < 7 && ret == 0; p++) {
            const dod_pass_t *dp = &dod_passes[p];
            uint8_t pat[1] = { dp->byte };

            ret = do_write_pass(fd, disk_size, write_buf, BUFFER_SIZE,
                                 dp->is_random, pat, 1, p + 1, 7,
                                 dp->description, config, result);

            if (ret == 0) {
                result->passes_completed++;

                if (config->verify && !dp->is_random) {
                    int vfd = open(raw_path, O_RDONLY);
                    if (vfd >= 0) {
                        ret = do_verify_pass(vfd, disk_size, write_buf,
                                              verify_buf, BUFFER_SIZE,
                                              dp->is_random, pat, 1,
                                              p + 1, 7, config, result);
                        close(vfd);
                    }
                }
            }
        }
        break;
    }

    case ALG_SCHNEIER: {
        for (int p = 0; p < 3 && ret == 0; p++) {
            char desc[128];
            snprintf(desc, sizeof(desc),
                     "Pass %d/3: Cryptographic random", p + 1);

            ret = do_write_pass(fd, disk_size, write_buf, BUFFER_SIZE,
                                 true, NULL, 0, p + 1, 3, desc,
                                 config, result);
            if (ret == 0) {
                result->passes_completed++;

                /* For random passes, verify readability only */
                if (config->verify) {
                    int vfd = open(raw_path, O_RDONLY);
                    if (vfd >= 0) {
                        ret = do_verify_pass(vfd, disk_size, write_buf,
                                              verify_buf, BUFFER_SIZE,
                                              true, NULL, 0, p + 1, 3,
                                              config, result);
                        close(vfd);
                    }
                }
            }
        }
        break;
    }

    case ALG_RANDOM: {
        ret = do_write_pass(fd, disk_size, write_buf, BUFFER_SIZE,
                             true, NULL, 0, 1, 1,
                             "Pass 1/1: Cryptographic random",
                             config, result);
        if (ret == 0) result->passes_completed++;
        break;
    }

    case ALG_ZERO: {
        uint8_t zero = 0x00;
        ret = do_write_pass(fd, disk_size, write_buf, BUFFER_SIZE,
                             false, &zero, 1, 1, 1,
                             "Pass 1/1: Zero fill",
                             config, result);
        if (ret == 0) {
            result->passes_completed++;

            if (config->verify) {
                int vfd = open(raw_path, O_RDONLY);
                if (vfd >= 0) {
                    ret = do_verify_pass(vfd, disk_size, write_buf,
                                          verify_buf, BUFFER_SIZE,
                                          false, &zero, 1, 1, 1,
                                          config, result);
                    close(vfd);
                }
            }
        }
        break;
    }

    default:
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Unknown algorithm: %d", config->algorithm);
        ret = -1;
    }

    result->total_seconds = now_secs() - total_start;
    result->completed = (ret == 0);

    free(write_buf);
    free(verify_buf);
    close(fd);

    return ret;
}

/* ================================================================== */
/*  CLI MAIN                                                           */
/* ================================================================== */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: sudo %s --device <path> --algorithm <alg> [OPTIONS]\n\n"
        "Secure Drive Wiper for macOS\n\n"
        "Required:\n"
        "  --device <path>       Device to wipe (e.g., /dev/disk4 or /dev/rdisk4)\n"
        "  --algorithm <alg>     Wipe algorithm:\n"
        "                          gutmann    - Gutmann 35-pass\n"
        "                          dod        - DoD 5220.22-M 7-pass\n"
        "                          schneier   - Bruce Schneier 3-pass random\n"
        "                          random     - Single-pass cryptographic random\n"
        "                          zero       - Single-pass zero fill\n\n"
        "Options:\n"
        "  --verify              Read-back verification after each pass\n"
        "  --force               Skip interactive confirmation\n"
        "  --info                Show drive info and exit (no wipe)\n"
        "  --help                Show this help\n\n"
        "Examples:\n"
        "  sudo %s --device /dev/disk4 --algorithm gutmann --verify\n"
        "  sudo %s --device /dev/rdisk4 --algorithm schneier --force\n\n"
        "WARNING: This tool PERMANENTLY DESTROYS ALL DATA on the target device.\n"
        "         There is NO undo. Use with extreme caution.\n\n"
        "NOTE: For SSDs, software wiping cannot guarantee complete erasure due to\n"
        "      wear-leveling. Use full-disk encryption + ATA Secure Erase instead.\n",
        prog, prog, prog);
}

/*
 * CLI progress callback — prints to stderr
 */
static int cli_progress(const wipe_progress_t *p, void *ctx)
{
    (void)ctx;
    double pct = (p->bytes_total > 0) ?
        (100.0 * (double)p->bytes_written / (double)p->bytes_total) : 0;

    int eta_min = (int)(p->eta_secs / 60.0);
    int eta_sec = (int)(p->eta_secs) % 60;

    fprintf(stderr, "\r  %s%s  %5.1f%%  %6.1f MB/s  ETA %02d:%02d    ",
            p->verifying ? "[VERIFY] " : "",
            p->pass_description,
            pct, p->speed_mbps, eta_min, eta_sec);
    fflush(stderr);

    return 0; /* Continue */
}

static wipe_algorithm_t parse_algorithm(const char *name)
{
    if (strcasecmp(name, "gutmann") == 0)   return ALG_GUTMANN;
    if (strcasecmp(name, "dod") == 0)       return ALG_DOD_522022M;
    if (strcasecmp(name, "schneier") == 0)  return ALG_SCHNEIER;
    if (strcasecmp(name, "random") == 0)    return ALG_RANDOM;
    if (strcasecmp(name, "zero") == 0)      return ALG_ZERO;
    return ALG_COUNT; /* Invalid */
}

int main(int argc, char *argv[])
{
    const char *device = NULL;
    wipe_algorithm_t algorithm = ALG_COUNT;
    bool verify = false;
    bool force = false;
    bool info_only = false;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) {
            device = argv[++i];
        } else if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            algorithm = parse_algorithm(argv[++i]);
        } else if (strcmp(argv[i], "--verify") == 0) {
            verify = true;
        } else if (strcmp(argv[i], "--force") == 0) {
            force = true;
        } else if (strcmp(argv[i], "--info") == 0) {
            info_only = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!device) {
        fprintf(stderr, "Error: --device is required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Check root */
    if (geteuid() != 0) {
        fprintf(stderr, "Error: This tool requires root privileges.\n"
                        "Run with: sudo %s ...\n", argv[0]);
        return 1;
    }

    /* Get drive info */
    drive_type_t dtype = wipe_detect_drive_type(device);
    uint64_t disk_size = wipe_get_disk_size(device);

    printf("\n");
    printf("  Device:    %s\n", device);
    printf("  Type:      %s\n", wipe_drive_type_name(dtype));
    printf("  Size:      %.2f GB (%llu bytes)\n",
           (double)disk_size / (1024.0 * 1024.0 * 1024.0),
           (unsigned long long)disk_size);

    if (info_only) {
        printf("\n");
        return 0;
    }

    if (algorithm >= ALG_COUNT) {
        fprintf(stderr, "Error: --algorithm is required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("  Algorithm: %s (%d passes)\n",
           wipe_algorithm_name(algorithm),
           wipe_algorithm_passes(algorithm));
    printf("  Verify:    %s\n", verify ? "Yes" : "No");
    printf("\n");

    if (disk_size == 0) {
        fprintf(stderr, "Error: Cannot determine disk size. "
                        "Is the device path correct?\n");
        return 1;
    }

    /* Safety confirmation */
    if (!force) {
        printf("  *** WARNING: ALL DATA ON %s WILL BE PERMANENTLY DESTROYED ***\n",
               device);
        printf("  *** THIS CANNOT BE UNDONE ***\n\n");
        printf("  Type 'YES' (uppercase) to confirm: ");
        fflush(stdout);

        char confirm[16] = {0};
        if (!fgets(confirm, sizeof(confirm), stdin)) {
            fprintf(stderr, "Aborted.\n");
            return 1;
        }
        /* Strip newline */
        confirm[strcspn(confirm, "\n")] = '\0';

        if (strcmp(confirm, "YES") != 0) {
            fprintf(stderr, "Aborted. You typed '%s', expected 'YES'.\n",
                    confirm);
            return 1;
        }
    }

    /* Unmount all volumes on the disk */
    printf("\n  Unmounting all volumes on %s...\n", device);
    char umount_cmd[512];
    snprintf(umount_cmd, sizeof(umount_cmd),
             "diskutil unmountDisk %s 2>/dev/null", device);
    system(umount_cmd);

    /* Execute wipe */
    printf("  Starting wipe...\n\n");

    wipe_config_t wipe_cfg = {
        .device_path  = device,
        .algorithm    = algorithm,
        .verify       = verify,
        .force        = force,
        .progress_cb  = cli_progress,
        .progress_ctx = NULL,
    };

    wipe_result_t wipe_result;
    int ret = wipe_execute(&wipe_cfg, &wipe_result);

    printf("\n\n");
    printf("  ============= WIPE REPORT =============\n");
    printf("  Device:               %s\n", device);
    printf("  Drive Type:           %s\n",
           wipe_drive_type_name(wipe_result.detected_drive_type));
    printf("  Algorithm:            %s\n", wipe_algorithm_name(algorithm));
    printf("  Passes Completed:     %d / %d\n",
           wipe_result.passes_completed, wipe_result.total_passes);
    printf("  Total Data Written:   %.2f GB\n",
           (double)wipe_result.total_bytes_written /
           (1024.0 * 1024.0 * 1024.0));
    printf("  Time Elapsed:         %.1f seconds\n",
           wipe_result.total_seconds);
    printf("  Verification Errors:  %d\n",
           wipe_result.verification_failures);
    printf("  Status:               %s\n",
           wipe_result.completed ? "COMPLETED" : "FAILED");

    if (!wipe_result.completed && wipe_result.error_msg[0]) {
        printf("  Error:                %s\n", wipe_result.error_msg);
    }

    printf("  =========================================\n\n");

    return ret;
}
