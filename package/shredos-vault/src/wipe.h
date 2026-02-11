/*
 * wipe.h — Unified Secure Wipe Engine Interface
 *
 * Cross-platform wipe engine supporting Gutmann (35-pass), DoD 5220.22-M
 * (7-pass), Bruce Schneier (3-pass), single-pass random, zero fill, and
 * verify-only mode.
 *
 * On Linux: tries nwipe first, falls back to direct I/O.
 * On macOS: direct I/O via /dev/rdiskN with F_FULLFSYNC.
 * On Windows: direct I/O via CreateFile with FILE_FLAG_NO_BUFFERING.
 *
 * Copyright 2025 — GPL-2.0+
 */

#ifndef VAULT_WIPE_H
#define VAULT_WIPE_H

#include "config.h"
#include <stdint.h>

/* Progress callback for direct wipe */
typedef struct {
    int      current_pass;
    int      total_passes;
    uint64_t bytes_written;
    uint64_t bytes_total;
    double   speed_mbps;
    double   eta_secs;
    const char *pass_description;
    int      verifying;         /* 1 if verification pass, 0 if write pass */
} vault_wipe_progress_t;

typedef void (*vault_wipe_progress_cb)(const vault_wipe_progress_t *prog);

/*
 * Wipe a device using the best available method.
 *
 * On Linux: tries nwipe first, falls back to direct I/O.
 * On macOS/Windows: uses direct I/O only.
 *
 * Blocks until the wipe completes.
 * Returns 0 on success, -1 on failure.
 */
int vault_wipe_device(const char *device, wipe_algorithm_t algorithm,
                       int verify);

/*
 * Wipe a device using direct I/O (no nwipe dependency).
 * Implements Gutmann, DoD, Schneier directly with cryptographic randomness.
 * Includes per-pass verification and progress tracking.
 * Returns 0 on success, -1 on failure.
 */
int vault_wipe_device_direct(const char *device, wipe_algorithm_t algorithm,
                              int verify, vault_wipe_progress_cb progress_cb);

/*
 * Check if nwipe is available on the system.
 * Always returns 0 on macOS and Windows.
 * Returns 1 if available, 0 if not.
 */
int vault_wipe_nwipe_available(void);

/*
 * Detect if a device is SSD or HDD.
 *   Linux: /sys/block/X/queue/rotational
 *   macOS: IOKit registry tree
 *   Windows: not implemented (returns -1)
 * Returns 1 for SSD, 0 for HDD, -1 on error/unknown.
 */
int vault_wipe_is_ssd(const char *device);

/*
 * Get the size of a block device in bytes.
 * Returns 0 on failure.
 */
uint64_t vault_wipe_get_device_size(const char *device);

#endif /* VAULT_WIPE_H */
