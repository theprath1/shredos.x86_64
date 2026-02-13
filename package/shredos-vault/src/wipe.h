/*
 * wipe.h -- Unified Cross-Platform Secure Wipe Engine
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_WIPE_H
#define VAULT_WIPE_H

#include "config.h"
#include <stdint.h>

/* Progress callback data */
typedef struct {
    int      current_pass;
    int      total_passes;
    uint64_t bytes_written;
    uint64_t bytes_total;
    double   speed_mbps;
    double   eta_secs;
    const char *pass_description;
    int      verifying;
} vault_wipe_progress_t;

typedef void (*vault_wipe_progress_cb)(const vault_wipe_progress_t *prog);

/* Wipe using the best available method.
 * Linux: tries nwipe first, falls back to direct I/O.
 * macOS/Windows: direct I/O only.
 * Returns 0 on success, -1 on failure. */
int vault_wipe_device(const char *device, wipe_algorithm_t algorithm,
                       int verify);

/* Wipe using direct I/O (no nwipe dependency).
 * Returns 0 on success, -1 on failure. */
int vault_wipe_device_direct(const char *device, wipe_algorithm_t algorithm,
                              int verify, vault_wipe_progress_cb progress_cb);

/* Check if nwipe is available. */
int vault_wipe_nwipe_available(void);

/* Detect SSD (1) vs HDD (0). Returns -1 on unknown. */
int vault_wipe_is_ssd(const char *device);

/* Get device size in bytes. Returns 0 on failure. */
uint64_t vault_wipe_get_device_size(const char *device);

#endif /* VAULT_WIPE_H */
