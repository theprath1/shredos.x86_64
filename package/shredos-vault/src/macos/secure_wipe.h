/*
 * secure_wipe.h — macOS Secure Drive Wiper
 *
 * Direct low-level disk access via raw device files (/dev/rdiskN).
 * Cryptographically secure random data via SecRandomCopyBytes.
 * Supports HDD and SSD with appropriate strategy per drive type.
 *
 * REQUIRES: root/sudo privileges for raw disk access.
 * BUILD:    cc -O2 -Wall -framework Security -framework IOKit \
 *               -framework CoreFoundation secure_wipe.c -o secure_wipe
 */

#ifndef SECURE_WIPE_H
#define SECURE_WIPE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/*  Wipe algorithms                                                    */
/* ------------------------------------------------------------------ */

typedef enum {
    ALG_GUTMANN = 0,       /* Gutmann 35-pass (designed for older magnetic media) */
    ALG_DOD_522022M,       /* DoD 5220.22-M 7-pass */
    ALG_SCHNEIER,          /* Bruce Schneier 3-pass (random, random, random) */
    ALG_RANDOM,            /* Single pass cryptographic random */
    ALG_ZERO,              /* Single pass zeros */
    ALG_COUNT
} wipe_algorithm_t;

/* ------------------------------------------------------------------ */
/*  Drive type                                                         */
/* ------------------------------------------------------------------ */

typedef enum {
    DRIVE_HDD = 0,
    DRIVE_SSD,
    DRIVE_NVME,
    DRIVE_UNKNOWN
} drive_type_t;

/* ------------------------------------------------------------------ */
/*  Progress callback                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    int            current_pass;    /* 1-based */
    int            total_passes;
    uint64_t       bytes_written;   /* in this pass */
    uint64_t       bytes_total;     /* total bytes per pass (= disk size) */
    double         elapsed_secs;    /* elapsed this pass */
    double         eta_secs;        /* estimated remaining this pass */
    double         speed_mbps;      /* MB/s this pass */
    const char    *pass_description;/* e.g. "Pass 3/35: pattern 0x92 0x49 0x24" */
    bool           verifying;       /* true if this is a verification read */
} wipe_progress_t;

/* Return 0 to continue, non-zero to abort */
typedef int (*wipe_progress_cb)(const wipe_progress_t *progress, void *ctx);

/* ------------------------------------------------------------------ */
/*  Configuration                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    const char        *device_path;   /* e.g. "/dev/rdisk4" or "/dev/disk4" */
    wipe_algorithm_t   algorithm;
    bool               verify;        /* read-back verification after each pass */
    bool               force;         /* skip interactive confirmation */
    wipe_progress_cb   progress_cb;   /* may be NULL */
    void              *progress_ctx;
} wipe_config_t;

/* ------------------------------------------------------------------ */
/*  Results                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int          passes_completed;
    int          passes_total;
    int          verification_failures;
    uint64_t     total_bytes_written;
    double       total_seconds;
    drive_type_t detected_drive_type;
    bool         completed;           /* false if aborted or error */
    char         error_msg[512];
} wipe_result_t;

/* ------------------------------------------------------------------ */
/*  API                                                                */
/* ------------------------------------------------------------------ */

/* Detect drive type (HDD / SSD / NVMe) via IOKit.
 * device_path: "/dev/disk4" or "/dev/rdisk4" */
drive_type_t wipe_detect_drive_type(const char *device_path);

/* Get human-readable name for drive type */
const char *wipe_drive_type_name(drive_type_t type);

/* Get human-readable name for algorithm */
const char *wipe_algorithm_name(wipe_algorithm_t alg);

/* Get number of passes for algorithm */
int wipe_algorithm_passes(wipe_algorithm_t alg);

/* Get disk size in bytes. Returns 0 on error. */
uint64_t wipe_get_disk_size(const char *device_path);

/* Execute the wipe. Blocks until complete.
 * Returns 0 on success, -1 on error (see result->error_msg). */
int wipe_execute(const wipe_config_t *config, wipe_result_t *result);

#endif /* SECURE_WIPE_H */
