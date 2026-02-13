/*
 * installer.h -- ShredOS Vault USB Install Wizard
 *
 * Scans host drives, detects installed OS, copies vault binary
 * and config onto the host, hooks into the host boot process.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_INSTALLER_H
#define VAULT_INSTALLER_H

#include "config.h"
#include <stdint.h>

/* Detected OS on a host partition */
typedef enum {
    DETECTED_OS_UNKNOWN = 0,
    DETECTED_OS_LINUX,
    DETECTED_OS_MACOS,
    DETECTED_OS_WINDOWS,
} detected_os_t;

/* Information about a detected drive */
typedef struct {
    char device_path[256];       /* e.g. /dev/sda */
    char label[128];             /* human-readable label */
    uint64_t size_bytes;
    int is_ssd;                  /* 1=SSD, 0=HDD, -1=unknown */
    int is_boot_usb;             /* 1 if this is the ShredOS USB */

    detected_os_t detected_os;
    char os_name[128];           /* e.g. "Ubuntu 22.04 LTS" */
    char root_partition[256];    /* e.g. /dev/sda2 */

    /* Linux-specific */
    int has_initramfs_tools;
    int has_dracut;
} drive_info_t;

/* Scan all drives, populate array. Returns count. */
int vault_installer_scan_drives(drive_info_t *drives, int max_drives);

/* Detect what OS is on a given partition.
 * Mounts the partition temporarily and probes for OS markers.
 * Returns the detected OS type. */
detected_os_t vault_installer_detect_os(const char *partition,
                                         drive_info_t *info);

/* Run the full install wizard TUI. Returns 0 on success. */
int vault_installer_run_wizard(void);

/* Platform-specific installation routines */
int vault_installer_install_linux(const drive_info_t *drive,
                                   const vault_config_t *cfg);
int vault_installer_install_macos(const drive_info_t *drive,
                                   const vault_config_t *cfg);
int vault_installer_install_windows(const drive_info_t *drive,
                                     const vault_config_t *cfg);

#endif /* VAULT_INSTALLER_H */
