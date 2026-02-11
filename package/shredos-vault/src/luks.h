/*
 * luks.h — LUKS Volume Management Interface
 *
 * Provides LUKS open/close/mount/unmount/format operations.
 * Requires libcryptsetup (Linux only). On platforms without
 * HAVE_LIBCRYPTSETUP, all functions return -1.
 *
 * Copyright 2025 — GPL-2.0+
 */

#ifndef VAULT_LUKS_H
#define VAULT_LUKS_H

#include "config.h"

/*
 * Open (unlock) a LUKS device.
 * Maps device to /dev/mapper/<dm_name>.
 * Returns 0 on success, -1 on failure or unavailable.
 */
int vault_luks_open(const char *device, const char *passphrase,
                     const char *dm_name);

/*
 * Close (lock) a LUKS device.
 * Returns 0 on success, -1 on failure or unavailable.
 */
int vault_luks_close(const char *dm_name);

/*
 * Mount the unlocked LUKS volume.
 * Returns 0 on success, -1 on failure or unavailable.
 */
int vault_luks_mount(const char *dm_name, const char *mount_point);

/*
 * Unmount the LUKS volume.
 * Returns 0 on success, -1 on failure or unavailable.
 */
int vault_luks_unmount(const char *mount_point);

/*
 * Format a device as LUKS with the given passphrase.
 * WARNING: Destroys all data on the device.
 * Returns 0 on success, -1 on failure or unavailable.
 */
int vault_luks_format(const char *device, const char *passphrase);

/*
 * Format a device as LUKS with a random key (for dead man's switch).
 * The key is generated from vault_platform_random() and never stored.
 * This effectively makes the existing data permanently unrecoverable.
 * Returns 0 on success, -1 on failure or unavailable.
 */
int vault_luks_format_random_key(const char *device);

/*
 * Check if a device is a LUKS device.
 * Returns 1 if LUKS, 0 if not, -1 on error or unavailable.
 */
int vault_luks_is_luks(const char *device);

/*
 * Check if LUKS support is available at compile time.
 * Returns 1 if available, 0 if not.
 */
int vault_luks_available(void);

#endif /* VAULT_LUKS_H */
