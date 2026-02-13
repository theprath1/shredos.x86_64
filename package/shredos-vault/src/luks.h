/*
 * luks.h -- LUKS Encryption Wrapper
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_LUKS_H
#define VAULT_LUKS_H

#include "platform.h"

#define VAULT_DM_NAME "vault_crypt"

/* Check if LUKS support is compiled in. */
int vault_luks_available(void);

/* Format a device as LUKS2 with AES-XTS-plain64.
 * Returns 0 on success, -1 on failure. */
int vault_luks_format(const char *device, const char *passphrase);

/* Format a device with a random key (for encrypt-before-wipe).
 * The key is discarded -- data is irrecoverably encrypted.
 * Returns 0 on success, -1 on failure. */
int vault_luks_format_random_key(const char *device);

/* Open (unlock) a LUKS device.
 * Returns 0 on success, -1 on failure. */
int vault_luks_open(const char *device, const char *passphrase,
                     const char *dm_name);

/* Close a LUKS device.
 * Returns 0 on success, -1 on failure. */
int vault_luks_close(const char *dm_name);

/* Mount a device-mapper device at mount_point.
 * Returns 0 on success, -1 on failure. */
int vault_luks_mount(const char *dm_name, const char *mount_point);

/* Unmount a mount point.
 * Returns 0 on success, -1 on failure. */
int vault_luks_unmount(const char *mount_point);

#endif /* VAULT_LUKS_H */
