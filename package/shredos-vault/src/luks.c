/*
 * luks.c -- LUKS Encryption Wrapper
 *
 * Uses libcryptsetup when available, otherwise stubs.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#include "luks.h"
#include "platform.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  libcryptsetup backend                                              */
/* ------------------------------------------------------------------ */

#ifdef HAVE_LIBCRYPTSETUP

#include <libcryptsetup.h>

#ifndef VAULT_PLATFORM_WINDOWS
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

int vault_luks_available(void) { return 1; }

int vault_luks_format(const char *device, const char *passphrase)
{
    struct crypt_device *cd = NULL;
    int ret;

    ret = crypt_init(&cd, device);
    if (ret < 0) return -1;

    struct crypt_params_luks2 params = {
        .sector_size = 512
    };

    ret = crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64",
                       NULL, NULL, 64, &params);
    if (ret < 0) { crypt_free(cd); return -1; }

    ret = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL, 0,
                                           passphrase, strlen(passphrase));
    crypt_free(cd);
    return (ret >= 0) ? 0 : -1;
}

int vault_luks_format_random_key(const char *device)
{
    /* Generate a random 64-byte key -- immediately discarded */
    uint8_t key[64];
    if (vault_platform_random(key, sizeof(key)) != 0) return -1;

    char passphrase[129];
    for (int i = 0; i < 64; i++)
        snprintf(passphrase + i * 2, 3, "%02x", key[i]);

    vault_secure_memzero(key, sizeof(key));

    struct crypt_device *cd = NULL;
    int ret = crypt_init(&cd, device);
    if (ret < 0) { vault_secure_memzero(passphrase, sizeof(passphrase)); return -1; }

    struct crypt_params_luks2 params = { .sector_size = 512 };
    ret = crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64",
                       NULL, NULL, 64, &params);
    if (ret < 0) {
        crypt_free(cd);
        vault_secure_memzero(passphrase, sizeof(passphrase));
        return -1;
    }

    ret = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL, 0,
                                           passphrase, strlen(passphrase));
    crypt_free(cd);
    vault_secure_memzero(passphrase, sizeof(passphrase));
    return (ret >= 0) ? 0 : -1;
}

int vault_luks_open(const char *device, const char *passphrase,
                     const char *dm_name)
{
    struct crypt_device *cd = NULL;
    int ret = crypt_init(&cd, device);
    if (ret < 0) return -1;

    ret = crypt_load(cd, CRYPT_LUKS, NULL);
    if (ret < 0) { crypt_free(cd); return -1; }

    ret = crypt_activate_by_passphrase(cd, dm_name, CRYPT_ANY_SLOT,
                                        passphrase, strlen(passphrase), 0);
    crypt_free(cd);
    return (ret >= 0) ? 0 : -1;
}

int vault_luks_close(const char *dm_name)
{
    struct crypt_device *cd = NULL;
    int ret = crypt_init_by_name(&cd, dm_name);
    if (ret < 0) return -1;
    ret = crypt_deactivate(cd, dm_name);
    crypt_free(cd);
    return (ret == 0) ? 0 : -1;
}

int vault_luks_mount(const char *dm_name, const char *mount_point)
{
#ifndef VAULT_PLATFORM_WINDOWS
    char dev_path[256];
    snprintf(dev_path, sizeof(dev_path), "/dev/mapper/%s", dm_name);
    mkdir(mount_point, 0700);
    return mount(dev_path, mount_point, "ext4", 0, NULL);
#else
    (void)dm_name; (void)mount_point;
    return -1;
#endif
}

int vault_luks_unmount(const char *mount_point)
{
#ifndef VAULT_PLATFORM_WINDOWS
    return umount(mount_point);
#else
    (void)mount_point;
    return -1;
#endif
}

#else /* No libcryptsetup */

int vault_luks_available(void) { return 0; }

int vault_luks_format(const char *device, const char *passphrase)
{
    (void)device; (void)passphrase; return -1;
}

int vault_luks_format_random_key(const char *device)
{
    (void)device; return -1;
}

int vault_luks_open(const char *device, const char *passphrase,
                     const char *dm_name)
{
    (void)device; (void)passphrase; (void)dm_name; return -1;
}

int vault_luks_close(const char *dm_name)
{
    (void)dm_name; return -1;
}

int vault_luks_mount(const char *dm_name, const char *mount_point)
{
    (void)dm_name; (void)mount_point; return -1;
}

int vault_luks_unmount(const char *mount_point)
{
    (void)mount_point; return -1;
}

#endif /* HAVE_LIBCRYPTSETUP */
