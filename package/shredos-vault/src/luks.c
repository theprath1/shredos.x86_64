/*
 * luks.c — LUKS Volume Management (Linux libcryptsetup)
 *
 * Full LUKS2/LUKS1 support when HAVE_LIBCRYPTSETUP is defined.
 * Stubs returning -1 when libcryptsetup is not available
 * (macOS, Windows, or Linux without the library).
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "luks.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================== */
/*  Full implementation (Linux with libcryptsetup)                      */
/* ================================================================== */

#ifdef HAVE_LIBCRYPTSETUP

#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <libcryptsetup.h>

#define LUKS_CIPHER      "aes"
#define LUKS_CIPHER_MODE "xts-plain64"
#define LUKS_HASH        "sha256"
#define LUKS_KEY_SIZE    512   /* bits */
#define RANDOM_KEY_BYTES 64    /* 512 bits */

int vault_luks_available(void) { return 1; }

int vault_luks_open(const char *device, const char *passphrase,
                     const char *dm_name)
{
    struct crypt_device *cd = NULL;
    int ret;

    ret = crypt_init(&cd, device);
    if (ret < 0) {
        fprintf(stderr, "vault: crypt_init failed: %s\n", strerror(-ret));
        return -1;
    }

    ret = crypt_load(cd, CRYPT_LUKS2, NULL);
    if (ret < 0) {
        /* Try LUKS1 */
        ret = crypt_load(cd, CRYPT_LUKS1, NULL);
        if (ret < 0) {
            fprintf(stderr, "vault: not a LUKS device: %s\n", strerror(-ret));
            crypt_free(cd);
            return -1;
        }
    }

    ret = crypt_activate_by_passphrase(cd, dm_name, CRYPT_ANY_SLOT,
                                        passphrase, strlen(passphrase), 0);
    if (ret < 0) {
        fprintf(stderr, "vault: unlock failed: %s\n", strerror(-ret));
        crypt_free(cd);
        return -1;
    }

    crypt_free(cd);
    return 0;
}

int vault_luks_close(const char *dm_name)
{
    struct crypt_device *cd = NULL;
    int ret;

    ret = crypt_init_by_name(&cd, dm_name);
    if (ret < 0) {
        fprintf(stderr, "vault: crypt_init_by_name failed: %s\n",
                strerror(-ret));
        return -1;
    }

    ret = crypt_deactivate(cd, dm_name);
    crypt_free(cd);

    if (ret < 0) {
        fprintf(stderr, "vault: deactivate failed: %s\n", strerror(-ret));
        return -1;
    }

    return 0;
}

int vault_luks_mount(const char *dm_name, const char *mount_point)
{
    char dev_path[512];
    snprintf(dev_path, sizeof(dev_path), "/dev/mapper/%s", dm_name);

    /* Create mount point if it doesn't exist */
    mkdir(mount_point, 0700);

    /* Try ext4 first, then ext3, ext2, xfs */
    const char *fstypes[] = {"ext4", "ext3", "ext2", "xfs", "btrfs", NULL};

    for (int i = 0; fstypes[i]; i++) {
        if (mount(dev_path, mount_point, fstypes[i], 0, NULL) == 0)
            return 0;
    }

    fprintf(stderr, "vault: failed to mount %s on %s: %s\n",
            dev_path, mount_point, strerror(errno));
    return -1;
}

int vault_luks_unmount(const char *mount_point)
{
    if (umount(mount_point) != 0) {
        fprintf(stderr, "vault: umount %s failed: %s\n",
                mount_point, strerror(errno));
        /* Try lazy unmount */
        if (umount2(mount_point, MNT_DETACH) != 0)
            return -1;
    }
    return 0;
}

int vault_luks_format(const char *device, const char *passphrase)
{
    struct crypt_device *cd = NULL;
    struct crypt_params_luks2 params = {
        .sector_size = 512,
    };
    int ret;

    ret = crypt_init(&cd, device);
    if (ret < 0) {
        fprintf(stderr, "vault: crypt_init failed: %s\n", strerror(-ret));
        return -1;
    }

    ret = crypt_format(cd, CRYPT_LUKS2, LUKS_CIPHER, LUKS_CIPHER_MODE,
                        NULL, NULL, LUKS_KEY_SIZE / 8, &params);
    if (ret < 0) {
        fprintf(stderr, "vault: format failed: %s\n", strerror(-ret));
        crypt_free(cd);
        return -1;
    }

    ret = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, NULL,
                                           0, passphrase,
                                           strlen(passphrase));
    if (ret < 0) {
        fprintf(stderr, "vault: add keyslot failed: %s\n", strerror(-ret));
        crypt_free(cd);
        return -1;
    }

    crypt_free(cd);
    return 0;
}

int vault_luks_format_random_key(const char *device)
{
    struct crypt_device *cd = NULL;
    unsigned char random_key[RANDOM_KEY_BYTES];
    char random_passphrase[128];
    int ret;

    /* Generate random key material */
    if (vault_platform_random(random_key, sizeof(random_key)) != 0) {
        fprintf(stderr, "vault: cannot generate random key\n");
        return -1;
    }
    if (vault_platform_random((uint8_t *)random_passphrase,
                               sizeof(random_passphrase) - 1) != 0) {
        vault_secure_memzero(random_key, sizeof(random_key));
        return -1;
    }
    random_passphrase[sizeof(random_passphrase) - 1] = '\0';

    ret = crypt_init(&cd, device);
    if (ret < 0) {
        fprintf(stderr, "vault: crypt_init failed: %s\n", strerror(-ret));
        goto cleanup;
    }

    struct crypt_params_luks2 params = { .sector_size = 512 };

    /* Format with random volume key — destroys existing LUKS header */
    ret = crypt_format(cd, CRYPT_LUKS2, LUKS_CIPHER, LUKS_CIPHER_MODE,
                        NULL, (const char *)random_key,
                        LUKS_KEY_SIZE / 8, &params);
    if (ret < 0) {
        fprintf(stderr, "vault: random format failed: %s\n", strerror(-ret));
        crypt_free(cd);
        goto cleanup;
    }

    /* Add a keyslot with random passphrase (we'll never use it) */
    ret = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT,
                                           (const char *)random_key,
                                           LUKS_KEY_SIZE / 8,
                                           random_passphrase,
                                           strlen(random_passphrase));
    crypt_free(cd);

cleanup:
    vault_secure_memzero(random_key, sizeof(random_key));
    vault_secure_memzero(random_passphrase, sizeof(random_passphrase));

    return ret < 0 ? -1 : 0;
}

int vault_luks_is_luks(const char *device)
{
    struct crypt_device *cd = NULL;
    int ret;

    ret = crypt_init(&cd, device);
    if (ret < 0)
        return -1;

    ret = crypt_load(cd, CRYPT_LUKS2, NULL);
    if (ret < 0)
        ret = crypt_load(cd, CRYPT_LUKS1, NULL);

    crypt_free(cd);
    return ret >= 0 ? 1 : 0;
}

/* ================================================================== */
/*  Stub implementation (no libcryptsetup)                             */
/* ================================================================== */

#else /* !HAVE_LIBCRYPTSETUP */

int vault_luks_available(void) { return 0; }

int vault_luks_open(const char *device, const char *passphrase,
                     const char *dm_name)
{
    (void)device; (void)passphrase; (void)dm_name;
    fprintf(stderr, "vault: LUKS support not available (no libcryptsetup)\n");
    return -1;
}

int vault_luks_close(const char *dm_name)
{
    (void)dm_name;
    return -1;
}

int vault_luks_mount(const char *dm_name, const char *mount_point)
{
    (void)dm_name; (void)mount_point;
    return -1;
}

int vault_luks_unmount(const char *mount_point)
{
    (void)mount_point;
    return 0; /* No-op success — nothing was mounted */
}

int vault_luks_format(const char *device, const char *passphrase)
{
    (void)device; (void)passphrase;
    fprintf(stderr, "vault: LUKS format not available (no libcryptsetup)\n");
    return -1;
}

int vault_luks_format_random_key(const char *device)
{
    (void)device;
    fprintf(stderr, "vault: LUKS format not available (no libcryptsetup)\n");
    return -1;
}

int vault_luks_is_luks(const char *device)
{
    (void)device;
    return -1;
}

#endif /* HAVE_LIBCRYPTSETUP */
