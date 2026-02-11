/*
 * auth_password.c — Password Authentication (Cross-Platform)
 *
 * SHA-512 password hashing and verification.
 *   POSIX (Linux/macOS): uses crypt() with $6$ format
 *   Windows: uses CryptoAPI SHA-512 with $vg$ format
 *
 * Supports both hash formats — auto-detects on verify.
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "auth_password.h"
#include "platform.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Windows: SHA-512 via CryptoAPI ($vg$ format)                       */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_WINDOWS)

#include <windows.h>
#include <wincrypt.h>

static int win_sha512(const uint8_t *data, size_t len, uint8_t out[64])
{
    HCRYPTPROV prov;
    HCRYPTHASH hash;

    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT))
        return -1;

    if (!CryptCreateHash(prov, CALG_SHA_512, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        return -1;
    }

    CryptHashData(hash, data, (DWORD)len, 0);

    DWORD hash_len = 64;
    CryptGetHashParam(hash, HP_HASHVAL, out, &hash_len, 0);

    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return 0;
}

static void to_hex(const uint8_t *data, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", data[i]);
}

static int from_hex(const char *hex, uint8_t *out, size_t max_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int val;
        if (sscanf(hex + i * 2, "%2x", &val) != 1) return -1;
        out[i] = (uint8_t)val;
    }
    return (int)(hex_len / 2);
}

int vault_auth_password_hash(const char *password, char *hash_out,
                              size_t hash_out_size)
{
    uint8_t salt[16];
    if (vault_platform_random(salt, sizeof(salt)) != 0) return -1;

    /* Hash = SHA512(salt || password), iterated 10000 times */
    size_t pw_len = strlen(password);
    size_t buf_len = sizeof(salt) + pw_len;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    if (!buf) return -1;

    memcpy(buf, salt, sizeof(salt));
    memcpy(buf + sizeof(salt), password, pw_len);

    uint8_t hash[64];
    if (win_sha512(buf, buf_len, hash) != 0) {
        free(buf);
        return -1;
    }
    free(buf);

    for (int i = 1; i < 10000; i++) {
        if (win_sha512(hash, 64, hash) != 0) return -1;
    }

    /* Format: $vg$<hex-salt>$<hex-hash> */
    char salt_hex[33], hash_hex[129];
    to_hex(salt, sizeof(salt), salt_hex);
    to_hex(hash, sizeof(hash), hash_hex);

    snprintf(hash_out, hash_out_size, "$vg$%s$%s", salt_hex, hash_hex);
    vault_secure_memzero(hash, sizeof(hash));
    return 0;
}

static auth_result_t verify_vg_format(const char *input,
                                       const char *stored_hash)
{
    /* Parse $vg$<salt-hex>$<hash-hex> */
    const char *salt_start = stored_hash + 4;
    const char *sep = strchr(salt_start, '$');
    if (!sep) return AUTH_ERROR;

    size_t salt_hex_len = (size_t)(sep - salt_start);
    char salt_hex[33] = {0};
    if (salt_hex_len >= sizeof(salt_hex)) return AUTH_ERROR;
    memcpy(salt_hex, salt_start, salt_hex_len);

    uint8_t salt[16];
    int salt_len = from_hex(salt_hex, salt, sizeof(salt));
    if (salt_len < 0) return AUTH_ERROR;

    size_t pw_len = strlen(input);
    size_t buf_len = (size_t)salt_len + pw_len;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    if (!buf) return AUTH_ERROR;

    memcpy(buf, salt, (size_t)salt_len);
    memcpy(buf + salt_len, input, pw_len);

    uint8_t hash[64];
    if (win_sha512(buf, buf_len, hash) != 0) {
        free(buf);
        return AUTH_ERROR;
    }
    free(buf);

    for (int i = 1; i < 10000; i++) {
        if (win_sha512(hash, 64, hash) != 0) return AUTH_ERROR;
    }

    char computed_hex[129];
    to_hex(hash, 64, computed_hex);
    vault_secure_memzero(hash, sizeof(hash));

    /* Constant-time comparison */
    const char *expected_hex = sep + 1;
    size_t expected_len = strlen(expected_hex);
    size_t computed_len = strlen(computed_hex);
    if (expected_len != computed_len) return AUTH_FAILURE;

    volatile unsigned char diff = 0;
    for (size_t i = 0; i < expected_len; i++)
        diff |= (unsigned char)(expected_hex[i] ^ computed_hex[i]);

    return diff == 0 ? AUTH_SUCCESS : AUTH_FAILURE;
}

auth_result_t vault_auth_password_verify(const vault_config_t *cfg,
                                          const char *input)
{
    if (!cfg->password_hash[0]) {
        fprintf(stderr, "vault: no password hash configured\n");
        return AUTH_ERROR;
    }

    /* Only $vg$ format on Windows */
    if (strncmp(cfg->password_hash, "$vg$", 4) == 0)
        return verify_vg_format(input, cfg->password_hash);

    return AUTH_ERROR;
}

#else /* POSIX (Linux + macOS) */

/* ------------------------------------------------------------------ */
/*  POSIX: crypt() with $6$ (SHA-512) format                           */
/* ------------------------------------------------------------------ */

#include <unistd.h>
#include <time.h>

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

int vault_auth_password_hash(const char *password, char *hash_out,
                              size_t hash_out_size)
{
    static const char salt_chars[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    char salt[24];

    strcpy(salt, "$6$");

    /* Generate random salt */
    uint8_t randbuf[16];
    if (vault_platform_random(randbuf, sizeof(randbuf)) != 0) {
        /* Fallback to time-based seed (less secure) */
        srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
        for (int i = 3; i < 19; i++)
            salt[i] = salt_chars[rand() % (sizeof(salt_chars) - 1)];
    } else {
        for (int i = 0; i < 16; i++)
            salt[i + 3] = salt_chars[randbuf[i] % (sizeof(salt_chars) - 1)];
    }
    salt[19] = '$';
    salt[20] = '\0';

    vault_secure_memzero(randbuf, sizeof(randbuf));

    char *result = crypt(password, salt);
    if (!result)
        return -1;

    strncpy(hash_out, result, hash_out_size - 1);
    hash_out[hash_out_size - 1] = '\0';
    return 0;
}

auth_result_t vault_auth_password_verify(const vault_config_t *cfg,
                                          const char *input)
{
    if (!cfg->password_hash[0]) {
        fprintf(stderr, "vault: no password hash configured\n");
        return AUTH_ERROR;
    }

    char *result = crypt(input, cfg->password_hash);
    if (!result)
        return AUTH_ERROR;

    /* Constant-time comparison to prevent timing attacks */
    size_t hash_len = strlen(cfg->password_hash);
    size_t result_len = strlen(result);
    if (hash_len != result_len)
        return AUTH_FAILURE;

    volatile unsigned char diff = 0;
    for (size_t i = 0; i < hash_len; i++)
        diff |= (unsigned char)(cfg->password_hash[i] ^ result[i]);

    return diff == 0 ? AUTH_SUCCESS : AUTH_FAILURE;
}

#endif /* Platform */
