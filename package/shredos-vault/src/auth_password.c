/*
 * auth_password.c -- Password Authentication (SHA-512 via crypt())
 *
 * Uses POSIX crypt() with $6$ (SHA-512) and a 16-byte random salt.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#include "auth_password.h"
#include "platform.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if defined(VAULT_PLATFORM_WINDOWS)
  /* Windows: simple SHA-256 fallback using CryptoAPI */
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <wincrypt.h>
#else
  #ifdef HAVE_CRYPT_H
    #include <crypt.h>
  #endif
  #include <unistd.h>
#endif

/* Base64 alphabet for salt generation */
static const char salt_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

#if !defined(VAULT_PLATFORM_WINDOWS)

int vault_auth_password_hash(const char *password,
                              char *hash_out, size_t hash_out_size)
{
    /* Generate 16-byte random salt */
    uint8_t raw_salt[16];
    if (vault_platform_random(raw_salt, sizeof(raw_salt)) != 0)
        return -1;

    char salt[32];
    snprintf(salt, sizeof(salt), "$6$");
    for (int i = 0; i < 16; i++)
        salt[3 + i] = salt_chars[raw_salt[i] % (sizeof(salt_chars) - 1)];
    salt[19] = '$';
    salt[20] = '\0';

    char *result = crypt(password, salt);
    if (!result || result[0] == '*')
        return -1;

    strncpy(hash_out, result, hash_out_size - 1);
    hash_out[hash_out_size - 1] = '\0';
    return 0;
}

int vault_auth_password_verify(const char *password, const char *stored_hash)
{
    char *result = crypt(password, stored_hash);
    if (!result) return 0;
    return strcmp(result, stored_hash) == 0;
}

#else /* Windows */

int vault_auth_password_hash(const char *password,
                              char *hash_out, size_t hash_out_size)
{
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    int ret = -1;

    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES,
                               CRYPT_VERIFYCONTEXT))
        return -1;

    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash))
        goto out;

    DWORD pw_len = (DWORD)strlen(password);
    if (!CryptHashData(hash, (const BYTE *)password, pw_len, 0))
        goto out;

    BYTE digest[32];
    DWORD digest_len = sizeof(digest);
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_len, 0))
        goto out;

    /* Format as hex string */
    if (hash_out_size < 65) goto out;
    for (DWORD i = 0; i < 32; i++)
        snprintf(hash_out + i * 2, 3, "%02x", digest[i]);
    hash_out[64] = '\0';
    ret = 0;

out:
    if (hash) CryptDestroyHash(hash);
    if (prov) CryptReleaseContext(prov, 0);
    return ret;
}

int vault_auth_password_verify(const char *password, const char *stored_hash)
{
    char computed[256];
    if (vault_auth_password_hash(password, computed, sizeof(computed)) != 0)
        return 0;
    return strcmp(computed, stored_hash) == 0;
}

#endif /* VAULT_PLATFORM_WINDOWS */
