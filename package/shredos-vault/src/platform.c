/*
 * platform.c -- Platform Abstraction Implementations
 *
 * CSPRNG, memory locking, secure memzero, system shutdown.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Windows                                                            */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_WINDOWS)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

void vault_platform_shutdown(void)
{
    ExitWindowsEx(EWX_POWEROFF | EWX_FORCE, 0);
    exit(0);
}

void vault_platform_lock_memory(void)
{
    /* Lock the working set -- best effort */
    SIZE_T min_ws, max_ws;
    if (GetProcessWorkingSetSize(GetCurrentProcess(), &min_ws, &max_ws)) {
        SetProcessWorkingSetSize(GetCurrentProcess(),
                                 min_ws + 4 * 1024 * 1024,
                                 max_ws + 4 * 1024 * 1024);
    }
}

int vault_platform_random(uint8_t *buf, size_t len)
{
    HCRYPTPROV prov;
    if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_FULL,
                               CRYPT_VERIFYCONTEXT))
        return -1;
    BOOL ok = CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    return ok ? 0 : -1;
}

void vault_secure_memzero(void *ptr, size_t len)
{
    SecureZeroMemory(ptr, len);
}

/* ------------------------------------------------------------------ */
/*  macOS                                                              */
/* ------------------------------------------------------------------ */

#elif defined(VAULT_PLATFORM_MACOS)

#include <unistd.h>
#include <sys/mman.h>
#include <Security/Security.h>

void vault_platform_shutdown(void)
{
    system("shutdown -h now");
    _exit(0);
}

void vault_platform_lock_memory(void)
{
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        fprintf(stderr, "vault: warning: mlockall failed\n");
}

int vault_platform_random(uint8_t *buf, size_t len)
{
    return SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess
               ? 0 : -1;
}

void vault_secure_memzero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

/* ------------------------------------------------------------------ */
/*  Linux                                                              */
/* ------------------------------------------------------------------ */

#else

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

void vault_platform_shutdown(void)
{
    sync();
    system("poweroff -f");
    _exit(0);
}

void vault_platform_lock_memory(void)
{
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        fprintf(stderr, "vault: warning: mlockall failed\n");
}

int vault_platform_random(uint8_t *buf, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, buf + done, len - done);
        if (n <= 0) { close(fd); return -1; }
        done += (size_t)n;
    }
    close(fd);
    return 0;
}

void vault_secure_memzero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

#endif
