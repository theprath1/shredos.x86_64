/*
 * platform.c — Platform Abstraction Layer Implementation
 *
 * Provides unified implementations of platform-specific operations:
 *   - System shutdown
 *   - Memory locking (anti-swap)
 *   - Cryptographic random number generation
 *   - Secure memory zeroing
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Platform includes                                                  */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_WINDOWS)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <wincrypt.h>
#elif defined(VAULT_PLATFORM_MACOS)
  #include <unistd.h>
  #include <sys/mman.h>
  #include <fcntl.h>
  #include <Security/Security.h>
#else /* Linux */
  #include <unistd.h>
  #include <sys/mman.h>
  #include <sys/reboot.h>
  #include <fcntl.h>
#endif

/* ------------------------------------------------------------------ */
/*  System shutdown                                                    */
/* ------------------------------------------------------------------ */

void vault_platform_shutdown(void)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    /* Enable shutdown privilege */
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
                             &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(hToken);
    }

    InitiateSystemShutdownExW(
        NULL,
        L"ShredOS Vault: Security wipe complete. System shutting down.",
        0, TRUE, FALSE,
        SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_FLAG_PLANNED);

    /* Fallback */
    ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE, 0);

#elif defined(VAULT_PLATFORM_MACOS)
    sync();
    system("shutdown -h now");
    /* Fallback */
    system("halt");

#else /* Linux */
    sync();
    reboot(RB_POWER_OFF);
    /* Fallback */
    system("poweroff");
#endif
}

/* ------------------------------------------------------------------ */
/*  Memory locking                                                     */
/* ------------------------------------------------------------------ */

void vault_platform_lock_memory(void)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    /* Windows: VirtualLock requires specific addresses.
     * SetProcessWorkingSetSize prevents swapping somewhat. */
    SetProcessWorkingSetSize(GetCurrentProcess(),
                             (SIZE_T)-1, (SIZE_T)-1);

#else /* POSIX (Linux + macOS) */
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        perror("vault: mlockall (non-fatal)");
    }
#endif
}

/* ------------------------------------------------------------------ */
/*  Cryptographic random                                               */
/* ------------------------------------------------------------------ */

int vault_platform_random(uint8_t *buf, size_t len)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    HCRYPTPROV prov;
    if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT))
        return -1;
    BOOL ok = CryptGenRandom(prov, (DWORD)len, buf);
    CryptReleaseContext(prov, 0);
    return ok ? 0 : -1;

#elif defined(VAULT_PLATFORM_MACOS)
    if (SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess)
        return 0;
    /* Fallback to /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t rd = read(fd, buf + total, len - total);
        if (rd <= 0) { close(fd); return -1; }
        total += (size_t)rd;
    }
    close(fd);
    return 0;

#else /* Linux */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t rd = read(fd, buf + total, len - total);
        if (rd <= 0) { close(fd); return -1; }
        total += (size_t)rd;
    }
    close(fd);
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/*  Secure memzero                                                     */
/* ------------------------------------------------------------------ */

void vault_secure_memzero(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}
