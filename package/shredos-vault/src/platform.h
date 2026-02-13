/*
 * platform.h -- Platform Abstraction Layer
 *
 * Compile-time platform detection, feature flags, default paths,
 * and cross-platform API declarations.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_PLATFORM_H
#define VAULT_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  Platform detection                                                 */
/* ------------------------------------------------------------------ */

#if defined(_WIN32) || defined(_WIN64)
  #define VAULT_PLATFORM_WINDOWS 1
#elif defined(__APPLE__) && defined(__MACH__)
  #define VAULT_PLATFORM_MACOS 1
#elif defined(__linux__)
  #define VAULT_PLATFORM_LINUX 1
#else
  #error "Unsupported platform"
#endif

/* ------------------------------------------------------------------ */
/*  Feature flags (set via -D from the build system)                   */
/*                                                                     */
/*  HAVE_NCURSES        -- ncurses terminal library                    */
/*  HAVE_LIBCONFIG      -- libconfig config parser                     */
/*  HAVE_LIBCRYPTSETUP  -- libcryptsetup LUKS support                  */
/*  HAVE_FINGERPRINT    -- libfprint fingerprint reader                */
/*  HAVE_VOICE          -- PocketSphinx + PortAudio voice auth         */
/*  HAVE_IOKIT          -- macOS IOKit framework                       */
/*  HAVE_CRYPT_H        -- POSIX crypt() function                      */
/* ------------------------------------------------------------------ */

/* Config backend selection */
#ifdef HAVE_LIBCONFIG
  #define VAULT_CONFIG_BACKEND_LIBCONFIG 1
#else
  #define VAULT_CONFIG_BACKEND_INI 1
#endif

/* TUI backend selection */
#ifdef HAVE_NCURSES
  #define VAULT_TUI_BACKEND_NCURSES 1
#elif defined(VAULT_PLATFORM_WINDOWS)
  #define VAULT_TUI_BACKEND_WIN32 1
#else
  #define VAULT_TUI_BACKEND_VT100 1
#endif

/* Disk encryption backend */
#ifdef HAVE_LIBCRYPTSETUP
  #define VAULT_DISK_BACKEND_LUKS 1
#else
  #define VAULT_DISK_BACKEND_NONE 1
#endif

/* ------------------------------------------------------------------ */
/*  Default paths per platform                                         */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_WINDOWS)
  #define VAULT_CONFIG_PATH_DEFAULT  "C:\\ProgramData\\ShredOS-Vault\\vault.conf"
  #define VAULT_CONFIG_DIR_DEFAULT   "C:\\ProgramData\\ShredOS-Vault"
#elif defined(VAULT_PLATFORM_MACOS)
  #define VAULT_CONFIG_PATH_DEFAULT  "/Library/Application Support/ShredOS-Vault/vault.conf"
  #define VAULT_CONFIG_DIR_DEFAULT   "/Library/Application Support/ShredOS-Vault"
#else /* Linux */
  #define VAULT_CONFIG_PATH_DEFAULT  "/etc/shredos-vault/vault.conf"
  #define VAULT_CONFIG_DIR_DEFAULT   "/etc/shredos-vault"
#endif

/* ------------------------------------------------------------------ */
/*  Platform API                                                       */
/* ------------------------------------------------------------------ */

/* Initiate system power off. Does not return on success. */
void vault_platform_shutdown(void);

/* Lock all memory pages to prevent swapping sensitive data. */
void vault_platform_lock_memory(void);

/* Fill buffer with cryptographically secure random bytes.
 * Returns 0 on success, -1 on failure. */
int vault_platform_random(uint8_t *buf, size_t len);

/* Securely zero memory (prevents compiler optimisation). */
void vault_secure_memzero(void *ptr, size_t len);

#endif /* VAULT_PLATFORM_H */
