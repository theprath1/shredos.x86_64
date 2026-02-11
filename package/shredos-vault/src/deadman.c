/*
 * deadman.c — Dead Man's Switch (Cross-Platform)
 *
 * Executes the irreversible wipe sequence when authentication
 * threshold is exceeded:
 *   1. Block all signals (POSIX) — non-interruptible
 *   2. Display countdown warning via TUI
 *   3. Unmount/close any open LUKS volume
 *   4. Encrypt target with random key (if LUKS available)
 *   5. Wipe device using configured algorithm
 *   6. Sync and power off
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "deadman.h"
#include "luks.h"
#include "wipe.h"
#include "tui.h"
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
#else /* POSIX (Linux + macOS) */
  #include <unistd.h>
  #include <signal.h>
#endif

#define DEADMAN_COUNTDOWN_SECONDS 5

/* ------------------------------------------------------------------ */
/*  Block signals — make the wipe non-interruptible                    */
/* ------------------------------------------------------------------ */

static void deadman_block_signals(void)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    /* Windows: disable Ctrl+C handler */
    SetConsoleCtrlHandler(NULL, TRUE);
#else /* POSIX */
    sigset_t mask;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
#if !defined(VAULT_PLATFORM_MACOS) || defined(SIGQUIT)
    signal(SIGQUIT, SIG_IGN);
#endif
    signal(SIGTSTP, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
#endif
}

/* ------------------------------------------------------------------ */
/*  Platform-specific pre-wipe cleanup                                 */
/* ------------------------------------------------------------------ */

static void deadman_pre_wipe_cleanup(vault_config_t *cfg)
{
#ifdef HAVE_LIBCRYPTSETUP
    /* Close any open LUKS volume */
    vault_luks_unmount(cfg->mount_point);
    vault_luks_close(VAULT_DM_NAME);
#endif

#if defined(VAULT_PLATFORM_MACOS)
    /* Force unmount all volumes on the target disk */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "diskutil unmountDisk force %s 2>/dev/null", cfg->target_device);
    system(cmd);
#endif

    (void)cfg; /* suppress unused warning when no cleanup needed */
}

/* ------------------------------------------------------------------ */
/*  Platform-specific sleep                                            */
/* ------------------------------------------------------------------ */

static void deadman_sleep(int seconds)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    Sleep((DWORD)(seconds * 1000));
#else
    sleep((unsigned)seconds);
#endif
}

/* ------------------------------------------------------------------ */
/*  Platform-specific sync                                             */
/* ------------------------------------------------------------------ */

static void deadman_sync(void)
{
#if !defined(VAULT_PLATFORM_WINDOWS)
    sync();
#endif
}

/* ------------------------------------------------------------------ */
/*  Dead man's switch — point of no return                             */
/* ------------------------------------------------------------------ */

int vault_deadman_trigger(vault_config_t *cfg)
{
    /* Point of no return — block all interrupts */
    deadman_block_signals();

    /* Step 1: Display countdown warning */
    vault_tui_deadman_warning(DEADMAN_COUNTDOWN_SECONDS);

    /* Step 2: Pre-wipe cleanup (unmount LUKS, unmount macOS volumes) */
    deadman_pre_wipe_cleanup(cfg);

    /* Step 3: Encrypt the target with a random key (destroys LUKS header) */
    if (cfg->encrypt_before_wipe && vault_luks_available()) {
        vault_tui_status("Encrypting drive with random key...");
        if (vault_luks_format_random_key(cfg->target_device) != 0) {
            vault_tui_status("Encryption failed, proceeding to wipe...");
        }
    }

    /* Step 4: Wipe the device */
    vault_tui_wiping_screen(cfg->target_device,
                            vault_wipe_algorithm_name(cfg->wipe_algorithm));

    int wipe_result = vault_wipe_device(cfg->target_device,
                                         cfg->wipe_algorithm,
                                         cfg->verify_passes);
    if (wipe_result != 0) {
        vault_tui_status("Primary wipe failed, attempting raw overwrite...");
        /* Fallback: direct I/O wipe */
        vault_wipe_device_direct(cfg->target_device,
                                  WIPE_RANDOM, 0, NULL);
    }

    /* Step 5: Sync filesystems */
    deadman_sync();

    /* Step 6: Power off */
    vault_tui_status("Wipe complete. Powering off...");
    deadman_sleep(2);
    vault_tui_shutdown();
    vault_platform_shutdown();

    /* Should never reach here */
    return -1;
}
