/*
 * deadman.c -- Dead Man's Switch
 *
 * Non-interruptible wipe sequence:
 *   1. Block ALL signals
 *   2. Display countdown warning
 *   3. Unmount/close LUKS volumes
 *   4. Encrypt target with random key
 *   5. Wipe device with configured algorithm
 *   6. Sync and power off
 *
 * Copyright 2025 -- GPL-2.0+
 */

#include "deadman.h"
#include "luks.h"
#include "wipe.h"
#include "tui.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(VAULT_PLATFORM_WINDOWS)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <unistd.h>
  #include <signal.h>
#endif

#define DEADMAN_COUNTDOWN 5

static void block_all_signals(void)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    SetConsoleCtrlHandler(NULL, TRUE);
#else
    sigset_t mask;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
#endif
}

static void deadman_sleep(int seconds)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    Sleep((DWORD)(seconds * 1000));
#else
    sleep((unsigned)seconds);
#endif
}

int vault_deadman_trigger(vault_config_t *cfg)
{
    /* Point of no return */
    block_all_signals();

    /* Step 1: Warning countdown */
    vault_tui_deadman_warning(DEADMAN_COUNTDOWN);

    /* Step 2: Pre-wipe cleanup */
#ifdef HAVE_LIBCRYPTSETUP
    vault_luks_unmount(cfg->mount_point);
    vault_luks_close(VAULT_DM_NAME);
#endif

#if defined(VAULT_PLATFORM_MACOS)
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "diskutil unmountDisk force %s 2>/dev/null", cfg->target_device);
    system(cmd);
#endif

    /* Step 3: Encrypt with random key */
    if (cfg->encrypt_before_wipe && vault_luks_available()) {
        vault_tui_status("Encrypting drive with random key...");
        if (vault_luks_format_random_key(cfg->target_device) != 0)
            vault_tui_status("Encryption failed, proceeding to wipe...");
    }

    /* Step 4: Wipe */
    vault_tui_wiping_screen(cfg->target_device,
                            vault_wipe_algorithm_name(cfg->wipe_algorithm));

    int wret = vault_wipe_device(cfg->target_device,
                                  cfg->wipe_algorithm,
                                  cfg->verify_passes);
    if (wret != 0) {
        vault_tui_status("Primary wipe failed, attempting raw overwrite...");
        vault_wipe_device_direct(cfg->target_device, WIPE_RANDOM, 0, NULL);
    }

    /* Step 5: Sync */
#if !defined(VAULT_PLATFORM_WINDOWS)
    sync();
#endif

    /* Step 6: Power off */
    vault_tui_status("Wipe complete. Powering off...");
    deadman_sleep(2);
    vault_tui_shutdown();
    vault_platform_shutdown();

    return -1; /* Should never reach here */
}
