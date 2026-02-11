/*
 * main.c — ShredOS Vault Entry Point (Cross-Platform)
 *
 * Handles CLI argument parsing, kernel command line (Linux initramfs),
 * configuration loading, TUI initialization, authentication loop,
 * LUKS unlock (when available), and dead man's switch trigger.
 *
 * Copyright 2025 — GPL-2.0+
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"
#include "config.h"
#include "auth.h"
#include "luks.h"
#include "deadman.h"
#include "tui.h"

#if !defined(VAULT_PLATFORM_WINDOWS)
  #include <sys/stat.h>
  #include <unistd.h>
#endif

/* ------------------------------------------------------------------ */
/*  Usage                                                              */
/* ------------------------------------------------------------------ */

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --setup        Run first-time setup wizard\n");
    fprintf(stderr, "  --config PATH  Use alternate config file\n");
#if defined(VAULT_PLATFORM_LINUX)
    fprintf(stderr, "  --initramfs    Running from initramfs (LUKS unlock mode)\n");
#endif
    fprintf(stderr, "  --help         Show this help\n");
}

/* ------------------------------------------------------------------ */
/*  Kernel command line parsing (Linux initramfs only)                  */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_LINUX)

static void parse_kernel_cmdline(vault_config_t *cfg)
{
    FILE *fp = fopen("/proc/cmdline", "r");
    if (!fp)
        return;

    char cmdline[4096];
    if (!fgets(cmdline, sizeof(cmdline), fp)) {
        fclose(fp);
        return;
    }
    fclose(fp);

    /* Check for setup mode */
    if (strstr(cmdline, "vault_setup"))
        cfg->setup_mode = 1;

    /* Parse vault_device=XXX */
    char *p = strstr(cmdline, "vault_device=");
    if (p) {
        p += strlen("vault_device=");
        int i = 0;
        while (*p && *p != ' ' && *p != '\n' &&
               i < (int)sizeof(cfg->target_device) - 1) {
            cfg->target_device[i++] = *p++;
        }
        cfg->target_device[i] = '\0';
    }

    /* Parse vault_threshold=N */
    p = strstr(cmdline, "vault_threshold=");
    if (p) {
        p += strlen("vault_threshold=");
        int n = atoi(p);
        if (n > 0 && n <= 99)
            cfg->max_attempts = n;
    }

    /* Parse vault_wipe=algorithm */
    p = strstr(cmdline, "vault_wipe=");
    if (p) {
        p += strlen("vault_wipe=");
        char alg[32] = {0};
        int i = 0;
        while (*p && *p != ' ' && *p != '\n' && i < (int)sizeof(alg) - 1)
            alg[i++] = *p++;

        if (strcmp(alg, "gutmann") == 0)
            cfg->wipe_algorithm = WIPE_GUTMANN;
        else if (strcmp(alg, "dod") == 0)
            cfg->wipe_algorithm = WIPE_DOD_522022;
        else if (strcmp(alg, "dodshort") == 0)
            cfg->wipe_algorithm = WIPE_DOD_SHORT;
        else if (strcmp(alg, "random") == 0)
            cfg->wipe_algorithm = WIPE_RANDOM;
        else if (strcmp(alg, "zero") == 0)
            cfg->wipe_algorithm = WIPE_ZERO;
    }
}

#endif /* VAULT_PLATFORM_LINUX */

/* ------------------------------------------------------------------ */
/*  Create config directory if needed                                  */
/* ------------------------------------------------------------------ */

static void ensure_config_dir(void)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    /* Windows: CreateDirectoryA */
    CreateDirectoryA(VAULT_CONFIG_DIR, NULL);
#else
    mkdir(VAULT_CONFIG_DIR, 0700);
#endif
}

/* ------------------------------------------------------------------ */
/*  Platform sleep helper                                              */
/* ------------------------------------------------------------------ */

static void main_sleep(int seconds)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    Sleep((DWORD)(seconds * 1000));
#else
    sleep((unsigned)seconds);
#endif
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    vault_config_t cfg;
    const char *config_path = VAULT_CONFIG_PATH;
    int initramfs_mode = 0;

    vault_config_init(&cfg);

    /* Parse command-line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--setup") == 0) {
            cfg.setup_mode = 1;
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (strcmp(argv[i], "--initramfs") == 0) {
            initramfs_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

#if defined(VAULT_PLATFORM_LINUX)
    /* Parse kernel command line overrides (initramfs) */
    parse_kernel_cmdline(&cfg);
#endif

    /* Lock memory to prevent swapping sensitive data */
    vault_platform_lock_memory();

    /* Try to load existing config */
    int config_loaded = vault_config_load(&cfg, config_path);

    /* Initialize TUI */
    if (vault_tui_init() != 0) {
        fprintf(stderr, "vault: failed to initialize TUI\n");
        return 1;
    }

    /* Setup mode: run first-time wizard */
    if (cfg.setup_mode || config_loaded != 0) {
        if (config_loaded != 0) {
            vault_tui_status("No configuration found. Starting setup wizard...");
            main_sleep(2);
        }

        int setup_result = vault_tui_setup_screen(&cfg);
        if (setup_result != 0) {
            vault_tui_error("Setup cancelled.");
            vault_tui_shutdown();
            return 1;
        }

        /* Save config */
        ensure_config_dir();
        if (vault_config_save(&cfg, config_path) != 0) {
            vault_tui_error("Failed to save configuration!");
            vault_tui_shutdown();
            return 1;
        }

        vault_tui_status("Configuration saved. Rebooting...");
        main_sleep(2);
        vault_tui_shutdown();

#if !defined(VAULT_PLATFORM_WINDOWS)
        sync();
        system("reboot");
#else
        vault_platform_shutdown();
#endif
        return 0;
    }

    /* Validate config */
    if (!cfg.target_device[0]) {
        vault_tui_error("No target device configured! Run with --setup");
        vault_tui_shutdown();
        return 1;
    }

    if (!cfg.password_hash[0] && (cfg.auth_methods & AUTH_METHOD_PASSWORD)) {
        vault_tui_error("No password configured! Run with --setup");
        vault_tui_shutdown();
        return 1;
    }

    /* === Main Authentication Loop === */
    auth_result_t auth_result = vault_auth_run(&cfg);

    if (auth_result == AUTH_SUCCESS) {
        /*
         * Authentication successful
         */

        if (vault_luks_available() && !initramfs_mode) {
            /* Standard mode: unlock and mount LUKS volume */
            vault_tui_status("Unlocking encrypted volume...");

            char unlock_pass[256];
            memset(unlock_pass, 0, sizeof(unlock_pass));

            vault_tui_status("Enter password to unlock volume:");
            int n = vault_tui_login_screen(&cfg, unlock_pass,
                                            sizeof(unlock_pass));

            int luks_ret = -1;
            if (n > 0)
                luks_ret = vault_luks_open(cfg.target_device, unlock_pass,
                                            VAULT_DM_NAME);

            vault_secure_memzero(unlock_pass, sizeof(unlock_pass));

            if (luks_ret != 0) {
                vault_tui_error("Failed to unlock LUKS volume!");
                vault_tui_shutdown();
                return 1;
            }

            /* Mount the volume */
#if !defined(VAULT_PLATFORM_WINDOWS)
            mkdir(cfg.mount_point, 0700);
#endif
            if (vault_luks_mount(VAULT_DM_NAME, cfg.mount_point) != 0) {
                vault_tui_error("Failed to mount volume at %s",
                                cfg.mount_point);
                vault_luks_close(VAULT_DM_NAME);
                vault_tui_shutdown();
                return 1;
            }

            /* Show success screen */
            vault_tui_success_screen(&cfg);

            /* User chose to exit — clean up */
            vault_tui_status("Locking volume and shutting down...");
            vault_luks_unmount(cfg.mount_point);
            vault_luks_close(VAULT_DM_NAME);
#if !defined(VAULT_PLATFORM_WINDOWS)
            sync();
#endif
            vault_tui_shutdown();
            vault_platform_shutdown();

        } else if (initramfs_mode && vault_luks_available()) {
            /* Initramfs mode: unlock LUKS and exit (init takes over) */
            vault_tui_status("Unlocking boot volume...");

            char unlock_pass[256];
            memset(unlock_pass, 0, sizeof(unlock_pass));

            int n = vault_tui_login_screen(&cfg, unlock_pass,
                                            sizeof(unlock_pass));
            int luks_ret = -1;
            if (n > 0)
                luks_ret = vault_luks_open(cfg.target_device, unlock_pass,
                                            VAULT_DM_NAME);

            vault_secure_memzero(unlock_pass, sizeof(unlock_pass));

            if (luks_ret != 0) {
                vault_tui_error("Failed to unlock volume!");
                vault_tui_shutdown();
                return 1;
            }

            vault_tui_status("Volume unlocked. Resuming boot...");
            main_sleep(1);
            vault_tui_shutdown();
            /* Exit 0 — init/systemd will mount and continue boot */

        } else {
            /* No LUKS: just show success and shut down */
            vault_tui_success_screen(&cfg);
            vault_tui_shutdown();
            vault_platform_shutdown();
        }

        return 0;

    } else {
        /*
         * Authentication FAILED — threshold exceeded.
         * Trigger dead man's switch.
         */
        vault_deadman_trigger(&cfg);

        /* Should not reach here */
        vault_tui_shutdown();
        return 1;
    }
}
