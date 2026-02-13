/*
 * main.c -- ShredOS Vault Entry Point
 *
 * Modes:
 *   (default)          -- Authentication gate
 *   --setup            -- First-run setup wizard
 *   --install-wizard   -- Install vault onto host OS drive
 *   --initramfs        -- Running from initramfs (pre-boot gate)
 *
 * Kernel command line overrides (Linux):
 *   vault_setup        -- Enter setup mode
 *   vault_install      -- Enter install wizard mode
 *   vault_device=X     -- Override target device
 *   vault_threshold=N  -- Override failure threshold
 *   vault_wipe=ALG     -- Override wipe algorithm
 *
 * Copyright 2025 -- GPL-2.0+
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"
#include "config.h"
#include "auth.h"
#include "luks.h"
#include "deadman.h"
#include "installer.h"
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
    fprintf(stderr, "  --setup            Run first-time setup wizard\n");
    fprintf(stderr, "  --install-wizard   Install vault onto host drive\n");
    fprintf(stderr, "  --config PATH      Use alternate config file\n");
#if defined(VAULT_PLATFORM_LINUX)
    fprintf(stderr, "  --initramfs        Running from initramfs\n");
#endif
    fprintf(stderr, "  --help             Show this help\n");
}

/* ------------------------------------------------------------------ */
/*  Kernel command line parsing (Linux)                                 */
/* ------------------------------------------------------------------ */

#if defined(VAULT_PLATFORM_LINUX)

static void parse_kernel_cmdline(vault_config_t *cfg,
                                  int *install_wizard_mode)
{
    FILE *fp = fopen("/proc/cmdline", "r");
    if (!fp) return;

    char cmdline[4096];
    if (!fgets(cmdline, sizeof(cmdline), fp)) {
        fclose(fp);
        return;
    }
    fclose(fp);

    if (strstr(cmdline, "vault_setup"))
        cfg->setup_mode = 1;

    if (strstr(cmdline, "vault_install"))
        *install_wizard_mode = 1;

    char *p = strstr(cmdline, "vault_device=");
    if (p) {
        p += strlen("vault_device=");
        int i = 0;
        while (*p && *p != ' ' && *p != '\n' &&
               i < (int)sizeof(cfg->target_device) - 1)
            cfg->target_device[i++] = *p++;
        cfg->target_device[i] = '\0';
    }

    p = strstr(cmdline, "vault_threshold=");
    if (p) {
        int n = atoi(p + strlen("vault_threshold="));
        if (n > 0 && n <= 99) cfg->max_attempts = n;
    }

    p = strstr(cmdline, "vault_wipe=");
    if (p) {
        p += strlen("vault_wipe=");
        char alg[32] = {0};
        int i = 0;
        while (*p && *p != ' ' && *p != '\n' && i < (int)sizeof(alg) - 1)
            alg[i++] = *p++;
        if (strcmp(alg, "gutmann") == 0)     cfg->wipe_algorithm = WIPE_GUTMANN;
        else if (strcmp(alg, "dod") == 0)    cfg->wipe_algorithm = WIPE_DOD_522022;
        else if (strcmp(alg, "dodshort") == 0) cfg->wipe_algorithm = WIPE_DOD_SHORT;
        else if (strcmp(alg, "random") == 0)  cfg->wipe_algorithm = WIPE_RANDOM;
        else if (strcmp(alg, "zero") == 0)    cfg->wipe_algorithm = WIPE_ZERO;
    }
}

#endif

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static void ensure_config_dir(void)
{
#if defined(VAULT_PLATFORM_WINDOWS)
    CreateDirectoryA(VAULT_CONFIG_DIR, NULL);
#else
    mkdir(VAULT_CONFIG_DIR, 0700);
#endif
}

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
    int install_wizard_mode = 0;

    vault_config_init(&cfg);

    /* Parse CLI arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--setup") == 0)
            cfg.setup_mode = 1;
        else if (strcmp(argv[i], "--install-wizard") == 0)
            install_wizard_mode = 1;
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            config_path = argv[++i];
        else if (strcmp(argv[i], "--initramfs") == 0)
            initramfs_mode = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

#if defined(VAULT_PLATFORM_LINUX)
    parse_kernel_cmdline(&cfg, &install_wizard_mode);
#endif

    /* Lock memory */
    vault_platform_lock_memory();

    /* Try to load config */
    int config_ok = vault_config_load(&cfg, config_path);

    /* Init TUI */
    if (vault_tui_init() != 0) {
        fprintf(stderr, "vault: failed to initialise TUI\n");
        return 1;
    }

    /* === Install Wizard Mode === */
    if (install_wizard_mode) {
        int wiz = vault_installer_run_wizard();
        vault_tui_shutdown();
        return wiz;
    }

    /* === Setup Mode === */
    if (cfg.setup_mode || config_ok != 0) {
        if (config_ok != 0) {
            vault_tui_status("No configuration found. Starting setup...");
            main_sleep(2);
        }

        int sr = vault_tui_setup_screen(&cfg);
        if (sr != 0) {
            vault_tui_error("Setup cancelled.");
            vault_tui_shutdown();
            return 1;
        }

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

    /* === Authentication Loop === */
    auth_result_t result = vault_auth_run(&cfg);

    if (result == AUTH_SUCCESS) {
        if (initramfs_mode) {
            vault_tui_status("Authentication successful. Resuming boot...");
            main_sleep(1);
            vault_tui_shutdown();
            return 0;
        }

        if (vault_luks_available()) {
            vault_tui_status("Unlocking encrypted volume...");

            char unlock_pass[256];
            memset(unlock_pass, 0, sizeof(unlock_pass));
            vault_tui_status("Enter password to unlock volume:");
            int n = vault_tui_login_screen(&cfg, unlock_pass,
                                            sizeof(unlock_pass));

            int lr = -1;
            if (n > 0)
                lr = vault_luks_open(cfg.target_device, unlock_pass,
                                      VAULT_DM_NAME);
            vault_secure_memzero(unlock_pass, sizeof(unlock_pass));

            if (lr != 0) {
                vault_tui_error("Failed to unlock LUKS volume!");
                vault_tui_shutdown();
                return 1;
            }

#if !defined(VAULT_PLATFORM_WINDOWS)
            mkdir(cfg.mount_point, 0700);
#endif
            if (vault_luks_mount(VAULT_DM_NAME, cfg.mount_point) != 0) {
                vault_tui_error("Failed to mount volume!");
                vault_luks_close(VAULT_DM_NAME);
                vault_tui_shutdown();
                return 1;
            }

            vault_tui_success_screen(&cfg);

            vault_tui_status("Locking volume...");
            vault_luks_unmount(cfg.mount_point);
            vault_luks_close(VAULT_DM_NAME);
#if !defined(VAULT_PLATFORM_WINDOWS)
            sync();
#endif
            vault_tui_shutdown();
            vault_platform_shutdown();
        } else {
            vault_tui_success_screen(&cfg);
            vault_tui_shutdown();
            vault_platform_shutdown();
        }
        return 0;

    } else {
        /* Dead man's switch */
        vault_deadman_trigger(&cfg);
        vault_tui_shutdown();
        return 1;
    }
}
