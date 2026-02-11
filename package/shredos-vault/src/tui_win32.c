/*
 * tui_win32.c — Windows TUI Stub Backend
 *
 * On Windows, the Credential Provider DLL handles the login UI.
 * This file provides stub implementations of tui.h so the vault
 * code compiles, with status/error messages logged to a file.
 *
 * The setup wizard uses basic console I/O (stdio).
 *
 * Copyright 2025 — GPL-2.0+
 */

#if defined(_WIN32) || defined(_WIN64)

#include "tui.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static FILE *log_fp = NULL;

static void win_log(const char *fmt, ...)
{
    if (!log_fp) {
        log_fp = fopen(VAULT_LOG_PATH_DEFAULT, "a");
        if (!log_fp) return;
    }

    va_list ap;
    va_start(ap, fmt);
    vfprintf(log_fp, fmt, ap);
    va_end(ap);
    fprintf(log_fp, "\n");
    fflush(log_fp);
}

int vault_tui_init(void)
{
    log_fp = fopen(VAULT_LOG_PATH_DEFAULT, "a");
    win_log("vault_tui_init (Win32 stub)");
    return 0;
}

void vault_tui_shutdown(void)
{
    win_log("vault_tui_shutdown");
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }
}

int vault_tui_login_screen(const vault_config_t *cfg, char *password_out,
                            size_t password_size)
{
    /* Console mode: prompt via stdin/stdout */
    printf("ShredOS Vault - Password Authentication\n");
    printf("Attempt %d of %d\n", cfg->current_attempts + 1, cfg->max_attempts);
    printf("Password: ");
    fflush(stdout);

    if (!fgets(password_out, (int)password_size, stdin))
        return -1;

    /* Strip newline */
    password_out[strcspn(password_out, "\r\n")] = '\0';
    return (int)strlen(password_out);
}

int vault_tui_setup_screen(vault_config_t *cfg)
{
    printf("\n=== ShredOS Vault Setup ===\n\n");

    /* Device */
    printf("Target device (e.g., \\\\.\\PhysicalDrive0): ");
    fflush(stdout);
    if (!fgets(cfg->target_device, sizeof(cfg->target_device), stdin))
        return -1;
    cfg->target_device[strcspn(cfg->target_device, "\r\n")] = '\0';

    /* Password */
    char password[256];
    if (vault_tui_new_password(password, sizeof(password)) != 0)
        return -1;

    extern int vault_auth_password_hash(const char *, char *, size_t);
    vault_auth_password_hash(password, cfg->password_hash,
                              sizeof(cfg->password_hash));
    vault_secure_memzero(password, sizeof(password));

    /* Threshold */
    cfg->max_attempts = vault_tui_set_threshold();

    /* Algorithm */
    cfg->wipe_algorithm = vault_tui_select_algorithm();

    printf("\nSetup complete!\n");
    return 0;
}

void vault_tui_success_screen(const vault_config_t *cfg)
{
    printf("\nAUTHENTICATION SUCCESSFUL\n");
    printf("Volume mounted at: %s\n", cfg->mount_point);
    printf("Press Enter to lock and shutdown...\n");
    fflush(stdout);
    getchar();
}

void vault_tui_deadman_warning(int countdown_seconds)
{
    printf("\n!!! DEAD MAN'S SWITCH ACTIVATED !!!\n");
    printf("MAXIMUM AUTHENTICATION ATTEMPTS EXCEEDED\n");
    printf("Target drive will be ENCRYPTED and WIPED\n\n");

    for (int i = countdown_seconds; i > 0; i--) {
        printf("Starting in %d seconds...\r", i);
        fflush(stdout);
        Sleep(1000);
    }
    printf("INITIATING WIPE SEQUENCE\n");
    win_log("DEAD MAN'S SWITCH TRIGGERED");
}

void vault_tui_wiping_screen(const char *device, const char *algorithm_name)
{
    printf("\nWIPING IN PROGRESS\n");
    printf("Device:    %s\n", device);
    printf("Algorithm: %s\n", algorithm_name);
    printf("Do NOT power off.\n");
    fflush(stdout);
    win_log("Wipe started: %s with %s", device, algorithm_name);
}

void vault_tui_status(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    printf("[STATUS] %s\n", buf);
    fflush(stdout);
    win_log("[STATUS] %s", buf);
}

void vault_tui_error(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    printf("[ERROR] %s\n", buf);
    fflush(stdout);
    win_log("[ERROR] %s", buf);
}

int vault_tui_select_device(char *device_out, size_t device_size)
{
    printf("Enter target device (e.g., \\\\.\\PhysicalDrive0): ");
    fflush(stdout);
    if (!fgets(device_out, (int)device_size, stdin))
        return -1;
    device_out[strcspn(device_out, "\r\n")] = '\0';
    return device_out[0] ? 0 : -1;
}

int vault_tui_new_password(char *password_out, size_t password_size)
{
    char pass1[256], pass2[256];
    while (1) {
        printf("Enter new password: ");
        fflush(stdout);
        if (!fgets(pass1, sizeof(pass1), stdin)) return -1;
        pass1[strcspn(pass1, "\r\n")] = '\0';

        printf("Confirm password: ");
        fflush(stdout);
        if (!fgets(pass2, sizeof(pass2), stdin)) return -1;
        pass2[strcspn(pass2, "\r\n")] = '\0';

        if (strlen(pass1) == 0) {
            printf("Password cannot be empty!\n");
            continue;
        }
        if (strcmp(pass1, pass2) != 0) {
            printf("Passwords do not match!\n");
            continue;
        }

        strncpy(password_out, pass1, password_size - 1);
        password_out[password_size - 1] = '\0';
        vault_secure_memzero(pass1, sizeof(pass1));
        vault_secure_memzero(pass2, sizeof(pass2));
        return 0;
    }
}

wipe_algorithm_t vault_tui_select_algorithm(void)
{
    printf("\nSelect wipe algorithm:\n");
    printf("  0: Gutmann (35-pass)\n");
    printf("  1: DoD 5220.22-M (7-pass)\n");
    printf("  2: DoD Short (3-pass)\n");
    printf("  3: PRNG Random\n");
    printf("  4: Zero Fill\n");
    printf("  5: Verify Only\n");
    printf("Choice [0]: ");
    fflush(stdout);

    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return WIPE_GUTMANN;
    int choice = atoi(buf);
    if (choice < 0 || choice >= WIPE_COUNT) choice = 0;
    return (wipe_algorithm_t)choice;
}

int vault_tui_set_threshold(void)
{
    printf("Max failed attempts before wipe [3]: ");
    fflush(stdout);

    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return 3;
    int val = atoi(buf);
    if (val < 1) val = 3;
    if (val > 99) val = 99;
    return val;
}

#endif /* _WIN32 */
