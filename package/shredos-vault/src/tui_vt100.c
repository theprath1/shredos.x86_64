/*
 * tui_vt100.c -- VT100 Fallback TUI Backend
 *
 * Uses raw escape codes for minimal environments (initramfs, macOS).
 * No ncurses dependency.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef HAVE_NCURSES
#if !defined(VAULT_PLATFORM_WINDOWS)

#include "tui.h"
#include "auth_password.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <termios.h>
#include <dirent.h>
#include <signal.h>

static struct termios orig_termios;
static int raw_mode = 0;

/* VT100 escape helpers */
#define VT_CLEAR      "\033[2J"
#define VT_HOME       "\033[H"
#define VT_BOLD       "\033[1m"
#define VT_RED        "\033[31m"
#define VT_GREEN      "\033[32m"
#define VT_YELLOW     "\033[33m"
#define VT_CYAN       "\033[36m"
#define VT_BG_RED     "\033[41m"
#define VT_BG_BLUE    "\033[44m"
#define VT_RESET      "\033[0m"
#define VT_REVERSE    "\033[7m"

static void vt_goto(int row, int col)
{
    printf("\033[%d;%dH", row, col);
}

static void vt_clear(void)
{
    printf(VT_CLEAR VT_HOME);
}

static void enable_raw_mode(void)
{
    if (raw_mode) return;
    tcgetattr(STDIN_FILENO, &orig_termios);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON | ISIG);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    raw_mode = 1;
}

static void disable_raw_mode(void)
{
    if (!raw_mode) return;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    raw_mode = 0;
}

static int read_key(void)
{
    unsigned char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return -1;

    if (c == '\033') {
        unsigned char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return '\033';
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return '\033';
        if (seq[0] == '[') {
            if (seq[1] == 'A') return 1000; /* UP */
            if (seq[1] == 'B') return 1001; /* DOWN */
        }
        return '\033';
    }
    return c;
}

static void draw_banner_vt(void)
{
    printf(VT_CYAN VT_BOLD);
    printf("   ____  _                   _  ___  ____   __     __          _ _\n");
    printf("  / ___|| |__  _ __ ___  __| |/ _ \\/ ___|  \\ \\   / /_ _ _   _| | |_\n");
    printf("  \\___ \\| '_ \\| '__/ _ \\/ _` | | | \\___ \\   \\ \\ / / _` | | | | | __|\n");
    printf("   ___) | | | | | |  __/ (_| | |_| |___) |   \\ V / (_| | |_| | | |_\n");
    printf("  |____/|_| |_|_|  \\___|\\__,_|\\___/|____/     \\_/ \\__,_|\\__,_|_|\\__|\n");
    printf(VT_RESET "\n");
}

/* ------------------------------------------------------------------ */
/*  Init / Shutdown                                                    */
/* ------------------------------------------------------------------ */

int vault_tui_init(void)
{
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    enable_raw_mode();
    vt_clear();
    return 0;
}

void vault_tui_shutdown(void)
{
    disable_raw_mode();
    printf(VT_RESET VT_CLEAR VT_HOME);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/*  Login Screen                                                       */
/* ------------------------------------------------------------------ */

int vault_tui_login_screen(const vault_config_t *cfg,
                            char *password_out, size_t password_size)
{
    vt_clear();
    draw_banner_vt();

    printf("\n  Secure Vault Authentication\n\n");

    if (cfg->current_attempts > 0)
        printf(VT_RED);
    printf("  Attempt %d of %d\n", cfg->current_attempts + 1,
           cfg->max_attempts);
    printf(VT_RESET "\n");

    printf("  Password: ");
    fflush(stdout);

    int pos = 0;
    int max = (int)password_size - 1;

    while (1) {
        int ch = read_key();
        if (ch == '\n' || ch == '\r') break;
        if ((ch == 127 || ch == 8) && pos > 0) {
            pos--;
            password_out[pos] = '\0';
            printf("\b \b");
            fflush(stdout);
        } else if (pos < max && ch >= 32 && ch <= 126) {
            password_out[pos++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }
    password_out[pos] = '\0';
    printf("\n");
    return pos;
}

/* ------------------------------------------------------------------ */
/*  Setup Screen                                                       */
/* ------------------------------------------------------------------ */

int vault_tui_setup_screen(vault_config_t *cfg)
{
    vt_clear();
    draw_banner_vt();
    printf(VT_BOLD "\n  === First-Run Setup ===\n" VT_RESET "\n");

    /* Select device */
    if (vault_tui_select_device(cfg->target_device,
                                 sizeof(cfg->target_device)) != 0)
        return -1;

    /* Set password */
    char password[256];
    if (vault_tui_new_password(password, sizeof(password)) != 0)
        return -1;
    vault_auth_password_hash(password, cfg->password_hash,
                              sizeof(cfg->password_hash));
    vault_secure_memzero(password, sizeof(password));

    /* Set threshold */
    cfg->max_attempts = vault_tui_set_threshold();

    /* Select algorithm */
    cfg->wipe_algorithm = vault_tui_select_algorithm();

    /* Confirm */
    vt_clear();
    draw_banner_vt();
    printf(VT_RED VT_BOLD "\n  WARNING: Vault will be configured for %s\n",
           cfg->target_device);
    printf("  Failed auth will trigger the dead man's switch!\n" VT_RESET "\n");
    printf("  Press 'Y' to confirm, any other key to cancel: ");
    fflush(stdout);

    int ch = read_key();
    printf("\n");
    if (ch != 'Y' && ch != 'y') return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Success Screen                                                     */
/* ------------------------------------------------------------------ */

void vault_tui_success_screen(const vault_config_t *cfg)
{
    vt_clear();
    draw_banner_vt();
    printf(VT_GREEN VT_BOLD "\n  AUTHENTICATION SUCCESSFUL\n" VT_RESET "\n");
    printf("  Volume mounted at: %s\n\n", cfg->mount_point);
    printf("  Press 'q' to lock and shutdown.\n");
    fflush(stdout);

    while (1) {
        int ch = read_key();
        if (ch == 'q' || ch == 'Q') break;
    }
}

/* ------------------------------------------------------------------ */
/*  Dead Man's Warning                                                 */
/* ------------------------------------------------------------------ */

void vault_tui_deadman_warning(int countdown_seconds)
{
    vt_clear();
    printf(VT_BG_RED VT_BOLD "\n\n\n");
    printf("    !!! DEAD MAN'S SWITCH ACTIVATED !!!\n\n");
    printf("    MAXIMUM AUTHENTICATION ATTEMPTS EXCEEDED\n\n");
    printf("    Target drive will be ENCRYPTED and WIPED\n\n");
    printf("    THIS CANNOT BE STOPPED OR REVERSED\n\n");

    for (int i = countdown_seconds; i > 0; i--) {
        printf("\r    Starting in %d seconds...  ", i);
        fflush(stdout);
        sleep(1);
    }
    printf("\r    INITIATING WIPE SEQUENCE     \n");
    printf(VT_RESET);
    fflush(stdout);
    sleep(1);
}

/* ------------------------------------------------------------------ */
/*  Wiping Screen                                                      */
/* ------------------------------------------------------------------ */

void vault_tui_wiping_screen(const char *device, const char *algorithm_name)
{
    vt_clear();
    printf(VT_RED VT_BOLD "\n  WIPING IN PROGRESS\n" VT_RESET "\n");
    printf("  Device:    %s\n", device);
    printf("  Algorithm: %s\n\n", algorithm_name);
    printf("  Do NOT power off. This may take a long time.\n");
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/*  Status / Error                                                     */
/* ------------------------------------------------------------------ */

void vault_tui_status(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf(VT_CYAN "  ");
    vprintf(fmt, ap);
    printf(VT_RESET "\n");
    va_end(ap);
    fflush(stdout);
}

void vault_tui_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf(VT_RED VT_BOLD "  ERROR: ");
    vprintf(fmt, ap);
    printf(VT_RESET "\n");
    va_end(ap);
    fflush(stdout);

    printf("  Press any key to continue...\n");
    fflush(stdout);
    read_key();
}

/* ------------------------------------------------------------------ */
/*  Select Device                                                      */
/* ------------------------------------------------------------------ */

int vault_tui_select_device(char *device_out, size_t device_size)
{
    DIR *dir = opendir("/sys/block");
    if (!dir) {
        vault_tui_error("Cannot read /sys/block");
        return -1;
    }

    char devices[32][64];
    char sizes[32][32];
    int count = 0;

    struct dirent *ent;
    while ((ent = readdir(dir)) && count < 32) {
        if (strncmp(ent->d_name, "loop", 4) == 0) continue;
        if (strncmp(ent->d_name, "ram", 3) == 0) continue;
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        snprintf(devices[count], sizeof(devices[count]),
                 "/dev/%s", ent->d_name);

        char spath[256];
        snprintf(spath, sizeof(spath), "/sys/block/%s/size", ent->d_name);
        FILE *sf = fopen(spath, "r");
        if (sf) {
            unsigned long long sectors = 0;
            if (fscanf(sf, "%llu", &sectors) == 1) {
                double gb = (double)(sectors * 512) / (1024.0 * 1024.0 * 1024.0);
                snprintf(sizes[count], sizeof(sizes[count]), "%.1f GB", gb);
            }
            fclose(sf);
        } else {
            strncpy(sizes[count], "? GB", sizeof(sizes[count]) - 1);
        }
        count++;
    }
    closedir(dir);

    if (count == 0) {
        vault_tui_error("No block devices found!");
        return -1;
    }

    int sel = 0;
    while (1) {
        vt_clear();
        printf(VT_BOLD "\n  Select target device:\n" VT_RESET "\n");
        for (int i = 0; i < count; i++) {
            if (i == sel)
                printf(VT_REVERSE);
            printf("    %-20s  %s\n", devices[i], sizes[i]);
            if (i == sel)
                printf(VT_RESET);
        }
        printf("\n  UP/DOWN to select, ENTER to confirm, 'q' to cancel\n");
        fflush(stdout);

        int ch = read_key();
        if (ch == 1000 && sel > 0) sel--;           /* UP */
        else if (ch == 1001 && sel < count - 1) sel++; /* DOWN */
        else if (ch == '\n' || ch == '\r') break;
        else if (ch == 'q' || ch == 'Q') return -1;
    }

    strncpy(device_out, devices[sel], device_size - 1);
    device_out[device_size - 1] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/*  New Password                                                       */
/* ------------------------------------------------------------------ */

int vault_tui_new_password(char *password_out, size_t password_size)
{
    char pass1[256], pass2[256];

    while (1) {
        vt_clear();
        draw_banner_vt();
        printf("\n  Enter new password: ");
        fflush(stdout);

        int pos = 0;
        int max = (int)sizeof(pass1) - 1;
        while (1) {
            int ch = read_key();
            if (ch == '\n' || ch == '\r') break;
            if ((ch == 127 || ch == 8) && pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            } else if (pos < max && ch >= 32 && ch <= 126) {
                pass1[pos++] = (char)ch;
                printf("*");
                fflush(stdout);
            }
        }
        pass1[pos] = '\0';

        printf("\n  Confirm password:   ");
        fflush(stdout);

        int pos2 = 0;
        while (1) {
            int ch = read_key();
            if (ch == '\n' || ch == '\r') break;
            if ((ch == 127 || ch == 8) && pos2 > 0) {
                pos2--;
                printf("\b \b");
                fflush(stdout);
            } else if (pos2 < max && ch >= 32 && ch <= 126) {
                pass2[pos2++] = (char)ch;
                printf("*");
                fflush(stdout);
            }
        }
        pass2[pos2] = '\0';
        printf("\n");

        if (pos == 0) {
            vault_tui_error("Password cannot be empty!");
            continue;
        }
        if (strcmp(pass1, pass2) != 0) {
            vault_tui_error("Passwords do not match!");
            continue;
        }

        strncpy(password_out, pass1, password_size - 1);
        password_out[password_size - 1] = '\0';
        vault_secure_memzero(pass1, sizeof(pass1));
        vault_secure_memzero(pass2, sizeof(pass2));
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/*  Select Algorithm                                                   */
/* ------------------------------------------------------------------ */

wipe_algorithm_t vault_tui_select_algorithm(void)
{
    const char *names[] = {
        "Gutmann (35-pass)",
        "DoD 5220.22-M (7-pass)",
        "DoD Short (3-pass)",
        "PRNG Stream (random)",
        "Zero Fill",
    };
    int count = 5;
    int sel = 0;

    while (1) {
        vt_clear();
        printf(VT_BOLD "\n  Select wipe algorithm:\n" VT_RESET "\n");
        for (int i = 0; i < count; i++) {
            if (i == sel) printf(VT_REVERSE);
            printf("    %s\n", names[i]);
            if (i == sel) printf(VT_RESET);
        }
        printf("\n  UP/DOWN to select, ENTER to confirm\n");
        fflush(stdout);

        int ch = read_key();
        if (ch == 1000 && sel > 0) sel--;
        else if (ch == 1001 && sel < count - 1) sel++;
        else if (ch == '\n' || ch == '\r')
            return (wipe_algorithm_t)sel;
    }
}

/* ------------------------------------------------------------------ */
/*  Set Threshold                                                      */
/* ------------------------------------------------------------------ */

int vault_tui_set_threshold(void)
{
    int threshold = 3;

    while (1) {
        vt_clear();
        printf(VT_BOLD "\n  Set failure threshold:\n" VT_RESET "\n");
        printf("  After this many failed attempts, the drive will be wiped.\n\n");
        printf(VT_YELLOW VT_BOLD "    [ %2d ]\n" VT_RESET, threshold);
        printf("\n  UP/DOWN to adjust (1-99), ENTER to confirm\n");
        fflush(stdout);

        int ch = read_key();
        if (ch == 1000 && threshold < 99) threshold++;
        else if (ch == 1001 && threshold > 1) threshold--;
        else if (ch == '\n' || ch == '\r') return threshold;
    }
}

/* ------------------------------------------------------------------ */
/*  Generic Menu Select                                                */
/* ------------------------------------------------------------------ */

int vault_tui_menu_select(const char *title, const char **labels,
                           int count, int default_sel)
{
    int sel = default_sel;
    if (sel < 0 || sel >= count) sel = 0;

    while (1) {
        vt_clear();
        printf(VT_BOLD "\n  %s\n" VT_RESET "\n", title);
        for (int i = 0; i < count; i++) {
            if (i == sel) printf(VT_REVERSE);
            printf("    %s\n", labels[i]);
            if (i == sel) printf(VT_RESET);
        }
        printf("\n  UP/DOWN to select, ENTER to confirm, 'q' to cancel\n");
        fflush(stdout);

        int ch = read_key();
        if (ch == 1000 && sel > 0) sel--;
        else if (ch == 1001 && sel < count - 1) sel++;
        else if (ch == '\n' || ch == '\r') return sel;
        else if (ch == 'q' || ch == 'Q') return -1;
    }
}

#endif /* !VAULT_PLATFORM_WINDOWS */
#endif /* !HAVE_NCURSES */
