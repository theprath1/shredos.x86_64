/*
 * tui_vt100.c — VT100 Escape Code TUI Backend
 *
 * Implements the full tui.h interface using VT100 terminal escape codes.
 * No ncurses dependency — works in initramfs, macOS console, or any
 * terminal that supports basic ANSI/VT100 sequences.
 *
 * Used as fallback when ncurses is not available.
 *
 * Copyright 2025 — GPL-2.0+
 */

#ifndef HAVE_NCURSES
#if !defined(VAULT_PLATFORM_WINDOWS)

#include "tui.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <sys/stat.h>

/* ------------------------------------------------------------------ */
/*  VT100 escape sequences                                             */
/* ------------------------------------------------------------------ */

#define ESC         "\033"
#define CSI         ESC "["
#define CLEAR       CSI "2J" CSI "H"
#define BOLD        CSI "1m"
#define DIM         CSI "2m"
#define BLINK       CSI "5m"
#define REVERSE     CSI "7m"
#define RESET       CSI "0m"
#define FG_RED      CSI "31m"
#define FG_GREEN    CSI "32m"
#define FG_YELLOW   CSI "33m"
#define FG_BLUE     CSI "34m"
#define FG_CYAN     CSI "36m"
#define FG_WHITE    CSI "37m"
#define BG_RED      CSI "41m"
#define BG_BLUE     CSI "44m"
#define HIDE_CURSOR CSI "?25l"
#define SHOW_CURSOR CSI "?25h"
#define MOVE_TO(r,c)  printf(CSI "%d;%dH", (r), (c))

static struct termios orig_termios;
static int raw_mode = 0;
static int term_rows = 24;
static int term_cols = 80;

/* ------------------------------------------------------------------ */
/*  Terminal helpers                                                    */
/* ------------------------------------------------------------------ */

static void get_term_size(void)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        term_rows = ws.ws_row;
        term_cols = ws.ws_col;
    }
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

    if (c == 27) {
        unsigned char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1) return 27;
        if (read(STDIN_FILENO, &seq[1], 1) != 1) return 27;
        if (seq[0] == '[') {
            switch (seq[1]) {
            case 'A': return 1000; /* UP */
            case 'B': return 1001; /* DOWN */
            case 'C': return 1002; /* RIGHT */
            case 'D': return 1003; /* LEFT */
            }
        }
        return 27;
    }
    return (int)c;
}

static void center_print(int row, const char *str)
{
    int len = (int)strlen(str);
    int col = (term_cols - len) / 2;
    if (col < 1) col = 1;
    MOVE_TO(row, col);
    printf("%s", str);
}

/* ------------------------------------------------------------------ */
/*  Banner                                                             */
/* ------------------------------------------------------------------ */

static const char *banner[] = {
    " ____  _                   _  ___  ____   __     __          _ _   ",
    "/ ___|| |__  _ __ ___  __| |/ _ \\/ ___|  \\ \\   / /_ _ _   _| | |_ ",
    "\\___ \\| '_ \\| '__/ _ \\/ _` | | | \\___ \\   \\ \\ / / _` | | | | | __|",
    " ___) | | | | | |  __/ (_| | |_| |___) |   \\ V / (_| | |_| | | |_ ",
    "|____/|_| |_|_|  \\___|\\__,_|\\___/|____/     \\_/ \\__,_|\\__,_|_|\\__|",
    NULL
};

static void draw_banner(int start_row)
{
    printf(BOLD FG_CYAN);
    for (int i = 0; banner[i]; i++)
        center_print(start_row + i, banner[i]);
    printf(RESET);
}

/* ------------------------------------------------------------------ */
/*  TUI Interface Implementation                                       */
/* ------------------------------------------------------------------ */

int vault_tui_init(void)
{
    get_term_size();
    enable_raw_mode();
    printf(HIDE_CURSOR);

    /* Block Ctrl+C, Ctrl+Z */
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    return 0;
}

void vault_tui_shutdown(void)
{
    printf(SHOW_CURSOR RESET CLEAR);
    fflush(stdout);
    disable_raw_mode();
}

int vault_tui_login_screen(const vault_config_t *cfg, char *password_out,
                            size_t password_size)
{
    printf(CLEAR);
    get_term_size();
    draw_banner(2);

    int y = 8;
    center_print(y++, "Secure Vault Authentication");
    y++;

    /* Attempt counter */
    char attempt_str[64];
    snprintf(attempt_str, sizeof(attempt_str), "Attempt %d of %d",
             cfg->current_attempts + 1, cfg->max_attempts);
    if (cfg->current_attempts > 0) printf(FG_RED);
    center_print(y++, attempt_str);
    printf(RESET);
    y++;

    /* Password prompt */
    MOVE_TO(y, (term_cols - 40) / 2);
    printf(FG_YELLOW "Password: " RESET);
    fflush(stdout);

    /* Read password with masking */
    int pos = 0;
    int max_len = (int)password_size - 1;
    if (max_len > 40) max_len = 40;

    while (1) {
        int ch = read_key();
        if (ch == '\n' || ch == '\r') break;
        if ((ch == 127 || ch == 8) && pos > 0) {
            pos--;
            password_out[pos] = '\0';
            printf("\b \b");
            fflush(stdout);
        } else if (pos < max_len && ch >= 32 && ch <= 126) {
            password_out[pos++] = (char)ch;
            printf("*");
            fflush(stdout);
        }
    }
    password_out[pos] = '\0';

    return pos;
}

int vault_tui_setup_screen(vault_config_t *cfg)
{
    printf(CLEAR);
    get_term_size();
    draw_banner(2);

    int y = 8;
    printf(BOLD FG_CYAN);
    center_print(y++, "=== First-Run Setup ===");
    printf(RESET);
    y++;

    /* Step 1: Select device */
    MOVE_TO(y++, 4);
    printf("Step 1: Select target device to protect\n");
    fflush(stdout);
    if (vault_tui_select_device(cfg->target_device,
                                 sizeof(cfg->target_device)) != 0)
        return -1;

    /* Step 2: Set password */
    printf(CLEAR);
    draw_banner(2);
    y = 9;
    MOVE_TO(y++, 4);
    printf("Step 2: Set authentication password\n");
    fflush(stdout);

    char password[256];
    if (vault_tui_new_password(password, sizeof(password)) != 0)
        return -1;

    extern int vault_auth_password_hash(const char *, char *, size_t);
    vault_auth_password_hash(password, cfg->password_hash,
                              sizeof(cfg->password_hash));
    vault_secure_memzero(password, sizeof(password));

    /* Step 3: Set threshold */
    printf(CLEAR);
    draw_banner(2);
    y = 9;
    MOVE_TO(y++, 4);
    printf("Step 3: Set failure threshold\n");
    fflush(stdout);
    cfg->max_attempts = vault_tui_set_threshold();

    /* Step 4: Select algorithm */
    printf(CLEAR);
    draw_banner(2);
    y = 9;
    MOVE_TO(y++, 4);
    printf("Step 4: Select wipe algorithm\n");
    fflush(stdout);
    cfg->wipe_algorithm = vault_tui_select_algorithm();

    /* Step 5: Confirm */
    printf(CLEAR);
    draw_banner(2);
    y = 9;
    printf(BOLD BG_RED FG_WHITE);
    MOVE_TO(y++, 4);
    printf("WARNING: This will FORMAT %s as an encrypted volume!", cfg->target_device);
    MOVE_TO(y++, 4);
    printf("ALL DATA ON THIS DEVICE WILL BE DESTROYED!");
    printf(RESET);
    y++;
    MOVE_TO(y++, 4);
    printf("Press 'Y' to confirm, any other key to cancel.");
    fflush(stdout);

    int ch = read_key();
    if (ch != 'Y' && ch != 'y')
        return -1;

    MOVE_TO(y++, 4);
    printf("Formatting LUKS volume...\n");
    fflush(stdout);

    /* Re-prompt for password to format */
    MOVE_TO(y++, 4);
    printf("Enter your password again to format: ");
    fflush(stdout);

    char format_pass[256];
    int fpos = 0;
    while (1) {
        int fch = read_key();
        if (fch == '\n' || fch == '\r') break;
        if (fpos < (int)sizeof(format_pass) - 1 && fch >= 32 && fch <= 126) {
            format_pass[fpos++] = (char)fch;
            printf("*");
            fflush(stdout);
        }
    }
    format_pass[fpos] = '\0';

    extern int vault_luks_format(const char *, const char *);
    int ret = vault_luks_format(cfg->target_device, format_pass);
    vault_secure_memzero(format_pass, sizeof(format_pass));

    if (ret != 0) {
        vault_tui_error("Failed to format LUKS volume!");
        return -1;
    }

    y += 2;
    MOVE_TO(y, 4);
    printf("Setup complete! Press any key to reboot.");
    fflush(stdout);
    read_key();
    return 0;
}

void vault_tui_success_screen(const vault_config_t *cfg)
{
    printf(CLEAR);
    get_term_size();
    draw_banner(2);

    int y = 8;
    printf(BOLD FG_GREEN);
    center_print(y, "AUTHENTICATION SUCCESSFUL");
    printf(RESET);
    y += 2;

    center_print(y++, "Volume unlocked and mounted at:");
    printf(BOLD);
    center_print(y++, cfg->mount_point);
    printf(RESET);
    y += 2;
    center_print(y, "Press 'q' to lock and shutdown");
    fflush(stdout);

    while (1) {
        int ch = read_key();
        if (ch == 'q' || ch == 'Q') break;
    }
}

void vault_tui_deadman_warning(int countdown_seconds)
{
    printf(CLEAR BG_RED FG_WHITE BOLD);
    get_term_size();

    int y = term_rows / 2 - 4;
    printf(BLINK);
    center_print(y, "!!! DEAD MAN'S SWITCH ACTIVATED !!!");
    printf(RESET BG_RED FG_WHITE BOLD);

    y += 2;
    center_print(y++, "MAXIMUM AUTHENTICATION ATTEMPTS EXCEEDED");
    y++;
    center_print(y++, "Target drive will be ENCRYPTED and WIPED");
    y++;
    center_print(y++, "THIS CANNOT BE STOPPED OR REVERSED");
    y += 2;

    for (int i = countdown_seconds; i > 0; i--) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Starting in %d seconds...  ", i);
        center_print(y, msg);
        fflush(stdout);
        sleep(1);
    }

    center_print(y, "INITIATING WIPE SEQUENCE  ");
    fflush(stdout);
    sleep(1);
    printf(RESET);
}

void vault_tui_wiping_screen(const char *device, const char *algorithm_name)
{
    printf(CLEAR);
    get_term_size();

    int y = term_rows / 2 - 3;
    printf(BOLD FG_RED);
    center_print(y, "WIPING IN PROGRESS");
    printf(RESET);

    y += 2;
    char buf[128];
    snprintf(buf, sizeof(buf), "Device:    %s", device);
    center_print(y++, buf);
    snprintf(buf, sizeof(buf), "Algorithm: %s", algorithm_name);
    center_print(y++, buf);
    y++;
    center_print(y, "Do NOT power off. This may take a long time.");
    fflush(stdout);
}

void vault_tui_status(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    MOVE_TO(term_rows - 2, 1);
    printf(BG_BLUE FG_WHITE);
    printf("%-*s", term_cols, "");
    MOVE_TO(term_rows - 2, 2);
    printf("%s", buf);
    printf(RESET);
    fflush(stdout);
}

void vault_tui_error(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    get_term_size();
    int y = term_rows / 2;
    printf(BOLD FG_RED);
    center_print(y, buf);
    printf(RESET);
    y += 2;
    center_print(y, "Press any key to continue");
    fflush(stdout);
    read_key();
}

int vault_tui_select_device(char *device_out, size_t device_size)
{
    char devices[32][64];
    char sizes[32][32];
    int count = 0;

#ifdef VAULT_PLATFORM_MACOS
    /* macOS: use diskutil to list disks */
    FILE *pp = popen("diskutil list -plist 2>/dev/null | "
                     "grep -oE '/dev/disk[0-9]+' | sort -u", "r");
    if (pp) {
        char line[128];
        while (fgets(line, sizeof(line), pp) && count < 32) {
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0]) {
                strncpy(devices[count], line, sizeof(devices[count]) - 1);
                strncpy(sizes[count], "N/A", sizeof(sizes[count]) - 1);
                count++;
            }
        }
        pclose(pp);
    }
#else
    /* Linux: scan /sys/block */
    DIR *dir = opendir("/sys/block");
    if (!dir) {
        vault_tui_error("Cannot read /sys/block");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) && count < 32) {
        if (strncmp(entry->d_name, "loop", 4) == 0) continue;
        if (strncmp(entry->d_name, "ram", 3) == 0) continue;
        if (strcmp(entry->d_name, ".") == 0) continue;
        if (strcmp(entry->d_name, "..") == 0) continue;

        snprintf(devices[count], sizeof(devices[count]),
                 "/dev/%s", entry->d_name);

        char size_path[256];
        snprintf(size_path, sizeof(size_path),
                 "/sys/block/%s/size", entry->d_name);
        FILE *sf = fopen(size_path, "r");
        if (sf) {
            unsigned long long sectors = 0;
            if (fscanf(sf, "%llu", &sectors) == 1) {
                double gb = (double)(sectors * 512) / (1024.0*1024.0*1024.0);
                snprintf(sizes[count], sizeof(sizes[count]), "%.1f GB", gb);
            }
            fclose(sf);
        } else {
            strncpy(sizes[count], "? GB", sizeof(sizes[count]) - 1);
        }
        count++;
    }
    closedir(dir);
#endif

    if (count == 0) {
        vault_tui_error("No block devices found!");
        return -1;
    }

    int selected = 0;
    while (1) {
        printf(CLEAR);
        get_term_size();
        draw_banner(2);
        int y = 9;

        printf(BOLD FG_CYAN);
        MOVE_TO(y++, 4);
        printf("Select target device:");
        printf(RESET);
        y++;

        for (int i = 0; i < count; i++) {
            MOVE_TO(y + i, 6);
            if (i == selected) printf(REVERSE FG_YELLOW);
            printf("  %-20s  %s  ", devices[i], sizes[i]);
            if (i == selected) printf(RESET);
        }

        MOVE_TO(y + count + 2, 4);
        printf("UP/DOWN to select, ENTER to confirm, 'q' to cancel");
        fflush(stdout);

        int ch = read_key();
        if (ch == 1000 && selected > 0) selected--;
        else if (ch == 1001 && selected < count - 1) selected++;
        else if (ch == '\n' || ch == '\r') break;
        else if (ch == 'q' || ch == 'Q') return -1;
    }

    strncpy(device_out, devices[selected], device_size - 1);
    device_out[device_size - 1] = '\0';
    return 0;
}

int vault_tui_new_password(char *password_out, size_t password_size)
{
    char pass1[256], pass2[256];

    while (1) {
        printf(CLEAR);
        get_term_size();
        draw_banner(2);
        int y = 10;

        MOVE_TO(y++, 4);
        printf("Enter new password: ");
        fflush(stdout);

        int pos = 0;
        while (1) {
            int ch = read_key();
            if (ch == '\n' || ch == '\r') break;
            if ((ch == 127 || ch == 8) && pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            } else if (pos < (int)sizeof(pass1) - 1 && ch >= 32 && ch <= 126) {
                pass1[pos++] = (char)ch;
                printf("*");
                fflush(stdout);
            }
        }
        pass1[pos] = '\0';

        y++;
        MOVE_TO(y++, 4);
        printf("Confirm password:   ");
        fflush(stdout);

        pos = 0;
        while (1) {
            int ch = read_key();
            if (ch == '\n' || ch == '\r') break;
            if ((ch == 127 || ch == 8) && pos > 0) {
                pos--;
                printf("\b \b");
                fflush(stdout);
            } else if (pos < (int)sizeof(pass2) - 1 && ch >= 32 && ch <= 126) {
                pass2[pos++] = (char)ch;
                printf("*");
                fflush(stdout);
            }
        }
        pass2[pos] = '\0';

        if (strlen(pass1) == 0) {
            vault_tui_error("Password cannot be empty!");
            continue;
        }
        if (strcmp(pass1, pass2) != 0) {
            vault_tui_error("Passwords do not match! Try again.");
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
    const char *names[] = {
        "Gutmann (35-pass) - Most thorough",
        "DoD 5220.22-M (7-pass) - US Government standard",
        "DoD Short (3-pass) - Fast government standard",
        "PRNG Stream - Random data overwrite",
        "Zero Fill - Single pass with zeros",
        "Verify Only - Check if already wiped",
    };
    int count = WIPE_COUNT;
    int selected = 0;

    while (1) {
        printf(CLEAR);
        get_term_size();
        draw_banner(2);
        int y = 9;

        printf(BOLD FG_CYAN);
        MOVE_TO(y++, 4);
        printf("Select wipe algorithm for dead man's switch:");
        printf(RESET);
        y++;

        for (int i = 0; i < count; i++) {
            MOVE_TO(y + i, 6);
            if (i == selected) printf(REVERSE FG_YELLOW);
            printf("  %s  ", names[i]);
            if (i == selected) printf(RESET);
        }

        MOVE_TO(y + count + 2, 4);
        printf("UP/DOWN to select, ENTER to confirm");
        fflush(stdout);

        int ch = read_key();
        if (ch == 1000 && selected > 0) selected--;
        else if (ch == 1001 && selected < count - 1) selected++;
        else if (ch == '\n' || ch == '\r') return (wipe_algorithm_t)selected;
    }
}

int vault_tui_set_threshold(void)
{
    int threshold = 3;

    while (1) {
        printf(CLEAR);
        get_term_size();
        draw_banner(2);
        int y = 9;

        printf(BOLD FG_CYAN);
        MOVE_TO(y++, 4);
        printf("Set failure threshold:");
        printf(RESET);
        y++;

        MOVE_TO(y++, 6);
        printf("After this many failed authentication attempts,");
        MOVE_TO(y++, 6);
        printf("the dead man's switch will activate and wipe the drive.");
        y++;

        char val[16];
        snprintf(val, sizeof(val), "[ %2d ]", threshold);
        printf(BOLD FG_YELLOW);
        center_print(y, val);
        printf(RESET);

        y += 3;
        MOVE_TO(y, 6);
        printf("UP/DOWN to adjust (1-99), ENTER to confirm");
        fflush(stdout);

        int ch = read_key();
        if (ch == 1000 && threshold < 99) threshold++;
        else if (ch == 1001 && threshold > 1) threshold--;
        else if (ch == '\n' || ch == '\r') return threshold;
    }
}

#endif /* !VAULT_PLATFORM_WINDOWS */
#endif /* !HAVE_NCURSES */
