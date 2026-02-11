/*
 * tui_ncurses.c — ncurses TUI Backend
 *
 * Full terminal UI with colors, box drawing, ASCII art banner.
 * Used on Linux when ncurses is available.
 *
 * Copyright 2025 — GPL-2.0+
 */

#ifdef HAVE_NCURSES

#include "tui.h"
#include "auth_password.h"
#include "luks.h"
#include <ncurses.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <signal.h>

/* Color pairs */
#define CP_NORMAL   1
#define CP_TITLE    2
#define CP_ERROR    3
#define CP_SUCCESS  4
#define CP_DANGER   5
#define CP_INPUT    6
#define CP_STATUS   7

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
    attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
    for (int i = 0; banner[i]; i++) {
        int len = (int)strlen(banner[i]);
        int col = (COLS - len) / 2;
        if (col < 0) col = 0;
        mvprintw(start_row + i, col, "%s", banner[i]);
    }
    attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
}

static void draw_box(int y, int x, int h, int w)
{
    mvhline(y, x, ACS_HLINE, w);
    mvhline(y + h - 1, x, ACS_HLINE, w);
    mvvline(y, x, ACS_VLINE, h);
    mvvline(y, x + w - 1, ACS_VLINE, h);
    mvaddch(y, x, ACS_ULCORNER);
    mvaddch(y, x + w - 1, ACS_URCORNER);
    mvaddch(y + h - 1, x, ACS_LLCORNER);
    mvaddch(y + h - 1, x + w - 1, ACS_LRCORNER);
}

int vault_tui_init(void)
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    /* Block Ctrl+C, Ctrl+Z during auth */
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(CP_NORMAL,  COLOR_WHITE,  -1);
        init_pair(CP_TITLE,   COLOR_CYAN,   -1);
        init_pair(CP_ERROR,   COLOR_RED,    -1);
        init_pair(CP_SUCCESS, COLOR_GREEN,  -1);
        init_pair(CP_DANGER,  COLOR_WHITE,  COLOR_RED);
        init_pair(CP_INPUT,   COLOR_YELLOW, -1);
        init_pair(CP_STATUS,  COLOR_WHITE,  COLOR_BLUE);
    }

    return 0;
}

void vault_tui_shutdown(void)
{
    endwin();
}

int vault_tui_login_screen(const vault_config_t *cfg, char *password_out,
                            size_t password_size)
{
    int banner_height = 0;
    for (int i = 0; banner[i]; i++) banner_height++;

    clear();
    draw_banner(1);

    /* Status bar */
    int status_y = banner_height + 3;
    attron(COLOR_PAIR(CP_NORMAL));
    const char *subtitle = "Secure Vault Authentication";
    mvprintw(status_y, (COLS - (int)strlen(subtitle)) / 2, "%s", subtitle);
    attroff(COLOR_PAIR(CP_NORMAL));

    /* Attempt counter */
    int counter_y = status_y + 2;
    attron(COLOR_PAIR(cfg->current_attempts > 0 ? CP_ERROR : CP_NORMAL));
    mvprintw(counter_y, (COLS - 30) / 2,
             "Attempt %d of %d",
             cfg->current_attempts + 1, cfg->max_attempts);
    attroff(COLOR_PAIR(cfg->current_attempts > 0 ? CP_ERROR : CP_NORMAL));

    /* Password input box */
    int box_y = counter_y + 2;
    int box_w = 50;
    int box_x = (COLS - box_w) / 2;
    int box_h = 3;

    attron(COLOR_PAIR(CP_INPUT));
    draw_box(box_y, box_x, box_h, box_w);
    mvprintw(box_y - 1, box_x, " Password: ");
    attroff(COLOR_PAIR(CP_INPUT));

    /* Footer */
    int footer_y = LINES - 2;
    attron(COLOR_PAIR(CP_STATUS));
    mvhline(footer_y, 0, ' ', COLS);
    mvprintw(footer_y, 2, " ShredOS Vault v1.0 ");
    if (cfg->auth_methods & AUTH_METHOD_FINGERPRINT)
        mvprintw(footer_y, COLS - 30, "[Fingerprint available]");
    attroff(COLOR_PAIR(CP_STATUS));

    /* Read password with echo as asterisks */
    curs_set(1);
    echo();
    int input_y = box_y + 1;
    int input_x = box_x + 2;
    move(input_y, input_x);

    /* Custom password read with masking */
    noecho();
    int pos = 0;
    int ch;
    int max_len = (int)password_size - 1;
    if (max_len > box_w - 4)
        max_len = box_w - 4;

    while (1) {
        ch = getch();
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) {
            break;
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (pos > 0) {
                pos--;
                password_out[pos] = '\0';
                mvaddch(input_y, input_x + pos, ' ');
                move(input_y, input_x + pos);
            }
        } else if (pos < max_len && ch >= 32 && ch <= 126) {
            password_out[pos] = (char)ch;
            mvaddch(input_y, input_x + pos, '*');
            pos++;
        }
    }
    password_out[pos] = '\0';

    curs_set(0);
    return pos;
}

int vault_tui_setup_screen(vault_config_t *cfg)
{
    clear();
    draw_banner(1);

    int y = 8;
    attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
    mvprintw(y++, (COLS - 25) / 2, "=== First-Run Setup ===");
    attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
    y++;

    /* Step 1: Select device */
    mvprintw(y++, 4, "Step 1: Select target device to protect");
    y++;
    if (vault_tui_select_device(cfg->target_device,
                                 sizeof(cfg->target_device)) != 0) {
        return -1;
    }

    /* Step 2: Set password */
    clear();
    draw_banner(1);
    y = 9;
    mvprintw(y++, 4, "Step 2: Set authentication password");
    y++;
    char password[256];
    if (vault_tui_new_password(password, sizeof(password)) != 0) {
        return -1;
    }
    vault_auth_password_hash(password, cfg->password_hash,
                              sizeof(cfg->password_hash));
    /* Wipe plaintext */
    volatile char *vp = (volatile char *)password;
    for (size_t i = 0; i < sizeof(password); i++) vp[i] = 0;

    /* Step 3: Set threshold */
    clear();
    draw_banner(1);
    y = 9;
    mvprintw(y++, 4, "Step 3: Set failure threshold (auto-wipe after N failures)");
    cfg->max_attempts = vault_tui_set_threshold();

    /* Step 4: Select wipe algorithm */
    clear();
    draw_banner(1);
    y = 9;
    mvprintw(y++, 4, "Step 4: Select wipe algorithm for dead man's switch");
    cfg->wipe_algorithm = vault_tui_select_algorithm();

    /* Step 5: Format LUKS */
    clear();
    draw_banner(1);
    y = 9;
    attron(COLOR_PAIR(CP_DANGER) | A_BOLD);
    mvprintw(y++, 4, "WARNING: This will FORMAT %s as an encrypted volume!",
             cfg->target_device);
    mvprintw(y++, 4, "ALL DATA ON THIS DEVICE WILL BE DESTROYED!");
    attroff(COLOR_PAIR(CP_DANGER) | A_BOLD);
    y++;
    mvprintw(y++, 4, "Press 'Y' to confirm, any other key to cancel.");
    refresh();

    int ch = getch();
    if (ch != 'Y' && ch != 'y')
        return -1;

    mvprintw(y++, 4, "Formatting LUKS volume... (this may take a moment)");
    refresh();

    /* We need the password again to format — re-prompt */
    char format_pass[256];
    mvprintw(y++, 4, "Enter your password again to format: ");
    echo();
    curs_set(1);
    getnstr(format_pass, sizeof(format_pass) - 1);
    noecho();
    curs_set(0);

    int ret = vault_luks_format(cfg->target_device, format_pass);
    if (ret != 0) {
        vault_secure_memzero(format_pass, sizeof(format_pass));
        vault_tui_error("Failed to format LUKS volume!");
        return -1;
    }

    /* Create filesystem on the LUKS volume */
    vault_tui_status("Creating ext4 filesystem inside encrypted volume...");

    /* Open LUKS temporarily to create filesystem */
    if (vault_luks_open(cfg->target_device, format_pass, VAULT_DM_NAME) != 0) {
        vault_secure_memzero(format_pass, sizeof(format_pass));
        vault_tui_error("Cannot open newly created volume for fs creation.");
        return -1;
    }
    vault_secure_memzero(format_pass, sizeof(format_pass));

    char mkfs_cmd[512];
    snprintf(mkfs_cmd, sizeof(mkfs_cmd),
             "mkfs.ext4 -q /dev/mapper/%s 2>/dev/null", VAULT_DM_NAME);
    if (system(mkfs_cmd) != 0) {
        vault_luks_close(VAULT_DM_NAME);
        vault_tui_error("Failed to create filesystem on encrypted volume.");
        return -1;
    }
    vault_luks_close(VAULT_DM_NAME);

    mvprintw(y + 2, 4, "Setup complete! Press any key to reboot.");
    refresh();
    getch();

    return 0;
}

void vault_tui_success_screen(const vault_config_t *cfg)
{
    clear();
    draw_banner(1);

    int y = 8;
    attron(COLOR_PAIR(CP_SUCCESS) | A_BOLD);
    const char *msg = "AUTHENTICATION SUCCESSFUL";
    mvprintw(y, (COLS - (int)strlen(msg)) / 2, "%s", msg);
    attroff(COLOR_PAIR(CP_SUCCESS) | A_BOLD);

    y += 2;
    mvprintw(y++, (COLS - 40) / 2, "Volume unlocked and mounted at:");
    attron(A_BOLD);
    mvprintw(y++, (COLS - (int)strlen(cfg->mount_point)) / 2,
             "%s", cfg->mount_point);
    attroff(A_BOLD);

    y += 2;
    mvprintw(y, (COLS - 35) / 2, "Press 'q' to lock and shutdown");
    mvprintw(y + 1, (COLS - 35) / 2, "Press 's' to open a shell");
    refresh();

    int ch;
    while (1) {
        ch = getch();
        if (ch == 'q' || ch == 'Q')
            break;
        if (ch == 's' || ch == 'S') {
            /* Drop to shell */
            vault_tui_shutdown();
            system("/bin/bash");
            vault_tui_init();
            /* Redraw */
            vault_tui_success_screen(cfg);
            return;
        }
    }
}

void vault_tui_deadman_warning(int countdown_seconds)
{
    clear();

    /* Full-screen red danger */
    if (has_colors())
        bkgd(COLOR_PAIR(CP_DANGER));

    int y = LINES / 2 - 4;

    attron(A_BOLD | A_BLINK);
    const char *warn1 = "!!! DEAD MAN'S SWITCH ACTIVATED !!!";
    mvprintw(y, (COLS - (int)strlen(warn1)) / 2, "%s", warn1);
    attroff(A_BLINK);

    y += 2;
    const char *warn2 = "MAXIMUM AUTHENTICATION ATTEMPTS EXCEEDED";
    mvprintw(y++, (COLS - (int)strlen(warn2)) / 2, "%s", warn2);

    y++;
    const char *warn3 = "Target drive will be ENCRYPTED and WIPED";
    mvprintw(y++, (COLS - (int)strlen(warn3)) / 2, "%s", warn3);

    y++;
    const char *warn4 = "THIS CANNOT BE STOPPED OR REVERSED";
    mvprintw(y++, (COLS - (int)strlen(warn4)) / 2, "%s", warn4);
    attroff(A_BOLD);

    y += 2;

    for (int i = countdown_seconds; i > 0; i--) {
        mvprintw(y, (COLS - 25) / 2, "Starting in %d seconds...  ", i);
        refresh();
        sleep(1);
    }

    mvprintw(y, (COLS - 25) / 2, "INITIATING WIPE SEQUENCE  ");
    refresh();
    sleep(1);

    /* Reset background */
    if (has_colors())
        bkgd(COLOR_PAIR(CP_NORMAL));
}

void vault_tui_wiping_screen(const char *device, const char *algorithm_name)
{
    clear();

    int y = LINES / 2 - 3;
    attron(COLOR_PAIR(CP_DANGER) | A_BOLD);
    const char *msg = "WIPING IN PROGRESS";
    mvprintw(y, (COLS - (int)strlen(msg)) / 2, "%s", msg);
    attroff(COLOR_PAIR(CP_DANGER) | A_BOLD);

    y += 2;
    mvprintw(y++, (COLS - 40) / 2, "Device:    %s", device);
    mvprintw(y++, (COLS - 40) / 2, "Algorithm: %s", algorithm_name);
    y++;
    mvprintw(y, (COLS - 45) / 2, "Do NOT power off. This may take a long time.");
    refresh();
}

void vault_tui_status(const char *fmt, ...)
{
    va_list ap;
    char buf[512];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int y = LINES - 3;
    attron(COLOR_PAIR(CP_STATUS));
    mvhline(y, 0, ' ', COLS);
    mvprintw(y, 2, "%s", buf);
    attroff(COLOR_PAIR(CP_STATUS));
    refresh();
}

void vault_tui_error(const char *fmt, ...)
{
    va_list ap;
    char buf[512];

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int y = LINES / 2;
    attron(COLOR_PAIR(CP_ERROR) | A_BOLD);
    mvhline(y, 0, ' ', COLS);
    mvprintw(y, (COLS - (int)strlen(buf)) / 2, "%s", buf);
    attroff(COLOR_PAIR(CP_ERROR) | A_BOLD);

    mvprintw(y + 2, (COLS - 25) / 2, "Press any key to continue");
    refresh();
    getch();
}

int vault_tui_select_device(char *device_out, size_t device_size)
{
    /* Scan /sys/block for block devices */
    DIR *dir = opendir("/sys/block");
    if (!dir) {
        vault_tui_error("Cannot read /sys/block");
        return -1;
    }

    char devices[32][64];
    char sizes[32][32];
    int count = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) && count < 32) {
        /* Skip virtual devices */
        if (strncmp(entry->d_name, "loop", 4) == 0) continue;
        if (strncmp(entry->d_name, "ram", 3) == 0) continue;
        if (strcmp(entry->d_name, ".") == 0) continue;
        if (strcmp(entry->d_name, "..") == 0) continue;

        snprintf(devices[count], sizeof(devices[count]),
                 "/dev/%s", entry->d_name);

        /* Read size */
        char size_path[256];
        snprintf(size_path, sizeof(size_path),
                 "/sys/block/%s/size", entry->d_name);
        FILE *sf = fopen(size_path, "r");
        if (sf) {
            unsigned long long sectors = 0;
            if (fscanf(sf, "%llu", &sectors) == 1) {
                double gb = (double)(sectors * 512) / (1024.0 * 1024.0 * 1024.0);
                snprintf(sizes[count], sizeof(sizes[count]),
                         "%.1f GB", gb);
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

    /* Display selection menu */
    int selected = 0;
    int ch;

    while (1) {
        clear();
        draw_banner(1);
        int y = 9;

        attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvprintw(y++, 4, "Select target device:");
        attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
        y++;

        for (int i = 0; i < count; i++) {
            if (i == selected) {
                attron(COLOR_PAIR(CP_INPUT) | A_REVERSE);
            }
            mvprintw(y + i, 6, "  %-20s  %s  ",
                     devices[i], sizes[i]);
            if (i == selected) {
                attroff(COLOR_PAIR(CP_INPUT) | A_REVERSE);
            }
        }

        mvprintw(y + count + 2, 4,
                 "Use UP/DOWN arrows to select, ENTER to confirm, 'q' to cancel");
        refresh();

        ch = getch();
        if (ch == KEY_UP && selected > 0) selected--;
        else if (ch == KEY_DOWN && selected < count - 1) selected++;
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) break;
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
        clear();
        draw_banner(1);
        int y = 10;

        mvprintw(y++, 4, "Enter new password: ");
        curs_set(1);
        noecho();
        move(y - 1, 25);

        /* Read password (masked) */
        int pos = 0;
        int ch;
        while (1) {
            ch = getch();
            if (ch == '\n' || ch == '\r') break;
            if ((ch == KEY_BACKSPACE || ch == 127 || ch == 8) && pos > 0) {
                pos--;
                mvaddch(y - 1, 25 + pos, ' ');
                move(y - 1, 25 + pos);
            } else if (pos < (int)sizeof(pass1) - 1 && ch >= 32 && ch <= 126) {
                pass1[pos++] = (char)ch;
                addch('*');
            }
        }
        pass1[pos] = '\0';

        y++;
        mvprintw(y++, 4, "Confirm password:   ");
        move(y - 1, 25);

        pos = 0;
        while (1) {
            ch = getch();
            if (ch == '\n' || ch == '\r') break;
            if ((ch == KEY_BACKSPACE || ch == 127 || ch == 8) && pos > 0) {
                pos--;
                mvaddch(y - 1, 25 + pos, ' ');
                move(y - 1, 25 + pos);
            } else if (pos < (int)sizeof(pass2) - 1 && ch >= 32 && ch <= 126) {
                pass2[pos++] = (char)ch;
                addch('*');
            }
        }
        pass2[pos] = '\0';
        curs_set(0);

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

        /* Wipe temp buffers */
        volatile char *v1 = (volatile char *)pass1;
        volatile char *v2 = (volatile char *)pass2;
        for (size_t i = 0; i < sizeof(pass1); i++) v1[i] = 0;
        for (size_t i = 0; i < sizeof(pass2); i++) v2[i] = 0;

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
    int selected = 0; /* Default: Gutmann */

    while (1) {
        clear();
        draw_banner(1);
        int y = 9;

        attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvprintw(y++, 4, "Select wipe algorithm for dead man's switch:");
        attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
        y++;

        for (int i = 0; i < count; i++) {
            if (i == selected)
                attron(COLOR_PAIR(CP_INPUT) | A_REVERSE);
            mvprintw(y + i, 6, "  %s  ", names[i]);
            if (i == selected)
                attroff(COLOR_PAIR(CP_INPUT) | A_REVERSE);
        }

        mvprintw(y + count + 2, 4,
                 "UP/DOWN to select, ENTER to confirm");
        refresh();

        int ch = getch();
        if (ch == KEY_UP && selected > 0) selected--;
        else if (ch == KEY_DOWN && selected < count - 1) selected++;
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER)
            return (wipe_algorithm_t)selected;
    }
}

int vault_tui_set_threshold(void)
{
    int threshold = 3; /* Default */

    while (1) {
        clear();
        draw_banner(1);
        int y = 9;

        attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvprintw(y++, 4, "Set failure threshold:");
        attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
        y++;

        mvprintw(y++, 6, "After this many failed authentication attempts,");
        mvprintw(y++, 6, "the dead man's switch will activate and wipe the drive.");
        y++;

        attron(COLOR_PAIR(CP_INPUT) | A_BOLD);
        mvprintw(y, (COLS - 10) / 2, "[ %2d ]", threshold);
        attroff(COLOR_PAIR(CP_INPUT) | A_BOLD);

        y += 3;
        mvprintw(y, 6, "UP/DOWN to adjust (1-99), ENTER to confirm");
        refresh();

        int ch = getch();
        if (ch == KEY_UP && threshold < 99) threshold++;
        else if (ch == KEY_DOWN && threshold > 1) threshold--;
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER)
            return threshold;
    }
}

/* Forward declarations needed for setup */
extern int vault_auth_password_hash(const char *password, char *hash_out,
                                     size_t hash_out_size);
extern int vault_luks_format(const char *device, const char *passphrase);
extern int vault_luks_open(const char *device, const char *passphrase,
                            const char *dm_name);
extern int vault_luks_close(const char *dm_name);

#endif /* HAVE_NCURSES */
