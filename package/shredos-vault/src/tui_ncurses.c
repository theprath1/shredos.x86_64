/*
 * tui_ncurses.c -- ncurses TUI Backend
 *
 * Full terminal UI with colours, box drawing, ASCII art banner.
 *
 * Copyright 2025 -- GPL-2.0+
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

/* Colour pairs */
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

/* ------------------------------------------------------------------ */
/*  Init / Shutdown                                                    */
/* ------------------------------------------------------------------ */

int vault_tui_init(void)
{
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

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

/* ------------------------------------------------------------------ */
/*  Masked password input                                              */
/* ------------------------------------------------------------------ */

static int read_password_masked(int y, int x, char *out, int max_len)
{
    int pos = 0;
    int ch;

    curs_set(1);
    noecho();
    move(y, x);

    while (1) {
        ch = getch();
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER)
            break;
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            if (pos > 0) {
                pos--;
                out[pos] = '\0';
                mvaddch(y, x + pos, ' ');
                move(y, x + pos);
            }
        } else if (pos < max_len && ch >= 32 && ch <= 126) {
            out[pos++] = (char)ch;
            mvaddch(y, x + pos - 1, '*');
        }
    }
    out[pos] = '\0';
    curs_set(0);
    return pos;
}

/* ------------------------------------------------------------------ */
/*  Login Screen                                                       */
/* ------------------------------------------------------------------ */

int vault_tui_login_screen(const vault_config_t *cfg,
                            char *password_out, size_t password_size)
{
    int bh = 0;
    for (int i = 0; banner[i]; i++) bh++;

    clear();
    draw_banner(1);

    int sy = bh + 3;
    attron(COLOR_PAIR(CP_NORMAL));
    const char *sub = "Secure Vault Authentication";
    mvprintw(sy, (COLS - (int)strlen(sub)) / 2, "%s", sub);
    attroff(COLOR_PAIR(CP_NORMAL));

    int cy = sy + 2;
    attron(COLOR_PAIR(cfg->current_attempts > 0 ? CP_ERROR : CP_NORMAL));
    mvprintw(cy, (COLS - 30) / 2, "Attempt %d of %d",
             cfg->current_attempts + 1, cfg->max_attempts);
    attroff(COLOR_PAIR(cfg->current_attempts > 0 ? CP_ERROR : CP_NORMAL));

    int boxy = cy + 2;
    int boxw = 50;
    int boxx = (COLS - boxw) / 2;

    attron(COLOR_PAIR(CP_INPUT));
    draw_box(boxy, boxx, 3, boxw);
    mvprintw(boxy - 1, boxx, " Password: ");
    attroff(COLOR_PAIR(CP_INPUT));

    /* Footer */
    int fy = LINES - 2;
    attron(COLOR_PAIR(CP_STATUS));
    mvhline(fy, 0, ' ', COLS);
    mvprintw(fy, 2, " ShredOS Vault v1.0 ");
    attroff(COLOR_PAIR(CP_STATUS));

    refresh();

    int max = (int)password_size - 1;
    if (max > boxw - 4) max = boxw - 4;
    return read_password_masked(boxy + 1, boxx + 2, password_out, max);
}

/* ------------------------------------------------------------------ */
/*  Setup Screen                                                       */
/* ------------------------------------------------------------------ */

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
    refresh();
    if (vault_tui_select_device(cfg->target_device,
                                 sizeof(cfg->target_device)) != 0)
        return -1;

    /* Step 2: Set password */
    char password[256];
    if (vault_tui_new_password(password, sizeof(password)) != 0)
        return -1;
    vault_auth_password_hash(password, cfg->password_hash,
                              sizeof(cfg->password_hash));
    vault_secure_memzero(password, sizeof(password));

    /* Step 3: Set threshold */
    cfg->max_attempts = vault_tui_set_threshold();

    /* Step 4: Select wipe algorithm */
    cfg->wipe_algorithm = vault_tui_select_algorithm();

    /* Step 5: Confirmation */
    clear();
    draw_banner(1);
    y = 9;
    attron(COLOR_PAIR(CP_DANGER) | A_BOLD);
    mvprintw(y++, 4, "WARNING: ShredOS Vault will be configured for %s",
             cfg->target_device);
    mvprintw(y++, 4, "Failed authentication will trigger the dead man's switch!");
    attroff(COLOR_PAIR(CP_DANGER) | A_BOLD);
    y++;
    mvprintw(y++, 4, "Press 'Y' to confirm, any other key to cancel.");
    refresh();

    int ch = getch();
    if (ch != 'Y' && ch != 'y')
        return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Success Screen                                                     */
/* ------------------------------------------------------------------ */

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
    refresh();

    while (1) {
        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;
    }
}

/* ------------------------------------------------------------------ */
/*  Dead Man's Switch Warning                                          */
/* ------------------------------------------------------------------ */

void vault_tui_deadman_warning(int countdown_seconds)
{
    clear();

    if (has_colors())
        bkgd(COLOR_PAIR(CP_DANGER));

    int y = LINES / 2 - 4;

    attron(A_BOLD | A_BLINK);
    const char *w1 = "!!! DEAD MAN'S SWITCH ACTIVATED !!!";
    mvprintw(y, (COLS - (int)strlen(w1)) / 2, "%s", w1);
    attroff(A_BLINK);

    y += 2;
    const char *w2 = "MAXIMUM AUTHENTICATION ATTEMPTS EXCEEDED";
    mvprintw(y++, (COLS - (int)strlen(w2)) / 2, "%s", w2);
    y++;
    const char *w3 = "Target drive will be ENCRYPTED and WIPED";
    mvprintw(y++, (COLS - (int)strlen(w3)) / 2, "%s", w3);
    y++;
    const char *w4 = "THIS CANNOT BE STOPPED OR REVERSED";
    mvprintw(y++, (COLS - (int)strlen(w4)) / 2, "%s", w4);
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

    if (has_colors())
        bkgd(COLOR_PAIR(CP_NORMAL));
}

/* ------------------------------------------------------------------ */
/*  Wiping Screen                                                      */
/* ------------------------------------------------------------------ */

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
    mvprintw(y, (COLS - 45) / 2,
             "Do NOT power off. This may take a long time.");
    refresh();
}

/* ------------------------------------------------------------------ */
/*  Status / Error                                                     */
/* ------------------------------------------------------------------ */

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
        clear();
        draw_banner(1);
        int y = 9;

        attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvprintw(y++, 4, "Select target device:");
        attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
        y++;

        for (int i = 0; i < count; i++) {
            if (i == sel) attron(COLOR_PAIR(CP_INPUT) | A_REVERSE);
            mvprintw(y + i, 6, "  %-20s  %s  ", devices[i], sizes[i]);
            if (i == sel) attroff(COLOR_PAIR(CP_INPUT) | A_REVERSE);
        }

        mvprintw(y + count + 2, 4,
                 "UP/DOWN to select, ENTER to confirm, 'q' to cancel");
        refresh();

        int ch = getch();
        if (ch == KEY_UP && sel > 0) sel--;
        else if (ch == KEY_DOWN && sel < count - 1) sel++;
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) break;
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
        clear();
        draw_banner(1);
        int y = 10;

        mvprintw(y, 4, "Enter new password: ");
        int n1 = read_password_masked(y, 25, pass1, (int)sizeof(pass1) - 1);

        y += 2;
        mvprintw(y, 4, "Confirm password:   ");
        read_password_masked(y, 25, pass2, (int)sizeof(pass2) - 1);

        if (n1 == 0) {
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

/* ------------------------------------------------------------------ */
/*  Select Algorithm                                                   */
/* ------------------------------------------------------------------ */

wipe_algorithm_t vault_tui_select_algorithm(void)
{
    const char *names[] = {
        "Gutmann (35-pass) - Most thorough",
        "DoD 5220.22-M (7-pass) - US Government standard",
        "DoD Short (3-pass) - Fast government standard",
        "PRNG Stream - Random data overwrite",
        "Zero Fill - Single pass with zeros",
    };
    int count = 5;
    int sel = 0;

    while (1) {
        clear();
        draw_banner(1);
        int y = 9;

        attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvprintw(y++, 4, "Select wipe algorithm for dead man's switch:");
        attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
        y++;

        for (int i = 0; i < count; i++) {
            if (i == sel) attron(COLOR_PAIR(CP_INPUT) | A_REVERSE);
            mvprintw(y + i, 6, "  %s  ", names[i]);
            if (i == sel) attroff(COLOR_PAIR(CP_INPUT) | A_REVERSE);
        }

        mvprintw(y + count + 2, 4, "UP/DOWN to select, ENTER to confirm");
        refresh();

        int ch = getch();
        if (ch == KEY_UP && sel > 0) sel--;
        else if (ch == KEY_DOWN && sel < count - 1) sel++;
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER)
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
        clear();
        draw_banner(1);
        int y = 9;

        attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvprintw(y++, 4, "Set failure threshold:");
        attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
        y++;

        mvprintw(y++, 6, "After this many failed attempts,");
        mvprintw(y++, 6, "the dead man's switch will wipe the drive.");
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

/* ------------------------------------------------------------------ */
/*  Generic Menu Select                                                */
/* ------------------------------------------------------------------ */

int vault_tui_menu_select(const char *title, const char **labels,
                           int count, int default_sel)
{
    int sel = default_sel;
    if (sel < 0 || sel >= count) sel = 0;

    while (1) {
        clear();
        draw_banner(1);
        int y = 9;

        attron(COLOR_PAIR(CP_TITLE) | A_BOLD);
        mvprintw(y++, 4, "%s", title);
        attroff(COLOR_PAIR(CP_TITLE) | A_BOLD);
        y++;

        for (int i = 0; i < count; i++) {
            if (i == sel) attron(COLOR_PAIR(CP_INPUT) | A_REVERSE);
            mvprintw(y + i, 6, "  %s  ", labels[i]);
            if (i == sel) attroff(COLOR_PAIR(CP_INPUT) | A_REVERSE);
        }

        mvprintw(y + count + 2, 4,
                 "UP/DOWN to select, ENTER to confirm, 'q' to cancel");
        refresh();

        int ch = getch();
        if (ch == KEY_UP && sel > 0) sel--;
        else if (ch == KEY_DOWN && sel < count - 1) sel++;
        else if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) return sel;
        else if (ch == 'q' || ch == 'Q') return -1;
    }
}

#endif /* HAVE_NCURSES */
