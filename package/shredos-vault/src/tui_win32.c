/*
 * tui_win32.c -- Windows Console TUI Backend
 *
 * Uses Windows Console API for the vault UI.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifdef VAULT_PLATFORM_WINDOWS

#include "tui.h"
#include "auth_password.h"
#include "platform.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static HANDLE hConsole;
static WORD origAttrs;

#define ATTR_NORMAL  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
#define ATTR_TITLE   (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define ATTR_ERROR   (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define ATTR_SUCCESS (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define ATTR_DANGER  (BACKGROUND_RED | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define ATTR_INPUT   (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define ATTR_STATUS  (BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)

static void con_clear(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    DWORD size = csbi.dwSize.X * csbi.dwSize.Y;
    COORD origin = {0, 0};
    DWORD written;
    FillConsoleOutputCharacterA(hConsole, ' ', size, origin, &written);
    FillConsoleOutputAttribute(hConsole, origAttrs, size, origin, &written);
    SetConsoleCursorPosition(hConsole, origin);
}

static void con_goto(int row, int col)
{
    COORD pos = {(SHORT)col, (SHORT)row};
    SetConsoleCursorPosition(hConsole, pos);
}

int vault_tui_init(void)
{
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    origAttrs = csbi.wAttributes;

    /* Disable Ctrl+C */
    SetConsoleCtrlHandler(NULL, TRUE);
    con_clear();
    return 0;
}

void vault_tui_shutdown(void)
{
    SetConsoleTextAttribute(hConsole, origAttrs);
    con_clear();
}

int vault_tui_login_screen(const vault_config_t *cfg,
                            char *password_out, size_t password_size)
{
    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_TITLE);
    con_goto(2, 10);
    printf("ShredOS Vault - Authentication");

    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
    con_goto(5, 10);
    printf("Attempt %d of %d", cfg->current_attempts + 1, cfg->max_attempts);

    con_goto(7, 10);
    printf("Password: ");

    /* Read password with masking */
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode;
    GetConsoleMode(hInput, &oldMode);
    SetConsoleMode(hInput, oldMode & ~ENABLE_ECHO_INPUT);

    int pos = 0;
    int max = (int)password_size - 1;
    while (1) {
        DWORD nread;
        char ch;
        ReadConsoleA(hInput, &ch, 1, &nread, NULL);
        if (ch == '\r' || ch == '\n') break;
        if (ch == '\b' && pos > 0) {
            pos--;
            printf("\b \b");
        } else if (pos < max && ch >= 32 && ch <= 126) {
            password_out[pos++] = ch;
            printf("*");
        }
    }
    password_out[pos] = '\0';
    SetConsoleMode(hInput, oldMode);
    printf("\n");
    return pos;
}

int vault_tui_setup_screen(vault_config_t *cfg)
{
    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_TITLE);
    con_goto(2, 10);
    printf("ShredOS Vault - Setup Wizard");
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);

    if (vault_tui_select_device(cfg->target_device,
                                 sizeof(cfg->target_device)) != 0)
        return -1;

    char password[256];
    if (vault_tui_new_password(password, sizeof(password)) != 0)
        return -1;
    vault_auth_password_hash(password, cfg->password_hash,
                              sizeof(cfg->password_hash));
    vault_secure_memzero(password, sizeof(password));

    cfg->max_attempts = vault_tui_set_threshold();
    cfg->wipe_algorithm = vault_tui_select_algorithm();

    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_DANGER);
    con_goto(5, 5);
    printf("WARNING: Vault will protect %s", cfg->target_device);
    con_goto(7, 5);
    printf("Press 'Y' to confirm: ");
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);

    DWORD nread;
    char ch;
    ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), &ch, 1, &nread, NULL);
    return (ch == 'Y' || ch == 'y') ? 0 : -1;
}

void vault_tui_success_screen(const vault_config_t *cfg)
{
    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_SUCCESS);
    con_goto(5, 10);
    printf("AUTHENTICATION SUCCESSFUL");
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
    con_goto(7, 10);
    printf("Volume mounted at: %s", cfg->mount_point);
    con_goto(9, 10);
    printf("Press 'q' to lock and shutdown.");

    DWORD nread;
    char ch;
    while (1) {
        ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), &ch, 1, &nread, NULL);
        if (ch == 'q' || ch == 'Q') break;
    }
}

void vault_tui_deadman_warning(int countdown_seconds)
{
    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_DANGER);
    con_goto(5, 5);
    printf("!!! DEAD MAN'S SWITCH ACTIVATED !!!");
    con_goto(7, 5);
    printf("MAXIMUM AUTHENTICATION ATTEMPTS EXCEEDED");
    con_goto(9, 5);
    printf("Target drive will be ENCRYPTED and WIPED");
    con_goto(11, 5);
    printf("THIS CANNOT BE STOPPED OR REVERSED");

    for (int i = countdown_seconds; i > 0; i--) {
        con_goto(14, 5);
        printf("Starting in %d seconds...  ", i);
        Sleep(1000);
    }
    con_goto(14, 5);
    printf("INITIATING WIPE SEQUENCE     ");
    Sleep(1000);
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
}

void vault_tui_wiping_screen(const char *device, const char *algorithm_name)
{
    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_ERROR);
    con_goto(5, 10);
    printf("WIPING IN PROGRESS");
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
    con_goto(7, 10);
    printf("Device:    %s", device);
    con_goto(8, 10);
    printf("Algorithm: %s", algorithm_name);
    con_goto(10, 10);
    printf("Do NOT power off.");
}

void vault_tui_status(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    SetConsoleTextAttribute(hConsole, ATTR_STATUS);
    con_goto(23, 0);
    printf("%-79s", buf);
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
}

void vault_tui_error(const char *fmt, ...)
{
    va_list ap;
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    SetConsoleTextAttribute(hConsole, ATTR_ERROR);
    con_goto(12, 10);
    printf("ERROR: %s", buf);
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
    con_goto(14, 10);
    printf("Press any key...");
    DWORD nread;
    char ch;
    ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), &ch, 1, &nread, NULL);
}

int vault_tui_select_device(char *device_out, size_t device_size)
{
    /* Windows: list physical drives */
    const char *labels[16];
    char bufs[16][64];
    int count = 0;

    for (int i = 0; i < 16; i++) {
        char path[64];
        snprintf(path, sizeof(path), "\\\\.\\PhysicalDrive%d", i);
        HANDLE h = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        CloseHandle(h);
        snprintf(bufs[count], sizeof(bufs[count]), "PhysicalDrive%d", i);
        labels[count] = bufs[count];
        count++;
    }

    if (count == 0) {
        vault_tui_error("No drives found!");
        return -1;
    }

    int sel = vault_tui_menu_select("Select target drive:", labels, count, 0);
    if (sel < 0) return -1;

    snprintf(device_out, device_size, "\\\\.\\PhysicalDrive%d", sel);
    return 0;
}

int vault_tui_new_password(char *password_out, size_t password_size)
{
    /* Simplified for Win32 console */
    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_TITLE);
    con_goto(3, 10);
    printf("Set Password");
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);

    char pass1[256], pass2[256];
    while (1) {
        con_goto(5, 10);
        printf("Password: ");
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        DWORD oldMode;
        GetConsoleMode(hIn, &oldMode);
        SetConsoleMode(hIn, oldMode & ~ENABLE_ECHO_INPUT);

        int p = 0;
        DWORD nr;
        char ch;
        while (1) {
            ReadConsoleA(hIn, &ch, 1, &nr, NULL);
            if (ch == '\r') break;
            if (ch == '\b' && p > 0) { p--; printf("\b \b"); }
            else if (p < 255 && ch >= 32) { pass1[p++] = ch; printf("*"); }
        }
        pass1[p] = '\0';
        printf("\n");

        con_goto(7, 10);
        printf("Confirm:  ");
        int p2 = 0;
        while (1) {
            ReadConsoleA(hIn, &ch, 1, &nr, NULL);
            if (ch == '\r') break;
            if (ch == '\b' && p2 > 0) { p2--; printf("\b \b"); }
            else if (p2 < 255 && ch >= 32) { pass2[p2++] = ch; printf("*"); }
        }
        pass2[p2] = '\0';
        SetConsoleMode(hIn, oldMode);
        printf("\n");

        if (p == 0) { vault_tui_error("Password cannot be empty!"); continue; }
        if (strcmp(pass1, pass2) != 0) { vault_tui_error("Mismatch!"); continue; }

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
        "Gutmann (35-pass)", "DoD 5220.22-M (7-pass)",
        "DoD Short (3-pass)", "PRNG Stream", "Zero Fill",
    };
    int sel = vault_tui_menu_select("Select wipe algorithm:", names, 5, 0);
    return (sel >= 0) ? (wipe_algorithm_t)sel : WIPE_GUTMANN;
}

int vault_tui_set_threshold(void)
{
    con_clear();
    SetConsoleTextAttribute(hConsole, ATTR_TITLE);
    con_goto(3, 10);
    printf("Set Failure Threshold (1-99)");
    SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
    con_goto(5, 10);
    printf("Enter threshold: ");

    char buf[8];
    DWORD nr;
    ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), buf, sizeof(buf) - 1, &nr, NULL);
    buf[nr] = '\0';
    int n = atoi(buf);
    if (n < 1) n = 1;
    if (n > 99) n = 99;
    return n;
}

int vault_tui_menu_select(const char *title, const char **labels,
                           int count, int default_sel)
{
    int sel = default_sel;
    if (sel < 0 || sel >= count) sel = 0;

    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode;
    GetConsoleMode(hIn, &oldMode);
    SetConsoleMode(hIn, ENABLE_PROCESSED_INPUT);

    while (1) {
        con_clear();
        SetConsoleTextAttribute(hConsole, ATTR_TITLE);
        con_goto(2, 5);
        printf("%s", title);
        SetConsoleTextAttribute(hConsole, ATTR_NORMAL);

        for (int i = 0; i < count; i++) {
            con_goto(4 + i, 7);
            if (i == sel)
                SetConsoleTextAttribute(hConsole,
                    BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            printf("  %s  ", labels[i]);
            SetConsoleTextAttribute(hConsole, ATTR_NORMAL);
        }

        con_goto(5 + count, 5);
        printf("UP/DOWN, ENTER to confirm, 'q' to cancel");

        INPUT_RECORD rec;
        DWORD nr;
        ReadConsoleInputA(hIn, &rec, 1, &nr);
        if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown) {
            WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;
            if (vk == VK_UP && sel > 0) sel--;
            else if (vk == VK_DOWN && sel < count - 1) sel++;
            else if (vk == VK_RETURN) { SetConsoleMode(hIn, oldMode); return sel; }
            else if (rec.Event.KeyEvent.uChar.AsciiChar == 'q') {
                SetConsoleMode(hIn, oldMode);
                return -1;
            }
        }
    }
}

#endif /* VAULT_PLATFORM_WINDOWS */
