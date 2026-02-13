/*
 * tui.h -- Terminal UI Interface Contract
 *
 * Three backends: ncurses, VT100 (raw escape codes), Win32 console.
 * Only one is compiled based on HAVE_NCURSES / VAULT_PLATFORM_WINDOWS.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_TUI_H
#define VAULT_TUI_H

#include "config.h"
#include <stdarg.h>

/* Initialise the TUI. Returns 0 on success. */
int vault_tui_init(void);

/* Shut down the TUI and restore terminal state. */
void vault_tui_shutdown(void);

/* Show the login screen and read password.
 * Returns number of chars read, or -1 on error. */
int vault_tui_login_screen(const vault_config_t *cfg,
                            char *password_out, size_t password_size);

/* Run the first-time setup wizard. Returns 0 on success, -1 on cancel. */
int vault_tui_setup_screen(vault_config_t *cfg);

/* Show the "authentication successful" screen. Waits for keypress. */
void vault_tui_success_screen(const vault_config_t *cfg);

/* Show the dead man's switch warning with countdown. */
void vault_tui_deadman_warning(int countdown_seconds);

/* Show the wipe-in-progress screen. */
void vault_tui_wiping_screen(const char *device, const char *algorithm_name);

/* Display a status message. */
void vault_tui_status(const char *fmt, ...);

/* Display an error message and wait for keypress. */
void vault_tui_error(const char *fmt, ...);

/* Prompt user to select a block device.
 * Returns 0 on success, -1 on cancel. */
int vault_tui_select_device(char *device_out, size_t device_size);

/* Prompt user to enter and confirm a new password.
 * Returns 0 on success, -1 on cancel. */
int vault_tui_new_password(char *password_out, size_t password_size);

/* Prompt user to select a wipe algorithm. */
wipe_algorithm_t vault_tui_select_algorithm(void);

/* Prompt user to set the failure threshold (1-99). */
int vault_tui_set_threshold(void);

/* Generic menu selection.
 * Returns selected index (0-based), or -1 on cancel. */
int vault_tui_menu_select(const char *title, const char **labels,
                           int count, int default_sel);

#endif /* VAULT_TUI_H */
