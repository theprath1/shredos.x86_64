#ifndef VAULT_TUI_H
#define VAULT_TUI_H

#include "config.h"
#include <stdbool.h>

/* TUI screen identifiers */
typedef enum {
    TUI_SCREEN_LOGIN,
    TUI_SCREEN_SETUP,
    TUI_SCREEN_SUCCESS,
    TUI_SCREEN_DEADMAN_WARNING,
    TUI_SCREEN_WIPING,
} tui_screen_t;

/* Initialize ncurses TUI. Returns 0 on success. */
int vault_tui_init(void);

/* Shutdown ncurses TUI. */
void vault_tui_shutdown(void);

/* Draw the login screen and prompt for password.
 * password_out must be at least 256 bytes.
 * Returns number of chars read, or -1 on error. */
int vault_tui_login_screen(const vault_config_t *cfg, char *password_out,
                            size_t password_size);

/* Draw the setup screen. Returns 0 on success. */
int vault_tui_setup_screen(vault_config_t *cfg);

/* Draw success screen (volume unlocked). Waits for keypress. */
void vault_tui_success_screen(const vault_config_t *cfg);

/* Draw dead man's switch warning with countdown.
 * countdown_seconds: seconds to display before returning. */
void vault_tui_deadman_warning(int countdown_seconds);

/* Draw wiping-in-progress screen. */
void vault_tui_wiping_screen(const char *device, const char *algorithm_name);

/* Display a status message on the current screen. */
void vault_tui_status(const char *fmt, ...);

/* Display an error message and wait for keypress. */
void vault_tui_error(const char *fmt, ...);

/* Prompt user to select a device from available block devices.
 * device_out must be at least VAULT_CONFIG_MAX_PATH bytes.
 * Returns 0 on success, -1 if cancelled. */
int vault_tui_select_device(char *device_out, size_t device_size);

/* Prompt user to enter and confirm a new password.
 * password_out must be at least 256 bytes.
 * Returns 0 on success, -1 if cancelled. */
int vault_tui_new_password(char *password_out, size_t password_size);

/* Prompt user to select wipe algorithm.
 * Returns selected algorithm. */
wipe_algorithm_t vault_tui_select_algorithm(void);

/* Prompt user to set max attempts threshold.
 * Returns the threshold value (1-99). */
int vault_tui_set_threshold(void);

#endif /* VAULT_TUI_H */
