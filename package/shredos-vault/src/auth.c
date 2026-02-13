/*
 * auth.c -- Authentication Dispatcher
 *
 * Runs the authentication loop, calling TUI for password input
 * and checking against the stored hash. Tracks failed attempts.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#include "auth.h"
#include "auth_password.h"
#include "tui.h"
#include "platform.h"

#include <string.h>

auth_result_t vault_auth_run(vault_config_t *cfg)
{
    char password[256];

    for (cfg->current_attempts = 0;
         cfg->current_attempts < cfg->max_attempts;
         cfg->current_attempts++) {

        memset(password, 0, sizeof(password));

        int n = vault_tui_login_screen(cfg, password, sizeof(password));
        if (n <= 0)
            continue;

        /* Check password */
        if (cfg->auth_methods & AUTH_METHOD_PASSWORD) {
            if (vault_auth_password_verify(password, cfg->password_hash)) {
                vault_secure_memzero(password, sizeof(password));
                return AUTH_SUCCESS;
            }
        }

        vault_secure_memzero(password, sizeof(password));
        vault_tui_status("Authentication failed. Try again.");
    }

    /* Threshold exceeded */
    return AUTH_FAILED;
}
