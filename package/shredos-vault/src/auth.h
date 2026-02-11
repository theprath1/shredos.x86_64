#ifndef VAULT_AUTH_H
#define VAULT_AUTH_H

#include "config.h"
#include <stdbool.h>

/* Result of an authentication attempt */
typedef enum {
    AUTH_SUCCESS = 0,
    AUTH_FAILURE,
    AUTH_ERROR,
    AUTH_SKIPPED,        /* Method not available (no hardware) */
} auth_result_t;

/*
 * Run the authentication loop.
 * Presents available auth methods and handles retries.
 * Returns AUTH_SUCCESS if authenticated, AUTH_FAILURE if threshold exceeded.
 */
auth_result_t vault_auth_run(vault_config_t *cfg);

/*
 * Check if a specific auth method is available on this hardware.
 */
bool vault_auth_method_available(auth_method_t method);

#endif /* VAULT_AUTH_H */
