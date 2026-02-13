/*
 * auth.h -- Authentication Dispatcher
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_AUTH_H
#define VAULT_AUTH_H

#include "config.h"

typedef enum {
    AUTH_SUCCESS = 0,
    AUTH_FAILED  = 1,
} auth_result_t;

/* Run the authentication loop.
 * Prompts the user up to cfg->max_attempts times.
 * Returns AUTH_SUCCESS or AUTH_FAILED. */
auth_result_t vault_auth_run(vault_config_t *cfg);

#endif /* VAULT_AUTH_H */
