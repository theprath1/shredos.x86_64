/*
 * config.h -- Configuration Data Structures
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_CONFIG_H
#define VAULT_CONFIG_H

#include <stdbool.h>
#include "platform.h"

#define VAULT_CONFIG_PATH      VAULT_CONFIG_PATH_DEFAULT
#define VAULT_CONFIG_DIR       VAULT_CONFIG_DIR_DEFAULT
#define VAULT_CONFIG_MAX_PATH  256
#define VAULT_MOUNT_POINT      "/vault"
#define VAULT_DM_NAME          "vault_crypt"

/* Wipe algorithm identifiers */
typedef enum {
    WIPE_GUTMANN = 0,     /* Gutmann 35-pass */
    WIPE_DOD_522022,      /* DoD 5220.22-M 7-pass */
    WIPE_DOD_SHORT,       /* DoD Short 3-pass */
    WIPE_RANDOM,          /* PRNG stream */
    WIPE_ZERO,            /* Zero fill */
    WIPE_VERIFY_ONLY,     /* Verification pass only */
    WIPE_COUNT
} wipe_algorithm_t;

/* Authentication method flags */
typedef enum {
    AUTH_METHOD_PASSWORD    = (1 << 0),
    AUTH_METHOD_FINGERPRINT = (1 << 1),
    AUTH_METHOD_VOICE       = (1 << 2),
} auth_method_t;

typedef struct {
    /* Authentication */
    unsigned int auth_methods;          /* Bitmask of auth_method_t */
    int          max_attempts;          /* Threshold before auto-wipe */
    char         password_hash[256];    /* SHA-512 hash string */
    char         voice_passphrase[256]; /* Expected voice passphrase text */

    /* Target device */
    char         target_device[VAULT_CONFIG_MAX_PATH]; /* e.g. /dev/sda */
    char         mount_point[VAULT_CONFIG_MAX_PATH];   /* e.g. /vault */

    /* Wipe settings */
    wipe_algorithm_t wipe_algorithm;    /* Algorithm for dead man's switch */
    bool         encrypt_before_wipe;   /* Encrypt with random key first */
    bool         verify_passes;         /* Verify after each wipe pass */

    /* Runtime state (not persisted) */
    int          current_attempts;
    bool         setup_mode;
    bool         install_mode;          /* Install wizard from USB */
    bool         config_loaded;
} vault_config_t;

/* Initialise config with defaults */
void vault_config_init(vault_config_t *cfg);

/* Load config from file. Returns 0 on success, -1 on error. */
int vault_config_load(vault_config_t *cfg, const char *path);

/* Save config to file. Returns 0 on success, -1 on error. */
int vault_config_save(const vault_config_t *cfg, const char *path);

/* Human-readable name for a wipe algorithm */
const char *vault_wipe_algorithm_name(wipe_algorithm_t alg);

/* nwipe --method flag string for a wipe algorithm */
const char *vault_wipe_algorithm_nwipe_flag(wipe_algorithm_t alg);

#endif /* VAULT_CONFIG_H */
