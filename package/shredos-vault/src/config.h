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
    char         password_hash[256];    /* SHA-512 hash of password */
    char         voice_passphrase[256]; /* Expected voice passphrase text */

    /* Target device */
    char         target_device[VAULT_CONFIG_MAX_PATH]; /* e.g. /dev/sda2 */
    char         mount_point[VAULT_CONFIG_MAX_PATH];   /* e.g. /vault */

    /* Wipe settings */
    wipe_algorithm_t wipe_algorithm;    /* Algorithm for auto-wipe */
    bool         encrypt_before_wipe;   /* Encrypt with random key first */
    bool         verify_passes;         /* Read-back verify after each wipe pass */

    /* Runtime state (not saved to file) */
    int          current_attempts;      /* Current failed attempt count */
    bool         setup_mode;            /* Running in setup mode */
    bool         config_loaded;         /* Config successfully loaded */
} vault_config_t;

/* Initialize config with defaults */
void vault_config_init(vault_config_t *cfg);

/* Load config from file. Returns 0 on success, -1 on error */
int vault_config_load(vault_config_t *cfg, const char *path);

/* Save config to file. Returns 0 on success, -1 on error */
int vault_config_save(const vault_config_t *cfg, const char *path);

/* Get human-readable name for wipe algorithm */
const char *vault_wipe_algorithm_name(wipe_algorithm_t alg);

/* Get nwipe method flag string for the algorithm */
const char *vault_wipe_algorithm_nwipe_flag(wipe_algorithm_t alg);

#endif /* VAULT_CONFIG_H */
