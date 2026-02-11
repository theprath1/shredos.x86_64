/*
 * config.c — Configuration Management
 *
 * Supports two backends:
 *   - libconfig (rich format with arrays, used on Linux with libconfig)
 *   - INI (lightweight key=value, used when libconfig is not available)
 *
 * Both backends read/write the full vault_config_t structure.
 *
 * Copyright 2025 — GPL-2.0+
 */

#include "config.h"
#include "platform.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#ifndef VAULT_PLATFORM_WINDOWS
#include <sys/stat.h>
#endif

/* ------------------------------------------------------------------ */
/*  Algorithm name/flag tables (shared by both backends)               */
/* ------------------------------------------------------------------ */

static const char *wipe_algorithm_names[] = {
    [WIPE_GUTMANN]     = "Gutmann (35-pass)",
    [WIPE_DOD_522022]  = "DoD 5220.22-M (7-pass)",
    [WIPE_DOD_SHORT]   = "DoD Short (3-pass)",
    [WIPE_RANDOM]      = "PRNG Stream",
    [WIPE_ZERO]        = "Zero Fill",
    [WIPE_VERIFY_ONLY] = "Verify Only",
};

static const char *wipe_algorithm_nwipe_flags[] = {
    [WIPE_GUTMANN]     = "--method=gutmann",
    [WIPE_DOD_522022]  = "--method=dod522022m",
    [WIPE_DOD_SHORT]   = "--method=dodshort",
    [WIPE_RANDOM]      = "--method=random",
    [WIPE_ZERO]        = "--method=zero",
    [WIPE_VERIFY_ONLY] = "--method=verify",
};

static const char *wipe_algorithm_config_names[] = {
    "gutmann", "dod522022m", "dodshort", "random", "zero", "verify"
};

/* ------------------------------------------------------------------ */
/*  Defaults                                                           */
/* ------------------------------------------------------------------ */

void vault_config_init(vault_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->auth_methods = AUTH_METHOD_PASSWORD;
    cfg->max_attempts = 3;
    cfg->wipe_algorithm = WIPE_GUTMANN;
    cfg->encrypt_before_wipe = true;
    cfg->verify_passes = false;
    strncpy(cfg->mount_point, VAULT_MOUNT_POINT, sizeof(cfg->mount_point) - 1);
    cfg->current_attempts = 0;
    cfg->setup_mode = false;
    cfg->config_loaded = false;
}

const char *vault_wipe_algorithm_name(wipe_algorithm_t alg)
{
    if (alg >= WIPE_COUNT)
        return "Unknown";
    return wipe_algorithm_names[alg];
}

const char *vault_wipe_algorithm_nwipe_flag(wipe_algorithm_t alg)
{
    if (alg >= WIPE_COUNT)
        return "--method=gutmann";
    return wipe_algorithm_nwipe_flags[alg];
}

/* ------------------------------------------------------------------ */
/*  Shared helpers                                                     */
/* ------------------------------------------------------------------ */

static wipe_algorithm_t parse_algorithm_string(const char *str)
{
    if (strcasecmp(str, "gutmann") == 0)     return WIPE_GUTMANN;
    if (strcasecmp(str, "dod522022m") == 0)  return WIPE_DOD_522022;
    if (strcasecmp(str, "dod") == 0)         return WIPE_DOD_522022;
    if (strcasecmp(str, "dodshort") == 0)    return WIPE_DOD_SHORT;
    if (strcasecmp(str, "schneier") == 0)    return WIPE_DOD_SHORT;
    if (strcasecmp(str, "random") == 0)      return WIPE_RANDOM;
    if (strcasecmp(str, "zero") == 0)        return WIPE_ZERO;
    if (strcasecmp(str, "verify") == 0)      return WIPE_VERIFY_ONLY;
    return WIPE_GUTMANN;
}

#ifndef VAULT_CONFIG_BACKEND_LIBCONFIG
static int parse_bool_string(const char *str)
{
    if (strcasecmp(str, "true") == 0 || strcasecmp(str, "yes") == 0 ||
        strcmp(str, "1") == 0)
        return 1;
    return 0;
}
#endif

/* ================================================================== */
/*  LIBCONFIG BACKEND                                                  */
/* ================================================================== */

#ifdef VAULT_CONFIG_BACKEND_LIBCONFIG

#include <libconfig.h>

int vault_config_load(vault_config_t *cfg, const char *path)
{
    config_t libcfg;
    int ret = -1;

    config_init(&libcfg);

    if (config_read_file(&libcfg, path) != CONFIG_TRUE) {
        fprintf(stderr, "vault: config error %s:%d - %s\n",
                config_error_file(&libcfg),
                config_error_line(&libcfg),
                config_error_text(&libcfg));
        goto out;
    }

    /* Authentication settings */
    int methods = 0;
    config_setting_t *auth_list = config_lookup(&libcfg, "auth_methods");
    if (auth_list && config_setting_is_array(auth_list)) {
        int count = config_setting_length(auth_list);
        for (int i = 0; i < count; i++) {
            const char *m = config_setting_get_string_elem(auth_list, i);
            if (m) {
                if (strcmp(m, "password") == 0)
                    methods |= AUTH_METHOD_PASSWORD;
                else if (strcmp(m, "fingerprint") == 0)
                    methods |= AUTH_METHOD_FINGERPRINT;
                else if (strcmp(m, "voice") == 0)
                    methods |= AUTH_METHOD_VOICE;
            }
        }
    }
    if (methods)
        cfg->auth_methods = methods;

    int max_attempts;
    if (config_lookup_int(&libcfg, "max_attempts", &max_attempts))
        cfg->max_attempts = max_attempts;

    const char *str;
    if (config_lookup_string(&libcfg, "password_hash", &str))
        strncpy(cfg->password_hash, str, sizeof(cfg->password_hash) - 1);

    if (config_lookup_string(&libcfg, "voice_passphrase", &str))
        strncpy(cfg->voice_passphrase, str, sizeof(cfg->voice_passphrase) - 1);

    /* Target device */
    if (config_lookup_string(&libcfg, "target_device", &str))
        strncpy(cfg->target_device, str, sizeof(cfg->target_device) - 1);

    if (config_lookup_string(&libcfg, "mount_point", &str))
        strncpy(cfg->mount_point, str, sizeof(cfg->mount_point) - 1);

    /* Wipe settings */
    if (config_lookup_string(&libcfg, "wipe_algorithm", &str))
        cfg->wipe_algorithm = parse_algorithm_string(str);

    int bval;
    if (config_lookup_bool(&libcfg, "encrypt_before_wipe", &bval))
        cfg->encrypt_before_wipe = bval;

    if (config_lookup_bool(&libcfg, "verify_passes", &bval))
        cfg->verify_passes = bval;

    cfg->config_loaded = true;
    ret = 0;

out:
    config_destroy(&libcfg);
    return ret;
}

int vault_config_save(const vault_config_t *cfg, const char *path)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "vault: cannot write config to %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(fp, "# ShredOS Vault Configuration\n");
    fprintf(fp, "# Auto-generated - edit with care\n\n");

    /* Auth methods */
    fprintf(fp, "auth_methods = [");
    int first = 1;
    if (cfg->auth_methods & AUTH_METHOD_PASSWORD) {
        fprintf(fp, "\"password\"");
        first = 0;
    }
    if (cfg->auth_methods & AUTH_METHOD_FINGERPRINT) {
        fprintf(fp, "%s\"fingerprint\"", first ? "" : ", ");
        first = 0;
    }
    if (cfg->auth_methods & AUTH_METHOD_VOICE) {
        fprintf(fp, "%s\"voice\"", first ? "" : ", ");
    }
    fprintf(fp, "];\n\n");

    fprintf(fp, "max_attempts = %d;\n\n", cfg->max_attempts);

    if (cfg->password_hash[0])
        fprintf(fp, "password_hash = \"%s\";\n\n", cfg->password_hash);

    if (cfg->voice_passphrase[0])
        fprintf(fp, "voice_passphrase = \"%s\";\n\n", cfg->voice_passphrase);

    /* Target */
    fprintf(fp, "target_device = \"%s\";\n", cfg->target_device);
    fprintf(fp, "mount_point = \"%s\";\n\n", cfg->mount_point);

    /* Wipe */
    fprintf(fp, "wipe_algorithm = \"%s\";\n",
            wipe_algorithm_config_names[cfg->wipe_algorithm]);
    fprintf(fp, "encrypt_before_wipe = %s;\n",
            cfg->encrypt_before_wipe ? "true" : "false");
    fprintf(fp, "verify_passes = %s;\n",
            cfg->verify_passes ? "true" : "false");

    fclose(fp);
    return 0;
}

#else /* VAULT_CONFIG_BACKEND_INI */

/* ================================================================== */
/*  INI BACKEND (no libconfig dependency)                              */
/* ================================================================== */

static char *ini_trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) end--;
    *end = '\0';
    return s;
}

static void ini_strip_quotes(char *s)
{
    size_t len = strlen(s);
    if (len >= 2 && s[0] == '"' && s[len-1] == '"') {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

static unsigned int parse_auth_methods(const char *str)
{
    unsigned int methods = 0;
    /* Handle both comma-separated and libconfig array formats */
    if (strstr(str, "password"))    methods |= AUTH_METHOD_PASSWORD;
    if (strstr(str, "fingerprint")) methods |= AUTH_METHOD_FINGERPRINT;
    if (strstr(str, "voice"))       methods |= AUTH_METHOD_VOICE;
    return methods ? methods : AUTH_METHOD_PASSWORD;
}

int vault_config_load(vault_config_t *cfg, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *trimmed = ini_trim(line);

        if (!*trimmed || *trimmed == '#' || *trimmed == ';')
            continue;

        char *eq = strchr(trimmed, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key   = ini_trim(trimmed);
        char *value = ini_trim(eq + 1);

        /* Strip trailing semicolons (libconfig compat) */
        size_t vlen = strlen(value);
        if (vlen > 0 && value[vlen-1] == ';') value[vlen-1] = '\0';
        value = ini_trim(value);

        /* Strip array brackets */
        if (value[0] == '[') {
            value++;
            char *rb = strchr(value, ']');
            if (rb) *rb = '\0';
        }

        ini_strip_quotes(value);

        if (strcmp(key, "auth_methods") == 0) {
            cfg->auth_methods = parse_auth_methods(value);
        }
        else if (strcmp(key, "max_attempts") == 0) {
            cfg->max_attempts = atoi(value);
            if (cfg->max_attempts < 1) cfg->max_attempts = 1;
            if (cfg->max_attempts > 100) cfg->max_attempts = 100;
        }
        else if (strcmp(key, "password_hash") == 0) {
            strncpy(cfg->password_hash, value,
                    sizeof(cfg->password_hash) - 1);
        }
        else if (strcmp(key, "voice_passphrase") == 0) {
            strncpy(cfg->voice_passphrase, value,
                    sizeof(cfg->voice_passphrase) - 1);
        }
        else if (strcmp(key, "target_device") == 0) {
            strncpy(cfg->target_device, value,
                    sizeof(cfg->target_device) - 1);
        }
        else if (strcmp(key, "mount_point") == 0) {
            strncpy(cfg->mount_point, value,
                    sizeof(cfg->mount_point) - 1);
        }
        else if (strcmp(key, "wipe_algorithm") == 0) {
            cfg->wipe_algorithm = parse_algorithm_string(value);
        }
        else if (strcmp(key, "encrypt_before_wipe") == 0) {
            cfg->encrypt_before_wipe = parse_bool_string(value);
        }
        else if (strcmp(key, "verify_passes") == 0) {
            cfg->verify_passes = parse_bool_string(value);
        }
    }

    fclose(fp);
    cfg->config_loaded = true;
    return 0;
}

int vault_config_save(const vault_config_t *cfg, const char *path)
{
    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "vault: cannot write config to %s: %s\n",
                path, strerror(errno));
        return -1;
    }

    fprintf(fp, "# ShredOS Vault Configuration\n");
    fprintf(fp, "# Auto-generated - edit with care\n\n");

    fprintf(fp, "auth_methods = ");
    int first = 1;
    if (cfg->auth_methods & AUTH_METHOD_PASSWORD) {
        fprintf(fp, "password");
        first = 0;
    }
    if (cfg->auth_methods & AUTH_METHOD_FINGERPRINT) {
        fprintf(fp, "%sfingerprint", first ? "" : ",");
        first = 0;
    }
    if (cfg->auth_methods & AUTH_METHOD_VOICE) {
        fprintf(fp, "%svoice", first ? "" : ",");
    }
    fprintf(fp, "\n\n");

    fprintf(fp, "max_attempts = %d\n\n", cfg->max_attempts);

    if (cfg->password_hash[0])
        fprintf(fp, "password_hash = \"%s\"\n\n", cfg->password_hash);

    if (cfg->voice_passphrase[0])
        fprintf(fp, "voice_passphrase = \"%s\"\n\n", cfg->voice_passphrase);

    if (cfg->target_device[0])
        fprintf(fp, "target_device = \"%s\"\n", cfg->target_device);
    fprintf(fp, "mount_point = \"%s\"\n\n", cfg->mount_point);

    fprintf(fp, "wipe_algorithm = %s\n",
            wipe_algorithm_config_names[cfg->wipe_algorithm]);
    fprintf(fp, "encrypt_before_wipe = %s\n",
            cfg->encrypt_before_wipe ? "true" : "false");
    fprintf(fp, "verify_passes = %s\n",
            cfg->verify_passes ? "true" : "false");

    fclose(fp);
    return 0;
}

#endif /* VAULT_CONFIG_BACKEND_LIBCONFIG / INI */
