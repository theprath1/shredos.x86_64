#include "auth.h"
#include "auth_password.h"
#include "tui.h"
#include <stdio.h>
#include <string.h>

#ifdef HAVE_FINGERPRINT
#include "auth_fingerprint.h"
#endif

#ifdef HAVE_VOICE
#include "auth_voice.h"
#endif

bool vault_auth_method_available(auth_method_t method)
{
    switch (method) {
    case AUTH_METHOD_PASSWORD:
        return true; /* Always available */

    case AUTH_METHOD_FINGERPRINT:
#ifdef HAVE_FINGERPRINT
        return vault_auth_fingerprint_available();
#else
        return false;
#endif

    case AUTH_METHOD_VOICE:
#ifdef HAVE_VOICE
        return vault_auth_voice_available();
#else
        return false;
#endif

    default:
        return false;
    }
}

auth_result_t vault_auth_run(vault_config_t *cfg)
{
    char password[256];
    auth_result_t result;

    while (cfg->current_attempts < cfg->max_attempts) {

        /* Password authentication */
        if (cfg->auth_methods & AUTH_METHOD_PASSWORD) {
            memset(password, 0, sizeof(password));

            int n = vault_tui_login_screen(cfg, password, sizeof(password));
            if (n <= 0) {
                cfg->current_attempts++;
                continue;
            }

            result = vault_auth_password_verify(cfg, password);

            /* Securely wipe password from memory */
            volatile char *vp = (volatile char *)password;
            for (size_t i = 0; i < sizeof(password); i++)
                vp[i] = 0;

            if (result == AUTH_SUCCESS)
                return AUTH_SUCCESS;

            cfg->current_attempts++;
            if (cfg->current_attempts < cfg->max_attempts) {
                vault_tui_error("Authentication failed. %d attempt(s) remaining.",
                                cfg->max_attempts - cfg->current_attempts);
            }
            continue;
        }

#ifdef HAVE_FINGERPRINT
        /* Fingerprint authentication */
        if (cfg->auth_methods & AUTH_METHOD_FINGERPRINT) {
            if (vault_auth_method_available(AUTH_METHOD_FINGERPRINT)) {
                vault_tui_status("Place your finger on the reader...");
                result = vault_auth_fingerprint_verify(cfg);
                if (result == AUTH_SUCCESS)
                    return AUTH_SUCCESS;

                cfg->current_attempts++;
                if (cfg->current_attempts < cfg->max_attempts) {
                    vault_tui_error("Fingerprint mismatch. %d attempt(s) remaining.",
                                    cfg->max_attempts - cfg->current_attempts);
                }
                continue;
            }
        }
#endif

#ifdef HAVE_VOICE
        /* Voice passphrase authentication */
        if (cfg->auth_methods & AUTH_METHOD_VOICE) {
            if (vault_auth_method_available(AUTH_METHOD_VOICE)) {
                vault_tui_status("Speak your passphrase now...");
                result = vault_auth_voice_verify(cfg);
                if (result == AUTH_SUCCESS)
                    return AUTH_SUCCESS;

                cfg->current_attempts++;
                if (cfg->current_attempts < cfg->max_attempts) {
                    vault_tui_error("Voice not recognized. %d attempt(s) remaining.",
                                    cfg->max_attempts - cfg->current_attempts);
                }
                continue;
            }
        }
#endif

        /* No available auth method matched — should not happen */
        cfg->current_attempts++;
    }

    /* Threshold exceeded */
    return AUTH_FAILURE;
}
