#ifndef VAULT_AUTH_VOICE_H
#define VAULT_AUTH_VOICE_H

#include "auth.h"

#ifdef HAVE_VOICE

/*
 * Check if voice authentication hardware (microphone) is available.
 * Returns true if a recording device is detected.
 */
bool vault_auth_voice_available(void);

/*
 * Verify spoken passphrase against stored text.
 * Records audio, runs speech-to-text, compares result.
 * Returns AUTH_SUCCESS on match, AUTH_FAILURE on mismatch.
 */
auth_result_t vault_auth_voice_verify(const vault_config_t *cfg);

/*
 * Initialize the voice recognition subsystem.
 * Sets up PortAudio and PocketSphinx.
 * Returns 0 on success.
 */
int vault_auth_voice_init(void);

/*
 * Cleanup the voice recognition subsystem.
 */
void vault_auth_voice_cleanup(void);

#endif /* HAVE_VOICE */

#endif /* VAULT_AUTH_VOICE_H */
