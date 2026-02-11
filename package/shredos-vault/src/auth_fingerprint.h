#ifndef VAULT_AUTH_FINGERPRINT_H
#define VAULT_AUTH_FINGERPRINT_H

#include "auth.h"

#ifdef HAVE_FINGERPRINT

/*
 * Check if a fingerprint reader is available.
 * Returns true if a compatible reader is detected.
 */
bool vault_auth_fingerprint_available(void);

/*
 * Verify a fingerprint against enrolled prints.
 * Blocks until finger is placed on reader or timeout.
 * Returns AUTH_SUCCESS on match, AUTH_FAILURE on mismatch.
 */
auth_result_t vault_auth_fingerprint_verify(const vault_config_t *cfg);

/*
 * Enroll a new fingerprint during setup.
 * Guides user through multiple scans.
 * Saves fingerprint data to the config directory.
 * Returns 0 on success, -1 on failure.
 */
int vault_auth_fingerprint_enroll(const char *storage_dir);

/*
 * Initialize the fingerprint subsystem.
 * Must be called before verify/enroll.
 * Returns 0 on success.
 */
int vault_auth_fingerprint_init(void);

/*
 * Cleanup the fingerprint subsystem.
 */
void vault_auth_fingerprint_cleanup(void);

#endif /* HAVE_FINGERPRINT */

#endif /* VAULT_AUTH_FINGERPRINT_H */
