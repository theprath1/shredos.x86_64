#ifndef VAULT_AUTH_PASSWORD_H
#define VAULT_AUTH_PASSWORD_H

#include "auth.h"

/*
 * Verify password against stored SHA-512 hash.
 * Prompts user via TUI and returns result.
 */
auth_result_t vault_auth_password_verify(const vault_config_t *cfg,
                                          const char *input);

/*
 * Hash a plaintext password using SHA-512 with salt.
 * Stores result in hash_out (must be at least 256 bytes).
 * Returns 0 on success.
 */
int vault_auth_password_hash(const char *password, char *hash_out,
                              size_t hash_out_size);

#endif /* VAULT_AUTH_PASSWORD_H */
