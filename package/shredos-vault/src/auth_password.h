/*
 * auth_password.h -- Password Authentication (SHA-512)
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_AUTH_PASSWORD_H
#define VAULT_AUTH_PASSWORD_H

#include <stddef.h>

/* Hash a password with SHA-512 and random salt.
 * Writes the full $6$salt$hash string into hash_out.
 * Returns 0 on success, -1 on failure. */
int vault_auth_password_hash(const char *password,
                              char *hash_out, size_t hash_out_size);

/* Verify a password against a stored hash.
 * Returns 1 if match, 0 if no match. */
int vault_auth_password_verify(const char *password, const char *stored_hash);

#endif /* VAULT_AUTH_PASSWORD_H */
