#ifndef VAULT_DEADMAN_H
#define VAULT_DEADMAN_H

#include "config.h"

/*
 * Execute the dead man's switch sequence:
 *  1. Display warning countdown on TUI (5 seconds, non-cancellable)
 *  2. Encrypt target device with random key (destroys LUKS header)
 *  3. Wipe device using configured algorithm via nwipe
 *  4. Sync all filesystems
 *  5. Power off the machine
 *
 * This function does NOT return on success.
 * Returns -1 only if it fails to initiate the sequence.
 */
int vault_deadman_trigger(vault_config_t *cfg);

#endif /* VAULT_DEADMAN_H */
