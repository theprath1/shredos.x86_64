/*
 * deadman.h -- Dead Man's Switch
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_DEADMAN_H
#define VAULT_DEADMAN_H

#include "config.h"

/* Trigger the dead man's switch. Non-interruptible.
 * Sequence: block signals -> warning -> encrypt -> wipe -> power off.
 * Does not return. */
int vault_deadman_trigger(vault_config_t *cfg);

#endif /* VAULT_DEADMAN_H */
