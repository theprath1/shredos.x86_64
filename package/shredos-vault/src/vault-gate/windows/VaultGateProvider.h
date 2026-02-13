/*
 * VaultGateProvider.h -- Windows Credential Provider for ShredOS Vault
 *
 * Replaces the Windows login screen with the vault authentication gate.
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifndef VAULT_GATE_PROVIDER_H
#define VAULT_GATE_PROVIDER_H

#ifdef VAULT_PLATFORM_WINDOWS

#include <windows.h>
#include <credentialprovider.h>

/* GUID for ShredOS Vault Credential Provider */
/* {A1B2C3D4-E5F6-7890-ABCD-EF1234567890} */
DEFINE_GUID(CLSID_VaultGateProvider,
    0xa1b2c3d4, 0xe5f6, 0x7890,
    0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90);

#endif /* VAULT_PLATFORM_WINDOWS */
#endif /* VAULT_GATE_PROVIDER_H */
