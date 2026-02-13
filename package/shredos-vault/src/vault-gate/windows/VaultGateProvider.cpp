/*
 * VaultGateProvider.cpp -- Windows Credential Provider DLL
 *
 * Implements ICredentialProvider and ICredentialProviderCredential
 * to replace the Windows login screen with ShredOS Vault auth.
 *
 * Build with MSVC:
 *   cl /EHsc /LD /DUNICODE /D_UNICODE /DVAULT_PLATFORM_WINDOWS
 *      VaultGateProvider.cpp ..\auth_password.c ..\config.c ..\platform.c
 *      /link ole32.lib advapi32.lib shlwapi.lib crypt32.lib
 *      /OUT:VaultGateProvider.dll
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifdef VAULT_PLATFORM_WINDOWS

#include "VaultGateProvider.h"
#include <windows.h>
#include <stdio.h>

/* DLL entry point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL; (void)fdwReason; (void)lpvReserved;
    return TRUE;
}

/*
 * NOTE: Full ICredentialProvider implementation requires extensive COM
 * boilerplate. This file is a skeleton showing the structure.
 *
 * A complete implementation would:
 * 1. Implement ICredentialProvider::SetUsageScenario
 * 2. Implement ICredentialProvider::GetCredentialCount
 * 3. Implement ICredentialProvider::GetCredentialAt
 * 4. Implement ICredentialProviderCredential with password field
 * 5. Call vault auth on credential submission
 * 6. On failure, communicate with vault-gate-service for dead man's switch
 *
 * The service (vault-gate-service.exe) handles the actual wipe since
 * the Credential Provider runs in the LogonUI process and cannot
 * directly perform destructive disk operations.
 */

#endif /* VAULT_PLATFORM_WINDOWS */
