/*
 * vault-gate-service.c -- Windows Service for ShredOS Vault
 *
 * Runs as a Windows service with SYSTEM privileges.
 * Handles vault authentication before user login.
 *
 * Build with MSVC:
 *   cl /O2 /W4 /DUNICODE /D_UNICODE /DVAULT_PLATFORM_WINDOWS
 *      ..\platform.c ..\config.c ..\auth.c ..\auth_password.c
 *      ..\luks.c ..\wipe.c ..\deadman.c ..\tui_win32.c
 *      vault-gate-service.c
 *      advapi32.lib crypt32.lib /Fe:shredos-vault-service.exe
 *
 * Copyright 2025 -- GPL-2.0+
 */

#ifdef VAULT_PLATFORM_WINDOWS

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

#define SERVICE_NAME "ShredOSVault"

static SERVICE_STATUS svc_status;
static SERVICE_STATUS_HANDLE svc_handle;

static void WINAPI ServiceCtrlHandler(DWORD ctrl)
{
    /* Ignore stop requests -- non-interruptible */
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        /* Do not stop -- vault must complete */
        break;
    }
}

static void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
    (void)argc; (void)argv;

    svc_handle = RegisterServiceCtrlHandlerA(SERVICE_NAME,
                                              ServiceCtrlHandler);
    if (!svc_handle) return;

    svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    svc_status.dwCurrentState = SERVICE_RUNNING;
    svc_status.dwControlsAccepted = 0; /* Accept nothing -- non-interruptible */
    SetServiceStatus(svc_handle, &svc_status);

    /* Run vault in auth mode */
    /* In a real implementation, this would call main() or vault_auth_run() */
    /* For now, this is a skeleton */

    svc_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(svc_handle, &svc_status);
}

int main(void)
{
    SERVICE_TABLE_ENTRYA table[] = {
        { SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherA(table)) {
        /* Running interactively */
        fprintf(stderr, "ShredOS Vault service must be started by SCM.\n");
        fprintf(stderr, "Use install.bat to register the service.\n");
        return 1;
    }
    return 0;
}

#endif /* VAULT_PLATFORM_WINDOWS */
