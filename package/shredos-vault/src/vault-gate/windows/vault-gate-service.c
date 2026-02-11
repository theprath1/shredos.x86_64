/*
 * vault-gate-service.c — Windows ShredOS Vault Wipe Service
 *
 * Runs as a Windows service (SYSTEM privileges). Listens on a named pipe
 * for commands from the Credential Provider. When triggered, wipes the
 * entire physical drive and shuts down.
 *
 * Build (MSVC):
 *   cl /O2 /W4 vault-gate-service.c ..\..\platform.c ..\..\config.c
 *      ..\..\auth_password.c ..\..\wipe.c ..\..\deadman.c
 *      advapi32.lib crypt32.lib /Fe:shredos-vault-service.exe
 *
 * Install:
 *   sc create ShredOSVault binPath= "C:\Program Files\ShredOS-Vault\shredos-vault-service.exe"
 *   sc start ShredOSVault
 *
 * Copyright 2025 — GPL-2.0+
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "../../config.h"
#include "../../wipe.h"
#include "../../deadman.h"
#include "../../platform.h"

#define SERVICE_NAME    "ShredOSVault"
#define PIPE_NAME       "\\\\.\\pipe\\VaultGateTrigger"
#define LOG_FILE        "C:\\ProgramData\\ShredOS-Vault\\shredos-vault.log"
#define CONFIG_PATH     "C:\\ProgramData\\ShredOS-Vault\\vault.conf"

/* ------------------------------------------------------------------ */
/*  Service globals                                                    */
/* ------------------------------------------------------------------ */

static SERVICE_STATUS        g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle;
static HANDLE                g_StopEvent = NULL;
static FILE                 *g_LogFile   = NULL;

/* ------------------------------------------------------------------ */
/*  Logging                                                            */
/* ------------------------------------------------------------------ */

static void log_msg(const char *fmt, ...)
{
    if (!g_LogFile) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_LogFile, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_LogFile, fmt, args);
    va_end(args);

    fprintf(g_LogFile, "\n");
    fflush(g_LogFile);
}

/* ------------------------------------------------------------------ */
/*  Dead man's switch — wipe and shutdown                              */
/* ------------------------------------------------------------------ */

static void trigger_wipe(void)
{
    log_msg("=== DEAD MAN'S SWITCH TRIGGERED ===");

    vault_config_t cfg;
    vault_config_init(&cfg);

    if (vault_config_load(&cfg, CONFIG_PATH) != 0) {
        log_msg("ERROR: Cannot load config from %s", CONFIG_PATH);
        /* Fall back to defaults */
        strncpy(cfg.target_device, "\\\\.\\PhysicalDrive0",
                sizeof(cfg.target_device) - 1);
    }

    if (!cfg.target_device[0]) {
        strncpy(cfg.target_device, "\\\\.\\PhysicalDrive0",
                sizeof(cfg.target_device) - 1);
    }

    log_msg("Target device: %s", cfg.target_device);
    log_msg("Algorithm: %d", cfg.wipe_algorithm);

    /* Use the real deadman trigger which handles encrypt + wipe + shutdown */
    log_msg("Calling vault_deadman_trigger()...");
    vault_deadman_trigger(&cfg);

    /* Should not reach here — deadman calls vault_platform_shutdown() */
    log_msg("WARNING: deadman_trigger returned, forcing shutdown");
    vault_platform_shutdown();
}

/* ------------------------------------------------------------------ */
/*  Named pipe server                                                  */
/* ------------------------------------------------------------------ */

static DWORD WINAPI PipeServerThread(LPVOID lpParam)
{
    (void)lpParam;

    log_msg("Pipe server started on %s", PIPE_NAME);

    while (WaitForSingleObject(g_StopEvent, 0) != WAIT_OBJECT_0) {
        HANDLE hPipe = CreateNamedPipeA(
            PIPE_NAME,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,              /* Max instances */
            512,            /* Out buffer */
            512,            /* In buffer */
            5000,           /* Default timeout ms */
            NULL);          /* Default security */

        if (hPipe == INVALID_HANDLE_VALUE) {
            log_msg("CreateNamedPipe failed: %lu", GetLastError());
            Sleep(1000);
            continue;
        }

        /* Wait for client connection */
        BOOL connected = ConnectNamedPipe(hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(hPipe);
            continue;
        }

        /* Read command */
        char buffer[256] = {0};
        DWORD bytesRead;
        BOOL ok = ReadFile(hPipe, buffer, sizeof(buffer) - 1,
                           &bytesRead, NULL);
        CloseHandle(hPipe);

        if (!ok || bytesRead == 0) continue;
        buffer[bytesRead] = '\0';

        log_msg("Received command: %s", buffer);

        if (strcmp(buffer, "WIPE") == 0) {
            log_msg("WIPE command received — triggering dead man's switch");
            trigger_wipe();
            /* Should not return */
            break;
        } else if (strcmp(buffer, "AUTH_OK") == 0) {
            log_msg("Authentication successful");
        } else {
            log_msg("Unknown command: %s", buffer);
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Service control handler                                            */
/* ------------------------------------------------------------------ */

static VOID WINAPI ServiceCtrlHandler(DWORD dwCtrl)
{
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        SetEvent(g_StopEvent);
        break;

    case SERVICE_CONTROL_INTERROGATE:
        break;

    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Service main                                                       */
/* ------------------------------------------------------------------ */

static VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    (void)argc;
    (void)argv;

    /* Register control handler */
    g_StatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME,
                                                  ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    /* Initialize status */
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState     = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    /* Create stop event */
    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    /* Open log file */
    CreateDirectoryA("C:\\ProgramData\\ShredOS-Vault", NULL);
    fopen_s(&g_LogFile, LOG_FILE, "a");
    log_msg("ShredOS Vault service starting");

    /* Report running */
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    /* Start pipe server in a thread */
    HANDLE hThread = CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);

    /* Wait for stop signal */
    WaitForSingleObject(g_StopEvent, INFINITE);

    /* Cleanup */
    log_msg("ShredOS Vault service stopping");
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }
    CloseHandle(g_StopEvent);

    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = NULL;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                        */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    /* Allow running as console app for testing */
    if (argc > 1 && strcmp(argv[1], "--console") == 0) {
        g_LogFile = stderr;
        log_msg("Running in console mode (testing)");

        g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        PipeServerThread(NULL);
        return 0;
    }

    /* Normal service startup */
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        { SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcherA(ServiceTable)) {
        /* If not started by SCM, show usage */
        fprintf(stderr,
            "ShredOS Vault Wipe Service\n\n"
            "This program is a Windows service. Install with:\n"
            "  sc create ShredOSVault binPath= \"%s\"\n"
            "  sc start ShredOSVault\n\n"
            "For testing:\n"
            "  %s --console\n",
            argv[0], argv[0]);
        return 1;
    }

    return 0;
}
