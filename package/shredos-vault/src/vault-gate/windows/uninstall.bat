@echo off
REM VaultGate Windows Uninstaller
REM
REM Removes VaultGate Credential Provider and wipe service.
REM Must be run as Administrator.
REM
REM Copyright 2025 — GPL-2.0+

setlocal EnableDelayedExpansion

set PRODUCT_NAME=ShredOS-Vault
set SERVICE_NAME=ShredOSVault
set INSTALL_DIR=C:\Program Files\%PRODUCT_NAME%
set LEGACY_INSTALL_DIR=C:\Program Files\VaultGate
set CONFIG_DIR=C:\ProgramData\%PRODUCT_NAME%
set LEGACY_CONFIG_DIR=C:\ProgramData\VaultGate

echo ====================================================
echo   ShredOS Vault — Windows Uninstaller
echo ====================================================
echo.

REM ---- Check admin ----
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This uninstaller must be run as Administrator.
    echo Right-click and select "Run as administrator".
    pause
    exit /b 1
)

echo This will completely remove ShredOS Vault from your system.
set /p confirm="Continue? (yes/no): "
if /i not "%confirm%"=="yes" (
    echo Aborted.
    pause
    exit /b 0
)

echo.

set CP_GUID={A7B1C8D2-3E4F-5A6B-7C8D-9E0F1A2B3C4D}

REM ---- Stop and remove service ----
sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %SERVICE_NAME% >nul 2>&1
    echo [+] Removed service: %SERVICE_NAME%
)

REM Remove legacy service name (if present)
sc query VaultGate >nul 2>&1
if %errorLevel% equ 0 (
    sc stop VaultGate >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete VaultGate >nul 2>&1
    echo [+] Removed legacy service: VaultGate
)

REM ---- Unregister Credential Provider ----
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%CP_GUID%" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Classes\CLSID\%CP_GUID%" /f >nul 2>&1
echo [+] Unregistered Credential Provider

REM ---- Remove DLL ----
if exist "%SystemRoot%\System32\VaultGateProvider.dll" (
    del /f "%SystemRoot%\System32\VaultGateProvider.dll" >nul 2>&1
    echo [+] Removed: %SystemRoot%\System32\VaultGateProvider.dll
)

REM ---- Remove install directory ----
if exist "%INSTALL_DIR%" (
    rmdir /s /q "%INSTALL_DIR%" >nul 2>&1
    echo [+] Removed: %INSTALL_DIR%
)

if exist "%LEGACY_INSTALL_DIR%" (
    rmdir /s /q "%LEGACY_INSTALL_DIR%" >nul 2>&1
    echo [+] Removed legacy directory: %LEGACY_INSTALL_DIR%
)

REM ---- Remove config (ask first) ----
set HAS_CFG=0
if exist "%CONFIG_DIR%" set HAS_CFG=1
if exist "%LEGACY_CONFIG_DIR%" set HAS_CFG=1

if "%HAS_CFG%"=="1" (
    set /p rmcfg="Remove config directories %CONFIG_DIR% and %LEGACY_CONFIG_DIR%? (yes/no): "
    if /i "!rmcfg!"=="yes" (
        if exist "%CONFIG_DIR%" (
            rmdir /s /q "%CONFIG_DIR%" >nul 2>&1
            echo [+] Removed: %CONFIG_DIR%
        )
        if exist "%LEGACY_CONFIG_DIR%" (
            rmdir /s /q "%LEGACY_CONFIG_DIR%" >nul 2>&1
            echo [+] Removed: %LEGACY_CONFIG_DIR%
        )
    ) else (
        echo [!] Keeping config directories.
    )
)

echo.
echo ====================================================
echo   ShredOS Vault removed successfully.
echo ====================================================
echo.
echo   The Credential Provider and service have been removed.
echo   The standard Windows login screen will be used.
echo.

pause
