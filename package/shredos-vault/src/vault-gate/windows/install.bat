@echo off
REM VaultGate Windows Installer
REM
REM Installs the VaultGate Credential Provider and wipe service.
REM Must be run as Administrator.
REM
REM Copyright 2025 — GPL-2.0+

setlocal

set PRODUCT_NAME=ShredOS-Vault
set SERVICE_NAME=ShredOSVault
set INSTALL_DIR=C:\Program Files\%PRODUCT_NAME%
set CONFIG_DIR=C:\ProgramData\%PRODUCT_NAME%
set SCRIPT_DIR=%~dp0
set SERVICE_EXE=shredos-vault-service.exe
set CONFIG_SOURCE=%SCRIPT_DIR%..\vault-gate.conf

if exist "%SCRIPT_DIR%..\vault.conf" (
    set CONFIG_SOURCE=%SCRIPT_DIR%..\vault.conf
)

if not exist "%SCRIPT_DIR%%SERVICE_EXE%" (
    set SERVICE_EXE=vault-gate-service.exe
)

if not exist "%SCRIPT_DIR%%SERVICE_EXE%" (
    echo ERROR: Service binary not found.
    echo Expected one of:
    echo   %SCRIPT_DIR%shredos-vault-service.exe
    echo   %SCRIPT_DIR%vault-gate-service.exe
    pause
    exit /b 1
)

if not exist "%CONFIG_SOURCE%" (
    echo ERROR: Config template not found:
    echo   %CONFIG_SOURCE%
    pause
    exit /b 1
)

echo ====================================================
echo   ShredOS Vault — Windows Installer
echo ====================================================
echo.

REM ---- Check admin ----
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This installer must be run as Administrator.
    echo Right-click and select "Run as administrator".
    pause
    exit /b 1
)

echo [+] Admin privileges confirmed
echo.

REM ---- Check for BitLocker ----
manage-bde -status C: 2>nul | findstr /i "Protection On" >nul
if %errorLevel% equ 0 (
    echo [+] BitLocker is enabled on C: (recommended)
) else (
    echo [!] WARNING: BitLocker is NOT enabled on C:
    echo     Strongly recommend enabling BitLocker for full-disk encryption.
    echo     Run: manage-bde -on C:
    echo.
)

REM ---- Create directories ----
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
echo [+] Created directories

REM ---- Copy files ----
copy /Y "%SCRIPT_DIR%%SERVICE_EXE%" "%INSTALL_DIR%\shredos-vault-service.exe" >nul
echo [+] Installed: %INSTALL_DIR%\shredos-vault-service.exe

copy /Y "%SCRIPT_DIR%VaultGateProvider.dll" "%SystemRoot%\System32\VaultGateProvider.dll" >nul
echo [+] Installed: %SystemRoot%\System32\VaultGateProvider.dll

REM ---- Install default config ----
if not exist "%CONFIG_DIR%\vault.conf" (
    copy /Y "%CONFIG_SOURCE%" "%CONFIG_DIR%\vault.conf" >nul
    echo [+] Installed default config: %CONFIG_DIR%\vault.conf
) else (
    echo [!] Config already exists, not overwriting
)

REM ---- Register Credential Provider ----
set CP_GUID={A7B1C8D2-3E4F-5A6B-7C8D-9E0F1A2B3C4D}
set CP_KEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\%CP_GUID%

reg add "%CP_KEY%" /ve /d "ShredOS Vault Security Provider" /f >nul
echo [+] Registered Credential Provider: %CP_GUID%

REM Also register the CLSID
set CLSID_KEY=HKLM\SOFTWARE\Classes\CLSID\%CP_GUID%
reg add "%CLSID_KEY%" /ve /d "ShredOS Vault Credential Provider" /f >nul
reg add "%CLSID_KEY%\InprocServer32" /ve /d "%SystemRoot%\System32\VaultGateProvider.dll" /f >nul
reg add "%CLSID_KEY%\InprocServer32" /v "ThreadingModel" /d "Apartment" /f >nul
echo [+] Registered COM class

REM ---- Install service ----
sc query VaultGate >nul 2>&1
if %errorLevel% equ 0 (
    echo [!] Legacy VaultGate service found, stopping...
    sc stop VaultGate >nul 2>&1
    sc delete VaultGate >nul 2>&1
    timeout /t 2 /nobreak >nul
)

sc query %SERVICE_NAME% >nul 2>&1
if %errorLevel% equ 0 (
    echo [!] %SERVICE_NAME% service already exists, stopping...
    sc stop %SERVICE_NAME% >nul 2>&1
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
)

sc create %SERVICE_NAME% binPath= "%INSTALL_DIR%\shredos-vault-service.exe" start= auto >nul
sc description %SERVICE_NAME% "ShredOS Vault security wipe service - dead man's switch" >nul
echo [+] Created service: %SERVICE_NAME%

sc start %SERVICE_NAME% >nul 2>&1
echo [+] Started service: %SERVICE_NAME%

echo.
echo ====================================================
echo   IMPORTANT: Configure ShredOS Vault before rebooting!
echo ====================================================
echo.
echo   Edit the config file to set your password hash and target device:
echo     %CONFIG_DIR%\vault.conf
echo.
echo   You need to set:
echo     1. password_hash (use the setup tool or manually hash)
echo     2. target_device (default: \\.\PhysicalDrive0)
echo     3. max_attempts (default: 3)
echo.
echo ====================================================
echo   ShredOS Vault installed successfully!
echo ====================================================
echo.
echo   Service:     %SERVICE_NAME% (running)
echo   Provider:    %SystemRoot%\System32\VaultGateProvider.dll
echo   Config:      %CONFIG_DIR%\vault.conf
echo.
echo   CAUTION: Ensure you remember your password!
echo   Forgetting it will trigger the dead man's switch.
echo.

pause
