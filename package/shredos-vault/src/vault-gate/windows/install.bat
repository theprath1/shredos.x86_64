@echo off
:: ShredOS Vault -- Windows Installer
:: Must be run as Administrator

echo ShredOS Vault -- Windows Installer
echo.

:: Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This must be run as Administrator.
    echo Right-click and select "Run as administrator".
    pause
    exit /b 1
)

:: Create program directory
mkdir "C:\Program Files\ShredOS-Vault" 2>nul
mkdir "C:\ProgramData\ShredOS-Vault" 2>nul

:: Copy files
copy /Y "%~dp0shredos-vault-service.exe" "C:\Program Files\ShredOS-Vault\" >nul
copy /Y "%~dp0VaultGateProvider.dll" "C:\Program Files\ShredOS-Vault\" >nul

:: Copy config if not already present
if not exist "C:\ProgramData\ShredOS-Vault\vault.conf" (
    copy /Y "%~dp0vault.conf" "C:\ProgramData\ShredOS-Vault\" >nul
)

:: Register the Windows service
sc create ShredOSVault binPath= "\"C:\Program Files\ShredOS-Vault\shredos-vault-service.exe\"" start= auto type= own >nul 2>&1
sc description ShredOSVault "ShredOS Vault pre-boot authentication gate" >nul 2>&1

:: Register the Credential Provider
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" /ve /d "ShredOS Vault" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" /v "DllPath" /d "C:\Program Files\ShredOS-Vault\VaultGateProvider.dll" /f >nul

:: Start the service
sc start ShredOSVault >nul 2>&1

echo.
echo ShredOS Vault installed successfully.
echo.
echo IMPORTANT: Run setup before rebooting:
echo   "C:\Program Files\ShredOS-Vault\shredos-vault-service.exe" --setup
echo.
echo WARNING: Remember your password!
echo Forgetting it will trigger the dead man's switch.
echo.
pause
