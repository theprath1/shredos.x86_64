@echo off
:: ShredOS Vault -- Windows Uninstaller
:: Must be run as Administrator

echo ShredOS Vault -- Windows Uninstaller
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Must be run as Administrator.
    pause
    exit /b 1
)

:: Stop and remove service
sc stop ShredOSVault >nul 2>&1
sc delete ShredOSVault >nul 2>&1

:: Remove Credential Provider
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}" /f >nul 2>&1

:: Remove files
rmdir /s /q "C:\Program Files\ShredOS-Vault" 2>nul
rmdir /s /q "C:\ProgramData\ShredOS-Vault" 2>nul

echo ShredOS Vault removed.
pause
