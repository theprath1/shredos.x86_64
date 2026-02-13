#!/bin/bash
# ShredOS Vault -- macOS Uninstaller

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root."
    exit 1
fi

echo "Removing ShredOS Vault..."

launchctl unload /Library/LaunchDaemons/com.shredos.vault-gate.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.shredos.vault-gate.plist
rm -f /usr/local/sbin/shredos-vault
rm -rf "/Library/Application Support/ShredOS-Vault"

echo "ShredOS Vault removed."
