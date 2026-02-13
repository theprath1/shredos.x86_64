#!/bin/bash
# ShredOS Vault -- macOS Installer

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAKEFILE_DIR="$SCRIPT_DIR/.."

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root (use sudo)."
    exit 1
fi

echo "ShredOS Vault -- macOS Installer"
echo

cd "$MAKEFILE_DIR"
make clean 2>/dev/null || true
make macos

install -m 755 "$MAKEFILE_DIR/shredos-vault" /usr/local/sbin/shredos-vault

mkdir -p "/Library/Application Support/ShredOS-Vault"
if [ ! -f "/Library/Application Support/ShredOS-Vault/vault.conf" ]; then
    cp "$MAKEFILE_DIR/vault-gate.conf" \
        "/Library/Application Support/ShredOS-Vault/vault.conf"
    chmod 600 "/Library/Application Support/ShredOS-Vault/vault.conf"
fi

cp "$SCRIPT_DIR/com.shredos.vault-gate.plist" /Library/LaunchDaemons/
launchctl load /Library/LaunchDaemons/com.shredos.vault-gate.plist 2>/dev/null || true

echo
echo "ShredOS Vault installed."
echo "  Run: sudo shredos-vault --setup"
