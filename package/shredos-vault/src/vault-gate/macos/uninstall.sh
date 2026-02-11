#!/bin/bash
# ShredOS Vault macOS Uninstaller
#
# Removes ShredOS Vault from macOS.
#
# Usage:
#   sudo ./uninstall.sh
#
# Copyright 2025 — GPL-2.0+

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PLIST="/Library/LaunchDaemons/com.shredos.vault-gate.plist"
CONFIG_DIR="/Library/Application Support/ShredOS-Vault"
LEGACY_CONFIG_DIR="/Library/Application Support/VaultGate"

echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo -e "${CYAN}  ShredOS Vault — macOS Uninstaller${NC}"
echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This uninstaller must be run as root (use sudo).${NC}"
    exit 1
fi

echo -e "${YELLOW}  This will completely remove ShredOS Vault from your system.${NC}"
echo
read -p "  Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "  Aborted."
    exit 0
fi

echo

# ---- Unload LaunchDaemon ----

if [ -f "$PLIST" ]; then
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo -e "${GREEN}[+]${NC} Removed LaunchDaemon: $PLIST"
fi

# ---- Remove binary ----

if [ -f /usr/local/sbin/shredos-vault ]; then
    rm -f /usr/local/sbin/shredos-vault
    echo -e "${GREEN}[+]${NC} Removed: /usr/local/sbin/shredos-vault"
fi

if [ -f /usr/local/sbin/vault-gate ]; then
    rm -f /usr/local/sbin/vault-gate
    echo -e "${GREEN}[+]${NC} Removed legacy binary: /usr/local/sbin/vault-gate"
fi

# ---- Remove config ----

if [ -d "$CONFIG_DIR" ]; then
    read -p "  Remove config directory? (yes/no): " rm_cfg
    if [ "$rm_cfg" = "yes" ]; then
        rm -rf "$CONFIG_DIR"
        echo -e "${GREEN}[+]${NC} Removed: $CONFIG_DIR"
    else
        echo -e "${YELLOW}[!]${NC} Keeping: $CONFIG_DIR"
    fi
fi

if [ -d "$LEGACY_CONFIG_DIR" ]; then
    read -p "  Remove legacy config directory $LEGACY_CONFIG_DIR? (yes/no): " rm_cfg
    if [ "$rm_cfg" = "yes" ]; then
        rm -rf "$LEGACY_CONFIG_DIR"
        echo -e "${GREEN}[+]${NC} Removed: $LEGACY_CONFIG_DIR"
    else
        echo -e "${YELLOW}[!]${NC} Keeping: $LEGACY_CONFIG_DIR"
    fi
fi

# ---- Remove log ----

rm -f /var/log/shredos-vault.log 2>/dev/null || true
rm -f /var/log/vault-gate.log 2>/dev/null || true

echo
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ShredOS Vault removed successfully.${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo
