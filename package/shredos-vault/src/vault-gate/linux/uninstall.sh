#!/bin/bash
# ShredOS Vault Linux Uninstaller
#
# Removes ShredOS Vault from the system and restores normal boot process.
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

echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo -e "${CYAN}  ShredOS Vault — Linux Uninstaller${NC}"
echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This uninstaller must be run as root (use sudo).${NC}"
    exit 1
fi

# Confirmation
echo -e "${YELLOW}  This will remove ShredOS Vault from your system.${NC}"
echo -e "${YELLOW}  Your next boot will use the standard LUKS prompt.${NC}"
echo
read -p "  Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "  Aborted."
    exit 0
fi

echo

# ---- Remove initramfs-tools hooks ----

if [ -f /etc/initramfs-tools/hooks/shredos-vault ]; then
    rm -f /etc/initramfs-tools/hooks/shredos-vault
    echo -e "${GREEN}[+]${NC} Removed: /etc/initramfs-tools/hooks/shredos-vault"
fi

if [ -f /etc/initramfs-tools/hooks/vault-gate ]; then
    rm -f /etc/initramfs-tools/hooks/vault-gate
    echo -e "${GREEN}[+]${NC} Removed: /etc/initramfs-tools/hooks/vault-gate"
fi

if [ -f /etc/initramfs-tools/scripts/local-top/shredos-vault ]; then
    rm -f /etc/initramfs-tools/scripts/local-top/shredos-vault
    echo -e "${GREEN}[+]${NC} Removed: /etc/initramfs-tools/scripts/local-top/shredos-vault"
fi

if [ -f /etc/initramfs-tools/scripts/local-top/vault-gate ]; then
    rm -f /etc/initramfs-tools/scripts/local-top/vault-gate
    echo -e "${GREEN}[+]${NC} Removed: /etc/initramfs-tools/scripts/local-top/vault-gate"
fi

# ---- Remove dracut module ----

if [ -d /usr/lib/dracut/modules.d/90shredos-vault ]; then
    rm -rf /usr/lib/dracut/modules.d/90shredos-vault
    echo -e "${GREEN}[+]${NC} Removed: /usr/lib/dracut/modules.d/90shredos-vault/"
fi

if [ -d /usr/lib/dracut/modules.d/90vault-gate ]; then
    rm -rf /usr/lib/dracut/modules.d/90vault-gate
    echo -e "${GREEN}[+]${NC} Removed: /usr/lib/dracut/modules.d/90vault-gate/"
fi

# ---- Remove binary ----

if [ -f /usr/sbin/shredos-vault ]; then
    rm -f /usr/sbin/shredos-vault
    echo -e "${GREEN}[+]${NC} Removed: /usr/sbin/shredos-vault"
fi

if [ -f /usr/sbin/vault-gate ]; then
    rm -f /usr/sbin/vault-gate
    echo -e "${GREEN}[+]${NC} Removed: /usr/sbin/vault-gate"
fi

# ---- Remove config (ask first) ----

if [ -d /etc/shredos-vault ]; then
    echo
    read -p "  Remove config directory /etc/shredos-vault/? (yes/no): " rm_cfg
    if [ "$rm_cfg" = "yes" ]; then
        rm -rf /etc/shredos-vault
        echo -e "${GREEN}[+]${NC} Removed: /etc/shredos-vault/"
    else
        echo -e "${YELLOW}[!]${NC} Keeping: /etc/shredos-vault/"
    fi
fi

if [ -d /etc/vault-gate ]; then
    echo
    read -p "  Remove config directory /etc/vault-gate/? (yes/no): " rm_cfg
    if [ "$rm_cfg" = "yes" ]; then
        rm -rf /etc/vault-gate
        echo -e "${GREEN}[+]${NC} Removed: /etc/vault-gate/"
    else
        echo -e "${YELLOW}[!]${NC} Keeping: /etc/vault-gate/"
    fi
fi

# ---- Rebuild initramfs ----

echo
echo -e "${GREEN}[+]${NC} Rebuilding initramfs..."

if [ -d /etc/initramfs-tools ]; then
    update-initramfs -u
elif command -v dracut &>/dev/null; then
    dracut --force
fi

echo -e "${GREEN}[+]${NC} Initramfs rebuilt"

echo
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ShredOS Vault removed successfully.${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo
echo "  Your system will now boot with the standard LUKS prompt."
echo "  Reboot to complete the uninstallation."
echo
