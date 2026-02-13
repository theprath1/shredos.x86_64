#!/bin/bash
# ShredOS Vault -- Standalone Linux Installer
#
# Compiles and installs vault from the unified codebase.
# Auto-detects initramfs system (initramfs-tools or dracut).
#
# Usage: sudo ./install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAKEFILE_DIR="$SCRIPT_DIR/.."

echo -e "${CYAN}ShredOS Vault -- Linux Installer${NC}"
echo

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: must be run as root.${NC}"
    exit 1
fi

CC="${CC:-gcc}"
if ! command -v "$CC" &>/dev/null; then CC=cc; fi
if ! command -v "$CC" &>/dev/null; then
    echo -e "${RED}Error: no C compiler found.${NC}"
    exit 1
fi

echo -e "${GREEN}[+]${NC} Installing dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get install -y libncurses-dev libconfig-dev libcryptsetup-dev \
        cryptsetup nwipe pkg-config 2>/dev/null || true
elif command -v dnf &>/dev/null; then
    dnf install -y ncurses-devel libconfig-devel cryptsetup-devel \
        cryptsetup nwipe pkgconfig 2>/dev/null || true
elif command -v pacman &>/dev/null; then
    pacman -S --noconfirm --needed ncurses libconfig cryptsetup \
        nwipe pkgconf 2>/dev/null || true
fi

# Detect initramfs system
INITRAMFS=""
if [ -d /etc/initramfs-tools ]; then
    INITRAMFS="initramfs-tools"
elif command -v dracut &>/dev/null; then
    INITRAMFS="dracut"
fi
echo -e "${GREEN}[+]${NC} Initramfs: ${INITRAMFS:-none}"

echo -e "${GREEN}[+]${NC} Compiling..."
cd "$MAKEFILE_DIR"
make clean 2>/dev/null || true
make linux CC="$CC"

install -m 755 "$MAKEFILE_DIR/shredos-vault" /usr/sbin/shredos-vault
echo -e "${GREEN}[+]${NC} Installed: /usr/sbin/shredos-vault"

mkdir -p /etc/shredos-vault
if [ ! -f /etc/shredos-vault/vault.conf ]; then
    install -m 600 "$MAKEFILE_DIR/vault-gate.conf" /etc/shredos-vault/vault.conf
    echo -e "${GREEN}[+]${NC} Installed default config"
fi

if [ "$INITRAMFS" = "initramfs-tools" ]; then
    install -m 755 "$SCRIPT_DIR/initramfs-hook.sh" \
        /etc/initramfs-tools/hooks/shredos-vault
    install -m 755 "$SCRIPT_DIR/initramfs-script.sh" \
        /etc/initramfs-tools/scripts/local-top/shredos-vault
    update-initramfs -u
    echo -e "${GREEN}[+]${NC} Initramfs rebuilt"
elif [ "$INITRAMFS" = "dracut" ]; then
    DDIR="/usr/lib/dracut/modules.d/90shredos-vault"
    mkdir -p "$DDIR"
    install -m 755 "$SCRIPT_DIR/dracut-module/module-setup.sh" "$DDIR/"
    install -m 755 "$SCRIPT_DIR/dracut-module/vault-gate-hook.sh" "$DDIR/"
    install -m 644 "$SCRIPT_DIR/dracut-module/vault-gate.service" "$DDIR/"
    dracut --force
    echo -e "${GREEN}[+]${NC} Initramfs rebuilt"
fi

echo
echo -e "${GREEN}ShredOS Vault installed.${NC}"
echo "  Run: sudo shredos-vault --setup"
echo -e "${RED}  REMEMBER YOUR PASSWORD!${NC}"
