#!/bin/bash
# ShredOS Vault — Linux Installer
#
# Compiles the full ShredOS Vault from the unified codebase and integrates
# with the boot process via initramfs (initramfs-tools or dracut).
#
# Auto-detects and installs dependencies where possible.
#
# Prerequisites:
#   - Root/sudo access
#   - C compiler (gcc or clang)
#   - pkg-config
#
# Usage:
#   sudo ./install.sh
#
# Copyright 2025 — GPL-2.0+

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULT_DIR="$SCRIPT_DIR/../.."
MAKEFILE_DIR="$SCRIPT_DIR/.."

echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo -e "${CYAN}  ShredOS Vault — Linux Installer${NC}"
echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo

# ---- Preflight checks ----

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This installer must be run as root (use sudo).${NC}"
    exit 1
fi

# Check for compiler
CC="${CC:-gcc}"
if ! command -v "$CC" &>/dev/null; then
    CC=cc
fi
if ! command -v "$CC" &>/dev/null; then
    echo -e "${RED}Error: No C compiler found. Install gcc or clang.${NC}"
    exit 1
fi

# Check for pkg-config
if ! command -v pkg-config &>/dev/null; then
    echo -e "${YELLOW}[!]${NC} pkg-config not found. Installing..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y pkg-config
    elif command -v dnf &>/dev/null; then
        dnf install -y pkgconfig
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm pkgconf
    fi
fi

echo -e "${GREEN}[+]${NC} Preflight checks passed"

# ---- Install dependencies ----

echo -e "${GREEN}[+]${NC} Installing dependencies..."

install_deps_apt() {
    apt-get install -y \
        libncurses-dev \
        libconfig-dev \
        libcryptsetup-dev \
        cryptsetup \
        2>/dev/null || true

    # Optional: nwipe
    apt-get install -y nwipe 2>/dev/null || true
}

install_deps_dnf() {
    dnf install -y \
        ncurses-devel \
        libconfig-devel \
        cryptsetup-devel \
        cryptsetup \
        2>/dev/null || true

    dnf install -y nwipe 2>/dev/null || true
}

install_deps_pacman() {
    pacman -S --noconfirm --needed \
        ncurses \
        libconfig \
        cryptsetup \
        2>/dev/null || true

    # nwipe may be in AUR
    pacman -S --noconfirm nwipe 2>/dev/null || true
}

if command -v apt-get &>/dev/null; then
    install_deps_apt
elif command -v dnf &>/dev/null; then
    install_deps_dnf
elif command -v pacman &>/dev/null; then
    install_deps_pacman
else
    echo -e "${YELLOW}[!]${NC} Unknown package manager. Install manually:"
    echo "    ncurses-dev, libconfig-dev, cryptsetup-dev, nwipe"
fi

# ---- Detect initramfs system ----

INITRAMFS_SYSTEM=""
if [ -d /etc/initramfs-tools ]; then
    INITRAMFS_SYSTEM="initramfs-tools"
    echo -e "${GREEN}[+]${NC} Detected: initramfs-tools (Debian/Ubuntu)"
elif command -v dracut &>/dev/null; then
    INITRAMFS_SYSTEM="dracut"
    echo -e "${GREEN}[+]${NC} Detected: dracut (Fedora/RHEL/Arch)"
else
    echo -e "${YELLOW}[!]${NC} No supported initramfs system detected."
    echo "    ShredOS Vault will be installed but not integrated into boot."
fi

# ---- Compile ----

echo -e "${GREEN}[+]${NC} Compiling shredos-vault (auto-detecting libraries)..."

cd "$MAKEFILE_DIR"
make clean 2>/dev/null || true
make linux CC="$CC"

echo -e "${GREEN}[+]${NC} Compilation successful"

# ---- Install binary ----

install -m 755 "$MAKEFILE_DIR/shredos-vault" /usr/sbin/shredos-vault
echo -e "${GREEN}[+]${NC} Installed: /usr/sbin/shredos-vault"

# ---- Install config ----

mkdir -p /etc/shredos-vault
if [ ! -f /etc/shredos-vault/vault.conf ]; then
    install -m 600 "$MAKEFILE_DIR/vault-gate.conf" /etc/shredos-vault/vault.conf
    echo -e "${GREEN}[+]${NC} Installed default config: /etc/shredos-vault/vault.conf"
else
    echo -e "${YELLOW}[!]${NC} Config already exists, not overwriting: /etc/shredos-vault/vault.conf"
fi

# ---- Install initramfs hooks ----

if [ "$INITRAMFS_SYSTEM" = "initramfs-tools" ]; then
    # initramfs-tools (Debian/Ubuntu)
    install -m 755 "$SCRIPT_DIR/initramfs-hook.sh" \
        /etc/initramfs-tools/hooks/shredos-vault
    install -m 755 "$SCRIPT_DIR/initramfs-script.sh" \
        /etc/initramfs-tools/scripts/local-top/shredos-vault
    echo -e "${GREEN}[+]${NC} Installed initramfs-tools hooks"

    echo -e "${GREEN}[+]${NC} Rebuilding initramfs..."
    update-initramfs -u
    echo -e "${GREEN}[+]${NC} Initramfs rebuilt"

elif [ "$INITRAMFS_SYSTEM" = "dracut" ]; then
    # Dracut (Fedora/RHEL/Arch)
    DRACUT_MOD_DIR="/usr/lib/dracut/modules.d/90shredos-vault"
    mkdir -p "$DRACUT_MOD_DIR"
    install -m 755 "$SCRIPT_DIR/dracut-module/module-setup.sh" \
        "$DRACUT_MOD_DIR/module-setup.sh"
    install -m 755 "$SCRIPT_DIR/dracut-module/vault-gate-hook.sh" \
        "$DRACUT_MOD_DIR/shredos-vault-hook.sh"
    install -m 644 "$SCRIPT_DIR/dracut-module/vault-gate.service" \
        "$DRACUT_MOD_DIR/shredos-vault.service"
    echo -e "${GREEN}[+]${NC} Installed dracut module"

    echo -e "${GREEN}[+]${NC} Rebuilding initramfs..."
    dracut --force
    echo -e "${GREEN}[+]${NC} Initramfs rebuilt"
fi

# ---- Run setup if no password configured ----

if ! grep -q 'password_hash' /etc/shredos-vault/vault.conf 2>/dev/null || \
   grep -q 'password_hash = ""' /etc/shredos-vault/vault.conf 2>/dev/null; then
    echo
    echo -e "${YELLOW}════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  IMPORTANT: Run initial setup now!${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════${NC}"
    echo
    echo "  You must configure a password and target device before rebooting."
    echo "  Run:"
    echo
    echo "    sudo shredos-vault --setup"
    echo
    echo -e "${RED}  WARNING: If you reboot without running setup, shredos-vault${NC}"
    echo -e "${RED}  will start the setup wizard on next boot.${NC}"
fi

echo
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ShredOS Vault installed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo
echo "  Binary:  /usr/sbin/shredos-vault"
echo "  Config:  /etc/shredos-vault/vault.conf"
echo
echo "  Next steps:"
echo "    1. Run:  sudo shredos-vault --setup"
echo "    2. Test: sudo shredos-vault  (runs without initramfs mode)"
echo "    3. Reboot to activate the vault gate"
echo
echo -e "${RED}  CAUTION: Ensure you remember your password!${NC}"
echo -e "${RED}  Forgetting it will trigger the dead man's switch.${NC}"
echo
