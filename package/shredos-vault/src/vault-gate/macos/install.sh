#!/bin/bash
# ShredOS Vault — macOS Installer
#
# Compiles the full ShredOS Vault from the unified codebase and installs
# it as a LaunchDaemon that runs at boot (VT100 TUI on /dev/console).
#
# Prerequisites:
#   - macOS 10.15+
#   - Root/sudo access
#   - Xcode Command Line Tools (for compiler)
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
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAKEFILE_DIR="$SCRIPT_DIR/.."

echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo -e "${CYAN}  ShredOS Vault — macOS Installer${NC}"
echo -e "${CYAN}═══════════════════════════════════════════${NC}"
echo

# ---- Preflight ----

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This installer must be run as root (use sudo).${NC}"
    exit 1
fi

if ! command -v cc &>/dev/null; then
    echo -e "${RED}Error: No C compiler found.${NC}"
    echo "Install Xcode Command Line Tools: xcode-select --install"
    exit 1
fi

# Check SIP status
SIP_STATUS=$(csrutil status 2>&1 || true)
if echo "$SIP_STATUS" | grep -q "enabled"; then
    echo -e "${YELLOW}[!]${NC} System Integrity Protection (SIP) is enabled."
    echo "    ShredOS Vault will run as a LaunchDaemon."
    echo
fi

# Check FileVault
FV_STATUS=$(fdesetup status 2>&1 || true)
if echo "$FV_STATUS" | grep -q "On"; then
    echo -e "${GREEN}[+]${NC} FileVault is enabled (recommended)"
else
    echo -e "${YELLOW}[!]${NC} FileVault is NOT enabled."
    echo "    Strongly recommend enabling FileVault for full-disk encryption."
    echo "    Run: sudo fdesetup enable"
    echo
fi

echo -e "${GREEN}[+]${NC} Preflight checks passed"

# ---- Compile ----

echo -e "${GREEN}[+]${NC} Compiling shredos-vault (VT100 TUI + IOKit)..."

cd "$MAKEFILE_DIR"
make clean 2>/dev/null || true
make macos

echo -e "${GREEN}[+]${NC} Compilation successful"

# ---- Install binary ----

install -m 755 "$MAKEFILE_DIR/shredos-vault" /usr/local/sbin/shredos-vault
echo -e "${GREEN}[+]${NC} Installed: /usr/local/sbin/shredos-vault"

# ---- Install config ----

CONFIG_DIR="/Library/Application Support/ShredOS-Vault"
mkdir -p "$CONFIG_DIR"

if [ ! -f "$CONFIG_DIR/vault.conf" ]; then
    install -m 600 "$MAKEFILE_DIR/vault-gate.conf" "$CONFIG_DIR/vault.conf"
    echo -e "${GREEN}[+]${NC} Installed default config: $CONFIG_DIR/vault.conf"
else
    echo -e "${YELLOW}[!]${NC} Config already exists, not overwriting"
fi

# ---- Install LaunchDaemon ----

PLIST_DEST="/Library/LaunchDaemons/com.shredos.vault-gate.plist"
install -m 644 "$SCRIPT_DIR/com.shredos.vault-gate.plist" "$PLIST_DEST"
chown root:wheel "$PLIST_DEST"
echo -e "${GREEN}[+]${NC} Installed LaunchDaemon: $PLIST_DEST"

# Don't load yet — need setup first
echo -e "${YELLOW}[!]${NC} LaunchDaemon installed but NOT loaded yet."

# ---- Run setup prompt ----

echo
echo -e "${YELLOW}════════════════════════════════════════════${NC}"
echo -e "${YELLOW}  IMPORTANT: Run initial setup now!${NC}"
echo -e "${YELLOW}════════════════════════════════════════════${NC}"
echo
echo "  You must configure a password and target device before activating."
echo "  Run:"
echo
echo "    sudo shredos-vault --setup"
echo
echo "  After setup, activate ShredOS Vault:"
echo
echo "    sudo launchctl load $PLIST_DEST"
echo

echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ShredOS Vault installed successfully!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo
echo "  Binary:  /usr/local/sbin/shredos-vault"
echo "  Config:  $CONFIG_DIR/vault.conf"
echo "  Daemon:  $PLIST_DEST"
echo
echo "  Next steps:"
echo "    1. Run:  sudo shredos-vault --setup"
echo "    2. Test: sudo shredos-vault  (runs interactively)"
echo "    3. Activate: sudo launchctl load $PLIST_DEST"
echo "    4. Reboot to verify"
echo
echo -e "${RED}  CAUTION: Ensure you remember your password!${NC}"
echo -e "${RED}  Forgetting it will trigger the dead man's switch.${NC}"
echo
