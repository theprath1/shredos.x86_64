#!/bin/bash
# ShredOS Vault -- Linux Uninstaller

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be run as root."
    exit 1
fi

echo "Removing ShredOS Vault..."

rm -f /usr/sbin/shredos-vault
rm -rf /etc/shredos-vault

# initramfs-tools
rm -f /etc/initramfs-tools/hooks/shredos-vault
rm -f /etc/initramfs-tools/scripts/local-top/shredos-vault
if [ -d /etc/initramfs-tools ]; then
    update-initramfs -u 2>/dev/null || true
fi

# dracut
rm -rf /usr/lib/dracut/modules.d/90shredos-vault
if command -v dracut &>/dev/null; then
    dracut --force 2>/dev/null || true
fi

echo "ShredOS Vault removed."
