#!/bin/sh
# initramfs-tools script for ShredOS Vault
#
# Runs shredos-vault authentication before the root filesystem is mounted.
# Install location: /etc/initramfs-tools/scripts/local-top/shredos-vault

PREREQ="udev"

prereqs() {
    echo "$PREREQ"
}

case "$1" in
    prereqs)
        prereqs
        exit 0
        ;;
esac

# Only run if binary exists
if [ ! -x /usr/sbin/shredos-vault ]; then
    echo "shredos-vault: binary not found, skipping"
    exit 0
fi

# Only run if config exists
if [ ! -f /etc/shredos-vault/vault.conf ]; then
    echo "shredos-vault: config not found, skipping"
    exit 0
fi

# Ensure we have a console
exec < /dev/console > /dev/console 2>&1

# Set TERM for TUI
export TERM="${TERM:-linux}"

# Run vault in initramfs mode
/usr/sbin/shredos-vault --initramfs --config /etc/shredos-vault/vault.conf
exit $?
