#!/bin/sh
# initramfs-tools hook for ShredOS Vault
#
# Copies the vault binary, config, and required libraries into the initramfs.
# Install location: /etc/initramfs-tools/hooks/shredos-vault

PREREQ=""

prereqs() {
    echo "$PREREQ"
}

case "$1" in
    prereqs)
        prereqs
        exit 0
        ;;
esac

. /usr/share/initramfs-tools/hook-functions

# Copy the vault binary
if [ -x /usr/sbin/shredos-vault ]; then
    copy_exec /usr/sbin/shredos-vault /usr/sbin/shredos-vault
fi

# Copy the config file
if [ -f /etc/shredos-vault/vault.conf ]; then
    mkdir -p "${DESTDIR}/etc/shredos-vault"
    cp /etc/shredos-vault/vault.conf "${DESTDIR}/etc/shredos-vault/"
fi

# Copy required shared libraries (auto-detected by copy_exec above)
# Explicitly copy ncurses terminfo if available
if [ -d /lib/terminfo ]; then
    mkdir -p "${DESTDIR}/lib/terminfo/l"
    cp /lib/terminfo/l/linux "${DESTDIR}/lib/terminfo/l/" 2>/dev/null || true
fi
if [ -d /usr/share/terminfo ]; then
    mkdir -p "${DESTDIR}/usr/share/terminfo/l"
    cp /usr/share/terminfo/l/linux "${DESTDIR}/usr/share/terminfo/l/" 2>/dev/null || true
fi
