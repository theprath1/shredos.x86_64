#!/bin/sh
# Dracut pre-mount hook for ShredOS Vault
#
# Runs shredos-vault authentication before the root filesystem is mounted.
# On success, the LUKS root volume is opened.
# On failure, the dead man's switch triggers total drive destruction.

# Only run if shredos-vault binary exists
if [ ! -x /usr/sbin/shredos-vault ]; then
    warn "shredos-vault: binary not found, skipping"
    exit 0
fi

# Only run if config exists
if [ ! -f /etc/shredos-vault/vault.conf ]; then
    warn "shredos-vault: config not found, skipping"
    exit 0
fi

# Set TERM for ncurses/VT100 TUI
if [ -z "$TERM" ]; then
    export TERM=linux
fi

# Ensure we have a console
exec < /dev/console > /dev/console 2>&1

# Run shredos-vault in initramfs mode
/usr/sbin/shredos-vault --initramfs --config /etc/shredos-vault/vault.conf
exit $?
