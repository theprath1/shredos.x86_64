#!/bin/sh
# dracut pre-mount hook for ShredOS Vault

if [ ! -x /usr/sbin/shredos-vault ]; then
    echo "shredos-vault: binary not found, skipping"
    exit 0
fi

if [ ! -f /etc/shredos-vault/vault.conf ]; then
    echo "shredos-vault: config not found, skipping"
    exit 0
fi

exec < /dev/console > /dev/console 2>&1
export TERM="${TERM:-linux}"

/usr/sbin/shredos-vault --initramfs --config /etc/shredos-vault/vault.conf
