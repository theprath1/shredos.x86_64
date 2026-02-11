#!/bin/sh
# initramfs-tools hook for ShredOS Vault
#
# Install location: /etc/initramfs-tools/hooks/shredos-vault
# Copies shredos-vault binary, config, and dependencies into initramfs.
#
# copy_exec automatically copies shared library dependencies (.so files).
#
# After installing, rebuild initramfs: update-initramfs -u

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

# Copy shredos-vault binary (auto-copies .so dependencies)
copy_exec /usr/sbin/shredos-vault /usr/sbin/shredos-vault

# Copy cryptsetup (should already be there via cryptroot hook)
if [ -x /sbin/cryptsetup ]; then
    copy_exec /sbin/cryptsetup /sbin/cryptsetup
fi

# Copy nwipe if available
if [ -x /usr/bin/nwipe ]; then
    copy_exec /usr/bin/nwipe /usr/bin/nwipe
elif [ -x /usr/sbin/nwipe ]; then
    copy_exec /usr/sbin/nwipe /usr/sbin/nwipe
fi

# Copy config file
if [ -f /etc/shredos-vault/vault.conf ]; then
    mkdir -p "${DESTDIR}/etc/shredos-vault"
    cp /etc/shredos-vault/vault.conf "${DESTDIR}/etc/shredos-vault/vault.conf"
    chmod 600 "${DESTDIR}/etc/shredos-vault/vault.conf"
fi

# Copy terminfo entries for ncurses TUI
for term in linux xterm xterm-256color vt100; do
    for dir in /usr/share/terminfo /lib/terminfo /etc/terminfo; do
        first_char=$(echo "$term" | cut -c1)
        if [ -f "$dir/$first_char/$term" ]; then
            mkdir -p "${DESTDIR}/$dir/$first_char"
            cp "$dir/$first_char/$term" "${DESTDIR}/$dir/$first_char/$term"
        fi
    done
done

exit 0
