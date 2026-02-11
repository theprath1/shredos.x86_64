#!/bin/bash
# Dracut module for ShredOS Vault
#
# Install location: /usr/lib/dracut/modules.d/90shredos-vault/module-setup.sh
# Integrates shredos-vault into the dracut-generated initramfs.
#
# inst_binary automatically copies shared library dependencies.
#
# Usage:
#   dracut --force    (rebuild initramfs)

check() {
    # Only include if shredos-vault is installed
    require_binaries shredos-vault || return 1
    return 0
}

depends() {
    echo "crypt"  # Depends on cryptsetup dracut module
    return 0
}

install() {
    # Install shredos-vault binary (auto-copies .so dependencies)
    inst_binary /usr/sbin/shredos-vault

    # Install cryptsetup (should already be there via crypt module)
    inst_binary /sbin/cryptsetup 2>/dev/null || true

    # Install nwipe if available
    inst_binary /usr/bin/nwipe 2>/dev/null || true
    inst_binary /usr/sbin/nwipe 2>/dev/null || true

    # Install config
    inst_simple /etc/shredos-vault/vault.conf /etc/shredos-vault/vault.conf

    # Install terminfo for ncurses TUI
    inst_dir /usr/share/terminfo/l 2>/dev/null || true
    inst_dir /usr/share/terminfo/x 2>/dev/null || true
    inst_simple /usr/share/terminfo/l/linux 2>/dev/null || true
    inst_simple /usr/share/terminfo/x/xterm 2>/dev/null || true
    inst_simple /usr/share/terminfo/x/xterm-256color 2>/dev/null || true

    # Install the pre-mount hook
    inst_hook pre-mount 10 "$moddir/shredos-vault-hook.sh"

    # Install systemd service if using systemd in initramfs
    if dracut_module_included "systemd"; then
        inst_simple "$moddir/shredos-vault.service" \
            "${systemdsystemunitdir}/shredos-vault.service"
        mkdir -p "${initdir}/${systemdsystemunitdir}/initrd.target.wants"
        ln_r "${systemdsystemunitdir}/shredos-vault.service" \
             "${systemdsystemunitdir}/initrd.target.wants/shredos-vault.service"
    fi
}
