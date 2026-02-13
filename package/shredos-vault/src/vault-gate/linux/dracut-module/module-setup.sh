#!/bin/bash
# dracut module setup for ShredOS Vault

check() {
    require_binaries shredos-vault || return 1
    return 0
}

depends() {
    echo "udev-rules"
    return 0
}

install() {
    inst_binary /usr/sbin/shredos-vault
    inst_simple /etc/shredos-vault/vault.conf /etc/shredos-vault/vault.conf

    # Install the hook script
    inst_hook pre-mount 10 "$moddir/vault-gate-hook.sh"

    # Install systemd service if using systemd
    if dracut_module_included "systemd"; then
        inst_simple "$moddir/vault-gate.service" \
            "${systemdsystemunitdir}/vault-gate.service"
        $SYSTEMCTL -q --root "$initdir" enable vault-gate.service 2>/dev/null || true
    fi

    # Copy terminfo for ncurses
    inst_simple /lib/terminfo/l/linux 2>/dev/null || true
    inst_simple /usr/share/terminfo/l/linux 2>/dev/null || true
}
