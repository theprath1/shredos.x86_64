################################################################################
#
# shredos-vault
#
################################################################################

SHREDOS_VAULT_VERSION = 1.0.0
SHREDOS_VAULT_SITE = $(pkgdir)/src
SHREDOS_VAULT_SITE_METHOD = local

SHREDOS_VAULT_DEPENDENCIES = ncurses cryptsetup libconfig nwipe
SHREDOS_VAULT_LICENSE = GPL-2.0+

# Optional dependencies
ifeq ($(BR2_PACKAGE_SHREDOS_VAULT_FINGERPRINT),y)
SHREDOS_VAULT_DEPENDENCIES += libfprint
endif

ifeq ($(BR2_PACKAGE_SHREDOS_VAULT_VOICE),y)
SHREDOS_VAULT_DEPENDENCIES += portaudio
endif

ifeq ($(BR2_PACKAGE_SHREDOS_VAULT_NTFS),y)
SHREDOS_VAULT_DEPENDENCIES += ntfs-3g
endif

# Install vault-gate boot integration files for the installer wizard
define SHREDOS_VAULT_INSTALL_VAULTGATE
	$(INSTALL) -d $(TARGET_DIR)/usr/share/shredos-vault
	$(INSTALL) -m 755 $(SHREDOS_VAULT_SITE)/vault-gate/linux/initramfs-hook.sh \
		$(TARGET_DIR)/usr/share/shredos-vault/
	$(INSTALL) -m 755 $(SHREDOS_VAULT_SITE)/vault-gate/linux/initramfs-script.sh \
		$(TARGET_DIR)/usr/share/shredos-vault/
	$(INSTALL) -d $(TARGET_DIR)/usr/share/shredos-vault/dracut-module
	$(INSTALL) -m 755 $(SHREDOS_VAULT_SITE)/vault-gate/linux/dracut-module/module-setup.sh \
		$(TARGET_DIR)/usr/share/shredos-vault/dracut-module/
	$(INSTALL) -m 755 $(SHREDOS_VAULT_SITE)/vault-gate/linux/dracut-module/vault-gate-hook.sh \
		$(TARGET_DIR)/usr/share/shredos-vault/dracut-module/
	$(INSTALL) -m 644 $(SHREDOS_VAULT_SITE)/vault-gate/linux/dracut-module/vault-gate.service \
		$(TARGET_DIR)/usr/share/shredos-vault/dracut-module/
	$(INSTALL) -m 644 $(SHREDOS_VAULT_SITE)/vault-gate/vault-gate.conf \
		$(TARGET_DIR)/usr/share/shredos-vault/
	$(INSTALL) -m 644 $(SHREDOS_VAULT_SITE)/vault-gate/macos/com.shredos.vault-gate.plist \
		$(TARGET_DIR)/usr/share/shredos-vault/
endef
SHREDOS_VAULT_POST_INSTALL_TARGET_HOOKS += SHREDOS_VAULT_INSTALL_VAULTGATE

$(eval $(autotools-package))
