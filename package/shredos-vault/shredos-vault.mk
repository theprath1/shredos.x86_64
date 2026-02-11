################################################################################
#
# shredos-vault
#
################################################################################

SHREDOS_VAULT_VERSION = 1.0.0
SHREDOS_VAULT_SITE = $(pkgdir)/src
SHREDOS_VAULT_SITE_METHOD = local

SHREDOS_VAULT_DEPENDENCIES = ncurses cryptsetup libconfig nwipe

ifeq ($(BR2_PACKAGE_SHREDOS_VAULT_FINGERPRINT),y)
SHREDOS_VAULT_DEPENDENCIES += libfprint
SHREDOS_VAULT_CONF_OPTS += --enable-fingerprint
else
SHREDOS_VAULT_CONF_OPTS += --disable-fingerprint
endif

ifeq ($(BR2_PACKAGE_SHREDOS_VAULT_VOICE),y)
SHREDOS_VAULT_DEPENDENCIES += portaudio sphinxbase pocketsphinx
SHREDOS_VAULT_CONF_OPTS += --enable-voice
else
SHREDOS_VAULT_CONF_OPTS += --disable-voice
endif

SHREDOS_VAULT_LICENSE = GPL-2.0+
SHREDOS_VAULT_LICENSE_FILES = COPYING

$(eval $(autotools-package))
