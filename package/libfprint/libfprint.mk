################################################################################
#
# libfprint
#
################################################################################

LIBFPRINT_VERSION = v1.94.8
LIBFPRINT_SITE = https://gitlab.freedesktop.org/libfprint/libfprint.git
LIBFPRINT_SITE_METHOD = git
LIBFPRINT_GIT_SUBMODULES = YES
LIBFPRINT_LICENSE = LGPL-2.1+
LIBFPRINT_LICENSE_FILES = COPYING
LIBFPRINT_INSTALL_STAGING = YES

LIBFPRINT_DEPENDENCIES = \
	host-pkgconf \
	libusb \
	libglib2 \
	pixman

LIBFPRINT_CONF_OPTS = \
	-Ddoc=false \
	-Dexamples=false \
	-Dgtk-examples=false \
	-Dudev_hwdb=disabled \
	-Dudev_rules=disabled

# Disable drivers that need extra deps we don't want to pull in
ifeq ($(BR2_PACKAGE_LIBNSS),y)
LIBFPRINT_DEPENDENCIES += libnss
LIBFPRINT_CONF_OPTS += -Dnss=enabled
else
LIBFPRINT_CONF_OPTS += -Dnss=disabled
endif

$(eval $(meson-package))
