################################################################################
#
# pocketsphinx
#
################################################################################

POCKETSPHINX_VERSION = v5prealpha
POCKETSPHINX_SITE = https://github.com/cmusphinx/pocketsphinx.git
POCKETSPHINX_SITE_METHOD = git
POCKETSPHINX_LICENSE = BSD-2-Clause
POCKETSPHINX_LICENSE_FILES = LICENSE
POCKETSPHINX_INSTALL_STAGING = YES

POCKETSPHINX_DEPENDENCIES = sphinxbase host-pkgconf

POCKETSPHINX_CONF_OPTS = \
	--without-python \
	--without-swig

$(eval $(autotools-package))
