AC_INIT([shredos-vault], [1.0.0], [https://github.com/PartialVolume/shredos.x86_64])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_PROG_CC
AC_PROG_CC_C99

# ncurses
PKG_CHECK_MODULES([NCURSES], [ncurses], [
    AC_DEFINE([HAVE_NCURSES], [1], [ncurses available])
    have_ncurses=yes
], [have_ncurses=no])
AM_CONDITIONAL([USE_NCURSES], [test "x$have_ncurses" = "xyes"])

# libconfig
PKG_CHECK_MODULES([LIBCONFIG], [libconfig], [
    AC_DEFINE([HAVE_LIBCONFIG], [1], [libconfig available])
    have_libconfig=yes
], [have_libconfig=no])

# libcryptsetup
PKG_CHECK_MODULES([CRYPTSETUP], [libcryptsetup], [
    AC_DEFINE([HAVE_LIBCRYPTSETUP], [1], [libcryptsetup available])
    have_cryptsetup=yes
], [have_cryptsetup=no])

# crypt() -- may need -lcrypt
AC_SEARCH_LIBS([crypt], [crypt], [
    AC_DEFINE([HAVE_CRYPT_H], [1], [crypt() available])
])

# Optional: libfprint
AC_ARG_ENABLE([fingerprint],
    AS_HELP_STRING([--enable-fingerprint], [Enable fingerprint auth via libfprint]),
    [enable_fingerprint=$enableval], [enable_fingerprint=no])
if test "x$enable_fingerprint" = "xyes"; then
    PKG_CHECK_MODULES([FPRINT], [libfprint-2], [
        AC_DEFINE([HAVE_FINGERPRINT], [1], [libfprint available])
    ])
fi
AM_CONDITIONAL([USE_FINGERPRINT], [test "x$enable_fingerprint" = "xyes"])

# Optional: voice auth
AC_ARG_ENABLE([voice],
    AS_HELP_STRING([--enable-voice], [Enable voice passphrase auth]),
    [enable_voice=$enableval], [enable_voice=no])
if test "x$enable_voice" = "xyes"; then
    PKG_CHECK_MODULES([POCKETSPHINX], [pocketsphinx])
    PKG_CHECK_MODULES([PORTAUDIO], [portaudio-2.0])
    AC_DEFINE([HAVE_VOICE], [1], [Voice auth available])
fi
AM_CONDITIONAL([USE_VOICE], [test "x$enable_voice" = "xyes"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo ""
echo "  ShredOS Vault build configuration:"
echo "    ncurses ........... $have_ncurses"
echo "    libconfig ......... $have_libconfig"
echo "    libcryptsetup ..... $have_cryptsetup"
echo "    fingerprint ....... $enable_fingerprint"
echo "    voice ............. $enable_voice"
echo ""
