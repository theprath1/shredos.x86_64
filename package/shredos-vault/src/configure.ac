AC_PREREQ([2.69])
AC_INIT([shredos-vault], [1.0.0], [https://github.com/PartialVolume/shredos.x86_64/issues])
AC_CONFIG_SRCDIR([main.c])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_PROG_CC
AC_PROG_CC_C99

# ncurses (preferred backend for Linux/Buildroot)
have_ncurses=no
PKG_CHECK_MODULES([NCURSES], [ncursesw], [have_ncurses=yes],
  [PKG_CHECK_MODULES([NCURSES], [ncurses], [have_ncurses=yes], [have_ncurses=no])])
if test "x$have_ncurses" = "xyes"; then
  AC_DEFINE([HAVE_NCURSES], [1], [ncurses TUI support enabled])
fi
AM_CONDITIONAL([HAVE_NCURSES], [test "x$have_ncurses" = "xyes"])

# Required libraries
PKG_CHECK_MODULES([LIBCONFIG], [libconfig])
PKG_CHECK_MODULES([LIBCRYPTSETUP], [libcryptsetup])

# Optional: fingerprint support
AC_ARG_ENABLE([fingerprint],
  [AS_HELP_STRING([--enable-fingerprint], [Enable fingerprint authentication via libfprint])],
  [enable_fingerprint=$enableval],
  [enable_fingerprint=no])

if test "x$enable_fingerprint" = "xyes"; then
  PKG_CHECK_MODULES([LIBFPRINT], [libfprint-2])
  AC_DEFINE([HAVE_FINGERPRINT], [1], [Fingerprint support enabled])
fi
AM_CONDITIONAL([ENABLE_FINGERPRINT], [test "x$enable_fingerprint" = "xyes"])

# Optional: voice passphrase support
AC_ARG_ENABLE([voice],
  [AS_HELP_STRING([--enable-voice], [Enable voice passphrase authentication])],
  [enable_voice=$enableval],
  [enable_voice=no])

if test "x$enable_voice" = "xyes"; then
  PKG_CHECK_MODULES([PORTAUDIO], [portaudio-2.0])
  PKG_CHECK_MODULES([POCKETSPHINX], [pocketsphinx])
  AC_DEFINE([HAVE_VOICE], [1], [Voice passphrase support enabled])
fi
AM_CONDITIONAL([ENABLE_VOICE], [test "x$enable_voice" = "xyes"])

AC_CHECK_HEADERS([crypt.h])
AC_SEARCH_LIBS([crypt], [crypt])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
