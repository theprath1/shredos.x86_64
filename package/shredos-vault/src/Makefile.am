bin_PROGRAMS = shredos-vault

shredos_vault_SOURCES = \
	main.c \
	platform.c platform.h \
	config.c config.h \
	auth.c auth.h \
	auth_password.c auth_password.h \
	installer.c installer.h \
	luks.c luks.h \
	deadman.c deadman.h \
	wipe.c wipe.h \
	tui.h

# TUI backend selection
if USE_NCURSES
shredos_vault_SOURCES += tui_ncurses.c
else
shredos_vault_SOURCES += tui_vt100.c
endif

# Optional fingerprint auth
if USE_FINGERPRINT
shredos_vault_SOURCES += auth_fingerprint.c auth_fingerprint.h
endif

# Optional voice auth
if USE_VOICE
shredos_vault_SOURCES += auth_voice.c auth_voice.h
endif

shredos_vault_CFLAGS = $(AM_CFLAGS) -Wall -Wextra -std=c11
shredos_vault_LDADD =

if USE_NCURSES
shredos_vault_CFLAGS += $(NCURSES_CFLAGS)
shredos_vault_LDADD += $(NCURSES_LIBS)
endif

shredos_vault_CFLAGS += $(LIBCONFIG_CFLAGS) $(CRYPTSETUP_CFLAGS)
shredos_vault_LDADD += $(LIBCONFIG_LIBS) $(CRYPTSETUP_LIBS)

if USE_FINGERPRINT
shredos_vault_CFLAGS += $(FPRINT_CFLAGS)
shredos_vault_LDADD += $(FPRINT_LIBS)
endif

if USE_VOICE
shredos_vault_CFLAGS += $(POCKETSPHINX_CFLAGS) $(PORTAUDIO_CFLAGS)
shredos_vault_LDADD += $(POCKETSPHINX_LIBS) $(PORTAUDIO_LIBS) -lm
endif
