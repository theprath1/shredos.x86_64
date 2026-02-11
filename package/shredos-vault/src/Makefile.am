bin_PROGRAMS = shredos-vault

shredos_vault_SOURCES = \
	main.c \
	platform.c platform.h \
	config.c config.h \
	auth.c auth.h \
	auth_password.c auth_password.h \
	luks.c luks.h \
	deadman.c deadman.h \
	wipe.c wipe.h \
	tui.h

if HAVE_NCURSES
shredos_vault_SOURCES += tui_ncurses.c
else
shredos_vault_SOURCES += tui_vt100.c
endif

if ENABLE_FINGERPRINT
shredos_vault_SOURCES += auth_fingerprint.c auth_fingerprint.h
endif

if ENABLE_VOICE
shredos_vault_SOURCES += auth_voice.c auth_voice.h
endif

shredos_vault_CFLAGS = \
	$(NCURSES_CFLAGS) \
	$(LIBCONFIG_CFLAGS) \
	$(LIBCRYPTSETUP_CFLAGS) \
	-Wall -Wextra -Wpedantic -Wno-unused-parameter

shredos_vault_LDADD = \
	$(NCURSES_LIBS) \
	$(LIBCONFIG_LIBS) \
	$(LIBCRYPTSETUP_LIBS)

if ENABLE_FINGERPRINT
shredos_vault_CFLAGS += $(LIBFPRINT_CFLAGS)
shredos_vault_LDADD += $(LIBFPRINT_LIBS)
endif

if ENABLE_VOICE
shredos_vault_CFLAGS += $(PORTAUDIO_CFLAGS) $(POCKETSPHINX_CFLAGS)
shredos_vault_LDADD += $(PORTAUDIO_LIBS) $(POCKETSPHINX_LIBS)
endif
