# ShredOS Vault — Persistent Install Build System
#
# Builds the full ShredOS Vault binary from the unified codebase.
# Auto-detects platform and available libraries via pkg-config.
#
# Usage:
#   make                    Build for current platform
#   make linux              Build Linux binary
#   make macos              Build macOS binary
#   make windows            Print Windows build instructions
#   make detect-libs        Show detected libraries
#   make clean              Remove build artifacts
#   make install            Install for current platform
#   make uninstall          Uninstall from current platform
#
# Copyright 2025 — GPL-2.0+

CC ?= cc
CFLAGS = -O2 -Wall -Wextra -Wpedantic -std=c11

# Source directory (real vault sources, one level up)
SRC = ..

# Core sources (always compiled)
CORE_SRCS = $(SRC)/platform.c $(SRC)/config.c $(SRC)/auth.c \
            $(SRC)/auth_password.c $(SRC)/luks.c $(SRC)/wipe.c \
            $(SRC)/deadman.c $(SRC)/main.c

# Output binary name
BINARY = shredos-vault

# Detect platform
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

.PHONY: all clean install uninstall linux macos windows detect-libs

# ---- Auto-detect platform ----

ifeq ($(UNAME_S),Linux)
all: linux
install:
	@cd linux && sudo bash install.sh
uninstall:
	@cd linux && sudo bash uninstall.sh
endif

ifeq ($(UNAME_S),Darwin)
all: macos
install:
	@cd macos && sudo bash install.sh
uninstall:
	@cd macos && sudo bash uninstall.sh
endif

ifeq ($(UNAME_S),Windows)
all:
	@echo "Use install.bat on Windows, or 'make linux' / 'make macos' on Unix."
install:
	@echo "Use install.bat on Windows."
uninstall:
	@echo "Use uninstall.bat on Windows."
endif

# ---- Linux build ----

linux: $(BINARY)

# Auto-detect available libraries
LINUX_CFLAGS = $(CFLAGS)
LINUX_LDFLAGS =
AUTH_EXTRA_SRC =

# ncurses detection
HAS_NCURSES := $(shell pkg-config --exists ncurses 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_NCURSES),yes)
  LINUX_CFLAGS += -DHAVE_NCURSES $(shell pkg-config --cflags ncurses)
  LINUX_LDFLAGS += $(shell pkg-config --libs ncurses)
  TUI_SRC = $(SRC)/tui_ncurses.c
else
  TUI_SRC = $(SRC)/tui_vt100.c
endif

# libconfig detection
HAS_LIBCONFIG := $(shell pkg-config --exists libconfig 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_LIBCONFIG),yes)
  LINUX_CFLAGS += -DHAVE_LIBCONFIG $(shell pkg-config --cflags libconfig)
  LINUX_LDFLAGS += $(shell pkg-config --libs libconfig)
endif

# libcryptsetup detection
HAS_CRYPTSETUP := $(shell pkg-config --exists libcryptsetup 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_CRYPTSETUP),yes)
  LINUX_CFLAGS += -DHAVE_LIBCRYPTSETUP $(shell pkg-config --cflags libcryptsetup)
  LINUX_LDFLAGS += $(shell pkg-config --libs libcryptsetup)
endif

# libcrypt detection (for crypt())
HAS_CRYPT := $(shell echo 'int main(){}' | $(CC) -x c - -lcrypt -o /dev/null 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_CRYPT),yes)
  LINUX_CFLAGS += -DHAVE_CRYPT_H
  LINUX_LDFLAGS += -lcrypt
endif

# libfprint detection (optional)
HAS_FPRINT := $(shell pkg-config --exists libfprint-2 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_FPRINT),yes)
  LINUX_CFLAGS += -DHAVE_FINGERPRINT $(shell pkg-config --cflags libfprint-2)
  LINUX_LDFLAGS += $(shell pkg-config --libs libfprint-2)
  AUTH_EXTRA_SRC += $(SRC)/auth_fingerprint.c
endif

# PocketSphinx + PortAudio detection (optional)
HAS_PSPHINX := $(shell pkg-config --exists pocketsphinx 2>/dev/null && echo yes || echo no)
HAS_PORTAUDIO := $(shell pkg-config --exists portaudio-2.0 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_PSPHINX)-$(HAS_PORTAUDIO),yes-yes)
  LINUX_CFLAGS += -DHAVE_VOICE $(shell pkg-config --cflags pocketsphinx portaudio-2.0)
  LINUX_LDFLAGS += $(shell pkg-config --libs pocketsphinx portaudio-2.0) -lm
  AUTH_EXTRA_SRC += $(SRC)/auth_voice.c
endif

$(BINARY): $(CORE_SRCS) $(TUI_SRC) $(AUTH_EXTRA_SRC)
	@echo "Building shredos-vault for Linux..."
	@echo "  ncurses:       $(HAS_NCURSES)"
	@echo "  libconfig:     $(HAS_LIBCONFIG)"
	@echo "  libcryptsetup: $(HAS_CRYPTSETUP)"
	@echo "  libcrypt:      $(HAS_CRYPT)"
	@echo "  libfprint:     $(HAS_FPRINT)"
	@echo "  voice:         $(HAS_PSPHINX)-$(HAS_PORTAUDIO)"
	$(CC) $(LINUX_CFLAGS) \
		$(CORE_SRCS) $(TUI_SRC) $(AUTH_EXTRA_SRC) \
		$(LINUX_LDFLAGS) \
		-o $(BINARY)
	@echo "Built: $(BINARY)"

# ---- macOS build ----

macos: $(BINARY)-macos

$(BINARY)-macos: $(CORE_SRCS) $(SRC)/tui_vt100.c
	@echo "Building shredos-vault for macOS..."
	$(CC) $(CFLAGS) -DHAVE_IOKIT \
		$(CORE_SRCS) $(SRC)/tui_vt100.c \
		-framework Security -framework IOKit -framework CoreFoundation \
		-o $(BINARY)
	@echo "Built: $(BINARY)"

# ---- Windows build (instructions only) ----

windows:
	@echo "Windows build requires MSVC (Visual Studio Developer Command Prompt)."
	@echo ""
	@echo "Build the service:"
	@echo "  cl /O2 /W4 /DUNICODE /D_UNICODE"
	@echo "     ..\\platform.c ..\\config.c ..\\auth.c ..\\auth_password.c"
	@echo "     ..\\luks.c ..\\wipe.c ..\\deadman.c ..\\tui_win32.c"
	@echo "     windows\\vault-gate-service.c"
	@echo "     advapi32.lib crypt32.lib /Fe:shredos-vault-service.exe"
	@echo ""
	@echo "Build the Credential Provider:"
	@echo "  cl /EHsc /LD /DUNICODE /D_UNICODE /DVAULT_PLATFORM_WINDOWS"
	@echo "     windows\\VaultGateProvider.cpp ..\\auth_password.c ..\\config.c ..\\platform.c"
	@echo "     /link ole32.lib advapi32.lib shlwapi.lib crypt32.lib /OUT:VaultGateProvider.dll"

# ---- Lib detection report ----

detect-libs:
	@echo "=== Library Detection ==="
	@echo "ncurses:       $(HAS_NCURSES)"
	@echo "libconfig:     $(HAS_LIBCONFIG)"
	@echo "libcryptsetup: $(HAS_CRYPTSETUP)"
	@echo "libcrypt:      $(HAS_CRYPT)"
	@echo "libfprint:     $(HAS_FPRINT)"
	@echo "pocketsphinx:  $(HAS_PSPHINX)"
	@echo "portaudio:     $(HAS_PORTAUDIO)"
	@echo ""
	@echo "TUI backend:   $(if $(filter yes,$(HAS_NCURSES)),ncurses,vt100)"
	@echo "Config backend: $(if $(filter yes,$(HAS_LIBCONFIG)),libconfig,ini)"
	@echo "Disk backend:  $(if $(filter yes,$(HAS_CRYPTSETUP)),luks,none)"

# ---- Clean ----

clean:
	rm -f $(BINARY)
	rm -f shredos-vault-service.exe vault-gate-service.exe VaultGateProvider.dll
	rm -f *.o *.obj *.lib *.exp
