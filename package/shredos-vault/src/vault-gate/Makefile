# ShredOS Vault -- Persistent Install Build System
#
# Auto-detects platform and available libraries.
#
# Usage:
#   make             Build for current platform
#   make linux       Build Linux binary
#   make macos       Build macOS binary
#   make clean       Remove build artefacts
#   make install     Install for current platform
#   make uninstall   Uninstall
#   make detect-libs Show detected libraries

CC ?= cc
CFLAGS = -O2 -Wall -Wextra -Wpedantic -std=c11

SRC = ..

CORE_SRCS = $(SRC)/platform.c $(SRC)/config.c $(SRC)/auth.c \
            $(SRC)/auth_password.c $(SRC)/luks.c $(SRC)/wipe.c \
            $(SRC)/deadman.c $(SRC)/installer.c $(SRC)/main.c

BINARY = shredos-vault

UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

.PHONY: all clean install uninstall linux macos windows detect-libs

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

# ---- Linux build ----

linux: $(BINARY)

LINUX_CFLAGS = $(CFLAGS)
LINUX_LDFLAGS =

HAS_NCURSES := $(shell pkg-config --exists ncurses 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_NCURSES),yes)
  LINUX_CFLAGS += -DHAVE_NCURSES $(shell pkg-config --cflags ncurses)
  LINUX_LDFLAGS += $(shell pkg-config --libs ncurses)
  TUI_SRC = $(SRC)/tui_ncurses.c
else
  TUI_SRC = $(SRC)/tui_vt100.c
endif

HAS_LIBCONFIG := $(shell pkg-config --exists libconfig 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_LIBCONFIG),yes)
  LINUX_CFLAGS += -DHAVE_LIBCONFIG $(shell pkg-config --cflags libconfig)
  LINUX_LDFLAGS += $(shell pkg-config --libs libconfig)
endif

HAS_CRYPTSETUP := $(shell pkg-config --exists libcryptsetup 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_CRYPTSETUP),yes)
  LINUX_CFLAGS += -DHAVE_LIBCRYPTSETUP $(shell pkg-config --cflags libcryptsetup)
  LINUX_LDFLAGS += $(shell pkg-config --libs libcryptsetup)
endif

HAS_CRYPT := $(shell echo 'int main(){}' | $(CC) -x c - -lcrypt -o /dev/null 2>/dev/null && echo yes || echo no)
ifeq ($(HAS_CRYPT),yes)
  LINUX_CFLAGS += -DHAVE_CRYPT_H
  LINUX_LDFLAGS += -lcrypt
endif

$(BINARY): $(CORE_SRCS) $(TUI_SRC)
	@echo "Building shredos-vault for Linux..."
	@echo "  ncurses:       $(HAS_NCURSES)"
	@echo "  libconfig:     $(HAS_LIBCONFIG)"
	@echo "  libcryptsetup: $(HAS_CRYPTSETUP)"
	@echo "  libcrypt:      $(HAS_CRYPT)"
	$(CC) $(LINUX_CFLAGS) $(CORE_SRCS) $(TUI_SRC) $(LINUX_LDFLAGS) -o $(BINARY)
	@echo "Built: $(BINARY)"

# ---- macOS build ----

macos: $(BINARY)-macos

$(BINARY)-macos: $(CORE_SRCS) $(SRC)/tui_vt100.c
	@echo "Building shredos-vault for macOS..."
	$(CC) $(CFLAGS) -DHAVE_IOKIT \
		$(CORE_SRCS) $(SRC)/tui_vt100.c \
		-framework Security -framework IOKit -framework CoreFoundation \
		-o $(BINARY)

# ---- Windows ----

windows:
	@echo "Windows build requires MSVC. See USAGE.md."

# ---- Info ----

detect-libs:
	@echo "ncurses:       $(HAS_NCURSES)"
	@echo "libconfig:     $(HAS_LIBCONFIG)"
	@echo "libcryptsetup: $(HAS_CRYPTSETUP)"
	@echo "libcrypt:      $(HAS_CRYPT)"

# ---- Clean ----

clean:
	rm -f $(BINARY) *.o
