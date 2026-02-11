# macOS Secure Drive Wiper — Build
#
# Usage:
#   make                  Build the secure_wipe binary
#   make clean            Remove build artifacts
#   make install          Install to /usr/local/bin (requires sudo)
#
# The binary requires root to run (raw disk access).

CC = cc
CFLAGS = -O2 -Wall -Wextra -Wpedantic -std=c11
FRAMEWORKS = -framework Security -framework IOKit -framework CoreFoundation
LDFLAGS = $(FRAMEWORKS)

TARGET = secure_wipe
SOURCES = secure_wipe.c
HEADERS = secure_wipe.h

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
