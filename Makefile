CC = gcc
CFLAGS = -Wall -Wextra -O2
LIBS = -lcrypto
TARGET = lssa
PREFIX = /usr/local

all: $(TARGET)

$(TARGET): LSSA.c
	$(CC) $(CFLAGS) LSSA.c -o $(TARGET) $(LIBS)

install: $(TARGET)
	install -m 755 $(TARGET) $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(TARGET)
