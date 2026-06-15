# Makefile — x86 Linux build test for esp-spotify-connect
# ======================================================
# Builds the library with POSIX sockets + OpenSSL for
# development/testing on x86 Linux.
#
# Usage: make
# Dependencies: gcc, OpenSSL (libssl-dev)

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wno-unused-parameter -O2 -g \
         -D_GNU_SOURCE \
         -I../../include -I../../include/internal

LDFLAGS = -lssl -lcrypto -lpthread

# Source files for x86 target
SRCS = ../../src/zeroconf.c \
       ../../src/mercury.c \
       ../../src/platform_posix.c \
       test_build.c

OBJS = $(SRCS:.c=.o)

TARGET = test_build

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
