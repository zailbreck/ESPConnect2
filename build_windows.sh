#!/bin/bash
# build_windows.sh — Cross-compile ESPConnect E2E test to Windows .exe
# Requires: mingw-w64, mbedtls 3.6.5 cross-compiled for mingw
#
# Prerequisites:
#   1. Install mingw-w64:     sudo apt install mingw-w64
#   2. Cross-compile mbedtls:
#       cd mbedtls-3.6.5
#       CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar make -j$(nproc)
#
# Output: espconnect_e2e.exe (static, no DLLs needed)
# Run on Windows: espconnect_e2e.exe

set -e

GCC="x86_64-w64-mingw32-gcc"
MBEDTLS_DIR="${MBEDTLS_DIR:-mbedtls-3.6.5}"
CFLAGS="-std=gnu11 -O2 -static"
WINFLAGS="-DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600"
INCLUDES="-I include -I include/internal -I ${MBEDTLS_DIR}/include"

LIBS="${MBEDTLS_DIR}/library/libmbedcrypto.a \
      ${MBEDTLS_DIR}/library/libmbedtls.a \
      ${MBEDTLS_DIR}/library/libmbedx509.a \
      -lws2_32 -lpthread -lbcrypt -lshlwapi -lm"

SRCS="src/mercury.c \
      src/spclient.c \
      src/zeroconf.c \
      src/decrypt.c \
      src/esp_spotify.c \
      src/platform_windows.c \
      test/x86/test_e2e.c"

OUT="espconnect_e2e.exe"

echo "=== Cross-compiling ESPConnect E2E for Windows ==="
echo "  Compiler: ${GCC}"
echo "  Target:   ${OUT}"

${GCC} ${CFLAGS} ${WINFLAGS} ${INCLUDES} ${SRCS} ${LIBS} -o ${OUT}

echo ""
echo "=== SUCCESS: ${OUT} ==="
file ${OUT} 2>/dev/null || echo "  (use 'file' to verify PE32+ executable)"
ls -lh ${OUT}
echo ""
echo "Copy to Windows and run:"
echo "  espconnect_e2e.exe"
