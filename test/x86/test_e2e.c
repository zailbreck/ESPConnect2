// test_e2e.c — Full End-to-End Pipeline Test
// ===========================================
// Pair → Login5 → ClientToken → Metadata → CDN → AudioKey → Download → Decrypt
//
// Build (Linux):
//   gcc -std=gnu11 -O2 -I include -I include/internal \
//       src/mercury.c src/spclient.c src/zeroconf.c src/decrypt.c \
//       src/esp_spotify.c src/platform_posix.c test/x86/test_e2e.c \
//       -lssl -lcrypto -lm -o e2e_test
//
// Build (Windows cross):
//   x86_64-w64-mingw32-gcc -std=gnu11 -O2 -static \
//       -I include -I include/internal \
//       -I mbedtls-3.6.5/include \
//       -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600 \
//       src/mercury.c src/spclient.c src/zeroconf.c src/decrypt.c \
//       src/esp_spotify.c src/platform_windows.c test/x86/test_e2e.c \
//       mbedtls-3.6.5/library/libmbedcrypto.a \
//       mbedtls-3.6.5/library/libmbedtls.a \
//       mbedtls-3.6.5/library/libmbedx509.a \
//       -lws2_32 -lpthread -lbcrypt -lshlwapi -lm \
//       -o e2e_test.exe
//
// License: MIT

#include "esp_spotify.h"
#include "internal/spclient.h"
#include "internal/mercury.h"
#include "internal/decrypt.h"
#include "internal/platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================== */
/*  Credentials (from earlier successful Login5 auth)                  */
/* ================================================================== */

static const char *AUTH_DATA_B64 =
    "QWdCLXRndUF2enJVWUdGaHg2V2hDRl9xdVNVaFAxd3pxdklTeXlzMTFyQzR6UkNVRVpq"
    "YW44VG9mb1pPc1JXdV84UlNpckxvMElBYTh3bjBweTU1Q3lxRVZ4VW1OelNnOXJFOXhy"
    "NjB0ZnE3VVhvYXJfaUZKckpNSDNTazA0TTRqNUJ5U2Vfc1dxdi1VcHFSV1dMNlVja0FP"
    "NWpXcVVDZWloWkJQRFZzek5DYWhHM3hBRTlzUkUtQWZZcU4tNHM0ekJV";

#define AUTH_TYPE           1
#define USERNAME            "31gs6dlgp5sdrb32kznvsklgwhiy"
#define DEVICE_ID           "142137fd329622137a14901634264e6f332e2411"
#define AP_HOST             "ap-gew4.spotify.com"
#define AP_PORT             443

/* Track GID from: 0daEJMXc3b4ZMTnvtHpuTt (base62 decoded) */
static const uint8_t TEST_TRACK_GID[16] = {
    0x06, 0xfa, 0xfd, 0xa4, 0x5f, 0x70, 0x4f, 0x18,
    0x88, 0x20, 0x10, 0xaa, 0x97, 0x2c, 0xdc, 0x6f,
};

/* ================================================================== */
/*  Hex dump helper                                                     */
/* ================================================================== */

static void hex_dump(const char *label, const uint8_t *d, size_t n) {
    fprintf(stderr, "%s (%zu): ", label, n);
    for (size_t i = 0; i < n && i < 48; i++)
        fprintf(stderr, "%02x", d[i]);
    if (n > 48) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

/* ================================================================== */
/*  Step 1: Login5 via raw Mercury (no pairing needed)                  */
/* ================================================================== */

static mercury_session_t *do_login5(const char *username,
                                     const char *auth_b64,
                                     int auth_type,
                                     const char *device_id,
                                     const char *ap_host, int ap_port) {
    fprintf(stderr, "\n===== STEP 1: LOGIN5 AUTH =====\n");

    mercury_session_t *sess = mercury_init();
    if (!sess) {
        fprintf(stderr, "FAIL: mercury_init\n");
        return NULL;
    }

    int ret = mercury_login5(sess, username, auth_b64,
                              auth_type, device_id,
                              ap_host, ap_port);
    if (ret != 0) {
        fprintf(stderr, "FAIL: mercury_login5 = %d\n", ret);
        mercury_destroy(sess);
        return NULL;
    }

    const char *canon = mercury_get_canonical_username(sess);
    fprintf(stderr, "OK: logged in as '%s'\n", canon ? canon : "?");

    return sess;
}

/* ================================================================== */
/*  Step 2: Client Token via spclient Mercury                          */
/* ================================================================== */

static char g_client_token[2048] = {0};

static int do_client_token(mercury_session_t *sess) {
    fprintf(stderr, "\n===== STEP 2: CLIENT TOKEN =====\n");
    int ret = spclient_get_client_token(sess, g_client_token,
                                        sizeof(g_client_token));
    if (ret != 0) {
        fprintf(stderr, "FAIL: spclient_get_client_token = %d\n", ret);
        return ret;
    }
    fprintf(stderr, "OK: token = %.20s... (%zu chars)\n",
            g_client_token, strlen(g_client_token));
    return 0;
}

/* ================================================================== */
/*  Step 3: Track Metadata                                             */
/* ================================================================== */

static spclient_track_meta_t g_track_meta = {0};

static int do_track_metadata(void) {
    fprintf(stderr, "\n===== STEP 3: TRACK METADATA =====\n");
    int ret = spclient_get_track_metadata(g_client_token,
                                          TEST_TRACK_GID,
                                          &g_track_meta);
    if (ret != 0) {
        fprintf(stderr, "FAIL: spclient_get_track_metadata = %d\n", ret);
        return ret;
    }
    fprintf(stderr, "OK: %d file(s) found\n", g_track_meta.num_files);
    return 0;
}

/* ================================================================== */
/*  Step 4: CDN Resolve (first file)                                    */
/* ================================================================== */

static char g_cdn_url[1024] = {0};

static int do_cdn_resolve(void) {
    fprintf(stderr, "\n===== STEP 4: CDN RESOLVE =====\n");
    if (g_track_meta.num_files < 1) {
        fprintf(stderr, "FAIL: no files in metadata\n");
        return -1;
    }

    const char *file_id = g_track_meta.files[0].file_id_hex;
    fprintf(stderr, "Resolving file: %s\n", file_id);

    int ret = spclient_resolve_cdn_url(g_client_token, file_id,
                                       g_cdn_url, sizeof(g_cdn_url));
    if (ret != 0) {
        fprintf(stderr, "FAIL: spclient_resolve_cdn_url = %d\n", ret);
        return ret;
    }
    fprintf(stderr, "OK: CDN = %.80s...\n", g_cdn_url);
    return 0;
}

/* ================================================================== */
/*  Step 5: AudioKey via Mercury                                        */
/* ================================================================== */

static uint8_t g_audio_key[16] = {0};
static uint8_t g_file_id_bin[20] = {0}; /* 20-byte file ID hex decoded */

static int hex_decode_file_id(const char *hex_20, uint8_t *out) {
    for (int i = 0; i < 20; i++) {
        char c = hex_20[i];
        int nib = (c >= '0' && c <= '9') ? c - '0' :
                  (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                  (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (nib < 0) return -1;
        if (i & 1) out[i / 2] |= (uint8_t)nib;
        else out[i / 2] = (uint8_t)(nib << 4);
    }
    return 0;
}

static int do_audio_key(mercury_session_t *sess) {
    fprintf(stderr, "\n===== STEP 5: AUDIO KEY =====\n");
    if (g_track_meta.num_files < 1) {
        fprintf(stderr, "FAIL: no files in metadata\n");
        return -1;
    }

    /* Decode 40-char hex file ID → 20 bytes binary */
    if (hex_decode_file_id(g_track_meta.files[0].file_id_hex,
                           g_file_id_bin) != 0) {
        fprintf(stderr, "FAIL: hex decode file_id\n");
        return -1;
    }

    /* First 16 bytes go to spclient_get_audio_key, full 20 to decrypt */
    int ret = spclient_get_audio_key(sess, TEST_TRACK_GID,
                                     g_file_id_bin, g_audio_key);
    if (ret != 0) {
        fprintf(stderr, "FAIL: spclient_get_audio_key = %d\n", ret);
        return ret;
    }

    hex_dump("  key", g_audio_key, 16);
    return 0;
}

/* ================================================================== */
/*  Step 6: Download & Decrypt one chunk                                */
/* ================================================================== */

static int do_download_decrypt(void) {
    fprintf(stderr, "\n===== STEP 6: CDN DOWNLOAD + DECRYPT =====\n");

    /* Download first 16KB from CDN */
    size_t chunk_size = 16384;
    uint8_t *buf = malloc(chunk_size);
    if (!buf) {
        fprintf(stderr, "FAIL: malloc\n");
        return -1;
    }

    int ret = spclient_download_audio(g_cdn_url, 0, chunk_size,
                                      buf, chunk_size);
    if (ret <= 0) {
        fprintf(stderr, "FAIL: spclient_download_audio = %d\n", ret);
        free(buf);
        return ret;
    }

    fprintf(stderr, "OK: downloaded %d bytes\n", ret);
    hex_dump("  before decrypt", buf, 32);

    /* Decrypt */
    decrypt_audio(buf, (size_t)ret, g_audio_key, g_file_id_bin);

    fprintf(stderr, "OK: decrypted %d bytes\n", ret);
    hex_dump("  after decrypt", buf, 32);

    /* Quick sanity: OGG pages start with "OggS" (0x4f 0x67 0x67 0x53) */
    if (ret >= 4 && buf[0] == 0x4f && buf[1] == 0x67 &&
        buf[2] == 0x67 && buf[3] == 0x53) {
        fprintf(stderr, "MAGIC: 'OggS' header found! ✅\n");
    } else {
        fprintf(stderr, "WARN: no OggS magic (first 4 bytes: %02x %02x %02x %02x)\n",
                buf[0], buf[1], buf[2], buf[3]);
    }

    free(buf);
    return 0;
}

/* ================================================================== */
/*  Main: full pipeline with rate-limit wait                            */
/* ================================================================== */

int main(void) {
    fprintf(stderr, "========================================\n");
    fprintf(stderr, " ESPConnect E2E Pipeline Test\n");
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "Track:  0daEJMXc3b4ZMTnvtHpuTt\n");
    fprintf(stderr, "AP:     %s:%d\n", AP_HOST, AP_PORT);
    fprintf(stderr, "User:   %s\n", USERNAME);
    fprintf(stderr, "Auth:   type=%d, %zu bytes (b64)\n",
            AUTH_TYPE, strlen(AUTH_DATA_B64));
    fprintf(stderr, "========================================\n\n");

    /* Rate limit awareness: wait before connecting */
    fprintf(stderr, "[WAIT] 15s rate-limit delay...\n");
    fflush(stderr);
    platform_sleep_ms(15000);

    /* STEP 1: Login5 */
    mercury_session_t *sess = do_login5(USERNAME, AUTH_DATA_B64,
                                         AUTH_TYPE, DEVICE_ID,
                                         AP_HOST, AP_PORT);
    if (!sess) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 1 (Login5)\n");
        return 1;
    }

    /* STEP 2: Client Token */
    if (do_client_token(sess) != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 2 (Client Token)\n");
        mercury_destroy(sess);
        return 2;
    }

    /* STEP 3: Track Metadata */
    if (do_track_metadata() != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 3 (Metadata)\n");
        mercury_destroy(sess);
        return 3;
    }

    /* STEP 4: CDN Resolve */
    if (do_cdn_resolve() != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 4 (CDN)\n");
        spclient_free_track_meta(&g_track_meta);
        mercury_destroy(sess);
        return 4;
    }

    /* STEP 5: AudioKey */
    if (do_audio_key(sess) != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 5 (AudioKey)\n");
        spclient_free_track_meta(&g_track_meta);
        mercury_destroy(sess);
        return 5;
    }

    /* STEP 6: Download + Decrypt */
    int decrypt_ok = do_download_decrypt();

    /* Cleanup */
    spclient_free_track_meta(&g_track_meta);
    mercury_destroy(sess);

    if (decrypt_ok != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 6 (Download/Decrypt)\n");
        return 6;
    }

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, " ✅ E2E PIPELINE SUCCESS!\n");
    fprintf(stderr, "========================================\n");
    return 0;
}
