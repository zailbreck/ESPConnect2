// test_e2e.c — Full End-to-End Pipeline Test
// ===========================================
// mDNS pair → Bell HTTP → DH decrypt → Login5 → Token → Metadata → CDN → AudioKey → Decrypt
//
// Build (Windows cross):
//   x86_64-w64-mingw32-gcc -std=gnu11 -O2 -static \
//       -I include -I include/internal -I mbedtls/include \
//       -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600 \
//       src/*.c thirdparty/mdns.c thirdparty/mdnsd.c test/x86/test_e2e.c \
//       -Wl,--start-group mbedtls/library/libmbedtls.a mbedtls/library/libmbedcrypto.a \
//       mbedtls/library/libmbedx509.a -Wl,--end-group \
//       -lws2_32 -lpthread -lbcrypt -lshlwapi -lm \
//       -o espconnect_e2e.exe
//
// License: MIT

#include "esp_spotify.h"
#include "internal/spclient.h"
#include "internal/mercury.h"
#include "internal/zeroconf.h"
#include "internal/decrypt.h"
#include "internal/platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================== */
/*  Config (edit device name before building)                          */
/* ================================================================== */

#define DEVICE_NAME         "ESPConnect-TEST"
#define DEVICE_ID           "142137fd329622137a14901634264e6f332e2411"
#define AP_HOST             "ap-gew4.spotify.com"
#define AP_PORT             443
#define BELL_PORT           7864
#define PAIRING_TIMEOUT     600     /* seconds to wait for pairing */

/* Track GID: 0daEJMXc3b4ZMTnvtHpuTt (base62 decoded) */
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

/* Hex decode (for file_id) */
static int hex_decode_20(const char *hex_40, uint8_t *out) {
    for (int i = 0; i < 20; i++) {
        char nl = hex_40[i*2], nh = hex_40[i*2+1];
        int lo = (nl >= 'a') ? nl - 'a' + 10 : (nl >= 'A') ? nl - 'A' + 10 : nl - '0';
        int hi = (nh >= 'a') ? nh - 'a' + 10 : (nh >= 'A') ? nh - 'A' + 10 : nh - '0';
        if (lo < 0 || hi < 0) return -1;
        out[i] = (uint8_t)((lo << 4) | hi);
    }
    return 0;
}

/* ================================================================== */
/*  Step 0: ZeroConf Pairing (mDNS + Bell HTTP + DH decrypt)           */
/* ================================================================== */

/* Pre-captured credentials (from V13 Linux — proven working) */
#define AUTH_B64_SKIP "QWdCLXRndUF2enJVWUdGaHg2V2hDRl9xdVNVaFAxd3pxdklTeXlzMTFyQzR6UkNVRVpqYW44VG9mb1pPc1JXdV84UlNpckxvMElBYTh3bjBweTU1Q3lxRVZ4VW1OelNnOXJFOXhyNjB0ZnE3VVhvYXJfaUZKckpNSDNTazA0TTRqNUJ5U2Vfc1dxdi1VcHFSV1dMNlVja0FPNWpXcVVDZWloWkJQRFZzek5DYWhHM3hBRTlzUkUtQWZZcU4tNHM0ekJV"
#define AUTH_TYPE_SKIP 1
#define USERNAME_SKIP   "31gs6dlgp5sdrb32kznvsklgwhiy"

#define SKIP_PAIRING  /* Use V13-captured credentials */

static char g_auth_b64[4096] = {0};
static int g_auth_loaded = 0;
static int   g_auth_type = 0;
static char g_username[256] = {0};

static int do_pairing(void) {
    fprintf(stderr, "\n===== STEP 0: ZEROCONF PAIRING =====\n");
    fprintf(stderr, "  Device: %s\n", DEVICE_NAME);
    fprintf(stderr, "  Bell port: %d\n", BELL_PORT);
    fprintf(stderr, "  IP detection: auto\n");
    fprintf(stderr, "\n"
    "  *** NOW OPEN SPOTIFY ON YOUR PHONE/DESKTOP ***\n"
    "  Tap 'Connect to a device' and look for '%s'\n"
    "  Waiting up to %d seconds...\n\n", DEVICE_NAME, PAIRING_TIMEOUT);

    zeroconf_config_t zc = {
        .device_name    = DEVICE_NAME,
        .device_id      = DEVICE_ID,
        .brand_display  = "ESPConnect",
        .model_display  = DEVICE_NAME,
        .bell_port      = BELL_PORT,
        .timeout_seconds = PAIRING_TIMEOUT,
    };

    zeroconf_session_t *z = zeroconf_init(&zc);
    if (!z) {
        fprintf(stderr, "FAIL: zeroconf_init\n");
        return -1;
    }

    zeroconf_start(z);

    /* Poll for pairing */
    int paired = 0;
    for (int waited = 0; waited < PAIRING_TIMEOUT; waited++) {
        int ret = zeroconf_poll(z, 1000);
        if (ret == 1) {
            zeroconf_credentials_t creds;
            if (zeroconf_get_credentials(z, &creds) == 0) {
                strncpy(g_auth_b64, creds.auth_data_b64, sizeof(g_auth_b64) - 1);
                g_auth_type = creds.auth_type;
                if (creds.username) {
                    strncpy(g_username, creds.username, sizeof(g_username) - 1);
                }
                fprintf(stderr, "\nOK: Paired! User=%s AuthType=%d\n",
                        g_username, g_auth_type);
                zeroconf_free_credentials(&creds);
                paired = 1;
                break;
            }
            zeroconf_free_credentials(&creds);
        }
        if (waited % 10 == 9) {
            fprintf(stderr, "  [%d/%ds] Waiting for Spotify app...\r",
                    waited + 1, PAIRING_TIMEOUT);
            fflush(stderr);
        }
    }

    zeroconf_destroy(z);

    if (!paired) {
        fprintf(stderr, "\nFAIL: Pairing timeout\n");
        return -1;
    }
    return 0;
}

/* ================================================================== */
/*  Step 1: Login5 via raw Mercury                                     */
/* ================================================================== */

static mercury_session_t *do_login5(void) {
    fprintf(stderr, "\n===== STEP 1: LOGIN5 AUTH =====\n");

    mercury_session_t *sess = mercury_init();
    if (!sess) {
        fprintf(stderr, "FAIL: mercury_init\n");
        return NULL;
    }

    int ret = mercury_login5(sess, g_username, g_auth_b64,
                              g_auth_type, DEVICE_ID, AP_HOST, AP_PORT);
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
/*  Step 2: Client Token                                               */
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
    fprintf(stderr, "OK: token = %.30s... (%zu chars)\n",
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
                                          TEST_TRACK_GID, &g_track_meta);
    if (ret != 0) {
        fprintf(stderr, "FAIL: spclient_get_track_metadata = %d\n", ret);
        return ret;
    }
    fprintf(stderr, "OK: %d file(s) found\n", g_track_meta.num_files);
    return 0;
}

/* ================================================================== */
/*  Step 4: CDN Resolve                                                */
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
    fprintf(stderr, "OK: CDN URL resolved\n");
    return 0;
}

/* ================================================================== */
/*  Step 5: AudioKey via Mercury                                        */
/* ================================================================== */

static uint8_t g_audio_key[16] = {0};
static uint8_t g_file_id_bin[20] = {0};

static int do_audio_key(mercury_session_t *sess) {
    fprintf(stderr, "\n===== STEP 5: AUDIO KEY =====\n");
    if (g_track_meta.num_files < 1) {
        fprintf(stderr, "FAIL: no files in metadata\n");
        return -1;
    }

    if (hex_decode_20(g_track_meta.files[0].file_id_hex, g_file_id_bin) != 0) {
        fprintf(stderr, "FAIL: hex decode file_id\n");
        return -1;
    }

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

    size_t chunk_size = 16384;
    uint8_t *buf = malloc(chunk_size);
    if (!buf) return -1;

    int ret = spclient_download_audio(g_cdn_url, 0, chunk_size,
                                      buf, chunk_size);
    if (ret <= 0) {
        fprintf(stderr, "FAIL: download = %d\n", ret);
        free(buf);
        return ret;
    }

    fprintf(stderr, "OK: downloaded %d bytes\n", ret);

    decrypt_audio(buf, (size_t)ret, g_audio_key, g_file_id_bin);
    fprintf(stderr, "OK: decrypted %d bytes\n", ret);

    if (ret >= 4 && buf[0] == 0x4f && buf[1] == 0x67 &&
        buf[2] == 0x67 && buf[3] == 0x53) {
        fprintf(stderr, "MAGIC: 'OggS' header found! ✅\n");
    } else {
        fprintf(stderr, "WARN: no OggS (first: %02x%02x%02x%02x)\n",
                buf[0], buf[1], buf[2], buf[3]);
    }

    free(buf);
    return 0;
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void) {
    fprintf(stderr, "===========================================\n");
    fprintf(stderr, "  ESPConnect E2E Pipeline Test\n");
    fprintf(stderr, "  Version : v24\n");
    fprintf(stderr, "  Build   : %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "  Device  : %s\n", DEVICE_NAME);
    fprintf(stderr, "  Track   : 0daEJMXc3b4ZMTnvtHpuTt\n");
    fprintf(stderr, "  AP      : %s:%d\n", AP_HOST, AP_PORT);
    fprintf(stderr, "===========================================\n\n");

    /* STEP 0: Pairing */
    if (do_pairing() != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 0 (Pairing)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 1;
    }

    /* Rate limit wait */
    fprintf(stderr, "\n[WAIT] 5s before connecting to AP...\n");
    platform_sleep_ms(5000);

    /* STEP 1-6: Auth + Pipeline */
    mercury_session_t *sess = do_login5();
    if (!sess) {
        fprintf(stderr, "\n❌ FAILED at step 1 (Login5)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 1;
    }

    if (do_client_token(sess) != 0) {
        mercury_destroy(sess);
        fprintf(stderr, "\n❌ FAILED at step 2 (ClientToken)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 2;
    }

    if (do_track_metadata() != 0) {
        mercury_destroy(sess);
        fprintf(stderr, "\n❌ FAILED at step 3 (Metadata)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 3;
    }

    if (do_cdn_resolve() != 0) {
        spclient_free_track_meta(&g_track_meta);
        mercury_destroy(sess);
        fprintf(stderr, "\n❌ FAILED at step 4 (CDN)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 4;
    }

    if (do_audio_key(sess) != 0) {
        spclient_free_track_meta(&g_track_meta);
        mercury_destroy(sess);
        fprintf(stderr, "\n❌ FAILED at step 5 (AudioKey)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 5;
    }

    int decrypt_ok = do_download_decrypt();
    spclient_free_track_meta(&g_track_meta);
    mercury_destroy(sess);

    if (decrypt_ok != 0) {
        fprintf(stderr, "\n❌ FAILED at step 6 (Decrypt)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 6;
    }

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, " ✅ E2E PIPELINE SUCCESS!\n");
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
    getchar();
    return 0;
}
