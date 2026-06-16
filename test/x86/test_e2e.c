// test_e2e.c — Full End-to-End Pipeline Test

#ifdef _WIN32
#include <winsock2.h>
#endif
#include "esp_spotify.h"
#include "internal/spclient.h"
#include "internal/mercury.h"
#include "internal/zeroconf.h"
#include "internal/decrypt.h"
#include "internal/platform.h"
#include "spotify_login5.h"
#include "spotify_login5_parse.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DEVICE_NAME         "ESPConnect-LIVE"
#define DEVICE_ID           "142137fd329622137a14901634264e6f332e2411"
#define AP_HOST             "ap-gew4.spotify.com"
#define AP_PORT             443
#define BELL_PORT           7864
#define PAIRING_TIMEOUT     600

static const uint8_t TEST_TRACK_GID[16] = {
    0x06, 0xfa, 0xfd, 0xa4, 0x5f, 0x70, 0x4f, 0x18,
    0x88, 0x20, 0x10, 0xaa, 0x97, 0x2c, 0xdc, 0x6f,
};

static void hex_dump(const char *label, const uint8_t *d, size_t n) {
    fprintf(stderr, "%s (%zu): ", label, n);
    for (size_t i = 0; i < n && i < 48; i++)
        fprintf(stderr, "%02x", d[i]);
    if (n > 48) fprintf(stderr, "...");
    fprintf(stderr, "\n");
}

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

static int base64_decode(const char *in, size_t in_len, uint8_t *out, size_t *out_len) {
    static const int b64[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    int i = 0, j = 0;
    while (i < in_len && in[i] != '=') {
        int v = -1;
        if (in[i] == '-') v = 62;
        else if (in[i] == '_') v = 63;
        else v = b64[(unsigned char)in[i]];
        
        if (v == -1) break;
        int d = i % 4;
        if (d == 0) out[j] = v << 2;
        else if (d == 1) { out[j++] |= v >> 4; out[j] = (v & 15) << 4; }
        else if (d == 2) { out[j++] |= v >> 2; out[j] = (v & 3) << 6; }
        else if (d == 3) out[j++] |= v;
        i++;
    }
    *out_len = j;
    return 0;
}

static char g_auth_b64[4096] = {0};
static int g_auth_loaded = 0;
static int   g_auth_type = 0;
static char g_username[256] = {0};

static char g_access_token_b64[2048] = {0};
static int g_login_auth_type = 3;

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

static int do_login5_exchange(void) {
    fprintf(stderr, "\n===== STEP 0.5: LOGIN5 HTTPS EXCHANGE =====\n");
    
    uint8_t inner_blob[2048];
    size_t inner_blob_len = 0;
    base64_decode(g_auth_b64, strlen(g_auth_b64), inner_blob, &inner_blob_len);
    fprintf(stderr, "OK: Decoded %zu bytes of AuthBlob\n", inner_blob_len);
    
    uint8_t login5_response[2048];
    size_t login5_response_len = sizeof(login5_response);
    
    fprintf(stderr, "Connecting to login5.spotify.com via mbedTLS...\n");
    int ret = spotify_login5_get_token(
        "65b708073fc0480ea92a077233ca87bd", // spotify desktop client id
        DEVICE_ID,
        g_username,
        inner_blob,
        inner_blob_len,
        login5_response,
        &login5_response_len
    );
    
    if (ret != 0) {
        fprintf(stderr, "FAIL: spotify_login5_get_token returned %d\n", ret);
        return -1;
    }
    
    
    fprintf(stderr, "OK: Received %zu bytes from Login5 API\n", login5_response_len);
    fprintf(stderr, "=== RAW PROTOBUF RESPONSE ===\n");
    for(size_t i=0; i<login5_response_len; i++) {
        fprintf(stderr, "%02x ", login5_response[i]);
        if ((i+1) % 16 == 0) fprintf(stderr, "\n");
    }
    fprintf(stderr, "\n=== END PROTOBUF ===\n");
    
    // Also try to print it as ASCII to see strings
    fprintf(stderr, "=== ASCII DUMP ===\n");
    for(size_t i=0; i<login5_response_len; i++) {
        if (login5_response[i] >= 32 && login5_response[i] <= 126) fputc(login5_response[i], stderr);
        else fputc('.', stderr);
    }
    fprintf(stderr, "\n==================\n");

    
    ret = spotify_login5_extract_token(login5_response, login5_response_len, g_access_token_b64, sizeof(g_access_token_b64));
    
    if (ret != 0) {
        fprintf(stderr, "FAIL: Could not find BQA... token string in Protobuf response. Maybe INVALID_CREDENTIALS?\n");
        return -1;
    }
    
    fprintf(stderr, "SUCCESS: Got Access Token! len=%zu\n", strlen(g_access_token_b64));
    fprintf(stderr, "Token = %.30s...\n", g_access_token_b64);
    
    return 0;
}

static mercury_session_t *do_mercury_login(void) {
    fprintf(stderr, "\n===== STEP 1: MERCURY AUTH =====\n");

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

int main(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#endif
    fprintf(stderr, "===========================================\n");
    fprintf(stderr, "  ESPConnect E2E LIVE mDNS Token Exchange Test\n");
    fprintf(stderr, "  Version : v42 (Login5 AccessToken + Native mDNS Windows)\n");
    fprintf(stderr, "  Build   : %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "  Device  : %s\n", DEVICE_NAME);
    fprintf(stderr, "  Track   : 0daEJMXc3b4ZMTnvtHpuTt\n");
    fprintf(stderr, "  AP      : %s:%d\n", AP_HOST, AP_PORT);
    fprintf(stderr, "===========================================\n\n");

    if (do_pairing() != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 0 (Pairing)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 1;
    }

    if (do_login5_exchange() != 0) {
        fprintf(stderr, "\n❌ E2E test FAILED at step 0.5 (Login5 HTTPS Token Exchange)\n");
        fprintf(stderr, "\n[PRESS ENTER TO EXIT]\n");
        getchar();
        return 1;
    }

    fprintf(stderr, "\n[WAIT] 2s before connecting to AP...\n");
    platform_sleep_ms(2000);

    mercury_session_t *sess = do_mercury_login();
    if (!sess) {
        fprintf(stderr, "\n❌ FAILED at step 1 (Login5 Mercury AP)\n");
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
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
