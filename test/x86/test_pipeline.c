#include <stdio.h>
#include <string.h>
#include "internal/platform.h"
#include "internal/mercury.h"
#include "internal/spclient.h"
#include "internal/decrypt.h"

/* === PRE-CAPTURED CREDENTIALS (from V13 Linux — already proven working) === */
#define DEVICE_NAME   "ESPConnect-TEST"
#define DEVICE_ID     "142137fd329622137a14901634264e6f332e2411"
#define TRACK_ID      "0daEJMXc3b4ZMTnvtHpuTt"
#define AP_HOST       "ap-gew4.spotify.com"
#define AP_PORT       443

/* Auth data from zeroconf pairing (V13 Linux) */
#define AUTH_B64 "QWdCLXRndUF2enJVWUdGaHg2V2hDRl9xdVNVaFAxd3pxdklTeXlzMTFyQzR6UkNVRVpqYW44VG9mb1pPc1JXdV84UlNpckxvMElBYTh3bjBweTU1Q3lxRVZ4VW1OelNnOXJFOXhyNjB0ZnE3VVhvYXJfaUZKckpNSDNTazA0TTRqNUJ5U2Vfc1dxdi1VcHFSV1dMNlVja0FPNWpXcVVDZWloWkJQRFZzek5DYWhHM3hBRTlzUkUtQWZZcU4tNHM0ekJV"
#define AUTH_TYPE 1
#define USERNAME   "31gs6dlgp5sdrb32kznvsklgwhiy"  /* from Windows run — might need update for Linux creds */

int main() {
    fprintf(stderr, "========================================\n");
    fprintf(stderr, " ESPConnect Pipeline Test (skip pairing)\n");
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "Device: %s\n", DEVICE_NAME);
    fprintf(stderr, "Track:  %s\n", TRACK_ID);
    fprintf(stderr, "AP:     %s:%d\n", AP_HOST, AP_PORT);
    fprintf(stderr, "========================================\n\n");

    /* STEP 1: Login5 */
    fprintf(stderr, "===== STEP 1: LOGIN5 AUTH =====\n");
    mercury_session_t *sess = mercury_create();
    if (!sess) { fprintf(stderr, "FAIL: mercury_create\n"); return -1; }

    int ret = mercury_login5(sess, USERNAME, AUTH_B64,
                              AUTH_TYPE, DEVICE_ID, AP_HOST, AP_PORT);
    if (ret != 0) {
        fprintf(stderr, "FAIL: Login5 returned %d\n", ret);
        mercury_destroy(sess);
        return -2;
    }
    fprintf(stderr, "STEP 1 PASSED: Login5 authenticated\n");

    /* STEP 2: Client token */
    fprintf(stderr, "\n===== STEP 2: CLIENT TOKEN =====\n");
    char token_buf[2048] = {0};
    ret = spclient_get_token(mercury_get_ap(sess), token_buf, sizeof(token_buf));
    if (ret != 0) {
        fprintf(stderr, "FAIL: Client token returned %d\n", ret);
        mercury_destroy(sess);
        return -3;
    }
    fprintf(stderr, "STEP 2 PASSED: Got client token (%zu chars)\n", strlen(token_buf));

    /* STEP 3: Track metadata */
    fprintf(stderr, "\n===== STEP 3: TRACK METADATA =====\n");
    spclient_track_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    ret = spclient_track_metadata(token_buf, TRACK_ID, &meta);
    if (ret != 0) {
        fprintf(stderr, "FAIL: Track metadata returned %d\n", ret);
        mercury_destroy(sess);
        return -4;
    }
    fprintf(stderr, "STEP 3 PASSED: %s - %s\n", meta.name, meta.artist);
    fprintf(stderr, "  File ID: %s (%zu chars)\n", meta.file_id, strlen(meta.file_id));

    /* STEP 4: CDN resolve */
    fprintf(stderr, "\n===== STEP 4: CDN RESOLVE =====\n");
    spclient_cdn_info_t cdn;
    memset(&cdn, 0, sizeof(cdn));
    ret = spclient_cdn_resolve(token_buf, meta.file_id, &cdn);
    if (ret != 0) {
        fprintf(stderr, "FAIL: CDN resolve returned %d\n", ret);
        mercury_destroy(sess);
        return -5;
    }
    fprintf(stderr, "STEP 4 PASSED: CDN %s:%d\n", cdn.hostname, cdn.port);

    /* STEP 5: AudioKey */
    fprintf(stderr, "\n===== STEP 5: AUDIO KEY =====\n");
    uint8_t audio_key[16] = {0};
    ret = spclient_audiokey(mercury_get_ap(sess), meta.file_id, TRACK_ID, audio_key);
    if (ret != 0) {
        fprintf(stderr, "FAIL: AudioKey returned %d\n", ret);
        mercury_destroy(sess);
        return -6;
    }
    fprintf(stderr, "STEP 5 PASSED: AudioKey=");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", audio_key[i]);
    fprintf(stderr, "\n");

    /* STEP 6: Download + Decrypt (first 16KB) */
    fprintf(stderr, "\n===== STEP 6: DOWNLOAD + DECRYPT =====\n");
    uint8_t *audio = malloc(16384);
    uint8_t *decrypted = malloc(16384);
    int dlen = 0;

    ret = spclient_audio_download(token_buf, &cdn, audio, 16384);
    if (ret > 0) {
        ret = decrypt_ogg_chunk(audio, ret, audio_key, meta.file_id,
                                decrypted, 16384, &dlen);
        if (ret == 0 && dlen > 0) {
            fprintf(stderr, "STEP 6 PASSED: Decrypted %d bytes\n", dlen);
            if (memcmp(decrypted, "OggS", 4) == 0)
                fprintf(stderr, "  Magic: OggS ✓ (valid Vorbis)\n");
            else
                fprintf(stderr, "  WARN: no OggS magic (first: %02x%02x%02x%02x)\n",
                        decrypted[0], decrypted[1], decrypted[2], decrypted[3]);
        } else {
            fprintf(stderr, "  Decrypt failed: %d\n", ret);
        }
    } else {
        fprintf(stderr, "  Download returned %d\n", ret);
    }

    free(audio);
    free(decrypted);
    mercury_destroy(sess);

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, "  PIPELINE COMPLETE!\n");
    fprintf(stderr, "========================================\n");
    return 0;
}
