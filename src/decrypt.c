// decrypt.c — Spotify Audio Decryption Module
// ===========================================
// AES-128-CTR audio decryption for Spotify OGG/Vorbis chunks.
//
// Sources & References:
//   AES-CTR decrypt:  librespot (MIT) — audio/src/decrypt.rs
//                     https://github.com/librespot-org/librespot/blob/dev/audio/src/decrypt.rs
//   IV derivation:    librespot (MIT) — SHA1("s" + file_id)[0:16]
//   mbedtls AES API:  mbedtls 3.x — https://github.com/Mbed-TLS/mbedtls
//
// License: MIT — derived from librespot

#include "internal/decrypt.h"
#include <string.h>
#include <esp_log.h>
#include <mbedtls/aes.h>

static const char *TAG = "decrypt";

/**
 * Spotify AES-CTR IV (fixed, derived from "s" + fileId):
 *   IV = SHA1("s" + file_id)[0:16]
 *
 * Reference: librespot audio/src/decrypt.rs
 */
static void derive_iv(const uint8_t *file_id, uint8_t iv[16]) {
    // Prefix "s" + file_id (20 bytes)
    uint8_t input[21];
    input[0] = 's';
    memcpy(input + 1, file_id, 20);

    // SHA1 hash
    uint8_t hash[20];
    mbedtls_sha1(input, 21, hash);

    // First 16 bytes of hash = IV
    memcpy(iv, hash, 16);
}

int decrypt_audio(uint8_t *buffer, size_t length, const uint8_t *audio_key,
                  const uint8_t *file_id) {
    if (!buffer || !audio_key || !file_id || length == 0) {
        return -1;
    }

    // Derive IV from file ID
    uint8_t iv[16];
    derive_iv(file_id, iv);

    // Initialize AES-CTR
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    size_t nc_off = 0;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];

    memcpy(nonce_counter, iv, 16);
    memset(stream_block, 0, 16);

    mbedtls_aes_setkey_enc(&aes, audio_key, 128);

    int ret = mbedtls_aes_crypt_ctr(&aes, length, &nc_off,
                                     nonce_counter, stream_block,
                                     buffer, buffer);

    mbedtls_aes_free(&aes);

    if (ret != 0) {
        ESP_LOGE(TAG, "AES-CTR decrypt failed: %d", ret);
        return -2;
    }

    ESP_LOGD(TAG, "Decrypted %zu bytes", length);
    return 0;
}
