// decrypt.c — Spotify Audio Decryption Module
// ===========================================
// AES-128-CTR audio decryption for Spotify OGG/Vorbis chunks.
//
// Sources & References:
//   AES-CTR decrypt:  librespot (MIT) — audio/src/decrypt.rs
//                     https://github.com/librespot-org/librespot/blob/dev/audio/src/decrypt.rs
//   IV derivation:    librespot (MIT) — SHA1("s" + file_id)[0:16]
//
// License: MIT — derived from librespot

#include "internal/decrypt.h"
#include "internal/platform.h"
#include <string.h>

/**
 * @brief Derive AES-CTR IV for Spotify audio.
 *
 * IV = SHA1("s" + file_id)[0:16]
 * The 's' is a literal ASCII byte; file_id is 20 hex chars.
 *
 * Ref: librespot audio/src/decrypt.rs
 */
static void decrypt_derive_iv(const uint8_t *file_id, uint8_t iv_out[16]) {
    uint8_t input[21];
    input[0] = 's';                          /* literal prefix */
    memcpy(input + 1, file_id, 20);          /* 20-byte file ID */

    uint8_t hash[20];
    platform_sha1(input, 21, hash);

    memcpy(iv_out, hash, 16);                /* first 16 bytes */
}

int decrypt_audio(uint8_t *buffer, size_t length,
                  const uint8_t audio_key[16],
                  const uint8_t file_id[20]) {
    if (!buffer || !audio_key || !file_id || length == 0)
        return -1;

    uint8_t iv[16];
    decrypt_derive_iv(file_id, iv);

    /* AES-128-CTR (encrypt == decrypt in CTR mode) */
    platform_aes_ctr128(audio_key, iv, buffer, length);

    return 0;
}
