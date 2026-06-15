// decrypt.h — Spotify Audio Decryption Interface
// ================================================
// Public API for AES-128-CTR audio decryption.
//
// Sources & References:
//   AES-CTR decrypt:  librespot (MIT) — audio/src/decrypt.rs
//                     https://github.com/librespot-org/librespot/blob/dev/audio/src/decrypt.rs
//   AudioKey format:  librespot (MIT) — core/src/audio_key.rs
//                     https://github.com/librespot-org/librespot/blob/dev/core/src/audio_key.rs
//
// License: MIT — derived from librespot

#ifndef SPOTIFY_DECRYPT_H
#define SPOTIFY_DECRYPT_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Spotify audio encryption uses AES-CTR with a 16-byte key and IV.
 *
 * The audio key is obtained via Mercury protocol (AudioKey request).
 * The AES IV is fixed: 0x72e067fbdd0af6d9eca0ba48d232c18a
 * (or derived from the file ID in some cases).
 */

#define AES_BLOCK_SIZE 16

/**
 * @brief Decrypt audio data from Spotify CDN
 *
 * @param buffer Encrypted audio data (will be decrypted in-place)
 * @param length Length of data (must be multiple of AES_BLOCK_SIZE)
 * @param audio_key 16-byte AES key
 * @param file_id 20-byte file ID (used for IV derivation)
 * @return 0 on success, negative on error
 */
int decrypt_audio(uint8_t *buffer, size_t length, const uint8_t *audio_key,
                  const uint8_t *file_id);

#endif /* SPOTIFY_DECRYPT_H */
