// spclient.h — Spotify Internal API Client (HTTP + Mercury)
// ==========================================================
// Full pipeline: client token → track metadata → file ID →
// CDN resolution → audio download.
//
// Sources & References:
//   Client token:     librespot (MIT) — core/src/token.rs
//                     https://github.com/librespot-org/librespot/blob/dev/core/src/token.rs
//   SpClient HTTP:    librespot (MIT) — core/src/spclient.rs
//                     https://github.com/librespot-org/librespot/blob/dev/core/src/spclient.rs
//   CDN fetch:        librespot (MIT) — audio/src/fetch.rs
//                     https://github.com/librespot-org/librespot/blob/dev/audio/src/fetch.rs
//   AudioKey:         librespot (MIT) — core/src/audio_key.rs
//   Track metadata:   Spotify internal API (undocumented)
//
// License: MIT — derived from librespot

#ifndef SPOTIFY_SPCLIENT_H
#define SPOTIFY_SPCLIENT_H

#include "internal/mercury.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Client Token                                                       */
/* ------------------------------------------------------------------ */

/**
 * @brief Request a client token via Mercury.
 *
 * Sends a request to hm://keymaster/client/token over the existing
 * Mercury session. The response is parsed and stored in token_out.
 *
 * @param sess       Authenticated Mercury session
 * @param token_out  Output buffer for token (owned by caller)
 * @param token_size Size of token_out buffer
 * @return 0 on success, negative on error
 */
int spclient_get_client_token(mercury_session_t *sess,
                              char *token_out, size_t token_size);

/* ------------------------------------------------------------------ */
/*  Track Metadata                                                     */
/* ------------------------------------------------------------------ */

#define SPCLIENT_FILE_ID_SIZE 20  /* hex string length */

typedef struct {
    char file_id_hex[SPCLIENT_FILE_ID_SIZE + 1];  /* 20-char hex string */
    char format[8];   /* "OGG_VORBIS_96", "OGG_VORBIS_160", "OGG_VORBIS_320", "AAC_24" etc */
} spclient_file_t;

typedef struct {
    spclient_file_t *files;
    int num_files;
} spclient_track_meta_t;

/**
 * @brief Fetch track metadata from spclient (audio file IDs).
 *
 * GET https://spclient.wg.spotify.com/metadata/4/track/{track_id_hex}
 * Requires Authorization: Bearer {client_token}
 *
 * @param client_token  Client token from spclient_get_client_token()
 * @param track_id     16-byte binary track ID
 * @param meta_out      Output structure (caller must free with spclient_free_track_meta)
 * @return 0 on success, negative on error
 */
int spclient_get_track_metadata(const char *client_token,
                                const uint8_t track_id[16],
                                spclient_track_meta_t *meta_out);

/** Free track metadata */
void spclient_free_track_meta(spclient_track_meta_t *meta);

/* ------------------------------------------------------------------ */
/*  CDN Resolution                                                     */
/* ------------------------------------------------------------------ */

/**
 * @brief Resolve CDN URL for an audio file.
 *
 * GET https://spclient.wg.spotify.com/storage-resolve/files/audio/interactive/{file_id_hex}
 *
 * @param client_token   Client token
 * @param file_id_hex    20-char hex file ID from track metadata
 * @param cdn_url_out    Output CDN URL buffer (caller owns, minimum 1024 bytes)
 * @param url_size       Size of cdn_url_out buffer
 * @return 0 on success, negative on error
 */
int spclient_resolve_cdn_url(const char *client_token,
                             const char *file_id_hex,
                             char *cdn_url_out, size_t url_size);

/* ------------------------------------------------------------------ */
/*  CDN Audio Download                                                 */
/* ------------------------------------------------------------------ */

/**
 * @brief Download audio data via HTTP Range request.
 *
 * GET {cdn_url} with header "Range: bytes={offset}-{offset+length-1}"
 *
 * @param cdn_url      Full CDN URL from spclient_resolve_cdn_url()
 * @param offset       Byte offset in file
 * @param length       Number of bytes to download
 * @param buffer       Output buffer (caller owns)
 * @param buffer_size  Size of buffer
 * @return Bytes downloaded on success, negative on error
 */
int spclient_download_audio(const char *cdn_url,
                            size_t offset, size_t length,
                            uint8_t *buffer, size_t buffer_size);

/* ------------------------------------------------------------------ */
/*  AudioKey Request (via Mercury)                                     */
/* ------------------------------------------------------------------ */

/**
 * @brief Request AudioKey (AES-128 key) for a track+file via Mercury.
 *
 * Sends AUDIO_KEY_REQUEST_COMMAND (0x0C) over Mercury and waits
 * for AUDIO_KEY_SUCCESS_RESPONSE (0x0D).
 *
 * @param sess       Authenticated Mercury session
 * @param track_id   16-byte binary track ID
 * @param file_id    16-byte binary file ID (from track metadata, hex-decoded)
 * @param key_out    Output: 16-byte AES key
 * @return 0 on success, negative on error
 */
int spclient_get_audio_key(mercury_session_t *sess,
                           const uint8_t track_id[16],
                           const uint8_t file_id[16],
                           uint8_t key_out[16]);

#ifdef __cplusplus
}
#endif

#endif /* SPOTIFY_SPCLIENT_H */
