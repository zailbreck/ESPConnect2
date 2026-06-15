// spclient.h — Spotify Web API Client Interface
// ================================================
// OAuth2 token + storage-resolve + CDN download API.
//
// Sources & References:
//   OAuth2 flow:      Spotify Web API docs — https://developer.spotify.com/documentation/web-api
//                     librespot (MIT) — core/src/oauth2.rs
//   Storage-resolve:  librespot (MIT) — core/src/spclient.rs
//                     https://github.com/librespot-org/librespot/blob/dev/core/src/spclient.rs
//   CDN download:     librespot (MIT) — audio/src/fetch.rs
//                     https://github.com/librespot-org/librespot/blob/dev/audio/src/fetch.rs
//
// License: MIT — derived from librespot & Spotify Web API docs

#ifndef SPOTIFY_SPCLIENT_H
#define SPOTIFY_SPCLIENT_H

#include "esp_spotify.h"

/**
 * @brief Get an OAuth2 token using Client Credentials flow
 *
 * POST https://accounts.spotify.com/api/token
 * Authorization: Basic base64(client_id:client_secret)
 * grant_type=client_credentials
 *
 * @param client_id Spotify App Client ID
 * @param client_secret Spotify App Client Secret
 * @param token Output buffer for access token (must be at least 512 bytes)
 * @param token_size Size of output buffer
 * @return 0 on success, negative on error
 */
int spclient_get_oauth_token(const char *client_id, const char *client_secret,
                             char *token, size_t token_size);

/**
 * @brief Resolve CDN URL via Spotify storage-resolve API
 *
 * GET https://api.spotify.com/v1/storage-resolve/files/audio/interactive/{fileId}?alt=json&product=9
 *
 * @param access_token OAuth2 Bearer token
 * @param file_id File ID as hex string (e.g., "844ecdb297a87ebfee4399f28892ef85d9ba725f")
 * @param cdn_info Output CDN info structure
 * @return 0 on success, negative on error
 */
int spclient_resolve_storage(const char *access_token, const char *file_id,
                             esp_spotify_cdn_info_t *cdn_info);

/**
 * @brief Download audio data from CDN URL with range request
 *
 * @param cdn_url CDN URL from storage-resolve
 * @param offset Byte offset
 * @param length Number of bytes to read
 * @param buffer Output buffer
 * @param buffer_size Buffer capacity
 * @return Number of bytes read, negative on error
 */
int spclient_download_audio(const char *cdn_url, size_t offset, size_t length,
                            uint8_t *buffer, size_t buffer_size);

#endif /* SPOTIFY_SPCLIENT_H */
