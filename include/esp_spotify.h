// esp_spotify.h — ESP-Spotify-Connect Public API
// ================================================
// Library entry point for ESP32 Spotify Connect functionality.
// Provides credential extraction, authentication, and audio streaming.
//
// Sources & References:
//   Login5 auth:       librespot (MIT) — authentication/login5.rs
//   Spclient API:      librespot (MIT) — spclient.rs, token.rs
//   Audio decrypt:     librespot (MIT) — audio/src/decrypt.rs
//   ZeroConf pairing:  cspot (MIT) — BellTask.cpp, ZeroconfTask.cpp
//
// License: MIT — derived from librespot & cspot

#ifndef ESP_SPOTIFY_H
#define ESP_SPOTIFY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "internal/spclient.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Configuration for Spotify Connect
 */
typedef struct {
    const char *client_id;      /**< Spotify App Client ID (optional) */
    const char *client_secret;  /**< Spotify App Client Secret (optional) */
    const char *device_name;    /**< Name shown as Spotify device */
    const char *device_id;      /**< 32-char hex device ID */
    const char *username;       /**< Spotify username (from zeroconf or manual) */
    const char *ap_host;        /**< Spotify AP host (default: ap-gew4.spotify.com) */
    int ap_port;                /**< AP port (default: 443) */
    int bell_port;              /**< Bell HTTP port for zeroconf (default: 7864) */
} esp_spotify_config_t;

/**
 * @brief Opaque handle for Spotify session
 */
typedef struct esp_spotify_session_t *esp_spotify_handle_t;

/**
 * @brief Audio stream state
 */
typedef enum {
    ESP_SPOTIFY_STATE_IDLE,
    ESP_SPOTIFY_STATE_CONNECTING,
    ESP_SPOTIFY_STATE_CONNECTED,
    ESP_SPOTIFY_STATE_AUTHENTICATED,
    ESP_SPOTIFY_STATE_PLAYING,
    ESP_SPOTIFY_STATE_ERROR,
} esp_spotify_state_t;

/* ======== Lifecycle ======== */

int esp_spotify_init(const esp_spotify_config_t *config, esp_spotify_handle_t *handle);
int esp_spotify_start(esp_spotify_handle_t handle);

/* ======== Pairing ======== */

int esp_spotify_pair(esp_spotify_handle_t handle, int timeout_seconds);

/* ======== Login & Auth ======== */

int esp_spotify_login(esp_spotify_handle_t handle);

/* ======== Track Metadata ======== */

/** Get track metadata (file IDs) from spclient */
int esp_spotify_get_track_meta(esp_spotify_handle_t handle,
                               const uint8_t track_id[16],
                               spclient_track_meta_t *meta);

/* ======== CDN ======== */

/** Resolve CDN URL for audio file (20-char hex file ID) */
int esp_spotify_resolve_cdn(esp_spotify_handle_t handle,
                            const char *file_id_hex,
                            char *cdn_url, size_t url_size);

/** Download audio from CDN via HTTP Range request */
int esp_spotify_download_audio(esp_spotify_handle_t handle,
                               const char *cdn_url,
                               size_t offset, size_t length,
                               uint8_t *buffer, size_t buffer_size);

/* ======== AudioKey ======== */

/** Request AES-128 decryption key via Mercury */
int esp_spotify_get_audio_key(esp_spotify_handle_t handle,
                              const uint8_t track_id[16],
                              const uint8_t file_id[16],
                              uint8_t key_out[16]);

/* ======== Decrypt ======== */

/** Decrypt Spotify OGG/Vorbis audio chunk (AES-128-CTR) */
int esp_spotify_decrypt_audio(uint8_t *buffer, size_t length,
                              const uint8_t key[16],
                              const uint8_t file_id[20]);

/* ======== Query ======== */

esp_spotify_state_t esp_spotify_get_state(esp_spotify_handle_t handle);
bool esp_spotify_is_connected(esp_spotify_handle_t handle);
const char *esp_spotify_get_username(esp_spotify_handle_t handle);

/* ======== Cleanup ======== */

void esp_spotify_stop(esp_spotify_handle_t handle);
void esp_spotify_destroy(esp_spotify_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* ESP_SPOTIFY_H */
