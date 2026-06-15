// esp_spotify.h — ESP-Spotify-Connect Public API
// ================================================
// Library entry point for ESP32 Spotify Connect functionality.
// Provides credential extraction, authentication, and audio streaming.
//
// Sources & References:
//   Protocol spec:    librespot (MIT) — https://github.com/librespot-org/librespot
//   ZeroConf pairing: cspot (MIT) — BellTask.cpp, ZeroconfTask.cpp
//                     https://github.com/feelfreelinux/cspot/tree/master/cspot/src
//   Mercury protocol: librespot (MIT) — core/src/mercury/
//   Audio decrypt:    librespot (MIT) — audio/src/decrypt.rs
//
// License: MIT — derived from librespot & cspot

#ifndef ESP_SPOTIFY_H
#define ESP_SPOTIFY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Configuration for Spotify Connect
 */
typedef struct {
    const char *client_id;      /**< Spotify App Client ID */
    const char *client_secret;  /**< Spotify App Client Secret */
    const char *device_name;    /**< Name shown as Spotify device */
    const char *username;       /**< Spotify username (for login5) */
    const char *password;       /**< Spotify password (for login5) */
} esp_spotify_config_t;

/**
 * @brief Opaque handle for Spotify session
 */
typedef struct esp_spotify_session_t *esp_spotify_handle_t;

/**
 * @brief CDN URL info from storage-resolve
 */
typedef struct {
    char **cdnurls;             /**< Array of CDN URLs */
    int num_urls;               /**< Number of CDN URLs */
    char fileid[64];            /**< File identifier */
    int ttl;                    /**< Time-to-live in seconds */
} esp_spotify_cdn_info_t;

/**
 * @brief Audio stream state
 */
typedef enum {
    ESP_SPOTIFY_STATE_IDLE,
    ESP_SPOTIFY_STATE_CONNECTING,
    ESP_SPOTIFY_STATE_CONNECTED,
    ESP_SPOTIFY_STATE_PLAYING,
    ESP_SPOTIFY_STATE_PAUSED,
    ESP_SPOTIFY_STATE_ERROR,
} esp_spotify_state_t;

/**
 * @brief Initialize Spotify Connect session
 *
 * @param config Configuration parameters
 * @param handle Output handle for the session
 * @return 0 on success, negative on error
 */
int esp_spotify_init(const esp_spotify_config_t *config, esp_spotify_handle_t *handle);

/**
 * @brief Start Spotify Connect (login + become a device)
 *
 * @param handle Session handle
 * @return 0 on success, negative on error
 */
int esp_spotify_start(esp_spotify_handle_t handle);

/**
 * @brief Resolve CDN URL for a given file ID
 *
 * Uses OAuth2 Client Credentials to get a token,
 * then queries storage-resolve endpoint.
 *
 * @param handle Session handle
 * @param file_id File ID as hex string
 * @param cdn_info Output CDN info (caller must free with esp_spotify_free_cdn_info)
 * @return 0 on success, negative on error
 */
int esp_spotify_resolve_cdn(esp_spotify_handle_t handle, const char *file_id,
                            esp_spotify_cdn_info_t *cdn_info);

/**
 * @brief Download audio from CDN URL
 *
 * @param handle Session handle
 * @param cdn_url CDN URL from esp_spotify_resolve_cdn
 * @param offset Byte offset for range request (0 for start)
 * @param length Number of bytes to read
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return Number of bytes read, negative on error
 */
int esp_spotify_download_audio(esp_spotify_handle_t handle, const char *cdn_url,
                               size_t offset, size_t length, uint8_t *buffer, size_t buffer_size);

/**
 * @brief Free CDN info allocated by esp_spotify_resolve_cdn
 */
void esp_spotify_free_cdn_info(esp_spotify_cdn_info_t *cdn_info);

/**
 * @brief Stop Spotify Connect
 */
void esp_spotify_stop(esp_spotify_handle_t handle);

/**
 * @brief Destroy Spotify session and free resources
 */
void esp_spotify_destroy(esp_spotify_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* ESP_SPOTIFY_H */
