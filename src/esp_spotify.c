// esp_spotify.c — ESP-Spotify-Connect Library Implementation
// =========================================================
// Core library: session management, OAuth2, CDN resolution,
// audio download, and decrypt orchestration.
//
// Sources & References:
//   Session API:      librespot (MIT) — core/src/session.rs
//                     https://github.com/librespot-org/librespot/blob/dev/core/src/session.rs
//   OAuth2 flow:      Spotify Web API — https://developer.spotify.com/documentation/web-api
//   Storage-resolve:  librespot (MIT) — core/src/spclient.rs
//   CDN download:     librespot (MIT) — audio/src/fetch.rs
//
// License: MIT — derived from librespot

#include "esp_spotify.h"
#include "internal/spclient.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <esp_log.h>

static const char *TAG = "esp_spotify";

struct esp_spotify_session_t {
    esp_spotify_config_t config;
    esp_spotify_state_t state;
    char oauth_token[512];
};

int esp_spotify_init(const esp_spotify_config_t *config, esp_spotify_handle_t *handle) {
    if (!config || !handle) {
        return -1;
    }

    struct esp_spotify_session_t *session = 
        (struct esp_spotify_session_t *)calloc(1, sizeof(struct esp_spotify_session_t));
    if (!session) {
        return -2;
    }

    // Copy config
    if (config->client_id) session->config.client_id = strdup(config->client_id);
    if (config->client_secret) session->config.client_secret = strdup(config->client_secret);
    if (config->device_name) session->config.device_name = strdup(config->device_name);
    if (config->username) session->config.username = strdup(config->username);
    if (config->password) session->config.password = strdup(config->password);

    session->state = ESP_SPOTIFY_STATE_IDLE;
    *handle = session;

    ESP_LOGI(TAG, "Spotify Connect initialized (device: %s)", 
             session->config.device_name ? session->config.device_name : "ESP32");

    return 0;
}

int esp_spotify_start(esp_spotify_handle_t handle) {
    if (!handle) return -1;

    handle->state = ESP_SPOTIFY_STATE_CONNECTING;

    // Get OAuth2 token for CDN resolution
    if (handle->config.client_id && handle->config.client_secret) {
        int ret = spclient_get_oauth_token(
            handle->config.client_id,
            handle->config.client_secret,
            handle->oauth_token,
            sizeof(handle->oauth_token));

        if (ret == 0) {
            ESP_LOGI(TAG, "OAuth token obtained");
        } else {
            ESP_LOGW(TAG, "Failed to get OAuth token: %d", ret);
        }
    }

    // TODO: Login5 authentication for Mercury/Spirc
    // TODO: ZeroConf discovery
    // TODO: Mercury session

    handle->state = ESP_SPOTIFY_STATE_CONNECTED;
    return 0;
}

int esp_spotify_resolve_cdn(esp_spotify_handle_t handle, const char *file_id,
                            esp_spotify_cdn_info_t *cdn_info) {
    if (!handle || !file_id || !cdn_info) return -1;

    // Ensure we have an OAuth token
    if (handle->oauth_token[0] == '\0') {
        if (handle->config.client_id && handle->config.client_secret) {
            int ret = spclient_get_oauth_token(
                handle->config.client_id,
                handle->config.client_secret,
                handle->oauth_token,
                sizeof(handle->oauth_token));
            if (ret != 0) {
                ESP_LOGE(TAG, "Cannot get OAuth token for CDN resolution");
                return ret;
            }
        } else {
            ESP_LOGE(TAG, "No client credentials configured");
            return -2;
        }
    }

    return spclient_resolve_storage(handle->oauth_token, file_id, cdn_info);
}

int esp_spotify_download_audio(esp_spotify_handle_t handle, const char *cdn_url,
                               size_t offset, size_t length, uint8_t *buffer, size_t buffer_size) {
    (void)handle; // Session handle not directly needed for raw CDN download
    return spclient_download_audio(cdn_url, offset, length, buffer, buffer_size);
}

void esp_spotify_stop(esp_spotify_handle_t handle) {
    if (!handle) return;
    handle->state = ESP_SPOTIFY_STATE_IDLE;
    // TODO: Mercury session cleanup
}

void esp_spotify_destroy(esp_spotify_handle_t handle) {
    if (!handle) return;

    if (handle->config.client_id) free((void *)handle->config.client_id);
    if (handle->config.client_secret) free((void *)handle->config.client_secret);
    if (handle->config.device_name) free((void *)handle->config.device_name);
    if (handle->config.username) free((void *)handle->config.username);
    if (handle->config.password) free((void *)handle->config.password);

    free(handle);
}
