// esp_spotify.c — ESP-Spotify-Connect Library Implementation
// =========================================================
// Core library: session management, OAuth2, CDN resolution,
// audio download, zeroConf pairing, and mercury login5.
//
// Sources & References:
//   Session API:      librespot (MIT) — core/src/session.rs
//   OAuth2 flow:      Spotify Web API — https://developer.spotify.com/documentation/web-api
//   Storage-resolve:  librespot (MIT) — core/src/spclient.rs
//   ZeroConf pairing: cspot (MIT) — BellTask.cpp, ZeroconfTask.cpp
//   Login5 auth:      librespot (MIT) — authentication/login5.rs
//   CDN download:     librespot (MIT) — audio/src/fetch.rs
//
// License: MIT — derived from librespot & cspot

#include "esp_spotify.h"
#include "internal/spclient.h"
#include "internal/zeroconf.h"
#include "internal/mercury.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <esp_log.h>

static const char *TAG = "esp_spotify";

struct esp_spotify_session_t {
    esp_spotify_config_t config;
    esp_spotify_state_t state;
    char oauth_token[512];

    /* ZeroConf pairing */
    zeroconf_session_t *zeroconf;
    char zeroconf_auth_data[4096];  /* base64-encoded authData from zeroconf */
    int zeroconf_auth_type;         /* auth type from zeroconf */

    /* Mercury login5 */
    mercury_session_t *mercury;
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

    /* Copy config strings */
    if (config->client_id)     session->config.client_id     = strdup(config->client_id);
    if (config->client_secret) session->config.client_secret = strdup(config->client_secret);
    if (config->device_name)   session->config.device_name   = strdup(config->device_name);
    if (config->device_id)     session->config.device_id     = strdup(config->device_id);
    if (config->username)      session->config.username      = strdup(config->username);
    if (config->password)      session->config.password      = strdup(config->password);
    if (config->ap_host)       session->config.ap_host       = strdup(config->ap_host);
    session->config.ap_port   = config->ap_port   ? config->ap_port   : 443;
    session->config.bell_port = config->bell_port ? config->bell_port : 7864;

    session->state = ESP_SPOTIFY_STATE_IDLE;
    *handle = session;

    ESP_LOGI(TAG, "Spotify Connect initialized (device: %s)", 
             session->config.device_name ? session->config.device_name : "ESP32");

    return 0;
}

int esp_spotify_start(esp_spotify_handle_t handle) {
    if (!handle) return -1;

    handle->state = ESP_SPOTIFY_STATE_CONNECTING;

    /* Get OAuth2 token for CDN resolution */
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

    /* Start zeroconf pairing */
    zeroconf_config_t zc_cfg = {
        .device_name    = handle->config.device_name,
        .device_id      = handle->config.device_id,
        .brand_display  = "cspot",
        .model_display  = handle->config.device_name,
        .bell_port      = handle->config.bell_port,
        .timeout_seconds = 600,
    };

    handle->zeroconf = zeroconf_init(&zc_cfg);
    if (handle->zeroconf) {
        zeroconf_start(handle->zeroconf);
        ESP_LOGI(TAG, "ZeroConf pairing started (port %d)", handle->config.bell_port);
    }

    handle->state = ESP_SPOTIFY_STATE_CONNECTED;
    return 0;
}

int esp_spotify_pair(esp_spotify_handle_t handle, int timeout_seconds) {
    if (!handle || !handle->zeroconf) return -1;

    int waited = 0;
    while (waited < timeout_seconds) {
        int ret = zeroconf_poll(handle->zeroconf, 1000);
        if (ret == 1) {
            /* Credentials captured! Extract them */
            zeroconf_credentials_t creds;
            if (zeroconf_get_credentials(handle->zeroconf, &creds) == 0) {
                strncpy(handle->zeroconf_auth_data, creds.auth_data_b64,
                        sizeof(handle->zeroconf_auth_data) - 1);
                handle->zeroconf_auth_type = creds.auth_type;

                ESP_LOGI(TAG, "Paired! User: %s, AuthType: %d",
                         creds.username, creds.auth_type);

                /* Also update username if not set */
                if (!handle->config.username && creds.username) {
                    handle->config.username = strdup(creds.username);
                }

                zeroconf_free_credentials(&creds);
                return 0;
            }
            zeroconf_free_credentials(&creds);
        } else if (ret < 0) {
            ESP_LOGE(TAG, "zeroconf poll error: %d", ret);
            return ret;
        }
        waited++;
    }
    ESP_LOGW(TAG, "Pairing timeout after %d seconds", timeout_seconds);
    return -2;
}

int esp_spotify_login(esp_spotify_handle_t handle) {
    if (!handle) return -1;

    /* Initialize mercury session */
    handle->mercury = mercury_init();
    if (!handle->mercury) {
        ESP_LOGE(TAG, "Failed to init mercury session");
        return -2;
    }

    /* Determine auth data: from config or from zeroconf pairing */
    const char *auth_b64 = handle->zeroconf_auth_data;
    int auth_type = handle->zeroconf_auth_type;
    const char *username = handle->config.username;
    const char *device_id = handle->config.device_id ?
                            handle->config.device_id :
                            "142137fd329622137a1490161234567890123456";
    const char *ap_host = handle->config.ap_host ?
                          handle->config.ap_host : "ap-gae2.spotify.com";

    if (!auth_b64[0] || !username) {
        ESP_LOGE(TAG, "No auth data or username. Run esp_spotify_pair() first.");
        return -3;
    }

    int ret = mercury_login5(handle->mercury, username, auth_b64,
                              auth_type, device_id, ap_host,
                              handle->config.ap_port);
    if (ret != 0) {
        ESP_LOGE(TAG, "Login5 failed: %d", ret);
        return ret;
    }

    const char *canon = mercury_get_canonical_username(handle->mercury);
    ESP_LOGI(TAG, "Logged in as: %s", canon ? canon : username);

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

    if (handle->zeroconf) {
        zeroconf_stop(handle->zeroconf);
    }
    if (handle->mercury) {
        mercury_disconnect(handle->mercury);
    }
}

void esp_spotify_destroy(esp_spotify_handle_t handle) {
    if (!handle) return;

    esp_spotify_stop(handle);

    if (handle->zeroconf) {
        zeroconf_destroy(handle->zeroconf);
        handle->zeroconf = NULL;
    }
    if (handle->mercury) {
        mercury_destroy(handle->mercury);
        handle->mercury = NULL;
    }

    if (handle->config.client_id)     free((void *)handle->config.client_id);
    if (handle->config.client_secret) free((void *)handle->config.client_secret);
    if (handle->config.device_name)   free((void *)handle->config.device_name);
    if (handle->config.device_id)     free((void *)handle->config.device_id);
    if (handle->config.username)      free((void *)handle->config.username);
    if (handle->config.password)      free((void *)handle->config.password);
    if (handle->config.ap_host)       free((void *)handle->config.ap_host);

    free(handle);
}
