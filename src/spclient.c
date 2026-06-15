// spclient.c — Spotify Web API Client Implementation
// ===================================================
// OAuth2 Client Credentials flow, storage-resolve CDN resolution,
// and audio data download via HTTP Range requests.
//
// Sources & References:
//   OAuth2 token:     Spotify Web API — POST /api/token
//                     https://developer.spotify.com/documentation/web-api/tutorials/client-credentials-flow
//   Storage-resolve:  librespot (MIT) — core/src/spclient.rs
//                     https://github.com/librespot-org/librespot/blob/dev/core/src/spclient.rs
//   CDN Range req:    librespot (MIT) — audio/src/fetch.rs
//                     https://github.com/librespot-org/librespot/blob/dev/audio/src/fetch.rs
//   Base64 encode:    Custom implementation (RFC 4648)
//
// License: MIT — derived from librespot & Spotify Web API docs

#include "internal/spclient.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <esp_log.h>
#include <esp_http_client.h>
#include <cJSON.h>

static const char *TAG = "spclient";

/**
 * @brief Base64 encode (RFC 4648)
 */
static void base64_encode(const unsigned char *input, int input_len, char *output, int output_size) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;

    if (output_size < 1) return;

    for (i = 0; i < input_len; i += 3) {
        int val = input[i];
        if (i + 1 < input_len) val = (val << 8) | input[i + 1];
        if (i + 2 < input_len) val = (val << 8) | input[i + 2];

        int pad = (i + 2 < input_len) ? 0 : (i + 1 < input_len) ? 1 : 2;
        int groups = 4 - pad;

        if (j < output_size) output[j++] = b64[(val >> (18 - groups * 6)) & 0x3F];
        if (groups > 1 && j < output_size) output[j++] = b64[(val >> 12) & 0x3F];
        if (groups > 2 && j < output_size) output[j++] = b64[(val >> 6) & 0x3F];
        if (groups > 3 && j < output_size) output[j++] = b64[val & 0x3F];

        for (int k = 0; k < pad && j < output_size; k++) output[j++] = '=';
    }
    if (j < output_size) output[j] = '\0';
}

/**
 * @brief HTTP event handler for collecting response body
 */
typedef struct {
    char *buffer;
    size_t buffer_size;
    size_t data_len;
} http_response_t;

static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    http_response_t *resp = (http_response_t *)evt->user_data;
    switch (evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            if (resp && resp->buffer && evt->data) {
                size_t copy_len = evt->data_len;
                if (resp->data_len + copy_len < resp->buffer_size) {
                    memcpy(resp->buffer + resp->data_len, evt->data, copy_len);
                    resp->data_len += copy_len;
                }
            }
            break;
        default:
            break;
    }
    return ESP_OK;
}

/**
 * @brief Make HTTP request and collect response body
 */
static int http_request(const char *url, const char *method,
                        const char *auth_header, const char *extra_header_name,
                        const char *extra_header_value,
                        const char *post_data,
                        char *response, size_t response_size) {
    esp_http_client_config_t config = {
        .url = url,
        .method = (strcmp(method, "POST") == 0) ? HTTP_METHOD_POST : HTTP_METHOD_GET,
        .event_handler = http_event_handler,
        .timeout_ms = 30000,
    };

    http_response_t resp = {
        .buffer = response,
        .buffer_size = response_size,
        .data_len = 0,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return -1;
    }

    if (auth_header) {
        esp_http_client_set_header(client, "Authorization", auth_header);
    }
    esp_http_client_set_header(client, "User-Agent", "Spotify/121000000");

    if (extra_header_name && extra_header_value) {
        esp_http_client_set_header(client, extra_header_name, extra_header_value);
    }

    if (post_data) {
        esp_http_client_set_post_field(client, post_data, strlen(post_data));
        esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    }

    esp_http_client_set_user_data(client, &resp);

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return -2;
    }

    int status_code = esp_http_client_get_status_code(client);
    resp.buffer[resp.data_len] = '\0';
    ESP_LOGD(TAG, "HTTP %d, response: %s", status_code, resp.buffer);

    esp_http_client_cleanup(client);

    if (status_code != 200) {
        ESP_LOGE(TAG, "HTTP error %d: %s", status_code, resp.buffer);
        return -status_code; // Return negative HTTP status
    }

    return resp.data_len;
}

int spclient_get_oauth_token(const char *client_id, const char *client_secret,
                             char *token, size_t token_size) {
    if (!client_id || !client_secret || !token || token_size < 64) {
        return -1;
    }

    // Build Basic auth header: base64(client_id:client_secret)
    char credentials[256];
    snprintf(credentials, sizeof(credentials), "%s:%s", client_id, client_secret);

    char base64_auth[384];
    base64_encode((unsigned char *)credentials, strlen(credentials),
                  base64_auth, sizeof(base64_auth));

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Basic %s", base64_auth);

    // Make request
    char response[2048];
    int ret = http_request(
        "https://accounts.spotify.com/api/token",
        "POST",
        auth_header, NULL, NULL,
        "grant_type=client_credentials",
        response, sizeof(response));

    if (ret < 0) {
        return ret;
    }

    // Parse JSON response
    cJSON *json = cJSON_Parse(response);
    if (!json) {
        ESP_LOGE(TAG, "Failed to parse token response JSON");
        return -3;
    }

    cJSON *access_token = cJSON_GetObjectItem(json, "access_token");
    if (!access_token || !cJSON_IsString(access_token)) {
        ESP_LOGE(TAG, "No access_token in response");
        cJSON_Delete(json);
        return -4;
    }

    strncpy(token, access_token->valuestring, token_size - 1);
    token[token_size - 1] = '\0';

    ESP_LOGI(TAG, "Got OAuth token: %s...", token + (strlen(token) > 20 ? strlen(token) - 20 : 0));
    cJSON_Delete(json);

    return 0;
}

int spclient_resolve_storage(const char *access_token, const char *file_id,
                             esp_spotify_cdn_info_t *cdn_info) {
    if (!access_token || !file_id || !cdn_info) {
        return -1;
    }

    memset(cdn_info, 0, sizeof(*cdn_info));

    // Build URL
    char url[512];
    snprintf(url, sizeof(url),
             "https://api.spotify.com/v1/storage-resolve/files/audio/interactive/"
             "%s?alt=json&product=9",
             file_id);

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Bearer %s", access_token);

    char response[4096];
    int ret = http_request(url, "GET", auth_header, NULL, NULL, NULL,
                           response, sizeof(response));

    if (ret < 0) {
        return ret;
    }

    // Parse JSON response
    cJSON *json = cJSON_Parse(response);
    if (!json) {
        ESP_LOGE(TAG, "Failed to parse storage-resolve response JSON");
        return -3;
    }

    // Check result field
    cJSON *result = cJSON_GetObjectItem(json, "result");
    if (result && cJSON_IsString(result)) {
        ESP_LOGD(TAG, "Storage result: %s", result->valuestring);
    }

    // Parse CDN URLs
    cJSON *cdnurl = cJSON_GetObjectItem(json, "cdnurl");
    if (!cdnurl || !cJSON_IsArray(cdnurl)) {
        ESP_LOGE(TAG, "No cdnurl array in response");
        cJSON_Delete(json);
        return -5;
    }

    int num_urls = cJSON_GetArraySize(cdnurl);
    if (num_urls <= 0) {
        ESP_LOGE(TAG, "Empty cdnurl array");
        cJSON_Delete(json);
        return -6;
    }

    cdn_info->num_urls = num_urls;
    cdn_info->cdnurls = (char **)calloc(num_urls, sizeof(char *));

    for (int i = 0; i < num_urls; i++) {
        cJSON *url_item = cJSON_GetArrayItem(cdnurl, i);
        if (url_item && cJSON_IsString(url_item)) {
            cdn_info->cdnurls[i] = strdup(url_item->valuestring);
            ESP_LOGD(TAG, "CDN URL[%d]: %s", i,
                     url_item->valuestring + (strlen(url_item->valuestring) > 40 ?
                         strlen(url_item->valuestring) - 40 : 0));
        }
    }

    // Parse file ID
    cJSON *fileid = cJSON_GetObjectItem(json, "fileid");
    if (fileid && cJSON_IsString(fileid)) {
        strncpy(cdn_info->fileid, fileid->valuestring, sizeof(cdn_info->fileid) - 1);
    }

    // Parse TTL
    cJSON *ttl = cJSON_GetObjectItem(json, "ttl");
    if (ttl && cJSON_IsNumber(ttl)) {
        cdn_info->ttl = ttl->valueint;
    }

    ESP_LOGI(TAG, "Resolved %d CDN URLs for file %s (TTL: %ds)",
             num_urls, cdn_info->fileid, cdn_info->ttl);

    cJSON_Delete(json);
    return 0;
}

int spclient_download_audio(const char *cdn_url, size_t offset, size_t length,
                            uint8_t *buffer, size_t buffer_size) {
    if (!cdn_url || !buffer || buffer_size == 0) {
        return -1;
    }

    // Build range header
    char range_header[64];
    snprintf(range_header, sizeof(range_header), "bytes=%zu-%zu", offset, offset + length - 1);

    http_response_t resp = {
        .buffer = (char *)buffer,
        .buffer_size = buffer_size,
        .data_len = 0,
    };

    esp_http_client_config_t config = {
        .url = cdn_url,
        .method = HTTP_METHOD_GET,
        .event_handler = http_event_handler,
        .timeout_ms = 30000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return -1;

    esp_http_client_set_header(client, "Range", range_header);
    esp_http_client_set_user_data(client, &resp);

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "CDN download failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return -2;
    }

    int status_code = esp_http_client_get_status_code(client);
    int content_length = esp_http_client_get_content_length(client);

    ESP_LOGD(TAG, "CDN: HTTP %d, content-length: %d, received: %zu",
             status_code, content_length, resp.data_len);

    esp_http_client_cleanup(client);

    if (status_code != 200 && status_code != 206) {
        return -status_code;
    }

    return resp.data_len;
}

void esp_spotify_free_cdn_info(esp_spotify_cdn_info_t *cdn_info) {
    if (!cdn_info) return;

    if (cdn_info->cdnurls) {
        for (int i = 0; i < cdn_info->num_urls; i++) {
            if (cdn_info->cdnurls[i]) {
                free(cdn_info->cdnurls[i]);
            }
        }
        free(cdn_info->cdnurls);
        cdn_info->cdnurls = NULL;
    }
    cdn_info->num_urls = 0;
}
