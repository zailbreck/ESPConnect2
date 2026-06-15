// esp_spotify.c — ESP-Spotify-Connect Library Implementation
// =========================================================
// Core library: session management, zeroconf pairing, mercury login5,
// client token, track metadata, CDN resolution, audio download.
//
// Sources & References:
//   Session API:      librespot (MIT) — core/src/session.rs
//   Login5 auth:      librespot (MIT) — authentication/login5.rs
//   Internal API:     librespot (MIT) — spclient.rs, token.rs
//   CDN download:     librespot (MIT) — audio/src/fetch.rs
//
// License: MIT — derived from librespot & cspot

#include "esp_spotify.h"
#include "internal/spclient.h"
#include "internal/zeroconf.h"
#include "internal/mercury.h"
#include "internal/decrypt.h"
#include "internal/platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TAG "esp_spotify"

struct esp_spotify_session_t {
    esp_spotify_config_t config;
    esp_spotify_state_t state;

    /* ZeroConf pairing */
    zeroconf_session_t *zeroconf;
    char zeroconf_auth_data[4096];
    int zeroconf_auth_type;

    /* Mercury login5 */
    mercury_session_t *mercury;

    /* Internal API tokens */
    char client_token[2048];
};

/* ------------------------------------------------------------------ */
/*  Init / Start / Stop                                                */
/* ------------------------------------------------------------------ */

int esp_spotify_init(const esp_spotify_config_t *config, esp_spotify_handle_t *handle) {
    if (!config || !handle) return -1;

    struct esp_spotify_session_t *s =
        calloc(1, sizeof(struct esp_spotify_session_t));
    if (!s) return -2;

    if (config->client_id)     s->config.client_id     = strdup(config->client_id);
    if (config->client_secret) s->config.client_secret = strdup(config->client_secret);
    if (config->device_name)   s->config.device_name   = strdup(config->device_name);
    if (config->device_id)     s->config.device_id     = strdup(config->device_id);
    if (config->username)      s->config.username      = strdup(config->username);
    if (config->ap_host)       s->config.ap_host       = strdup(config->ap_host);
    s->config.ap_port   = config->ap_port   ? config->ap_port   : 443;
    s->config.bell_port = config->bell_port ? config->bell_port : 7864;
    s->state = ESP_SPOTIFY_STATE_IDLE;

    *handle = s;
    fprintf(stderr, "[%s] Initialized (device: %s)\n", TAG,
            s->config.device_name ? s->config.device_name : "ESPConnect");
    return 0;
}

int esp_spotify_start(esp_spotify_handle_t h) {
    if (!h) return -1;
    h->state = ESP_SPOTIFY_STATE_CONNECTING;

    zeroconf_config_t zc = {
        .device_name    = h->config.device_name,
        .device_id      = h->config.device_id,
        .brand_display  = "ESPConnect",
        .model_display  = h->config.device_name,
        .bell_port      = h->config.bell_port,
        .timeout_seconds = 600,
    };

    h->zeroconf = zeroconf_init(&zc);
    if (h->zeroconf) {
        zeroconf_start(h->zeroconf);
        fprintf(stderr, "[%s] ZeroConf pairing started (port %d)\n",
                TAG, h->config.bell_port);
    }

    h->state = ESP_SPOTIFY_STATE_CONNECTED;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Pairing                                                            */
/* ------------------------------------------------------------------ */

int esp_spotify_pair(esp_spotify_handle_t h, int timeout_seconds) {
    if (!h || !h->zeroconf) return -1;

    for (int waited = 0; waited < timeout_seconds; waited++) {
        int ret = zeroconf_poll(h->zeroconf, 1000);
        if (ret == 1) {
            zeroconf_credentials_t creds;
            if (zeroconf_get_credentials(h->zeroconf, &creds) == 0) {
                strncpy(h->zeroconf_auth_data, creds.auth_data_b64,
                        sizeof(h->zeroconf_auth_data) - 1);
                h->zeroconf_auth_type = creds.auth_type;

                if (!h->config.username && creds.username) {
                    h->config.username = strdup(creds.username);
                }

                fprintf(stderr, "[%s] Paired! User=%s AuthType=%d\n",
                        TAG, creds.username, creds.auth_type);
                zeroconf_free_credentials(&creds);
                return 0;
            }
            zeroconf_free_credentials(&creds);
        } else if (ret < 0) {
            fprintf(stderr, "[%s] Pairing error: %d\n", TAG, ret);
            return ret;
        }
    }
    fprintf(stderr, "[%s] Pairing timeout\n", TAG);
    return -2;
}

/* ------------------------------------------------------------------ */
/*  Login & Token                                                      */
/* ------------------------------------------------------------------ */

int esp_spotify_login(esp_spotify_handle_t h) {
    if (!h) return -1;

    h->mercury = mercury_init();
    if (!h->mercury) {
        fprintf(stderr, "[%s] Mercury init failed\n", TAG);
        return -2;
    }

    const char *auth_b64 = h->zeroconf_auth_data;
    int auth_type = h->zeroconf_auth_type;
    const char *username = h->config.username;
    const char *device_id = h->config.device_id ?
        h->config.device_id : "142137fd329622137a14901634264e6f332e2411";
    const char *ap_host = h->config.ap_host ?
        h->config.ap_host : "ap-gew4.spotify.com";

    if (!auth_b64[0] || !username) {
        fprintf(stderr, "[%s] No credentials. Run pair() first.\n", TAG);
        return -3;
    }

    int ret = mercury_login5(h->mercury, username, auth_b64,
                              auth_type, device_id, ap_host,
                              h->config.ap_port);
    if (ret != 0) {
        fprintf(stderr, "[%s] Login5 failed: %d\n", TAG, ret);
        return ret;
    }

    const char *canon = mercury_get_canonical_username(h->mercury);
    fprintf(stderr, "[%s] Logged in as: %s\n", TAG, canon ? canon : username);

    /* Also get client token for HTTP API access */
    ret = spclient_get_client_token(h->mercury, h->client_token,
                                     sizeof(h->client_token));
    if (ret == 0) {
        fprintf(stderr, "[%s] Client token obtained\n", TAG);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Track Metadata + CDN                                               */
/* ------------------------------------------------------------------ */

int esp_spotify_get_track_meta(esp_spotify_handle_t h,
                               const uint8_t track_id[16],
                               spclient_track_meta_t *meta) {
    if (!h || !track_id || !meta) return -1;
    if (!h->client_token[0]) return -4;
    return spclient_get_track_metadata(h->client_token, track_id, meta);
}

int esp_spotify_resolve_cdn(esp_spotify_handle_t h,
                            const char *file_id_hex,
                            char *cdn_url, size_t url_size) {
    if (!h || !file_id_hex || !cdn_url) return -1;
    if (!h->client_token[0]) return -4;
    return spclient_resolve_cdn_url(h->client_token, file_id_hex,
                                     cdn_url, url_size);
}

int esp_spotify_download_audio(esp_spotify_handle_t h,
                               const char *cdn_url,
                               size_t offset, size_t length,
                               uint8_t *buffer, size_t buffer_size) {
    (void)h;
    return spclient_download_audio(cdn_url, offset, length, buffer, buffer_size);
}

/* ------------------------------------------------------------------ */
/*  AudioKey                                                           */
/* ------------------------------------------------------------------ */

int esp_spotify_get_audio_key(esp_spotify_handle_t h,
                              const uint8_t track_id[16],
                              const uint8_t file_id[16],
                              uint8_t key_out[16]) {
    if (!h || !h->mercury) return -1;
    return spclient_get_audio_key(h->mercury, track_id, file_id, key_out);
}

/* ------------------------------------------------------------------ */
/*  Decrypt                                                            */
/* ------------------------------------------------------------------ */

int esp_spotify_decrypt_audio(uint8_t *buffer, size_t length,
                              const uint8_t key[16],
                              const uint8_t file_id[20]) {
    return decrypt_audio(buffer, length, key, file_id);
}

/* ------------------------------------------------------------------ */
/*  Query                                                              */
/* ------------------------------------------------------------------ */

esp_spotify_state_t esp_spotify_get_state(esp_spotify_handle_t h) {
    return h ? h->state : ESP_SPOTIFY_STATE_ERROR;
}

bool esp_spotify_is_connected(esp_spotify_handle_t h) {
    return h && h->mercury && mercury_is_connected(h->mercury);
}

const char *esp_spotify_get_username(esp_spotify_handle_t h) {
    if (!h || !h->mercury) return NULL;
    return mercury_get_canonical_username(h->mercury);
}

/* ------------------------------------------------------------------ */
/*  Stop / Destroy                                                     */
/* ------------------------------------------------------------------ */

void esp_spotify_stop(esp_spotify_handle_t h) {
    if (!h) return;
    h->state = ESP_SPOTIFY_STATE_IDLE;
    if (h->zeroconf) zeroconf_stop(h->zeroconf);
    if (h->mercury) mercury_disconnect(h->mercury);
}

void esp_spotify_destroy(esp_spotify_handle_t h) {
    if (!h) return;
    esp_spotify_stop(h);
    if (h->zeroconf) { zeroconf_destroy(h->zeroconf); h->zeroconf = NULL; }
    if (h->mercury)  { mercury_destroy(h->mercury);   h->mercury = NULL; }
    if (h->config.client_id)     free((void *)h->config.client_id);
    if (h->config.client_secret) free((void *)h->config.client_secret);
    if (h->config.device_name)   free((void *)h->config.device_name);
    if (h->config.device_id)     free((void *)h->config.device_id);
    if (h->config.username)      free((void *)h->config.username);
    if (h->config.ap_host)       free((void *)h->config.ap_host);
    free(h);
}
