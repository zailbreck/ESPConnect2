/**
 * basic_pairing — ESP-Spotify-Connect Example
 * ============================================
 * ESP-IDF example demonstrating ZeroConf pairing with Spotify app.
 *
 * Hardware required: Any ESP32 board with WiFi
 * Configure: idf.py menuconfig → set WiFi SSID & Password
 *
 * Flow:
 *   1. Connect WiFi
 *   2. Start mDNS advertisement as "ESP-Speaker"
 *   3. Wait for Spotify app to pair (2 min timeout)
 *   4. Extract credentials & login
 *   5. Save reusable token to NVS
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_spotify.h"
#include "internal/zeroconf.h"
#include "internal/mercury.h"

static const char *TAG = "example";

/* ── WiFi Configuration ────────────────────────────────── */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static EventGroupHandle_t wifi_event_group;

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "WiFi disconnected, retrying...");
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "WiFi connected, IP: " IPSTR, IP2STR(&evt->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(const char *ssid, const char *password) {
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        &wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        &wifi_event_handler, NULL, NULL);

    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, ssid, sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy((char *)wifi_cfg.sta.password, password, sizeof(wifi_cfg.sta.password) - 1);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(30000));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "WiFi ready");
    } else {
        ESP_LOGE(TAG, "WiFi failed to connect");
    }
}

/* ── NVS Utilities ─────────────────────────────────────── */
#define NVS_NAMESPACE "espconnect"

static esp_err_t nvs_save_credentials(const char *username,
                                      const uint8_t *auth_data, size_t auth_len,
                                      uint32_t auth_type) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    nvs_set_str(handle, "username", username);
    nvs_set_u32(handle, "auth_type", auth_type);
    nvs_set_blob(handle, "auth_data", auth_data, auth_len);
    nvs_commit(handle);
    nvs_close(handle);

    ESP_LOGI(TAG, "Credentials saved to NVS (authType=%lu, %zu bytes)",
             auth_type, auth_len);
    return ESP_OK;
}

/* ── Main ──────────────────────────────────────────────── */
void app_main(void) {
    /* Init NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    /* ── Configure your device here ─────────────────────── */
    const char *DEVICE_NAME = "ESP-Speaker";   /* ← Change this! */
    const char *WIFI_SSID   = "YOUR_WIFI_SSID";
    const char *WIFI_PASS   = "YOUR_WIFI_PASSWORD";

    ESP_LOGI(TAG, "=== ESP-Spotify-Connect: Basic Pairing ===");
    ESP_LOGI(TAG, "Device name: %s", DEVICE_NAME);

    /* Connect WiFi */
    wifi_init_sta(WIFI_SSID, WIFI_PASS);

    /* 1. Start ZeroConf pairing */
    zeroconf_config_t zc_cfg = {
        .device_name    = DEVICE_NAME,
        .device_id      = NULL,          /* uses default */
        .brand_display  = "ESPConnect",
        .model_display  = DEVICE_NAME,
        .bell_port      = 7864,
        .timeout_seconds = 120,
    };

    zeroconf_session_t *zc = zeroconf_init(&zc_cfg);
    if (!zc) {
        ESP_LOGE(TAG, "zeroconf_init failed");
        return;
    }

    if (zeroconf_start(zc) != 0) {
        ESP_LOGE(TAG, "zeroconf_start failed");
        zeroconf_destroy(zc);
        return;
    }

    ESP_LOGI(TAG, "Waiting for Spotify app to pair...");
    ESP_LOGI(TAG, "Open Spotify → 'Connect to a device' → '%s'", DEVICE_NAME);

    /* 2. Wait for pairing */
    zeroconf_credentials_t creds;
    ret = zeroconf_wait_for_credentials(zc, &creds, pdMS_TO_TICKS(zc_cfg.timeout_seconds * 1000));
    zeroconf_stop(zc);

    if (ret != 0) {
        ESP_LOGW(TAG, "Pairing timed out or failed");
        zeroconf_destroy(zc);
        return;
    }

    ESP_LOGI(TAG, "Paired! Username: %s, authType: %d, authData: %zu bytes",
             creds.username, creds.auth_type, creds.auth_data_len);

    /* 3. Login to Spotify AP */
    mercury_session_t *ms = mercury_init();
    if (!ms) {
        zeroconf_destroy(zc);
        return;
    }

    ret = mercury_login(ms, creds.username, creds.auth_data, creds.auth_data_len,
                        creds.auth_type, "ap-gae2.spotify.com", 443);
    if (ret != 0) {
        ESP_LOGE(TAG, "Login failed");
        mercury_destroy(ms);
        zeroconf_destroy(zc);
        return;
    }

    ESP_LOGI(TAG, "Authenticated as: %s",
             mercury_get_canonical_username(ms));

    /* 4. Save reusable token to NVS */
    size_t token_len = 0;
    const uint8_t *token = mercury_get_stored_cred(ms, &token_len);
    if (token && token_len > 0) {
        nvs_save_credentials(creds.username, token, token_len, 1);
        ESP_LOGI(TAG, "Reusable token saved (%zu bytes)", token_len);
    }

    /* 5. Done — hold session open */
    ESP_LOGI(TAG, "Ready! Mercury session active.");
    while (1) {
        mercury_poll(ms, 1000);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}
