// basic_pairing.c — ESP-Spotify-Connect Library Example
// =====================================================
// Demonstrates: mDNS device discovery + Bluetooth-style pairing
//              with Spotify app → extract credentials → authenticate
//
// Build (Linux x86):
//   gcc -std=c11 -O2 basic_pairing.c ../src/*.c ../src/mdns.c ../src/mdnsd.c \
//       -I../include -lmbedtls -lmbedcrypto -lmbedx509 -lssl -lcrypto \
//       -o basic_pairing
//
// Run:
//   ./basic_pairing [device_name]

#include "esp_spotify.h"
#include "internal/zeroconf.h"
#include "internal/mercury.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *device_name = argc > 1 ? argv[1] : "ESP-Speaker";

    printf("=== ESP-Spotify-Connect: Basic Pairing ===\n");
    printf("Device: %s\n", device_name);
    printf("-----------------------------------------\n");

    /* Step 1: Start ZeroConf pairing */
    zeroconf_config_t zc_cfg = {
        .device_name = device_name,    // <<< Configurable!
        .device_id = NULL,             // uses default
        .brand_display = "ESPConnect",
        .model_display = device_name,  // same as device name
        .bell_port = 7864,
        .timeout_seconds = 120,        // 2 min timeout
    };

    zeroconf_session_t *zc = zeroconf_init(&zc_cfg);
    if (!zc) {
        fprintf(stderr, "Failed to init zeroconf\n");
        return 1;
    }

    if (zeroconf_start(zc) != 0) {
        fprintf(stderr, "Failed to start zeroconf\n");
        zeroconf_destroy(zc);
        return 1;
    }

    printf("\n📱 Open Spotify → 'Connect to a device' → look for '%s'\n", device_name);
    printf("Waiting for pairing... (Ctrl+C to cancel)\n\n");

    /* Step 2: Wait for pairing */
    zeroconf_credentials_t creds;
    int ret = zeroconf_wait_for_credentials(zc, &creds, zc_cfg.timeout_seconds * 1000);
    zeroconf_stop(zc);

    if (ret != 0) {
        printf("Pairing failed or timed out.\n");
        zeroconf_destroy(zc);
        return 1;
    }

    printf("\n✅ Paired! Username: %s\n", creds.username);
    printf("   authType: %d, authData: %zu bytes\n", creds.auth_type, creds.auth_data_len);

    /* Step 3: Login to Spotify AP */
    printf("\nAuthenticating to Spotify...\n");

    mercury_session_t *ms = mercury_init();
    if (!ms) {
        zeroconf_destroy(zc);
        return 1;
    }

    ret = mercury_login(ms, creds.username, creds.auth_data, creds.auth_data_len,
                        creds.auth_type, "ap-gae2.spotify.com", 443);
    if (ret != 0) {
        printf("Login failed.\n");
        mercury_destroy(ms);
        zeroconf_destroy(zc);
        return 1;
    }

    const char *canon = mercury_get_canonical_username(ms);
    printf("✅ Authenticated as: %s\n", canon ? canon : "(unknown)");

    /* Step 4: Get reusable token */
    size_t cred_len = 0;
    const uint8_t *stored = mercury_get_stored_cred(ms, &cred_len);
    if (stored && cred_len > 0) {
        printf("   Reusable token: %zu bytes (saved for next login)\n", cred_len);
    }

    mercury_disconnect(ms);
    mercury_destroy(ms);
    zeroconf_destroy(zc);

    printf("\nDone!\n");
    return 0;
}
