# esp-spotify-connect
# ESP-IDF component for Spotify Connect
#
# Dependencies (ESP32):
#   - mbedtls (crypto primitives)
#   - lwip / esp_netif (sockets)
#   - mdns (zeroconf pairing)
#   - esp_http_client (spclient HTTP / CDN)
#   - nvs_flash (credential storage, optional)
#
# For x86 Linux testing, link platform_posix.c instead of platform_esp32.c
# and use OpenSSL instead of mbedtls.

idf_component_register(
    INCLUDE_DIRS "include"
    REQUIRES "mbedtls" "esp_http_client" "mdns" "nvs_flash" "esp_netif"
    SRCS
        "src/spclient.c"
        "src/esp_spotify.c"
        "src/zeroconf.c"
        "src/mercury.c"
        "src/decrypt.c"
        "src/platform_esp32.c"
)
