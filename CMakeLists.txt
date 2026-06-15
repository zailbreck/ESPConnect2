# esp-spotify-connect
# ESP-IDF component for Spotify Connect

idf_component_register(
    INCLUDE_DIRS "include"
    REQUIRES "esp_http_client" "cJSON" "nvs_flash"
    SRCS
        "src/spclient.c"
        "src/esp_spotify.c"
)

# Enable C++ for Bell HTTP client (if used)
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/bell)
    idf_component_register(
        INCLUDE_DIRS "bell"
    )
endif()
