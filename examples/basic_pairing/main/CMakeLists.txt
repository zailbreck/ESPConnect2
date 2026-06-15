idf_component_register(
    SRCS "basic_pairing.c"
    INCLUDE_DIRS "."
    REQUIRES esp_spotify nvs_flash esp_wifi
)
