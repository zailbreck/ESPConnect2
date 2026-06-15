# ESP-IDF project file for basic_pairing example
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Add the library as an extra component
set(EXTRA_COMPONENT_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
)

project(esp_spotify_basic_pairing)
