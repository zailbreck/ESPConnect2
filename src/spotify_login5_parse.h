#ifndef SPOTIFY_LOGIN5_PARSE_H
#define SPOTIFY_LOGIN5_PARSE_H

#include <stdint.h>
#include <stddef.h>

int spotify_login5_extract_token(const uint8_t *payload, size_t payload_len, char *access_token_str, size_t max_len);

#endif
