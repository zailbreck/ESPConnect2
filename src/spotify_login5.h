#ifndef SPOTIFY_LOGIN5_H
#define SPOTIFY_LOGIN5_H

#include <stdint.h>
#include <stddef.h>

int spotify_login5_get_token(const char *client_id, const char *device_id, const char *username, const uint8_t *auth_data, size_t auth_data_len, uint8_t *access_token_out, size_t *access_token_out_len);

#endif
