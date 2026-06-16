#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

// Note: nanopb files will be compiled along with this
#include "pb_encode.h"
#include "pb_decode.h"
#include "spotify/login5/v3/login5.pb.h"
#include "spotify/login5/v3/client_info.pb.h"
#include "spotify/login5/v3/credentials/credentials.pb.h"

#define LOGIN5_HOST "login5.spotify.com"
#define LOGIN5_PORT "443"
#define LOGIN5_PATH "/v3/login"

bool write_string(pb_ostream_t *stream, const pb_field_iter_t *field, void *const *arg) {
    const char *str = (const char *)*arg;
    if (!str) return true;
    if (!pb_encode_tag_for_field(stream, field)) return false;
    return pb_encode_string(stream, (const pb_byte_t *)str, strlen(str));
}

typedef struct {
    const uint8_t *data;
    size_t len;
} byte_array_t;

bool write_bytes(pb_ostream_t *stream, const pb_field_iter_t *field, void *const *arg) {
    byte_array_t *arr = (byte_array_t *)*arg;
    if (!arr || !arr->data || arr->len == 0) return true;
    if (!pb_encode_tag_for_field(stream, field)) return false;
    return pb_encode_string(stream, arr->data, arr->len);
}

int spotify_login5_get_token(const char *client_id, const char *device_id, const char *username, const uint8_t *auth_data, size_t auth_data_len, uint8_t *access_token_out, size_t *access_token_out_len) {
    uint8_t payload[1024];
    pb_ostream_t stream = pb_ostream_from_buffer(payload, sizeof(payload));

    spotify_login5_v3_LoginRequest req = spotify_login5_v3_LoginRequest_init_zero;
    
    spotify_login5_v3_ClientInfo client_info = spotify_login5_v3_ClientInfo_init_zero;
    client_info.client_id.funcs.encode = write_string;
    client_info.client_id.arg = (void*)client_id;
    client_info.device_id.funcs.encode = write_string;
    client_info.device_id.arg = (void*)device_id;
    
    req.has_client_info = true;
    req.client_info = client_info;

    req.which_login_method = spotify_login5_v3_LoginRequest_stored_credential_tag;
    spotify_login5_v3_credentials_StoredCredential stored = spotify_login5_v3_credentials_StoredCredential_init_zero;
    
    stored.username.funcs.encode = write_string;
    stored.username.arg = (void*)username;
    
    byte_array_t b_arr = { auth_data, auth_data_len };
    stored.data.funcs.encode = write_bytes;
    stored.data.arg = &b_arr;

    req.login_method.stored_credential = stored;

    if (!pb_encode(&stream, spotify_login5_v3_LoginRequest_fields, &req)) {
        return -1;
    }
    size_t payload_len = stream.bytes_written;

    int ret;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "spotify_login5";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) return -1;
    if ((ret = mbedtls_net_connect(&server_fd, LOGIN5_HOST, LOGIN5_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) return -1;
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) return -1;

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, LOGIN5_HOST);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) return -1;
    }

    char http_req[2048];
    snprintf(http_req, sizeof(http_req),
             "POST %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Accept: application/x-protobuf\r\n"
             "Content-Type: application/x-protobuf\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n", LOGIN5_PATH, LOGIN5_HOST, payload_len);

    mbedtls_ssl_write(&ssl, (const unsigned char *)http_req, strlen(http_req));
    mbedtls_ssl_write(&ssl, payload, payload_len);

    unsigned char buf[2048];
    int len;
    int payload_offset = -1;
    size_t total_recv = 0;
    
    do {
        len = mbedtls_ssl_read(&ssl, buf + total_recv, sizeof(buf) - 1 - total_recv);
        if (len == MBEDTLS_ERR_SSL_WANT_READ || len == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        if (len == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || len == 0) break;
        if (len < 0) break;
        
        total_recv += len;
        
        if (payload_offset == -1) {
            for(int i=0; i<total_recv-4; i++) {
                if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                    payload_offset = i + 4;
                    break;
                }
            }
        }
    } while (1);

    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (payload_offset == -1) return -1;
    
    size_t proto_len = total_recv - payload_offset;
    if (proto_len > *access_token_out_len) return -1;
    
    memcpy(access_token_out, buf + payload_offset, proto_len);
    *access_token_out_len = proto_len;

    return 0;
}
