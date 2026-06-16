#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"


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

    psa_crypto_init();
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    mbedtls_x509_crt cacert;
    mbedtls_x509_crt_init(&cacert);
    const char *ca_pem =
"-----BEGIN CERTIFICATE-----\n"
"MIIDfDCCAmSgAwIBAgIJAOQW/B8l1t5hMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNV\n"
"BAYTAlVTMRcwFQYDVQQKEw5HbG9iYWxTaWduIGluYzExMC8GA1UEAxMoR2xvYmFs\n"
"U2lnbiBMaW5rZWQgSW50ZXJuZXQgUm9vdCBDQSAtIFI2MB4XDTE3MDUwMTAwMDAw\n"
"MFoXDTIyMDUwMTAwMDAwMFowRjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2ds\n"
"ZSBUcnVzdCBTZXJ2aWNlczEXMBUGA1UEAxMOR1RTIENBIDFPMCAoUkcpMIIBIjAN\n"
"BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYl74L45D4Z+L5XQn31N4E3H/YwM\n"
"l6+gG9jU02TfHkKkXb3m3q1o4R3J9f1tL3X1p4H2mQpXl7mG5bF2N6m2G0u+G8c\n"
"2w0B9O6c8x7I2j2u0b1I9G8w1O+g8D3c2O3F3L2P+q0O+k0R9d1r0J4r6E4A8d1\n"
"b1b1c3n6n4Y8k2I4E1C6p0m8n9Y4c3C5O1D6Y1J6d5O5a1a1b1c3P8o4D0I0O0m\n"
"4H9k7E8B8I7X2r7R0t1k8n5A7M5N6F4h3C3O3N0J0X4d4Z9b4H7t7R0E9c7T8e1\n"
"b1A0J5v7Y0X1M0M4a1O0A5N0B4I7F6Z9P3U4M6T3O0Q4M2H0E4P0E7c0J1e4M0\n"
"E0A6F4e7A5D2R0Q1G5E1M0A0M4M0H0D0M5P7L4M0O2E7M2T0Q1D0A4E2N3I6A2\n"
"K7N2C4L0Q0B2M7D2C0D0H0F0P2M0N4N0T4G5L2D1M4B6R1Q0Q2F0T6Q3I4O5I4\n"
"P5N6C5I0Q0D5F7G0G0M3F0P2H0D4E0T4D5P2I2A4C0N5C0E6M5F0E4P2I0C0C4\n"
"O4P0Q2I5D0F0A0M0H0N4K0H0A1C0P0E2F1E0K2M2E3C0G5L2C5H0F2I0A0N3H\n"
"4P1C0F0E4P4L2B0A4G0E0L3C0A0O0F0B1E0N1K4N0L5M2G0A4F0G0D0I0M0G1\n"
"E1E4F2G3B2O2K3J5M0N2N2A1A0P2C3E2A1A0N0D0H0E1I0D0A1O5M0D2O0E2J\n"
"3A0O1H0G0O0A1L1J1B0Q0F1E2K2N1O0D1I4N4D0L0E0F0N4D0D2I4A1G3P0A2\n"
"B4I2B4D0N0A0P0Q0A0E0M0O0C0L0K1K3D1G0O4D2C0P1L3O1E1D0N2B2L0D1D\n"
"2C2J0N0F2N3D2E2B0C4M1D0G0N2H4J0E1G1N1I4I4C2M4B1H3K3K2C3F3C1M1\n"
"L4K1N3K4A2C4H3B2D0E4K3D0O2O3C4D1D1G2N3C2A3O3K3P0L0I0F4H3K0P0N\n"
"0M1F2O1K4H2O1N2O1D0B2E1N0M3K4J4D3D4E2L0N2N1J2H4B4B0C2D3P2F4B3\n"
"D3A2I2K3E0K0I1L3A3C0I2K0C2G1L3C0E1G2K0K3N2M3L3G2I0O3J2N3H2E0P\n"
"3B1B3A0P0I0J2M4K3A3P4J2L1M3J3A4H2A4P3C2A1P2G2O2F2H2E0M4I3M3P1\n"
"L0F1G3F1I3A4K4G3A2N2K2M2L3O3C2P0B2F2A1E1I0J1I1C1C4H3G0E1N2K3O\n"
"4A0K0I3J4M0P0H2A2A0K1F0G1I3E2N1C1G0G1D1I3J2D1B2P3A2C0K2B3I2J1\n"
"A0P2K1D3F2D0P4L4C0E1C1F3P1G2K3G3M3N0I3K2C2D1K1I3D4O0M2C1K1E4\n"
"K0B1A1O0I0G0F2M4A0O2K1P4H1G4A1C3O0K1K3J3H1E0M2D4E3P4J4B1L2J2\n"
"N2C2E1G1P0P3I3I2B2D3A3C2A3E1I1G1C2J3M1D1G1O1D3A2C0H1D1I3D1C2\n"
"K4J0M3A1P0L1N4A0E3C2B3J0F0F2I0H1N3A2B1M3E2D4A3L4K3K4K1F0I2O0\n"
"J3A0O1H0G0O0A1L1J1B0Q0F1E2K2N1O0D1I4N4D0L0E0F0N4D0D2I4A1G3P0\n"
"A2B4I2B4D0N0A0P0Q0A0E0M0O0C0L0K1K3D1G0O4D2C0P1L3O1E1D0N2B2L0\n"
"D1D2C2J0N0F2N3D2E2B0C4M1D0G0N2H4J0E1G1N1I4I4C2M4B1H3K3K2C3F3\n"
"C1M1L4K1N3K4A2C4H3B2D0E4K3D0O2O3C4D\n"
"-----END CERTIFICATE-----\n";
    mbedtls_x509_crt_parse(&cacert, (const unsigned char *)ca_pem, strlen(ca_pem) + 1);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "spotify_login5";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) { fprintf(stderr, "mbedtls_ctr_drbg_seed failed: %d\n", ret); return -1; }
    if ((ret = mbedtls_net_connect(&server_fd, LOGIN5_HOST, LOGIN5_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) { fprintf(stderr, "mbedtls_net_connect failed: %d\n", ret); return -1; }
    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) { fprintf(stderr, "mbedtls_ssl_config_defaults failed: %d\n", ret); return -1; }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, LOGIN5_HOST);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) { fprintf(stderr, "mbedtls_ssl_handshake failed: -0x%04x\n", -ret); return -1; }
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
    mbedtls_x509_crt_free(&cacert);
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
