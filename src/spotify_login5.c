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
"-----BEGIN CERTIFICATE-----
"
"MIIGvzCCBaegAwIBAgIQBKe2zOxUs2zxRsDo2Mw4OTANBgkqhkiG9w0BAQsFADBZ
"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTMwMQYDVQQDEypE
"
"aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjUx
"
"MjA4MDAwMDAwWhcNMjYxMjA4MjM1OTU5WjBOMQswCQYDVQQGEwJTRTESMBAGA1UE
"
"BxMJU3RvY2tob2xtMRMwEQYDVQQKEwpTcG90aWZ5IEFCMRYwFAYDVQQDDA0qLnNw
"
"b3RpZnkuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtMomjLiz
"
"IpazOPFmBWA0E8TPf2u1H1ur0GGGuVeIxwFKJXgSFDY1HZhYXHwCBWLN61oTqFAx
"
"5cY6p9FTri2ceDQVeJr+3Kz0Kq9t2ajNUnuzTwO4Va9ATq6NW8x2ryiDqVgvtd0j
"
"cCi2lX+zCTi5RFYz2lhegnazS+TR9IkgQ8Kzx7JlX0B513c5ieNngW43GN0pBuNG
"
"SBPdIQT7maXaoLEBRpO+HdpslWR01VJGUny5W+8uCZTw9NvamhxyntaWWj+LSMdO
"
"BQg7fhVPdwDo9DFKhr1GCwhIrthxbLA3ACmC8uJj6Kf545YS0mkopofDD3cSq/Nu
"
"qYj5OLyc2ggsYQIDAQABo4IDjDCCA4gwHwYDVR0jBBgwFoAUdIWAwGbH3zfez70p
"
"N6oDHb7tzRcwHQYDVR0OBBYEFKriKIha1eaDHC2YxPR/8XNrz3TaMCUGA1UdEQQe
"
"MByCDSouc3BvdGlmeS5jb22CC3Nwb3RpZnkuY29tMD4GA1UdIAQ3MDUwMwYGZ4EM
"
"AQICMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAO
"
"BgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwgZ8GA1UdHwSBlzCB
"
"lDBIoEagRIZCaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFs
"
"RzJUTFNSU0FTSEEyNTYyMDIwQ0ExLTEuY3JsMEigRqBEhkJodHRwOi8vY3JsNC5k
"
"aWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHMlRMU1JTQVNIQTI1NjIwMjBDQTEt
"
"MS5jcmwwgYcGCCsGAQUFBwEBBHsweTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
"
"ZGlnaWNlcnQuY29tMFEGCCsGAQUFBzAChkVodHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
"
"dC5jb20vRGlnaUNlcnRHbG9iYWxHMlRMU1JTQVNIQTI1NjIwMjBDQTEtMS5jcnQw
"
"DAYDVR0TAQH/BAIwADCCAX4GCisGAQQB1nkCBAIEggFuBIIBagFoAHYA2AlVO5RP
"
"ev/IFhlvlE+Fq7D4/F6HVSYPFdEucrtFSxQAAAGa/MK2EgAABAMARzBFAiBzI7yy
"
"vuop7w8Wal8QCm7MWrLAB3RMfcSmvreXNw2zawIhAMRmBCsWc30eoOzJEGp1Vtmo
"
"p6S5TOS066Lt5RVldbv1AHcAyKPEf8ezrbk1awE/anoSbeM6TkOlxkb5l605dZkd
"
"z5oAAAGa/MK2HAAABAMASDBGAiEArLqDD1x902xTrgpmqJtQd6WXWyhCwUXFlDbE
"
"LM09UZkCIQDr5546V2pQkwzYiBl8ZXytVAfFqswtFf872TcJAOJD6wB1AMIxfldF
"
"GaNF7n843rKQQevHwiFaIr9/1bWtdprZDlLNAAABmvzCtiAAAAQDAEYwRAIgNhJM
"
"A+3jgHZ6DD96mueHZwyGoA609jQRfusDr2Fm+ggCIDAMRN0oAcyGBNL8N8iEOJ7m
"
"PgEtSVwMUnMnuv6huJ0+MA0GCSqGSIb3DQEBCwUAA4IBAQC7AT2ucxk2Q/Uw+exC
"
"cu1FZhy7ylgmpK9o2ChwrYjRJ5ewW+PqGJeZWiuPHByyVLRaC4Z7LPum0IXW6pdh
"
"MEvknFo9gwjO1XoCRtsJaQikWn48WvZr+goD3hDxEXuFDwthc12kiptvWmuNmA5m
"
"CmY8IyVFhvXBGEEr3PwBqQNWBkuqNvfY8kAkm33GvBI4jrDAuOY9Y7xSoCkjQQc2
"
"xX1yjh3xmOD91ZFKEChUD6ndzxBktsrbHeSUXQOeqpaSpQ/lxecDTW1woWdHRcVD
"
"hiT5rwZB0a50DdOFyHnzVdVYcmbZOmexTW0phQR0zTxcw1Z/OZQVmM85gMNL2sOx
"
"aMaW
"
"-----END CERTIFICATE-----
"
"-----BEGIN CERTIFICATE-----
"
"MIIEyDCCA7CgAwIBAgIQDPW9BitWAvR6uFAsI8zwZjANBgkqhkiG9w0BAQsFADBh
"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
"
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
"
"MjAeFw0yMTAzMzAwMDAwMDBaFw0zMTAzMjkyMzU5NTlaMFkxCzAJBgNVBAYTAlVT
"
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxMzAxBgNVBAMTKkRpZ2lDZXJ0IEdsb2Jh
"
"bCBHMiBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTCCASIwDQYJKoZIhvcNAQEBBQAD
"
"ggEPADCCAQoCggEBAMz3EGJPprtjb+2QUlbFbSd7ehJWivH0+dbn4Y+9lavyYEEV
"
"cNsSAPonCrVXOFt9slGTcZUOakGUWzUb+nv6u8W+JDD+Vu/E832X4xT1FE3LpxDy
"
"FuqrIvAxIhFhaZAmunjZlx/jfWardUSVc8is/+9dCopZQ+GssjoP80j812s3wWPc
"
"3kbW20X+fSP9kOhRBx5Ro1/tSUZUfyyIxfQTnJcVPAPooTncaQwywa8WV0yUR0J8
"
"osicfebUTVSvQpmowQTCd5zWSOTOEeAqgJnwQ3DPP3Zr0UxJqyRewg2C/Uaoq2yT
"
"zGJSQnWS+Jr6Xl6ysGHlHx+5fwmY6D36g39HaaECAwEAAaOCAYIwggF+MBIGA1Ud
"
"EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHSFgMBmx9833s+9KTeqAx2+7c0XMB8G
"
"A1UdIwQYMBaAFE4iVCAYlebjbuYP+vq5Eu0GF485MA4GA1UdDwEB/wQEAwIBhjAd
"
"BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdgYIKwYBBQUHAQEEajBoMCQG
"
"CCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKG
"
"NGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RH
"
"Mi5jcnQwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
"
"L0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDA9BgNVHSAENjA0MAsGCWCGSAGG/WwC
"
"ATAHBgVngQwBATAIBgZngQwBAgEwCAYGZ4EMAQICMAgGBmeBDAECAzANBgkqhkiG
"
"9w0BAQsFAAOCAQEAkPFwyyiXaZd8dP3A+iZ7U6utzWX9upwGnIrXWkOH7U1MVl+t
"
"wcW1BSAuWdH/SvWgKtiwla3JLko716f2b4gp/DA/JIS7w7d7kwcsr4drdjPtAFVS
"
"slme5LnQ89/nD/7d+MS5EHKBCQRfz5eeLjJ1js+aWNJXMX43AYGyZm0pGrFmCW3R
"
"bpD0ufovARTFXFZkAdl9h6g4U5+LXUZtXMYnhIHUfoyMo5tS58aI7Dd8KvvwVVo4
"
"chDYABPPTHPbqjc1qCmBaZx2vN4Ye5DUys/vZwP9BFohFrH/6j/f3IL16/RZkiMN
"
"JCqVJUzKoZHm1Lesh3Sz8W2jmdv51b2EQJ8HmA==
"
"-----END CERTIFICATE-----
"
;
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
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) { 
            char error_buf[100];
            mbedtls_strerror(ret, error_buf, 100);
            fprintf(stderr, "\n\n===========================================\n");
            fprintf(stderr, " [mbedtls ERROR] mbedtls_ssl_handshake failed!\n");
            fprintf(stderr, "  Code : -0x%04x\n", -ret);
            fprintf(stderr, "  Desc : %s\n", error_buf);
            fprintf(stderr, "===========================================\n\n");
            return -1; 
        }
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
