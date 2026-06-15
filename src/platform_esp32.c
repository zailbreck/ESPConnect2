// platform_esp32.c — ESP32 Platform Implementation (stub)
// ======================================================
// Stub implementations for ESP32 (mbedtls + esp_http_client).
// Fill in actual ESP-IDF calls as you build out the ESP32 target.
//
// License: MIT

#include "internal/platform.h"
#include <string.h>
#include <stdlib.h>

/* --- Networking (stub) --- */
platform_socket_t platform_tcp_connect(const char *host, int port) {
    (void)host; (void)port;
    return PLATFORM_SOCKET_INVALID;
}
void platform_tcp_close(platform_socket_t sock) { (void)sock; }
int platform_tcp_read(platform_socket_t sock, uint8_t *buf, size_t n) {
    (void)sock; (void)buf; (void)n; return -1;
}
int platform_tcp_write(platform_socket_t sock, const uint8_t *buf, size_t n) {
    (void)sock; (void)buf; (void)n; return -1;
}
void platform_tcp_set_timeout(platform_socket_t sock, int seconds) {
    (void)sock; (void)seconds;
}

/* --- HTTP server (stub) --- */
platform_http_server_t *platform_http_server_start(int port) { (void)port; return NULL; }
void platform_http_server_stop(platform_http_server_t *srv) { (void)srv; }
platform_socket_t platform_http_server_accept(platform_http_server_t *srv, int to) {
    (void)srv; (void)to; return PLATFORM_SOCKET_INVALID;
}
int platform_http_server_read(platform_socket_t cl, uint8_t *b, size_t m) {
    (void)cl; (void)b; (void)m; return -1;
}
int platform_http_server_write(platform_socket_t cl, const uint8_t *b, size_t l) {
    (void)cl; (void)b; (void)l; return -1;
}

/* --- mDNS (stub) --- */
platform_mdns_t *platform_mdns_start(const char *h) { (void)h; return calloc(1, 1); }
int platform_mdns_register_service(platform_mdns_t *m, const char *n,
                                   const char *t, int p, const char **txt) {
    (void)m; (void)n; (void)t; (void)p; (void)txt; return 0;
}
void platform_mdns_stop(platform_mdns_t *m) { free(m); }

/* --- Crypto (stub) --- */
void platform_sha1(const uint8_t *d, size_t l, uint8_t o[20]) { (void)d; (void)l; memset(o, 0, 20); }
void platform_hmac_sha1(const uint8_t *k, size_t kl, const uint8_t *d, size_t dl, uint8_t o[20]) {
    (void)k; (void)kl; (void)d; (void)dl; memset(o, 0, 20);
}
void platform_pbkdf2_sha1(const uint8_t *pw, size_t pl, const uint8_t *s, size_t sl,
                          uint32_t it, uint8_t *o, size_t ol) {
    (void)pw; (void)pl; (void)s; (void)sl; (void)it; memset(o, 0, ol);
}
void platform_aes_ctr128(const uint8_t *k, const uint8_t *iv, uint8_t *d, size_t l) {
    (void)k; (void)iv; (void)d; (void)l;
}
void platform_aes_ecb_decrypt192(const uint8_t *k, uint8_t *d, size_t l) {
    (void)k; (void)d; (void)l;
}
void platform_dh_generate_keypair(uint8_t pub[96], uint8_t priv[96]) {
    memset(pub, 0, 96); memset(priv, 0, 96);
}
void platform_dh_compute_shared(const uint8_t priv[96], const uint8_t *peer, size_t pl, uint8_t sh[96]) {
    (void)priv; (void)peer; (void)pl; memset(sh, 0, 96);
}
void platform_random(uint8_t *b, size_t l) { memset(b, 0, l); }
size_t platform_base64_decode(const char *in, size_t il, uint8_t *o, size_t oc) {
    (void)in; (void)il; (void)o; (void)oc; return 0;
}
size_t platform_base64_encode(const uint8_t *in, size_t il, char *o, size_t oc) {
    (void)in; (void)il; (void)o; (void)oc; return 0;
}

/* --- Shannon (stub) --- */
platform_shannon_t *platform_shannon_new(void) { return calloc(1, 1); }
void platform_shannon_free(platform_shannon_t *s) { free(s); }
void platform_shannon_key(platform_shannon_t *s, const uint8_t *k, size_t kl) { (void)s; (void)k; (void)kl; }
void platform_shannon_nonce(platform_shannon_t *s, const uint8_t *n, size_t nl) { (void)s; (void)n; (void)nl; }
void platform_shannon_encrypt(platform_shannon_t *s, uint8_t *b, size_t l) { (void)s; (void)b; (void)l; }
void platform_shannon_decrypt(platform_shannon_t *s, uint8_t *b, size_t l) { (void)s; (void)b; (void)l; }
void platform_shannon_finish(platform_shannon_t *s, uint8_t m[4]) { (void)s; memset(m, 0, 4); }

/* --- TLS / HTTPS (stub) --- */
platform_tls_t *platform_tls_connect(const char *host, int port) { (void)host; (void)port; return NULL; }
int platform_tls_write(platform_tls_t *tls, const uint8_t *data, size_t len) { (void)tls; (void)data; (void)len; return -1; }
int platform_tls_read(platform_tls_t *tls, uint8_t *buf, size_t max_len) { (void)tls; (void)buf; (void)max_len; return -1; }
void platform_tls_close(platform_tls_t *tls) { (void)tls; }
platform_http_response_t platform_https_get(const char *host, const char *path, const char *const *headers, int to) {
    (void)host; (void)path; (void)headers; (void)to;
    platform_http_response_t r = {0, NULL, 0}; return r;
}
void platform_http_response_free(platform_http_response_t *resp) { (void)resp; }
