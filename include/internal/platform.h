// platform.h — Platform Abstraction Layer
// =========================================
// Abstracts networking and crypto primitives for both ESP32 (mbedtls + esp_http_client)
// and POSIX (OpenSSL + BSD sockets) builds.
//
// Source references:
//   AES primitives:  mbedtls 3.x / OpenSSL
//   DH Oakley Grp2:  RFC 2409
//   Shannon cipher:  cspot (MIT) — Shannon.cpp
//
// License: MIT

#ifndef SPOTIFY_PLATFORM_H
#define SPOTIFY_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Networking                                                         */
/* ------------------------------------------------------------------ */

/** Opaque TCP socket handle */
typedef intptr_t platform_socket_t;
#define PLATFORM_SOCKET_INVALID (-1)

/** Connect to host:port, return socket handle or PLATFORM_SOCKET_INVALID */
platform_socket_t platform_tcp_connect(const char *host, int port);

/** Close socket */
void platform_tcp_close(platform_socket_t sock);

/** Read exactly n bytes (blocks) — returns 0 on success, -1 on error */
int platform_tcp_read(platform_socket_t sock, uint8_t *buf, size_t n);

/** Write exactly n bytes — returns 0 on success, -1 on error */
int platform_tcp_write(platform_socket_t sock, const uint8_t *buf, size_t n);

/** Set socket timeout in seconds */
void platform_tcp_set_timeout(platform_socket_t sock, int seconds);

/** Sleep for specified milliseconds */
void platform_sleep_ms(int ms);

/* ------------------------------------------------------------------ */
/*  TLS / HTTPS support                                                */
/* ------------------------------------------------------------------ */

typedef struct platform_tls_t platform_tls_t;

/** Create TLS connection to host:port. Returns NULL on failure. */
platform_tls_t *platform_tls_connect(const char *host, int port);

/** Write to TLS connection. Returns bytes sent, -1 on error. */
int platform_tls_write(platform_tls_t *tls, const uint8_t *data, size_t len);

/** Read from TLS connection. Returns bytes read, 0 on close, -1 on error. */
int platform_tls_read(platform_tls_t *tls, uint8_t *buf, size_t max_len);

/** Close TLS connection and free resources */
void platform_tls_close(platform_tls_t *tls);

/* ------------------------------------------------------------------ */
/*  HTTP/HTTPS Client                                                  */
/* ------------------------------------------------------------------ */

/** HTTP response from platform_http_request */
typedef struct {
    int status_code;
    uint8_t *body;
    size_t body_len;
} platform_http_response_t;

/**
 * Perform an HTTPS GET request.
 *
 * @param host        Hostname (e.g. spclient.wg.spotify.com)
 * @param path        URL path (e.g. /track-playback/v1/json/)
 * @param headers     NULL-terminated array of header strings, or NULL
 * @param timeout_sec Timeout in seconds
 * @return Response struct (caller must free resp.body)
 */
platform_http_response_t platform_https_get(
    const char *host, const char *path,
    const char *const *headers,
    int timeout_sec);

/**
 * Free HTTP response body.
 */
void platform_http_response_free(platform_http_response_t *resp);

/* ------------------------------------------------------------------ */
/*  HTTP server (for Bell zeroconf)                                     */
/* ------------------------------------------------------------------ */

typedef struct platform_http_server_t platform_http_server_t;

/** Start a blocking TCP server on the given port.
 *  Returns NULL on failure. */
platform_http_server_t *platform_http_server_start(int port);

/** Stop and free the server */
void platform_http_server_stop(platform_http_server_t *srv);

/** Accept a client, returns socket handle or PLATFORM_SOCKET_INVALID */
platform_socket_t platform_http_server_accept(platform_http_server_t *srv, int timeout_ms);

/** Read from client socket (returns bytes read, 0 on close, -1 on error) */
int platform_http_server_read(platform_socket_t client, uint8_t *buf, size_t max_len);

/** Write to client socket (returns bytes written, -1 on error) */
int platform_http_server_write(platform_socket_t client, const uint8_t *buf, size_t len);

/* ------------------------------------------------------------------ */
/*  mDNS advertisement                                                */
/* ------------------------------------------------------------------ */

typedef struct platform_mdns_t platform_mdns_t;

/** Start mDNS responder */
platform_mdns_t *platform_mdns_start(const char *hostname);

/** Register a service */
int platform_mdns_register_service(platform_mdns_t *m,
                                   const char *name, const char *type,
                                   int port, const char **txt_records);

/** Stop mDNS */
void platform_mdns_stop(platform_mdns_t *m);

/* ------------------------------------------------------------------ */
/*  Crypto: SHA1, HMAC-SHA1                                            */
/* ------------------------------------------------------------------ */

/** SHA1 hash — out must be 20 bytes */
void platform_sha1(const uint8_t *data, size_t len, uint8_t out[20]);

/** HMAC-SHA1 — out must be 20 bytes */
void platform_hmac_sha1(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[20]);

/** PBKDF2-HMAC-SHA1 */
void platform_pbkdf2_sha1(const uint8_t *password, size_t pw_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iterations,
                          uint8_t *out, size_t out_len);

/* ------------------------------------------------------------------ */
/*  Crypto: AES                                                        */
/* ------------------------------------------------------------------ */

/** AES-128-CTR encrypt/decrypt (xors data in-place, same operation) */
void platform_aes_ctr128(const uint8_t *key, const uint8_t *iv,
                         uint8_t *data, size_t len);

/** AES-192-ECB decrypt (data length must be multiple of 16) */
void platform_aes_ecb_decrypt128(const uint8_t *key, uint8_t *data, size_t len);
void platform_aes_ecb_decrypt192(const uint8_t *key, uint8_t *data, size_t len);

/* ------------------------------------------------------------------ */
/*  Crypto: DH (Oakley Group 2, 768-bit)                                */
/* ------------------------------------------------------------------ */

#define PLATFORM_DH_KEY_SIZE 96

/** Generate DH keypair (priv+pub, each 96 bytes). Caller allocates buffers. */
void platform_dh_generate_keypair(uint8_t pub_key[96], uint8_t priv_key[96]);

/** Compute shared secret: shared = peer_pub ^ priv_key mod prime.
 *  Result is 96 bytes. */
void platform_dh_compute_shared(const uint8_t priv_key[96],
                                const uint8_t *peer_pub, size_t peer_pub_len,
                                uint8_t shared[96]);

/* ------------------------------------------------------------------ */
/*  Crypto: Random                                                     */
/* ------------------------------------------------------------------ */

void platform_random(uint8_t *buf, size_t len);

/* ------------------------------------------------------------------ */
/*  Base64                                                             */
/* ------------------------------------------------------------------ */

/** Base64 decode. Returns bytes written, 0 on failure. */
size_t platform_base64_decode(const char *in, size_t in_len,
                              uint8_t *out, size_t out_capacity);

/** Base64 encode. Returns bytes written (excluding NUL), 0 on failure. */
size_t platform_base64_encode(const uint8_t *in, size_t in_len,
                              char *out, size_t out_capacity);

/* ------------------------------------------------------------------ */
/*  Shannon stream cipher (pure C, no platform deps)                   */
/* ------------------------------------------------------------------ */

/**
 * Shannon stream cipher state.
 *
 * Exact algorithm from cspot (MIT):
 *   https://github.com/feelfreelinux/cspot/blob/master/cspot/src/Shannon.cpp
 *
 * Parameters: N=16, INITKONST=0x6996c53a, KEYP=13, FOLD=16
 */
typedef struct platform_shannon_t platform_shannon_t;

platform_shannon_t *platform_shannon_new(void);
void platform_shannon_free(platform_shannon_t *s);
void platform_shannon_key(platform_shannon_t *s, const uint8_t *key, size_t key_len);
void platform_shannon_key_pair(platform_shannon_t *snd, platform_shannon_t *rcv,
                                const uint8_t *send_key, const uint8_t *recv_key);
void platform_shannon_nonce(platform_shannon_t *s, const uint8_t *nonce, size_t nonce_len);
void platform_shannon_encrypt(platform_shannon_t *s, uint8_t *buf, size_t len);
void platform_shannon_decrypt(platform_shannon_t *s, uint8_t *buf, size_t len);
void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]);

#ifdef __cplusplus
}
#endif

#endif /* SPOTIFY_PLATFORM_H */
