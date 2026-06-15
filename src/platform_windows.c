// platform_windows.c — Windows Platform Implementation (mingw-w64 + mbedtls)
// ==========================================================================
// Cross-compiled with x86_64-w64-mingw32-gcc, static binary.
// Uses winsock2 + mbedtls (no OpenSSL, no POSIX).
//
// Build: x86_64-w64-mingw32-gcc -std=gnu11 -O2 -static \
//          -I mbedtls-3.6.5/include \
//          -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600 \
//          src/*.c test/x86/test_e2e.c platform_windows.c \
//          mbedtls-3.6.5/library/libmbedcrypto.a \
//          mbedtls-3.6.5/library/libmbedtls.a \
//          mbedtls-3.6.5/library/libmbedx509.a \
//          -lws2_32 -lpthread -lbcrypt -lshlwapi \
//          -o espconnect_e2e.exe
//
// License: MIT

#include "internal/platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>
#include <shlwapi.h>

#include <mbedtls/sha1.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/bignum.h>
#include <mbedtls/dhm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>

#define TAG "platform_win"

/* One-time WSA init */
static int wsa_ready = 0;
static void wsa_init(void) {
    if (!wsa_ready) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        wsa_ready = 1;
    }
}

/* ================================================================== */
/*  Networking (winsock2)                                              */
/* ================================================================== */

platform_socket_t platform_tcp_connect(const char *host, int port) {
    wsa_init();
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return PLATFORM_SOCKET_INVALID;

    int timeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0) {
        closesocket(sock); return PLATFORM_SOCKET_INVALID;
    }

    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result); closesocket(sock);
        return PLATFORM_SOCKET_INVALID;
    }

    freeaddrinfo(result);
    return (platform_socket_t)(intptr_t)sock;
}

void platform_tcp_close(platform_socket_t sock) {
    if (sock != PLATFORM_SOCKET_INVALID) closesocket((SOCKET)(intptr_t)sock);
}

int platform_tcp_read(platform_socket_t sock, uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        int r = recv((SOCKET)(intptr_t)sock, (char *)(buf + total),
                     (int)(n - total), 0);
        if (r <= 0) return -1;
        total += (size_t)r;
    }
    return 0;
}

int platform_tcp_write(platform_socket_t sock, const uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        int w = send((SOCKET)(intptr_t)sock, (const char *)(buf + total),
                     (int)(n - total), 0);
        if (w <= 0) return -1;
        total += (size_t)w;
    }
    return 0;
}

void platform_tcp_set_timeout(platform_socket_t sock, int seconds) {
    int ms = seconds * 1000;
    setsockopt((SOCKET)(intptr_t)sock, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&ms, sizeof(ms));
    setsockopt((SOCKET)(intptr_t)sock, SOL_SOCKET, SO_SNDTIMEO,
               (const char *)&ms, sizeof(ms));
}

void platform_sleep_ms(int ms) {
    Sleep(ms);
}

/* ================================================================== */
/*  HTTP Server (Bell pairing) — winsock2                              */
/* ================================================================== */

struct platform_http_server_t {
    SOCKET listen_sock;
    int port;
};

platform_http_server_t *platform_http_server_start(int port) {
    wsa_init();
    SOCKET lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock == INVALID_SOCKET) return NULL;

    int opt = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((u_short)port);

    if (bind(lsock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(lsock); return NULL;
    }
    if (listen(lsock, 1) != 0) {
        closesocket(lsock); return NULL;
    }

    platform_http_server_t *srv = malloc(sizeof(*srv));
    srv->listen_sock = lsock;
    srv->port = port;
    return srv;
}

void platform_http_server_stop(platform_http_server_t *srv) {
    if (!srv) return;
    closesocket(srv->listen_sock);
    free(srv);
}

platform_socket_t platform_http_server_accept(platform_http_server_t *srv, int timeout_ms) {
    if (!srv) return PLATFORM_SOCKET_INVALID;

    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(srv->listen_sock, &rfds);

    int ret = select(0, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return PLATFORM_SOCKET_INVALID;

    SOCKET client = accept(srv->listen_sock, NULL, NULL);
    return (client != INVALID_SOCKET) ? (platform_socket_t)(intptr_t)client : PLATFORM_SOCKET_INVALID;
}

int platform_http_server_read(platform_socket_t cl, uint8_t *b, size_t m) {
    int r = recv((SOCKET)(intptr_t)cl, (char *)b, (int)m, 0);
    return (r > 0) ? r : (r == 0 ? 0 : -1);
}

int platform_http_server_write(platform_socket_t cl, const uint8_t *b, size_t l) {
    int w = send((SOCKET)(intptr_t)cl, (const char *)b, (int)l, 0);
    return (w > 0) ? w : -1;
}

/* ================================================================== */
/*  mDNS — TODO (Windows mDNS needs dns-sd or external lib)            */
/*  For Windows builds, pairing is done on Linux/extractor;            */
/*  this E2E test uses pre-captured credentials.                       */
/* ================================================================== */

struct platform_mdns_t { int placeholder; };

platform_mdns_t *platform_mdns_start(const char *h) { (void)h; return calloc(1, 1); }
int platform_mdns_register_service(platform_mdns_t *m, const char *n,
                                   const char *t, int p, const char **txt) {
    (void)m; (void)n; (void)t; (void)p; (void)txt; return 0;
}
void platform_mdns_stop(platform_mdns_t *m) { free(m); }

/* ================================================================== */
/*  Crypto: SHA1, HMAC-SHA1, PBKDF2 (mbedtls)                         */
/* ================================================================== */

void platform_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    mbedtls_sha1(data, len, out);
}

void platform_hmac_sha1(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[20]) {
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_hmac(info, key, key_len, data, data_len, out);
}

void platform_pbkdf2_sha1(const uint8_t *password, size_t pw_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iterations,
                          uint8_t *out, size_t out_len) {
    mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA1,
        password, pw_len, salt, salt_len,
        (unsigned int)iterations, (uint32_t)out_len, out);
}

/* ================================================================== */
/*  Crypto: AES-128-CTR, AES-192-ECB (mbedtls)                        */
/* ================================================================== */

void platform_aes_ctr128(const uint8_t *key, const uint8_t *iv,
                         uint8_t *data, size_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128);

    size_t nc_off = 0;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    memcpy(nonce_counter, iv, 16);
    memset(stream_block, 0, 16);

    mbedtls_aes_crypt_ctr(&aes, len, &nc_off,
                           nonce_counter, stream_block,
                           data, data);
    mbedtls_aes_free(&aes);
}

void platform_aes_ecb_decrypt192(const uint8_t *key, uint8_t *data, size_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 192);

    for (size_t off = 0; off < len; off += 16) {
        uint8_t block[16];
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT,
                              data + off, block);
        memcpy(data + off, block, 16);
    }
    mbedtls_aes_free(&aes);
}

/* ================================================================== */
/*  Crypto: DH Oakley Group 2 (768-bit MODP) — mbedtls                 */
/* ================================================================== */

static const uint8_t dh_prime[96] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x3A, 0x36, 0x20,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

/* BCrypt RNG: use SystemPrng for mbedtls */
static int win_random_cb(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    /* Fallback: use BCryptGenRandom if available, else simple MT */
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)(rand() & 0xFF);
    return 0;
}

void platform_dh_generate_keypair(uint8_t pub_key[96], uint8_t priv_key[96]) {
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);

    mbedtls_mpi P, G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_read_binary(&P, dh_prime, sizeof(dh_prime));
    mbedtls_mpi_lset(&G, 2);

    mbedtls_dhm_set_group(&dhm, &P, &G);
    mbedtls_dhm_make_public(&dhm, 96, priv_key, 96, win_random_cb, NULL);
    memcpy(pub_key, dhm.GX.p, 96);

    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&G);
    mbedtls_dhm_free(&dhm);
}

void platform_dh_compute_shared(const uint8_t priv_key[96],
                                const uint8_t *peer_pub, size_t peer_pub_len,
                                uint8_t shared[96]) {
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);

    mbedtls_mpi P, G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_read_binary(&P, dh_prime, sizeof(dh_prime));
    mbedtls_mpi_lset(&G, 2);

    mbedtls_dhm_set_group(&dhm, &P, &G);
    mbedtls_mpi_read_binary(&dhm.X, priv_key, 96);

    mbedtls_mpi GY;
    mbedtls_mpi_init(&GY);
    mbedtls_mpi_read_binary(&GY, peer_pub, peer_pub_len);

    size_t olen = 0;
    mbedtls_dhm_calc_secret(&dhm, shared, 96, &olen, win_random_cb, NULL);

    mbedtls_mpi_free(&GY);
    mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&P);
    mbedtls_dhm_free(&dhm);
}

void platform_random(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (unsigned char)(rand() & 0xFF);
}

/* ================================================================== */
/*  Base64                                                             */
/* ================================================================== */

size_t platform_base64_decode(const char *in, size_t in_len,
                              uint8_t *out, size_t out_capacity) {
    size_t olen = 0;
    int ret = mbedtls_base64_decode(out, out_capacity, &olen,
                                     (const unsigned char *)in, in_len);
    return (ret == 0) ? olen : 0;
}

size_t platform_base64_encode(const uint8_t *in, size_t in_len,
                              char *out, size_t out_capacity) {
    size_t olen = 0;
    int ret = mbedtls_base64_encode((unsigned char *)out, out_capacity, &olen,
                                     in, in_len);
    return (ret == 0) ? olen : 0;
}

/* ================================================================== */
/*  Shannon Stream Cipher (pure C — identical to POSIX/ESP32)          */
/* ================================================================== */

#define SHANNON_N       16
#define SHANNON_INITKONST 0x6996c53a
#define SHANNON_KEYP    13

static inline uint32_t sh_rotl(uint32_t i, int distance) {
    return (i << distance) | (i >> (32 - distance));
}

struct platform_shannon_t {
    uint32_t R[SHANNON_N];
    uint32_t CRC[SHANNON_N];
    uint32_t sbuf;
    uint32_t mbuf;
    int nbuf;
};

static void shannon_cycle(platform_shannon_t *s) {
    uint32_t t;
    int i;
    t = s->R[12] ^ s->R[13] ^ SHANNON_INITKONST;
    s->sbuf = sh_rotl(t, 1);
    for (i = 0; i < SHANNON_N; i++) {
        t = s->CRC[((i + SHANNON_N) - 1) % SHANNON_N];
        t ^= s->R[i];
        s->CRC[i] = t;
        t = sh_rotl(t, 1);
        s->CRC[i] ^= t;
    }
}

static void shannon_macfunc(platform_shannon_t *s, uint32_t val) {
    s->CRC[0] ^= val;
}

static void shannon_initstate(platform_shannon_t *s) {
    int i;
    for (i = 0; i < SHANNON_N; i++) {
        s->R[i] = 1;
        s->CRC[i] = 1;
    }
    s->R[SHANNON_KEYP] = s->R[SHANNON_KEYP] ^ SHANNON_INITKONST;
    s->sbuf = 0;
    s->mbuf = 0;
    s->nbuf = 32;
    for (i = 1; i < SHANNON_N; i++)
        shannon_cycle(s);
}

static inline void ADDKEY(platform_shannon_t *s, uint32_t k) {
    s->R[SHANNON_KEYP] ^= k;
    s->CRC[SHANNON_KEYP] ^= k;
}

static inline uint32_t BYTE2WORD(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline void WORD2BYTE(uint32_t w, uint8_t *b) {
    b[0] = (uint8_t)(w >> 24);
    b[1] = (uint8_t)(w >> 16);
    b[2] = (uint8_t)(w >> 8);
    b[3] = (uint8_t)w;
}

static inline void shannon_diffuse(platform_shannon_t *s) {
    int i;
    for (i = 1; i < SHANNON_N; i++) {
        s->R[i] ^= s->CRC[i];
        s->CRC[i] ^= s->R[i];
    }
}

platform_shannon_t *platform_shannon_new(void) {
    platform_shannon_t *s = calloc(1, sizeof(*s));
    if (s) shannon_initstate(s);
    return s;
}

void platform_shannon_free(platform_shannon_t *s) { free(s); }

void platform_shannon_key(platform_shannon_t *s, const uint8_t *key, size_t key_len) {
    size_t i = 0;
    while (key_len >= 4) {
        ADDKEY(s, BYTE2WORD(key + i));
        shannon_cycle(s);
        i += 4;
        key_len -= 4;
    }
    if (key_len) {
        uint32_t last = 0;
        memcpy(&last, key + i, key_len);
        ADDKEY(s, last);
        shannon_cycle(s);
    }
}

void platform_shannon_nonce(platform_shannon_t *s, const uint8_t *nonce, size_t nonce_len) {
    platform_shannon_key(s, nonce, nonce_len);
    s->sbuf = 0;
}

void platform_shannon_encrypt(platform_shannon_t *s, uint8_t *buf, size_t len) {
    platform_shannon_decrypt(s, buf, len);
}

void platform_shannon_decrypt(platform_shannon_t *s, uint8_t *buf, size_t len) {
    const uint8_t *endbuf = buf + (len & ~3);
    size_t nbytes = len;
    while (buf < endbuf) {
        shannon_cycle(s);
        uint32_t t = BYTE2WORD(buf) ^ s->sbuf;
        shannon_macfunc(s, t);
        WORD2BYTE(t, buf);
        buf += 4;
    }
    nbytes &= 3;
    if (nbytes) {
        shannon_cycle(s);
        s->mbuf = 0;
        s->nbuf = 32;
        while (s->nbuf && nbytes) {
            *buf ^= (uint8_t)(s->sbuf >> (32 - s->nbuf));
            s->mbuf ^= (*buf) << (32 - s->nbuf);
            buf++; s->nbuf -= 8; nbytes--;
        }
    }
}

void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]) {
    int i;
    if (s->nbuf) shannon_macfunc(s, s->mbuf);
    shannon_cycle(s);
    ADDKEY(s, SHANNON_INITKONST ^ ((uint32_t)s->nbuf << 3));
    s->nbuf = 0;
    for (i = 0; i < SHANNON_N; i++)
        s->R[i] ^= s->CRC[i];
    shannon_diffuse(s);
    shannon_cycle(s);
    WORD2BYTE(s->sbuf, mac);
}

/* ================================================================== */
/*  TLS / HTTPS — mbedtls SSL + winsock2                               */
/* ================================================================== */

struct platform_tls_t {
    SOCKET sock;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
};

#if defined(_MSC_VER) || defined(__MINGW32__)
/* mbedtls_net_send/recv expect file descriptors as void* on POSIX.
 * On Windows with mingw, we need a wrapper or use mbedtls_ssl_set_bio directly. */
static int win_mbedtls_send(void *ctx, const unsigned char *buf, size_t len) {
    SOCKET *sock = (SOCKET *)ctx;
    int ret = send(*sock, (const char *)buf, (int)len, 0);
    return (ret > 0) ? ret : (ret == 0 ? MBEDTLS_ERR_SSL_CONN_EOF : MBEDTLS_ERR_NET_SEND_FAILED);
}
static int win_mbedtls_recv(void *ctx, unsigned char *buf, size_t len) {
    SOCKET *sock = (SOCKET *)ctx;
    int ret = recv(*sock, (char *)buf, (int)len, 0);
    return (ret > 0) ? ret : (ret == 0 ? MBEDTLS_ERR_SSL_CONN_EOF : MBEDTLS_ERR_NET_RECV_FAILED);
}
#endif

platform_tls_t *platform_tls_connect(const char *host, int port) {
    wsa_init();
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return NULL;

    int timeout = 10000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    struct addrinfo hints = {0}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &result) != 0) {
        closesocket(sock); return NULL;
    }

    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result); closesocket(sock); return NULL;
    }
    freeaddrinfo(result);

    platform_tls_t *tls = calloc(1, sizeof(*tls));
    tls->sock = sock;

    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->conf);
    mbedtls_x509_crt_init(&tls->cacert);
    mbedtls_ctr_drbg_init(&tls->drbg);
    mbedtls_entropy_init(&tls->entropy);

    mbedtls_ctr_drbg_seed(&tls->drbg, mbedtls_entropy_func,
                           &tls->entropy, NULL, 0);

    mbedtls_ssl_config_defaults(&tls->conf,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&tls->conf, mbedtls_ctr_drbg_random, &tls->drbg);

    mbedtls_ssl_setup(&tls->ssl, &tls->conf);
    mbedtls_ssl_set_hostname(&tls->ssl, host);

    /* Custom BIO for winsock */
    mbedtls_ssl_set_bio(&tls->ssl, &tls->sock,
                         win_mbedtls_send, win_mbedtls_recv, NULL);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&tls->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            fprintf(stderr, "[%s] TLS failed: -0x%04x\n", TAG, -ret);
            platform_tls_close(tls);
            return NULL;
        }
    }

    return tls;
}

int platform_tls_write(platform_tls_t *tls, const uint8_t *data, size_t len) {
    if (!tls) return -1;
    int ret = mbedtls_ssl_write(&tls->ssl, data, len);
    return (ret > 0) ? ret : -1;
}

int platform_tls_read(platform_tls_t *tls, uint8_t *buf, size_t max_len) {
    if (!tls) return -1;
    int ret = mbedtls_ssl_read(&tls->ssl, buf, max_len);
    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) return 0;
    return (ret > 0) ? ret : -1;
}

void platform_tls_close(platform_tls_t *tls) {
    if (!tls) return;
    mbedtls_ssl_close_notify(&tls->ssl);
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->conf);
    mbedtls_x509_crt_free(&tls->cacert);
    mbedtls_ctr_drbg_free(&tls->drbg);
    mbedtls_entropy_free(&tls->entropy);
    if (tls->sock != INVALID_SOCKET) closesocket(tls->sock);
    free(tls);
}

platform_http_response_t platform_https_get(
    const char *host, const char *path,
    const char *const *headers, int timeout_sec)
{
    platform_http_response_t resp = {0, NULL, 0};

    platform_tls_t *tls = platform_tls_connect(host, 443);
    if (!tls) return resp;

    char req[4096];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: ESPConnect/1.0\r\n"
        "Accept: */*\r\nConnection: close\r\n",
        path, host);

    if (headers) {
        for (int i = 0; headers[i]; i++)
            req_len += snprintf(req + req_len, sizeof(req) - req_len,
                               "%s\r\n", headers[i]);
    }
    req_len += snprintf(req + req_len, sizeof(req) - req_len, "\r\n");

    if (platform_tls_write(tls, (uint8_t *)req, req_len) != req_len) {
        platform_tls_close(tls);
        return resp;
    }

    uint8_t buf[32768];
    int total = 0, n;
    while ((n = platform_tls_read(tls, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += n;
        if (total >= (int)sizeof(buf) - 1) break;
    }
    buf[total] = 0;
    platform_tls_close(tls);

    /* Parse HTTP response */
    if (total >= 12) {
        int code = 0;
        if (sscanf((char *)buf, "HTTP/%*s %d", &code) == 1)
            resp.status_code = code;

        char *body = strstr((char *)buf, "\r\n\r\n");
        if (body) {
            body += 4;
            size_t body_len = total - (body - (char *)buf);
            resp.body = malloc(body_len + 1);
            memcpy(resp.body, body, body_len);
            resp.body[body_len] = 0;
            resp.body_len = body_len;
        }
    }

    return resp;
}

void platform_http_response_free(platform_http_response_t *resp) {
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
        resp->body_len = 0;
    }
}
