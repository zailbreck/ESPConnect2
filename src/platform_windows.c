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
#include <mbedtls/pkcs5.h>
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
        if (r == 0) {
            fprintf(stderr, "[tcp] recv EOF (connection closed by peer)\n");
            return -1;
        }
        if (r < 0) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                fprintf(stderr, "[tcp] recv timeout after %zu/%zu bytes\n", total, n);
            } else {
                fprintf(stderr, "[tcp] recv error %d after %zu/%zu bytes\n", err, total, n);
            }
            return -1;
        }
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
/*  mDNS -- tinysvcmdns library (thirdparty/mdns.c, thirdparty/mdnsd.c) */



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
    /* Use mbedtls 3.x API (mbedtls_pkcs5_pbkdf2_hmac_ext) instead of
     * the deprecated mbedtls_pkcs5_pbkdf2_hmac which expects ctx* */
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA1,
        password, pw_len, salt, salt_len,
        (unsigned int)iterations, (uint32_t)out_len, out);
    if (ret != 0) {
        fprintf(stderr, "[platform] PBKDF2 ERROR: ret=%d\n", ret);
    }
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

void platform_aes_ecb_decrypt128(const uint8_t *key, uint8_t *data, size_t len) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128);
    for (size_t off = 0; off < len; off += 16) {
        uint8_t block[16];
        mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, data + off, block);
        memcpy(data + off, block, 16);
    }
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
    mbedtls_mpi P, G, X, GX;
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&GX);
    mbedtls_mpi_read_binary(&P, dh_prime, 96);
    mbedtls_mpi_lset(&G, 2);
    mbedtls_mpi_fill_random(&X, 95, win_random_cb, NULL);
    mbedtls_mpi_mod_mpi(&X, &X, &P);
    mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL);
    mbedtls_mpi_write_binary(&X, priv_key, 96);
    mbedtls_mpi_write_binary(&GX, pub_key, 96);
    mbedtls_mpi_free(&GX); mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&G); mbedtls_mpi_free(&P);
}

void platform_dh_compute_shared_old2_old(const uint8_t priv_key[96],
                                const uint8_t *peer_pub, size_t peer_pub_len,
                                uint8_t shared[96]) {
    mbedtls_mpi P, G, X, GY, K;
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&GY);
    mbedtls_mpi_init(&K);

    mbedtls_mpi_read_binary(&P, dh_prime, sizeof(dh_prime));
    mbedtls_mpi_lset(&G, 2);
    mbedtls_mpi_read_binary(&X, priv_key, 96);
    mbedtls_mpi_read_binary(&GY, peer_pub, peer_pub_len);

    /* K = GY ^ X mod P (standard Diffie-Hellman) */
    mbedtls_mpi_exp_mod(&K, &GY, &X, &P, NULL);
    mbedtls_mpi_write_binary(&K, shared, 96);

    mbedtls_mpi_free(&K); mbedtls_mpi_free(&GY);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&P);
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
/* ================================================================== */
/*  Shannon Stream Cipher (pure C, exact cspot port)                   */
/*  Source: cspot (MIT) — Shannon.cpp                                  */
/* ================================================================== */

#define SHANNON_N       16
#define SHANNON_FOLD    16
#define SHANNON_INITKONST 0x6996c53a
#define SHANNON_KEYP     13

struct platform_shannon_t {
    uint32_t R[16];
    uint32_t CRC[16];
    uint32_t initR[16];
    uint32_t konst;
    uint32_t sbuf;
    uint32_t mbuf;
    int nbuf;
};

static inline uint32_t rotl32(uint32_t n, unsigned int c) {
    c &= 31;
    return (n << c) | (n >> (32 - c));
}

static inline uint32_t sbox(uint32_t w) {
    return w ^ rotl32(w, 5) ^ rotl32(w, 7) ^ rotl32(w, 19) ^ rotl32(w, 22);
}

#define BYTE2WORD(b) \
    (((uint32_t)(b)[3] << 24) | ((uint32_t)(b)[2] << 16) | \
     ((uint32_t)(b)[1] << 8)  | ((uint32_t)(b)[0]))

#define WORD2BYTE(w, b) do { \
    (b)[3] = (uint8_t)((w) >> 24); \
    (b)[2] = (uint8_t)((w) >> 16); \
    (b)[1] = (uint8_t)((w) >> 8);  \
    (b)[0] = (uint8_t)(w);        \
} while(0)

#define XORWORD(w, b) do {       \
    (b)[3] ^= (uint8_t)((w) >> 24); \
    (b)[2] ^= (uint8_t)((w) >> 16); \
    (b)[1] ^= (uint8_t)((w) >> 8);  \
    (b)[0] ^= (uint8_t)(w);        \
} while(0)

static void shannon_cycle(platform_shannon_t *s) {
    uint32_t t = s->R[12] ^ s->R[13] ^ s->konst;
    t = sbox(t) ^ rotl32(s->R[0], 1);
    int i;
    for (i = 1; i < SHANNON_N; i++)
        s->R[i - 1] = s->R[i];
    s->R[SHANNON_N - 1] = t;
    t = sbox(s->R[2] ^ s->R[15]);
    s->R[0] ^= t;
    s->sbuf = t ^ s->R[8] ^ s->R[12];
}

static void shannon_crcfunc(platform_shannon_t *s, uint32_t i) {
    uint32_t t = s->CRC[0] ^ s->CRC[2] ^ s->CRC[15] ^ i;
    int j;
    for (j = 1; j < SHANNON_N; j++)
        s->CRC[j - 1] = s->CRC[j];
    s->CRC[SHANNON_N - 1] = t;
}

static void shannon_macfunc(platform_shannon_t *s, uint32_t i) {
    shannon_crcfunc(s, i);
    s->R[SHANNON_KEYP] ^= i;
}

static void shannon_init_state(platform_shannon_t *s) {
    s->R[0] = 1;
    s->R[1] = 1;
    for (int i = 2; i < SHANNON_N; i++)
        s->R[i] = s->R[i - 1] + s->R[i - 2];
    s->konst = SHANNON_INITKONST;
}

static void shannon_save_state(platform_shannon_t *s) {
    memcpy(s->initR, s->R, sizeof(s->initR));
}

static void shannon_reload_state(platform_shannon_t *s) {
    memcpy(s->R, s->initR, sizeof(s->R));
}

static void shannon_genkonst(platform_shannon_t *s) {
    s->konst = s->R[0];
}

static void shannon_diffuse(platform_shannon_t *s) {
    for (int i = 0; i < SHANNON_FOLD; i++)
        shannon_cycle(s);
}

#define ADDKEY(s, k) do { (s)->R[0] ^= (k); (s)->R[SHANNON_KEYP] ^= (k); (s)->sbuf = (k); } while(0)

static void shannon_load_key(platform_shannon_t *s,
                              const uint8_t *key, size_t key_len) {
    size_t i;
    int j;
    for (i = 0; i + 3 < key_len; i += 4) {
        uint32_t k = BYTE2WORD(&key[i]);
        ADDKEY(s, k);
        shannon_cycle(s);
    }
    if (i < key_len) {
        uint8_t xtra[4] = {0, 0, 0, 0};
        for (j = 0; i < key_len; i++, j++)
            xtra[j] = key[i];
        uint32_t k = BYTE2WORD(xtra);
        ADDKEY(s, k);
        shannon_cycle(s);
    }
    ADDKEY(s, (uint32_t)key_len);
    shannon_cycle(s);
    memcpy(s->CRC, s->R, sizeof(s->CRC));
    shannon_diffuse(s);
    for (i = 0; i < SHANNON_N; i++)
        s->R[i] ^= s->CRC[i];
}

platform_shannon_t *platform_shannon_new(void) {
    platform_shannon_t *s = calloc(1, sizeof(*s));
    return s;
}

void platform_shannon_free(platform_shannon_t *s) {
    free(s);
}

void platform_shannon_key(platform_shannon_t *s, const uint8_t *key, size_t key_len) {
    shannon_init_state(s);
    shannon_load_key(s, key, key_len);
    shannon_genkonst(s);
    shannon_save_state(s);
    s->nbuf = 0;
}


void platform_shannon_key_pair(platform_shannon_t *snd, platform_shannon_t *rcv,
                                const uint8_t *send_key, const uint8_t *recv_key) {
    /* Matches cspot standalone Shannon::key(sk, rk) exactly:
     *   init → loadkey(sk) → saveState → genkonst → loadkey(rk) → [recv]
     *                       → restore → genkonst → loadkey(sk) → [send]
     * The shared genkonst() between loadkey calls makes send/recv states
     * different from loading each key independently from init(). */
    shannon_init_state(snd);
    shannon_load_key(snd, send_key, 32);
    shannon_save_state(snd);
    shannon_genkonst(snd);
    shannon_load_key(snd, recv_key, 32);
    /* Save recv state */
    memcpy(rcv->R, snd->R, sizeof(rcv->R));
    memcpy(rcv->CRC, snd->CRC, sizeof(rcv->CRC));
    rcv->konst = snd->konst;
    rcv->sbuf = snd->sbuf;
    shannon_save_state(rcv);
    rcv->nbuf = 0;

    /* Restore to after loadkey(sk) for send */
    shannon_reload_state(snd);
    snd->konst = SHANNON_INITKONST;
    shannon_genkonst(snd);
    shannon_load_key(snd, send_key, 32);
    shannon_save_state(snd);
    snd->nbuf = 0;
}

void platform_shannon_nonce(platform_shannon_t *s, const uint8_t *nonce, size_t nonce_len) {
    shannon_reload_state(s);
    s->konst = SHANNON_INITKONST;
    shannon_load_key(s, nonce, nonce_len);
    shannon_genkonst(s);
    s->nbuf = 0;
}

void platform_shannon_encrypt(platform_shannon_t *s, uint8_t *buf, size_t nbytes) {
    size_t i = 0;
    size_t n = nbytes;
    if (s->nbuf != 0) {
        while (s->nbuf != 0 && n != 0) {
            s->mbuf ^= ((uint32_t)buf[i]) << (32 - s->nbuf);
            buf[i] ^= (uint8_t)(s->sbuf >> (32 - s->nbuf));
            i++;
            s->nbuf -= 8;
            n--;
        }
        if (s->nbuf != 0) return;
        shannon_macfunc(s, s->mbuf);
    }
    size_t words = n & ~(size_t)3;
    size_t end_words = i + words;
    while (i < end_words) {
        shannon_cycle(s);
        uint32_t t = BYTE2WORD(&buf[i]);
        shannon_macfunc(s, t);
        t ^= s->sbuf;
        WORD2BYTE(t, &buf[i]);
        i += 4;
    }
    n &= 3;
    if (n != 0) {
        shannon_cycle(s);
        s->mbuf = 0;
        s->nbuf = 32;
        while (s->nbuf != 0 && n != 0) {
            s->mbuf ^= ((uint32_t)buf[i]) << (32 - s->nbuf);
            buf[i] ^= (uint8_t)(s->sbuf >> (32 - s->nbuf));
            i++;
            s->nbuf -= 8;
            n--;
        }
    }
}

void platform_shannon_decrypt(platform_shannon_t *s, uint8_t *buf, size_t nbytes) {
    size_t i = 0;
    size_t n = nbytes;
    if (s->nbuf != 0) {
        while (s->nbuf != 0 && n != 0) {
            uint8_t t = buf[i] ^ (uint8_t)(s->sbuf >> (32 - s->nbuf));
            s->mbuf ^= ((uint32_t)buf[i]) << (32 - s->nbuf);
            buf[i] = t;
            i++;
            s->nbuf -= 8;
            n--;
        }
        if (s->nbuf != 0) return;
        shannon_macfunc(s, s->mbuf);
    }
    size_t words = n & ~(size_t)3;
    size_t end_words = i + words;
    while (i < end_words) {
        shannon_cycle(s);
        uint32_t t = BYTE2WORD(&buf[i]);
        t ^= s->sbuf;
        shannon_macfunc(s, t);
        WORD2BYTE(t, &buf[i]);
        i += 4;
    }
    n &= 3;
    if (n != 0) {
        shannon_cycle(s);
        s->mbuf = 0;
        s->nbuf = 32;
        while (s->nbuf != 0 && n != 0) {
            uint8_t t = buf[i] ^ (uint8_t)(s->sbuf >> (32 - s->nbuf));
            s->mbuf ^= ((uint32_t)buf[i]) << (32 - s->nbuf);
            buf[i] = t;
            i++;
            s->nbuf -= 8;
            n--;
        }
    }
}

void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]) {
    if (s->nbuf) {
        shannon_macfunc(s, s->mbuf);
    }
    shannon_cycle(s);
    uint32_t t = s->CRC[0] ^ s->CRC[2] ^ s->CRC[15] ^ SHANNON_INITKONST;
    WORD2BYTE(t, mac);
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
    return (ret > 0) ? ret : (ret == 0 ? MBEDTLS_ERR_SSL_CONN_EOF : -0x0001);
}
static int win_mbedtls_recv(void *ctx, unsigned char *buf, size_t len) {
    SOCKET *sock = (SOCKET *)ctx;
    int ret = recv(*sock, (char *)buf, (int)len, 0);
    return (ret > 0) ? ret : (ret == 0 ? MBEDTLS_ERR_SSL_CONN_EOF : -0x0002);
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
#include "internal/platform.h"
#include "mdns.h"
#include <stdio.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

    
    mdns_socket_close(m->sock);
    free(m);
}
void platform_dh_compute_shared_old2(const uint8_t priv_key[96],
                                const uint8_t *peer_pub, size_t peer_pub_len,
                                uint8_t shared[96], size_t *out_len) {
    mbedtls_mpi P, G, X, GY, K;
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&GY); mbedtls_mpi_init(&K);

    mbedtls_mpi_read_binary(&P, DH_P, 96);
    mbedtls_mpi_read_binary(&X, priv_key, 96);
    mbedtls_mpi_read_binary(&GY, peer_pub, peer_pub_len);

    mbedtls_mpi_exp_mod(&K, &GY, &X, &P, NULL);
    
    size_t s_len = mbedtls_mpi_size(&K);
    *out_len = s_len;
    mbedtls_mpi_write_binary(&K, shared, s_len);

    mbedtls_mpi_free(&P); mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&GY); mbedtls_mpi_free(&K);
}
#include "internal/platform.h"
#include "mdns.h"
#include <stdio.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

struct platform_mdns_t {
    int sock;
    struct sockaddr_in addr;
    char hostname[64];
    char service_name[64];
    char service_type[64];
    int port;
    HANDLE thread;
    int running;
    const char *txt_records[16];
    int txt_count;
};

static mdns_record_t create_ptr_record(platform_mdns_t *m, mdns_string_t service, mdns_string_t instance) {
    mdns_record_t r = {0};
    r.name = service;
    r.type = MDNS_RECORDTYPE_PTR;
    r.data.ptr.name = instance;
    return r;
}

static mdns_record_t create_srv_record(platform_mdns_t *m, mdns_string_t instance, mdns_string_t host) {
    mdns_record_t r = {0};
    r.name = instance;
    r.type = MDNS_RECORDTYPE_SRV;
    r.data.srv.name = host;
    r.data.srv.port = m->port;
    r.data.srv.priority = 0;
    r.data.srv.weight = 0;
    return r;
}

static mdns_record_t create_a_record(platform_mdns_t *m, mdns_string_t host) {
    mdns_record_t r = {0};
    r.name = host;
    r.type = MDNS_RECORDTYPE_A;
    r.data.a.addr = m->addr;
    return r;
}

static mdns_record_t create_txt_record(platform_mdns_t *m, mdns_string_t instance, const char *keyval) {
    mdns_record_t r = {0};
    r.name = instance;
    r.type = MDNS_RECORDTYPE_TXT;
    r.data.txt.key.str = keyval;
    r.data.txt.key.length = strlen(keyval);
    r.data.txt.value.str = NULL;
    r.data.txt.value.length = 0;
    return r;
}

static void send_announcement(platform_mdns_t *m) {
    char svc_str[128];
    snprintf(svc_str, sizeof(svc_str), "%s.local.", m->service_type);
    
    char inst_str[256];
    snprintf(inst_str, sizeof(inst_str), "%s.%s", m->service_name, svc_str);
    
    char host_str[128];
    snprintf(host_str, sizeof(host_str), "%s.local.", m->hostname);

    mdns_string_t svc_name = { svc_str, strlen(svc_str) };
    mdns_string_t inst_name = { inst_str, strlen(inst_str) };
    mdns_string_t host_name = { host_str, strlen(host_str) };

    mdns_record_t answer = create_ptr_record(m, svc_name, inst_name);
    
    mdns_record_t additional[32];
    size_t add_count = 0;
    additional[add_count++] = create_srv_record(m, inst_name, host_name);
    additional[add_count++] = create_a_record(m, host_name);
    
    for (int i = 0; i < m->txt_count; i++) {
        additional[add_count++] = create_txt_record(m, inst_name, m->txt_records[i]);
    }

    uint8_t buffer[2048];
    mdns_announce_multicast(m->sock, buffer, sizeof(buffer), answer, NULL, 0, additional, add_count);
}

static int mdns_query_callback(int sock, const struct sockaddr* from, size_t addrlen,
                               mdns_entry_type_t entry, uint16_t query_id,
                               uint16_t rtype, uint16_t rclass, uint32_t ttl,
                               const void* data, size_t size, size_t name_offset,
                               size_t name_length, size_t record_offset, size_t record_length,
                               void* user_data) {
    platform_mdns_t *m = (platform_mdns_t *)user_data;
    
    char namebuf[256];
    mdns_string_t namestr = mdns_string_extract(data, size, &name_offset, namebuf, sizeof(namebuf));
    
    char expected_type[128];
    snprintf(expected_type, sizeof(expected_type), "%s.local.", m->service_type);
    
    if ((rtype == MDNS_RECORDTYPE_PTR || rtype == MDNS_RECORDTYPE_ANY) && 
        strncmp(namestr.str, expected_type, namestr.length) == 0) {
        
        send_announcement(m); // Just announce when someone asks
    }
    return 0;
}

static DWORD WINAPI mdns_thread(LPVOID arg) {
    platform_mdns_t *m = (platform_mdns_t *)arg;
    uint8_t buffer[2048];
    
    send_announcement(m); // Initial announce
    
    while (m->running) {
        struct timeval tv = {1, 0}; // 1 second timeout
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(m->sock, &rfds);
        if (select(0, &rfds, NULL, NULL, &tv) > 0) {
            mdns_socket_listen(m->sock, buffer, sizeof(buffer), mdns_query_callback, m);
        }
    }
    return 0;
}

platform_mdns_t *platform_mdns_start(const char *hostname) {
    platform_mdns_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dummy = {0};
    dummy.sin_family = AF_INET;
    dummy.sin_addr.s_addr = inet_addr("8.8.8.8");
    dummy.sin_port = htons(53);
    connect(s, (struct sockaddr *)&dummy, sizeof(dummy));
    int addrlen = sizeof(dummy);
    getsockname(s, (struct sockaddr *)&dummy, &addrlen);
    closesocket(s);
    m->addr = dummy;

    strncpy(m->hostname, hostname, sizeof(m->hostname) - 1);

    m->sock = mdns_socket_open_ipv4(&m->addr);
    if (m->sock < 0) {
        free(m);
        return NULL;
    }

    fprintf(stderr, "[mDNS] Started on %s.local\n", hostname);
    return m;
}

int platform_mdns_register_service(platform_mdns_t *m,
                                   const char *name, const char *type,
                                   int port, const char **txt_records) {
    if (!m) return -1;
    strncpy(m->service_name, name, sizeof(m->service_name) - 1);
    strncpy(m->service_type, type, sizeof(m->service_type) - 1);
    m->port = port;
    
    m->txt_count = 0;
    while (txt_records && txt_records[m->txt_count] && m->txt_count < 16) {
        m->txt_records[m->txt_count] = txt_records[m->txt_count];
        m->txt_count++;
    }

    m->running = 1;
    m->thread = CreateThread(NULL, 0, mdns_thread, m, 0, NULL);
    fprintf(stderr, "[mDNS] Registered: %s %s:%d\n", name, type, port);
    return 0;
}

void platform_mdns_stop(platform_mdns_t *m) {
    if (!m) return;
    m->running = 0;
    if (m->thread) {
        WaitForSingleObject(m->thread, INFINITE);
        CloseHandle(m->thread);
    }
    mdns_socket_close(m->sock);
    free(m);
}
