// platform_esp32.c — ESP32 Platform Implementation (mbedtls + lwip)
// ===============================================================
// Full implementation for ESP-IDF target. Uses:
//   - lwip sockets (POSIX-compatible)
//   - mbedtls 3.x (crypto)
//   - esp_http_client (HTTP/HTTPS)
//   - ESP-IDF mdns component (mDNS)
//
// License: MIT

#include "internal/platform.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ESP-IDF headers */
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

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

#include <esp_random.h>
#include <esp_http_client.h>
#include <esp_log.h>
#include <mdns.h>

#define TAG "platform_esp32"

/* ================================================================== */
/*  Networking (lwip sockets)                                          */
/* ================================================================== */

platform_socket_t platform_tcp_connect(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return PLATFORM_SOCKET_INVALID;

    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct hostent *h = gethostbyname(host);
    if (!h) { close(sock); return PLATFORM_SOCKET_INVALID; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr, h->h_addr, h->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock); return PLATFORM_SOCKET_INVALID;
    }

    return (platform_socket_t)sock;
}

void platform_tcp_close(platform_socket_t sock) {
    if (sock != PLATFORM_SOCKET_INVALID) close((int)sock);
}

int platform_tcp_read(platform_socket_t sock, uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = recv((int)sock, buf + total, n - total, 0);
        if (r <= 0) return -1;
        total += (size_t)r;
    }
    return 0;
}

int platform_tcp_write(platform_socket_t sock, const uint8_t *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = send((int)sock, buf + total, n - total, 0);
        if (w <= 0) return -1;
        total += (size_t)w;
    }
    return 0;
}

void platform_tcp_set_timeout(platform_socket_t sock, int seconds) {
    struct timeval tv = {seconds, 0};
    setsockopt((int)sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt((int)sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void platform_sleep_ms(int ms) {
    vTaskDelay(pdMS_TO_TICKS(ms));
}

/* ================================================================== */
/*  HTTP Server (ZeroConf Bell pairing)                                */
/* ================================================================== */

struct platform_http_server_t {
    int listen_sock;
    int port;
};

platform_http_server_t *platform_http_server_start(int port) {
    int lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (lsock < 0) return NULL;

    int opt = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(lsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(lsock); return NULL;
    }
    if (listen(lsock, 1) < 0) {
        close(lsock); return NULL;
    }

    platform_http_server_t *srv = malloc(sizeof(*srv));
    srv->listen_sock = lsock;
    srv->port = port;
    return srv;
}

void platform_http_server_stop(platform_http_server_t *srv) {
    if (!srv) return;
    close(srv->listen_sock);
    free(srv);
}

platform_socket_t platform_http_server_accept(platform_http_server_t *srv, int timeout_ms) {
    if (!srv) return PLATFORM_SOCKET_INVALID;

    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(srv->listen_sock, &rfds);

    int ret = select(srv->listen_sock + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return PLATFORM_SOCKET_INVALID;

    int client = accept(srv->listen_sock, NULL, NULL);
    return (client >= 0) ? (platform_socket_t)client : PLATFORM_SOCKET_INVALID;
}

int platform_http_server_read(platform_socket_t cl, uint8_t *b, size_t m) {
    ssize_t r = recv((int)cl, b, m, 0);
    return (r > 0) ? (int)r : (r == 0 ? 0 : -1);
}

int platform_http_server_write(platform_socket_t cl, const uint8_t *b, size_t l) {
    ssize_t w = send((int)cl, b, l, 0);
    return (w > 0) ? (int)w : -1;
}

/* ================================================================== */
/*  mDNS (ESP-IDF mdns component)                                      */
/* ================================================================== */

struct platform_mdns_t {
    int initialized;
};

platform_mdns_t *platform_mdns_start(const char *hostname) {
    esp_err_t err = mdns_init();
    if (err != ESP_OK) return NULL;

    mdns_hostname_set(hostname);
    mdns_instance_name_set(hostname);

    platform_mdns_t *m = calloc(1, sizeof(*m));
    m->initialized = 1;
    return m;
}

int platform_mdns_register_service(platform_mdns_t *m,
                                   const char *name, const char *type,
                                   int port, const char **txt_records) {
    if (!m) return -1;

    /* Build mdns_txt_item_t array from NULL-terminated string array */
    mdns_txt_item_t items[16];
    int txt_count = 0;
    if (txt_records) {
        for (int i = 0; txt_records[i] && txt_count < 16; i++) {
            char *kv = strdup(txt_records[i]);
            char *eq = strchr(kv, '=');
            if (eq) {
                *eq = '\0';
                items[txt_count].key = kv;
                items[txt_count].value = eq + 1;
                txt_count++;
            } else {
                free(kv);
            }
        }
    }

    /* Remove trailing dot from type (mdns_service_add expects "_spotify-connect._tcp") */
    char type_buf[64];
    strncpy(type_buf, type, sizeof(type_buf) - 1);
    size_t tlen = strlen(type_buf);
    if (tlen > 0 && type_buf[tlen - 1] == '.') type_buf[tlen - 1] = '\0';

    esp_err_t err = mdns_service_add(name, type_buf, (uint16_t)port,
                                      items, txt_count);

    /* Free allocated keys */
    for (int i = 0; i < txt_count; i++) {
        free((void *)items[i].key);
    }

    return (err == ESP_OK) ? 0 : -1;
}

void platform_mdns_stop(platform_mdns_t *m) {
    if (m) {
        mdns_free();
        free(m);
    }
}

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
    /* mbedtls 3.x API */
    mbedtls_md_type_t md = MBEDTLS_MD_SHA1;
    mbedtls_pkcs5_pbkdf2_hmac_ext(md,
        password, pw_len,
        salt, salt_len,
        (unsigned int)iterations,
        (uint32_t)out_len, out);
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

/* RFC 2409 Oakley Group 2 — 768-bit MODP prime */
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

void platform_dh_generate_keypair(uint8_t pub_key[96], uint8_t priv_key[96]) {
    mbedtls_dhm_context dhm;
    mbedtls_dhm_init(&dhm);

    /* Set prime P and generator G=2 */
    mbedtls_mpi P, G;
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_read_binary(&P, dh_prime, sizeof(dh_prime));
    mbedtls_mpi_lset(&G, 2);

    mbedtls_dhm_set_group(&dhm, &P, &G);

    /* Generate keypair */
    mbedtls_dhm_make_public(&dhm, 96, priv_key, 96,
                             platform_random_cb, NULL);

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

    /* Read our private key */
    mbedtls_mpi_read_binary(&dhm.X, priv_key, 96);

    /* Read peer's public key */
    mbedtls_mpi GY;
    mbedtls_mpi_init(&GY);
    mbedtls_mpi_read_binary(&GY, peer_pub, peer_pub_len);

    /* Compute shared secret */
    size_t olen = 0;
    mbedtls_dhm_calc_secret(&dhm, shared, 96, &olen,
                             platform_random_cb, NULL);

    mbedtls_mpi_free(&GY);
    mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&P);
    mbedtls_dhm_free(&dhm);
}

/* ================================================================== */
/*  Crypto: Random                                                     */
/* ================================================================== */

void platform_random(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);
}

/* Random callback for mbedtls DHM (uses ESP hardware RNG) */
static int platform_random_cb(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
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

static inline uint32_t sbox1(uint32_t w) {
    w ^= rotl32(w, 5) | rotl32(w, 7);
    w ^= rotl32(w, 19) | rotl32(w, 22);
    return w;
}

static inline uint32_t sbox2(uint32_t w) {
    w ^= rotl32(w, 7) | rotl32(w, 22);
    w ^= rotl32(w, 5) | rotl32(w, 19);
    return w;
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
    t = sbox1(t) ^ rotl32(s->R[0], 1);
    int i;
    for (i = 1; i < SHANNON_N; i++)
        s->R[i - 1] = s->R[i];
    s->R[SHANNON_N - 1] = t;
    t = sbox2(s->R[2] ^ s->R[15]);
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

#define ADDKEY(s, k) (s)->R[SHANNON_KEYP] ^= (k)

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


void platform_shannon_nonce(platform_shannon_t *s, const uint8_t *nonce, size_t nonce_len) {
    shannon_reload_state(s);
    s->konst = SHANNON_INITKONST;
    shannon_load_key(s, nonce, nonce_len);
    shannon_genkonst(s);
    s->nbuf = 0;
}

void platform_shannon_encrypt(platform_shannon_t *s, uint8_t *buf, size_t nbytes) {
    uint8_t *endbuf;
    /* buffered bytes */
    while (s->nbuf && nbytes) {
        s->mbuf ^= (*buf) << (32 - s->nbuf);
        *buf ^= (uint8_t)(s->sbuf >> (32 - s->nbuf));
        buf++; s->nbuf -= 8; nbytes--;
    }
    if (!s->nbuf && !nbytes) return;

    /* whole words */
    endbuf = &buf[nbytes & ~(size_t)3];
    while (buf < endbuf) {
        shannon_cycle(s);
        uint32_t t = BYTE2WORD(buf);
        shannon_macfunc(s, t);
        t ^= s->sbuf;
        WORD2BYTE(t, buf);
        buf += 4;
    }

    /* trailing bytes */
    nbytes &= 3;
    if (nbytes) {
        shannon_cycle(s);
        s->mbuf = 0;
        s->nbuf = 32;
        while (s->nbuf && nbytes) {
            s->mbuf ^= (*buf) << (32 - s->nbuf);
            *buf ^= (uint8_t)(s->sbuf >> (32 - s->nbuf));
            buf++; s->nbuf -= 8; nbytes--;
        }
    }
}

void platform_shannon_decrypt(platform_shannon_t *s, uint8_t *buf, size_t nbytes) {
    uint8_t *endbuf;
    /* buffered bytes */
    while (s->nbuf && nbytes) {
        *buf ^= (uint8_t)(s->sbuf >> (32 - s->nbuf));
        s->mbuf ^= (*buf) << (32 - s->nbuf);
        buf++; s->nbuf -= 8; nbytes--;
    }
    if (!s->nbuf && !nbytes) return;

    /* whole words */
    endbuf = &buf[nbytes & ~(size_t)3];
    while (buf < endbuf) {
        shannon_cycle(s);
        uint32_t t = BYTE2WORD(buf) ^ s->sbuf;
        shannon_macfunc(s, t);
        WORD2BYTE(t, buf);
        buf += 4;
    }

    /* trailing bytes */
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

/* Matches cspot standalone Shannon::finish(uint8_t mac[4]) exactly */
void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]) {
    if (s->nbuf) {
        shannon_macfunc(s, s->mbuf);
    }
    shannon_cycle(s);
    uint32_t t = s->CRC[0] ^ s->CRC[2] ^ s->CRC[15] ^ SHANNON_INITKONST;
    WORD2BYTE(t, mac);
}

/* ================================================================== */
/*  TLS / HTTPS (OpenSSL)                                              */
/* ================================================================== */

#include <openssl/ssl.h>
#include <openssl/err.h>

struct platform_tls_t {
    SSL *ssl;
    SSL_CTX *ctx;
    int sock;
};

platform_tls_t *platform_tls_connect(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct hostent *h = gethostbyname(host);
    if (!h) { close(sock); return NULL; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, h->h_addr, h->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock); return NULL;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { close(sock); return NULL; }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); close(sock); return NULL; }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); close(sock); return NULL;
    }

    platform_tls_t *tls = malloc(sizeof(*tls));
    tls->ssl = ssl;
    tls->ctx = ctx;
    tls->sock = sock;
    return tls;
}

int platform_tls_write(platform_tls_t *tls, const uint8_t *data, size_t len) {
    if (!tls || !tls->ssl) return -1;
    return SSL_write(tls->ssl, data, (int)len);
}

int platform_tls_read(platform_tls_t *tls, uint8_t *buf, size_t max_len) {
    if (!tls || !tls->ssl) return -1;
    int n = SSL_read(tls->ssl, buf, (int)max_len);
    return n > 0 ? n : (n == 0 ? 0 : -1);
}

void platform_tls_close(platform_tls_t *tls) {
    if (!tls) return;
    if (tls->ssl) {
        SSL_shutdown(tls->ssl);
        SSL_free(tls->ssl);
    }
    if (tls->ctx) SSL_CTX_free(tls->ctx);
    if (tls->sock >= 0) close(tls->sock);
    free(tls);
}

platform_http_response_t platform_https_get(
    const char *host, const char *path,
    const char *const *headers,
    int timeout_sec)
{
    platform_http_response_t resp = {0, NULL, 0};

    platform_tls_t *tls = platform_tls_connect(host, 443);
    if (!tls) return resp;

    /* Build HTTP request */
    char req[4096];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: ESPConnect/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n",
        path, host);

    /* Add custom headers */
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            req_len += snprintf(req + req_len, sizeof(req) - req_len,
                               "%s\r\n", headers[i]);
        }
    }
    req_len += snprintf(req + req_len, sizeof(req) - req_len, "\r\n");

    if (platform_tls_write(tls, (uint8_t *)req, req_len) != req_len) {
        platform_tls_close(tls);
        return resp;
    }

    /* Read response */
    uint8_t buf[8192];
    int total = 0;
    int n;
    while ((n = platform_tls_read(tls, buf + total, sizeof(buf) - total - 1)) > 0) {
        total += n;
        if (total >= (int)sizeof(buf) - 1) break;
    }
    buf[total] = 0;
    platform_tls_close(tls);

    /* Parse HTTP response */
    if (total < 12) return resp;

    /* Parse status line: "HTTP/1.1 200 OK\r\n..." */
    int code = 0;
    if (sscanf((char *)buf, "HTTP/%*s %d", &code) != 1) return resp;
    resp.status_code = code;

    /* Find body (after \r\n\r\n) */
    char *body_start = strstr((char *)buf, "\r\n\r\n");
    if (!body_start) return resp;
    body_start += 4;

    size_t body_len = total - (body_start - (char *)buf);
    resp.body = malloc(body_len + 1);
    memcpy(resp.body, body_start, body_len);
    resp.body[body_len] = 0;
    resp.body_len = body_len;

    return resp;
}

void platform_http_response_free(platform_http_response_t *resp) {
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
        resp->body_len = 0;
    }
}

/* ================================================================== */
/*  TLS / HTTPS (mbedtls SSL + esp_http_client fallback)               */
/*  Uses raw mbedtls SSL for minimal overhead                          */
/* ================================================================== */

struct platform_tls_t {
    int sock;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
};

platform_tls_t *platform_tls_connect(const char *host, int port) {
    /* Connect TCP socket first */
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct hostent *h = gethostbyname(host);
    if (!h) { close(sock); return NULL; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    memcpy(&addr.sin_addr, h->h_addr, h->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock); return NULL;
    }

    /* Allocate TLS context */
    platform_tls_t *tls = calloc(1, sizeof(*tls));
    tls->sock = sock;

    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->conf);
    mbedtls_x509_crt_init(&tls->cacert);
    mbedtls_ctr_drbg_init(&tls->drbg);
    mbedtls_entropy_init(&tls->entropy);

    /* Seed DRBG */
    mbedtls_ctr_drbg_seed(&tls->drbg, mbedtls_entropy_func,
                           &tls->entropy, NULL, 0);

    /* Setup SSL */
    mbedtls_ssl_config_defaults(&tls->conf,
                                MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&tls->conf, mbedtls_ctr_drbg_random, &tls->drbg);

    mbedtls_ssl_setup(&tls->ssl, &tls->conf);
    mbedtls_ssl_set_hostname(&tls->ssl, host);
    mbedtls_ssl_set_bio(&tls->ssl, &tls->sock,
                         mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Handshake */
    int ret;
    while ((ret = mbedtls_ssl_handshake(&tls->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "TLS handshake failed: -0x%04x", -ret);
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
    if (tls->sock >= 0) close(tls->sock);
    free(tls);
}

/* HTTP response parser (shared between TLS and esp_http_client paths) */
static int parse_http_response(const uint8_t *buf, size_t len,
                               platform_http_response_t *resp) {
    if (len < 12) return -1;

    char *data = (char *)buf;
    int code = 0;
    if (sscanf(data, "HTTP/%*s %d", &code) != 1) return -1;
    resp->status_code = code;

    char *body = strstr(data, "\r\n\r\n");
    if (!body) return -1;
    body += 4;

    size_t body_len = len - (body - data);
    resp->body = malloc(body_len + 1);
    memcpy(resp->body, body, body_len);
    resp->body[body_len] = 0;
    resp->body_len = body_len;

    return 0;
}

platform_http_response_t platform_https_get(
    const char *host, const char *path,
    const char *const *headers, int timeout_sec)
{
    platform_http_response_t resp = {0, NULL, 0};

    /* Use esp_http_client for ESP32 (handles TLS internally) */
    char url[1024];
    snprintf(url, sizeof(url), "https://%s%s", host, path);

    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_GET,
        .timeout_ms = timeout_sec * 1000,
        .buffer_size = 8192,
        .buffer_size_tx = 2048,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        /* Fallback: use raw mbedtls TLS */
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

        uint8_t buf[8192];
        int total = 0, n;
        while ((n = platform_tls_read(tls, buf + total, sizeof(buf) - total - 1)) > 0) {
            total += n;
            if (total >= (int)sizeof(buf) - 1) break;
        }
        buf[total] = 0;
        platform_tls_close(tls);

        parse_http_response(buf, total, &resp);
        return resp;
    }

    /* Set headers */
    if (headers) {
        for (int i = 0; headers[i]; i++) {
            char key[128], val[1024];
            if (sscanf(headers[i], "%[^:]: %[^\n]", key, val) == 2)
                esp_http_client_set_header(client, key, val);
        }
    }

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        resp.status_code = esp_http_client_get_status_code(client);
        int content_len = esp_http_client_get_content_length(client);
        if (content_len > 0) {
            resp.body = malloc(content_len + 1);
            /* Body already read by esp_http_client, need to get from its buffer */
            resp.body_len = 0;
        }
    }

    esp_http_client_cleanup(client);
    return resp;
}

void platform_http_response_free(platform_http_response_t *resp) {
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
        resp->body_len = 0;
    }
}
