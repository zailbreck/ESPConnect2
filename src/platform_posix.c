// platform_posix.c — POSIX / OpenSSL Platform Implementation
// =======================================================
// Provides network (BSD sockets) and crypto (OpenSSL) primitives
// for x86 Linux development and testing.
//
// For ESP32 target, link platform_esp32.c instead (mbedtls + esp_http_client).
//
// Dependencies: OpenSSL (libssl, libcrypto), POSIX sockets
// License: MIT

#include "internal/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

/* ================================================================== */
/*  Networking                                                         */
/* ================================================================== */

platform_socket_t platform_tcp_connect(const char *host, int port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return PLATFORM_SOCKET_INVALID;

    platform_socket_t sock = PLATFORM_SOCKET_INVALID;
    for (rp = res; rp; rp = rp->ai_next) {
        if (rp->ai_family != AF_INET) continue;
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            int opt = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
            break;
        }
        close(sock);
        sock = PLATFORM_SOCKET_INVALID;
    }
    freeaddrinfo(res);
    return sock;
}

void platform_tcp_close(platform_socket_t sock) {
    if (sock >= 0) {
        shutdown(sock, SHUT_RDWR);
        close(sock);
    }
}

int platform_tcp_read(platform_socket_t sock, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(sock, (char *)buf + off, n - off, 0);
        if (r <= 0) return -1;
        off += r;
    }
    return 0;
}

int platform_tcp_write(platform_socket_t sock, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(sock, (const char *)buf + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        off += w;
    }
    return 0;
}

void platform_tcp_set_timeout(platform_socket_t sock, int seconds) {
    struct timeval tv = {seconds, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* ================================================================== */
/*  HTTP server (Bell)                                                 */
/* ================================================================== */

struct platform_http_server_t {
    int listen_fd;
    volatile int running;
    pthread_t thread;
};

platform_http_server_t *platform_http_server_start(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return NULL;
    }
    if (listen(fd, 5) < 0) {
        close(fd);
        return NULL;
    }

    platform_http_server_t *srv = calloc(1, sizeof(*srv));
    srv->listen_fd = fd;
    srv->running = 1;
    return srv;
}

void platform_http_server_stop(platform_http_server_t *srv) {
    if (!srv) return;
    srv->running = 0;
    if (srv->listen_fd >= 0) {
        close(srv->listen_fd);
        srv->listen_fd = -1;
    }
    free(srv);
}

platform_socket_t platform_http_server_accept(platform_http_server_t *srv, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = srv->listen_fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, timeout_ms) <= 0)
        return PLATFORM_SOCKET_INVALID;

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    return accept(srv->listen_fd, (struct sockaddr *)&addr, &len);
}

int platform_http_server_read(platform_socket_t client, uint8_t *buf, size_t max_len) {
    return (int)recv(client, (char *)buf, max_len - 1, 0);
}

int platform_http_server_write(platform_socket_t client, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(client, (const char *)buf + off, len - off, 0);
        if (w <= 0) return -1;
        off += w;
    }
    return (int)off;
}

/* ================================================================== */
/*  mDNS                                                               */
/* ================================================================== */

struct platform_mdns_t {
    int placeholder;
};

platform_mdns_t *platform_mdns_start(const char *hostname) {
    (void)hostname;
    /* POSIX: mDNS requires external mdnsd library (mjansson/mdns).
     * For x86 testing, this is a no-op. The zeroconf module will
     * still work — it just won't advertise via mDNS.
     * On ESP32, platform_esp32.c uses esp_mdns.
     */
    fprintf(stderr, "[platform] mDNS start (no-op on POSIX)\n");
    platform_mdns_t *m = calloc(1, sizeof(*m));
    return m;
}

int platform_mdns_register_service(platform_mdns_t *m,
                                   const char *name, const char *type,
                                   int port, const char **txt_records) {
    (void)m; (void)name; (void)type; (void)port; (void)txt_records;
    fprintf(stderr, "[platform] mDNS register svc: %s (%s:%d) — no-op\n", name, type, port);
    return 0;
}

void platform_mdns_stop(platform_mdns_t *m) {
    free(m);
}

/* ================================================================== */
/*  Crypto: SHA1, HMAC-SHA1, PBKDF2                                    */
/* ================================================================== */

void platform_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    SHA1(data, len, out);
}

void platform_hmac_sha1(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[20]) {
    unsigned int out_len = 20;
    HMAC(EVP_sha1(), key, (int)key_len, data, data_len, out, &out_len);
}

void platform_pbkdf2_sha1(const uint8_t *password, size_t pw_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iterations,
                          uint8_t *out, size_t out_len) {
    PKCS5_PBKDF2_HMAC_SHA1((const char *)password, (int)pw_len,
                           salt, (int)salt_len,
                           (int)iterations, (int)out_len, out);
}

/* ================================================================== */
/*  Crypto: AES                                                        */
/* ================================================================== */

void platform_aes_ctr128(const uint8_t *key, const uint8_t *iv,
                         uint8_t *data, size_t len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);
    int out_len = 0;
    EVP_EncryptUpdate(ctx, data, &out_len, data, (int)len);
    EVP_CIPHER_CTX_free(ctx);
}

void platform_aes_ecb_decrypt192(const uint8_t *key, uint8_t *data, size_t len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    for (size_t i = 0; i < len; i += 16) {
        int block_len = 0;
        EVP_DecryptUpdate(ctx, data + i, &block_len, data + i, 16);
    }
    EVP_CIPHER_CTX_free(ctx);
}

/* ================================================================== */
/*  Crypto: DH (Oakley Group 2, 768-bit)                               */
/* ================================================================== */

static const unsigned char dh_prime[] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,
    0x21,0x68,0xc2,0x34,0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,
    0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,0x02,0x0b,0xbe,0xa6,
    0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,
    0xf2,0x5f,0x14,0x37,0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,
    0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,0xf4,0x4c,0x42,0xe9,
    0xa6,0x3a,0x36,0x20,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

void platform_dh_generate_keypair(uint8_t pub_key[96], uint8_t priv_key[96]) {
    DH *dh = DH_new();
    BIGNUM *p = BN_bin2bn(dh_prime, sizeof(dh_prime), NULL);
    BIGNUM *g = BN_new();
    BN_set_word(g, 2);
    DH_set0_pqg(dh, p, NULL, g);
    DH_generate_key(dh);

    const BIGNUM *pk = DH_get0_pub_key(dh);
    const BIGNUM *sk = DH_get0_priv_key(dh);

    int pl = BN_bn2bin(pk, pub_key);
    if (pl < 96) {
        memmove(pub_key + 96 - pl, pub_key, pl);
        memset(pub_key, 0, 96 - pl);
    }
    int sl = BN_bn2bin(sk, priv_key);
    if (sl < 96) {
        memmove(priv_key + 96 - sl, priv_key, sl);
        memset(priv_key, 0, 96 - sl);
    }
    DH_free(dh);
}

void platform_dh_compute_shared(const uint8_t priv_key[96],
                                const uint8_t *peer_pub, size_t peer_pub_len,
                                uint8_t shared[96]) {
    DH *dh = DH_new();
    BIGNUM *p = BN_bin2bn(dh_prime, sizeof(dh_prime), NULL);
    BIGNUM *g = BN_new();
    BN_set_word(g, 2);
    DH_set0_pqg(dh, p, NULL, g);

    BIGNUM *sk = BN_bin2bn(priv_key, 96, NULL);
    DH_set0_key(dh, NULL, sk);

    BIGNUM *rb = BN_bin2bn(peer_pub, (int)peer_pub_len, NULL);
    int ol = DH_compute_key(shared, rb, dh);
    BN_free(rb);

    if (ol < 0) {
        memset(shared, 0, 96);
    } else if (ol < 96) {
        memmove(shared + 96 - ol, shared, ol);
        memset(shared, 0, 96 - ol);
    }
    DH_free(dh);
}

/* ================================================================== */
/*  Crypto: Random                                                     */
/* ================================================================== */

void platform_random(uint8_t *buf, size_t len) {
    RAND_bytes(buf, (int)len);
}

/* ================================================================== */
/*  Base64                                                             */
/* ================================================================== */

size_t platform_base64_decode(const char *in, size_t in_len,
                              uint8_t *out, size_t out_capacity) {
    /* Use OpenSSL's streaming base64 */
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(in, (int)in_len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int n = BIO_read(bio, out, (int)out_capacity);
    BIO_free_all(bio);
    return n > 0 ? (size_t)n : 0;
}

size_t platform_base64_encode(const uint8_t *in, size_t in_len,
                              char *out, size_t out_capacity) {
    if (out_capacity == 0) return 0;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, in, (int)in_len);
    (void)BIO_flush(bio);
    /* Use BIO_get_mem_data (available since OpenSSL 1.1) */
    const char *mem_data = NULL;
    long n = BIO_get_mem_data(bio, &mem_data);
    if (n > 0 && mem_data) {
        if ((size_t)n >= out_capacity) n = (long)(out_capacity - 1);
        memcpy(out, mem_data, (size_t)n);
        out[n] = '\0';
    } else {
        out[0] = '\0';
        n = 0;
    }
    BIO_free_all(bio);
    return (size_t)n;
}

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

void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]) {
    int i;
    if (s->nbuf)
        shannon_macfunc(s, s->mbuf);
    shannon_cycle(s);
    ADDKEY(s, SHANNON_INITKONST ^ ((uint32_t)s->nbuf << 3));
    s->nbuf = 0;
    for (i = 0; i < SHANNON_N; i++)
        s->R[i] ^= s->CRC[i];
    shannon_diffuse(s);
    /* produce MAC: 4 bytes from stream buffer */
    shannon_cycle(s);
    WORD2BYTE(s->sbuf, mac);
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
