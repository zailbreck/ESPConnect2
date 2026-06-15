// mercury.c — Spotify Login5 Authentication + Mercury Protocol
// ==========================================================
// Full Login5 authentication flow with Shannon cipher (exact cspot
// implementation) and Mercury messaging.
//
// Code sources and references:
//   Shannon cipher:      cspot (MIT) — Shannon.cpp / Shannon.h
//                         https://github.com/feelfreelinux/cspot/tree/master/cspot/src
//   Shannon connection:  cspot (MIT) — ShannonConnection.cpp
//   HMAC challenge:      librespot (MIT) — authentication/auth_challenge.rs
//   DH group:            RFC 2409 — Oakley Group 2 (768-bit MODP)
//   Protobuf schema:     cspot (MIT) — keyexchange.proto
//   Login5 flow:         librespot (MIT) — authentication/login5.rs
//   Base64:              Custom implementation (RFC 4648)
//   Pack/extract:        cspot (MIT) — Utils.h
//
// License: MIT — derived from cspot & librespot

#include "internal/mercury.h"
#include "internal/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define TAG "mercury"

/* ================================================================== */
/*  Protobuf Helpers (manual wire-format encoding, no codegen)         */
/*  Ref: cspot keyexchange.proto, librespot authentication protos      */
/* ================================================================== */

#define PB_VARINT    0
#define PB_LENGTH_DELIM 2

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} pb_buf_t;

static void pb_buf_init(pb_buf_t *b, size_t initial_cap) {
    b->data = malloc(initial_cap);
    b->size = 0;
    b->capacity = initial_cap;
}

static void pb_buf_free(pb_buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->size = b->capacity = 0;
}

static void pb_buf_reserve(pb_buf_t *b, size_t extra) {
    if (b->size + extra > b->capacity) {
        b->capacity = (b->size + extra) * 2;
        b->data = realloc(b->data, b->capacity);
    }
}

/* Encode varint */
static uint8_t *pb_enc_varint(uint8_t *out, uint64_t v) {
    while (v > 127) {
        *out++ = (uint8_t)((v & 0x7F) | 0x80);
        v >>= 7;
    }
    *out++ = (uint8_t)(v & 0x7F);
    return out;
}

/* Append varint field */
static void pb_write_varint(pb_buf_t *b, uint64_t field, uint64_t value) {
    pb_buf_reserve(b, 20);
    uint8_t *p = b->data + b->size;
    p = pb_enc_varint(p, (field << 3) | PB_VARINT);
    p = pb_enc_varint(p, value);
    b->size = p - b->data;
}

/* Append length-delimited field */
static void pb_write_bytes(pb_buf_t *b, uint64_t field,
                           const uint8_t *data, size_t len) {
    pb_buf_reserve(b, 20 + len);
    uint8_t *p = b->data + b->size;
    p = pb_enc_varint(p, (field << 3) | PB_LENGTH_DELIM);
    p = pb_enc_varint(p, len);
    memcpy(p, data, len);
    p += len;
    b->size = p - b->data;
}

/* ====== Protobuf Reader ====== */

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
} pb_reader_t;

static void pb_reader_init(pb_reader_t *r, const uint8_t *data, size_t size) {
    r->data = data;
    r->size = size;
    r->pos = 0;
}

static bool pb_read_tag(pb_reader_t *r, uint32_t *field, uint32_t *wire) {
    if (r->pos >= r->size) return false;

    uint64_t tag = 0;
    int shift = 0;
    while (r->pos < r->size) {
        uint8_t b = r->data[r->pos++];
        tag |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    *field = (uint32_t)(tag >> 3);
    *wire = (uint32_t)(tag & 7);
    return true;
}

static uint64_t pb_read_varint(pb_reader_t *r) {
    uint64_t val = 0;
    int shift = 0;
    while (r->pos < r->size) {
        uint8_t b = r->data[r->pos++];
        val |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return val;
}

static void pb_skip_field(pb_reader_t *r, uint32_t wire) {
    if (wire == PB_VARINT) {
        while (r->pos < r->size && (r->data[r->pos - 1] & 0x80))
            r->pos++;
    } else if (wire == PB_LENGTH_DELIM) {
        uint64_t len = pb_read_varint(r);
        if (r->pos + len <= r->size) r->pos += len;
        else r->pos = r->size;
    }
}

/* Read a length-delimited field as a sub-reader */
static void pb_read_bytes_as_sub(pb_reader_t *r, pb_reader_t *sub) {
    uint64_t len = pb_read_varint(r);
    if (r->pos + len <= r->size) {
        pb_reader_init(sub, r->data + r->pos, (size_t)len);
        r->pos += len;
    } else {
        pb_reader_init(sub, NULL, 0);
        r->pos = r->size;
    }
}

/* Copy length-delimited field to a buffer */
static size_t pb_read_bytes_to(pb_reader_t *r, uint8_t *out, size_t max_len) {
    uint64_t len = pb_read_varint(r);
    if (len > max_len) len = max_len;
    if (r->pos + len <= r->size) {
        memcpy(out, r->data + r->pos, len);
        r->pos += len;
        return (size_t)len;
    }
    return 0;
}

/* ================================================================== */
/*  Shannon Connection (cspot protocol: encrypt+MAC, nonce packing)     */
/*  Wire format: [encrypted(cmd|htons(size)|data)][4-byte-MAC]         */
/*  Nonce: pack<uint32_t>(htonl(n)), starts at 0, increments after pkt */
/* ================================================================== */

#define SHANNON_MAC_SIZE 4

static void uint32_pack_be(uint32_t val, uint8_t out[4]) {
    out[0] = (uint8_t)(val >> 24);
    out[1] = (uint8_t)(val >> 16);
    out[2] = (uint8_t)(val >> 8);
    out[3] = (uint8_t)(val);
}

static uint16_t uint16_unpack_be(const uint8_t in[2]) {
    return ((uint16_t)in[0] << 8) | (uint16_t)in[1];
}

static void uint16_pack_be(uint16_t val, uint8_t out[2]) {
    out[0] = (uint8_t)(val >> 8);
    out[1] = (uint8_t)(val);
}

/* ================================================================== */
/*  Mercury Session Structure                                          */
/* ================================================================== */

struct mercury_session_t {
    /* AP connection */
    platform_socket_t sock;
    bool connected;

    /* DH keypair */
    uint8_t dh_public[96];
    uint8_t dh_private[96];

    /* Shannon ciphers */
    platform_shannon_t *send_cipher;
    platform_shannon_t *recv_cipher;
    uint32_t send_nonce;
    uint32_t recv_nonce;

    /* Credentials from APWelcome */
    char canonical_username[256];
    uint8_t stored_cred[1024];
    size_t stored_cred_len;
};

/* ================================================================== */
/*  Protobuf Message Builders                                          */
/* ================================================================== */

/* Build ClientHello message */
static void build_client_hello(pb_buf_t *out,
                                const uint8_t dh_public[96],
                                const uint8_t *nonce, size_t nonce_len) {
    /* Build identity */
    pb_buf_t id_buf;
    pb_buf_init(&id_buf, 64);
    pb_write_varint(&id_buf, 10, 0);   /* product = PRODUCT_CLIENT */
    pb_write_varint(&id_buf, 30, 2);   /* platform = PLATFORM_LINUX_X86 */
    pb_write_varint(&id_buf, 40, 0x10800000000ULL); /* version */

    /* Build DH params */
    pb_buf_t dh_buf;
    pb_buf_init(&dh_buf, 256);
    pb_write_bytes(&dh_buf, 10, dh_public, 96);
    pb_write_varint(&dh_buf, 20, 1);  /* generator = 2 */

    /* Build login_crypto (nested inside DH) */
    pb_buf_t un_buf;
    pb_buf_init(&un_buf, 32);
    pb_write_bytes(&un_buf, 10, dh_buf.data, dh_buf.size);
    pb_buf_free(&dh_buf);

    /* Build ClientHello */
    pb_buf_init(out, 512);
    pb_write_bytes(out, 10, id_buf.data, id_buf.size);  /* build_info */
    pb_write_varint(out, 30, 0);    /* product_info */
    pb_write_bytes(out, 50, un_buf.data, un_buf.size);  /* login_crypto */
    pb_write_bytes(out, 60, nonce, nonce_len);          /* client_nonce */
    pb_write_bytes(out, 70, (const uint8_t *)"\x1E", 1); /* padding */
    pb_write_varint(out, 80, 1);    /* feature_set */

    pb_buf_free(&id_buf);
    pb_buf_free(&un_buf);
}

/* Build ClientResponse (HMAC answer) */
static void build_client_response(pb_buf_t *out,
                                   const uint8_t hmac_val[20]) {
    pb_buf_t dh, resp;
    pb_buf_init(&dh, 32);
    pb_write_bytes(&dh, 10, hmac_val, 20);

    pb_buf_init(&resp, 64);
    pb_write_bytes(&resp, 10, dh.data, dh.size);
    pb_buf_free(&dh);

    pb_buf_init(out, 128);
    pb_write_bytes(out, 10, resp.data, resp.size);
    pb_write_bytes(out, 20, NULL, 0);   /* empty */
    pb_write_bytes(out, 30, NULL, 0);   /* empty */

    pb_buf_free(&resp);
}

/* Build LoginRequest */
static void build_login_request(pb_buf_t *out,
                                 const uint8_t *auth_data, size_t auth_data_len,
                                 int auth_type,
                                 const char *username,
                                 const char *device_id) {
    /* login_credentials */
    pb_buf_t lc;
    pb_buf_init(&lc, 256);
    pb_write_bytes(&lc, 10, (const uint8_t *)username, strlen(username));
    pb_write_varint(&lc, 16, (uint64_t)auth_type);
    pb_write_bytes(&lc, 18, auth_data, auth_data_len);

    /* system_info */
    pb_buf_t si;
    pb_buf_init(&si, 64);
    pb_write_varint(&si, 10, 2);  /* OS = LINUX */
    pb_write_varint(&si, 20, 0);  /* cpu_family = CPU_UNKNOWN */

    /* LoginRequest */
    pb_buf_init(out, 512);
    pb_write_bytes(out, 10, lc.data, lc.size);
    pb_write_bytes(out, 20, si.data, si.size);
    pb_write_bytes(out, 30, (const uint8_t *)device_id, strlen(device_id));

    pb_buf_free(&lc);
    pb_buf_free(&si);
}

/* ================================================================== */
/*  HMAC Challenge (5-round SHA1-HMAC)                                 */
/*  Source: librespot auth_challenge.rs, cspot AuthChallenges.cpp       */
/* ================================================================== */

static void compute_hmac_challenge(const uint8_t *shared_key, size_t shared_len,
                                    const uint8_t *client_hello, size_t ch_len,
                                    const uint8_t *ap_response, size_t ar_len,
                                    uint8_t challenge_out[100]) {
    /* Combine CH + AR */
    size_t combined_len = ch_len + ar_len;
    uint8_t *combined = malloc(combined_len);
    memcpy(combined, client_hello, ch_len);
    memcpy(combined + ch_len, ap_response, ar_len);

    /* 5 rounds of HMAC */
    uint8_t result[100];
    uint8_t *dst = result;

    for (int x = 1; x <= 5; x++) {
        /* Prepend round counter */
        size_t cv_len = combined_len + 1;
        uint8_t *cv = malloc(cv_len);
        cv[0] = (uint8_t)x;
        memcpy(cv + 1, combined, combined_len);

        uint8_t hmac_out[20];
        platform_hmac_sha1(shared_key, shared_len, cv, cv_len, hmac_out);
        free(cv);

        memcpy(dst, hmac_out, 20);
        dst += 20;
    }

    memcpy(challenge_out, result, 100);
    free(combined);
}

/* ================================================================== */
/*  API Implementation                                                 */
/* ================================================================== */

mercury_session_t *mercury_init(void) {
    mercury_session_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->sock = PLATFORM_SOCKET_INVALID;
    s->connected = false;
    s->send_cipher = platform_shannon_new();
    s->recv_cipher = platform_shannon_new();
    s->send_nonce = 0;
    s->recv_nonce = 0;

    return s;
}

int mercury_send(mercury_session_t *s, uint8_t cmd,
                 const uint8_t *data, size_t len) {
    if (!s || !s->connected) return -1;

    /* Protocol: encrypt(cmd | htons(len) | data) then send 4-byte MAC */
    size_t total = 1 + 2 + len;  /* cmd + size + data */
    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    buf[0] = cmd;
    uint16_pack_be((uint16_t)len, buf + 1);
    if (len > 0) memcpy(buf + 3, data, len);

    /* Encrypt */
    platform_shannon_encrypt(s->send_cipher, buf, total);

    /* Write encrypted data */
    if (platform_tcp_write(s->sock, buf, total) != 0) {
        free(buf);
        return -2;
    }

    /* Generate and send MAC */
    uint8_t mac[SHANNON_MAC_SIZE];
    platform_shannon_finish(s->send_cipher, mac);
    if (platform_tcp_write(s->sock, mac, SHANNON_MAC_SIZE) != 0) {
        free(buf);
        return -3;
    }

    /* Advance nonce */
    s->send_nonce++;
    uint8_t nonce[4];
    uint32_pack_be(s->send_nonce, nonce);
    platform_shannon_nonce(s->send_cipher, nonce, 4);

    free(buf);
    return 0;
}

int mercury_recv(mercury_session_t *s, uint8_t *cmd,
                 uint8_t *data, size_t *len, size_t max_len) {
    if (!s || !s->connected) return -1;

    /* Read header: cmd (1 byte) + size (2 bytes) = 3 bytes */
    uint8_t hdr[3];
    if (platform_tcp_read(s->sock, hdr, 3) != 0) return -1;

    /* Decrypt header */
    platform_shannon_decrypt(s->recv_cipher, hdr, 3);

    *cmd = hdr[0];
    uint16_t pkt_len = uint16_unpack_be(hdr + 1);

    /* Read payload if any */
    size_t to_read = pkt_len;
    if (to_read > max_len) to_read = max_len;
    if (to_read > 0) {
        if (platform_tcp_read(s->sock, data, to_read) != 0) return -1;
        platform_shannon_decrypt(s->recv_cipher, data, to_read);
    }
    *len = to_read;

    /* Read and verify MAC */
    uint8_t recv_mac[SHANNON_MAC_SIZE];
    uint8_t computed_mac[SHANNON_MAC_SIZE];
    if (platform_tcp_read(s->sock, recv_mac, SHANNON_MAC_SIZE) != 0) return -1;
    platform_shannon_finish(s->recv_cipher, computed_mac);

    if (memcmp(recv_mac, computed_mac, SHANNON_MAC_SIZE) != 0) {
        fprintf(stderr, "[%s] MAC MISMATCH on recv!\n", TAG);
    }

    /* Advance nonce */
    s->recv_nonce++;
    uint8_t nonce[4];
    uint32_pack_be(s->recv_nonce, nonce);
    platform_shannon_nonce(s->recv_cipher, nonce, 4);

    return 0;
}

int mercury_login5(mercury_session_t *s,
                   const char *username,
                   const char *auth_data_b64,
                   int auth_type,
                   const char *device_id,
                   const char *ap_host,
                   int ap_port) {
    if (!s || !username || !auth_data_b64 || !device_id || !ap_host) return -1;

    int ret;

    /* Default port */
    if (ap_port <= 0) ap_port = 443;

    /* ----- Step 0: Decode auth data ----- */
    uint8_t auth_data[2048];
    size_t ad_len = platform_base64_decode(auth_data_b64, strlen(auth_data_b64),
                                            auth_data, sizeof(auth_data));
    if (ad_len == 0) {
        fprintf(stderr, "[%s] Failed to decode authData base64\n", TAG);
        return -2;
    }
    fprintf(stderr, "[%s] AuthData: %zu bytes\n", TAG, ad_len);

    /* ----- Step 1: TCP connect to AP ----- */
    fprintf(stderr, "[%s] Connecting to %s:%d...\n", TAG, ap_host, ap_port);
    s->sock = platform_tcp_connect(ap_host, ap_port);
    if (s->sock == PLATFORM_SOCKET_INVALID) {
        fprintf(stderr, "[%s] Connection failed\n", TAG);
        return -3;
    }
    platform_tcp_set_timeout(s->sock, 10);
    fprintf(stderr, "[%s] Connected to AP\n", TAG);

    /* ----- Step 2: Generate DH keypair ----- */
    fprintf(stderr, "[%s] Generating DH keypair...\n", TAG);
    platform_dh_generate_keypair(s->dh_public, s->dh_private);

    /* ----- Step 3: Build and send ClientHello ----- */
    uint8_t client_nonce[16];
    platform_random(client_nonce, 16);

    pb_buf_t ch_buf;
    build_client_hello(&ch_buf, s->dh_public, client_nonce, 16);
    fprintf(stderr, "[%s] ClientHello: %zu bytes\n", TAG, ch_buf.size);

    /* Send: prefix 0x00 0x04 + ClientHello (length-prefixed protocol) */
    uint8_t prefix[2] = {0x00, 0x04};
    uint32_t pkt_len_be = htonl((uint32_t)(ch_buf.size + 2 + 2));
    uint8_t pkt_len_buf[4];
    memcpy(pkt_len_buf, &pkt_len_be, 4);

    /* Build full packet: length(4) + prefix(2) + payload */
    size_t full_len = 4 + 2 + ch_buf.size;
    uint8_t *full_pkt = malloc(full_len);
    memcpy(full_pkt, pkt_len_buf, 4);
    memcpy(full_pkt + 4, prefix, 2);
    memcpy(full_pkt + 6, ch_buf.data, ch_buf.size);

    ret = platform_tcp_write(s->sock, full_pkt, full_len);
    free(full_pkt);

    if (ret != 0) {
        fprintf(stderr, "[%s] Failed to send ClientHello\n", TAG);
        pb_buf_free(&ch_buf);
        return -4;
    }

    /* ----- Step 4: Read APResponse ----- */
    /* Read 4-byte length prefix */
    uint8_t ar_len_buf[4];
    if (platform_tcp_read(s->sock, ar_len_buf, 4) != 0) {
        fprintf(stderr, "[%s] Failed to read APResponse length\n", TAG);
        pb_buf_free(&ch_buf);
        return -5;
    }
    uint32_t ar_pkt_len = ntohl(*(uint32_t *)ar_len_buf);

    if (ar_pkt_len < 4 || ar_pkt_len > 65536) {
        fprintf(stderr, "[%s] Invalid APResponse length: %u\n", TAG, ar_pkt_len);
        pb_buf_free(&ch_buf);
        return -6;
    }

    uint8_t *ar_data = malloc(ar_pkt_len);
    if (!ar_data || platform_tcp_read(s->sock, ar_data, ar_pkt_len) != 0) {
        fprintf(stderr, "[%s] Failed to read APResponse\n", TAG);
        free(ar_data);
        pb_buf_free(&ch_buf);
        return -7;
    }
    fprintf(stderr, "[%s] APResponse: %u bytes\n", TAG, ar_pkt_len);

    /* ----- Step 5: Extract server DH public key ----- */
    /* APResponse protobuf structure:
     *   LoginResponse {
     *     login_ok {                // field 1 (0x0a)
     *       LoginOk {
     *         login_crypto_response {  // field 1 (0x0a)
     *           LoginCryptoResponseUnion {
     *             diffie_hellman {     // field 1 (0x0a)
     *               DiffieHellman {
     *                 server_public_key // field 1 (0x0a) = bytes
     *               }
     *             }
     *           }
     *         }
     *       }
     *     }
     *   }
     *   Skip prefix bytes matching what the standalone does (4-byte skip)
     */
    uint8_t server_dh[96] = {0};
    bool found_dh = false;

    pb_reader_t pr;
    pb_reader_init(&pr, ar_data + 4, ar_pkt_len - 4); /* skip 4-byte header */

    uint32_t f1, w1;
    while (pb_read_tag(&pr, &f1, &w1) && !found_dh) {
        if (f1 == 10 && w1 == PB_LENGTH_DELIM) {  /* login_ok */
            pb_reader_t r1;
            pb_read_bytes_as_sub(&pr, &r1);

            uint32_t f2, w2;
            while (pb_read_tag(&r1, &f2, &w2) && !found_dh) {
                if (f2 == 10 && w2 == PB_LENGTH_DELIM) {  /* login_crypto_response */
                    pb_reader_t r2;
                    pb_read_bytes_as_sub(&r1, &r2);

                    uint32_t f3, w3;
                    while (pb_read_tag(&r2, &f3, &w3) && !found_dh) {
                        if (f3 == 10 && w3 == PB_LENGTH_DELIM) {  /* diffie_hellman */
                            pb_reader_t r3;
                            pb_read_bytes_as_sub(&r2, &r3);

                            uint32_t f4, w4;
                            while (pb_read_tag(&r3, &f4, &w4)) {
                                if (f4 == 10 && w4 == PB_LENGTH_DELIM) {  /* server_public_key */
                                    size_t sdh_len = pb_read_bytes_to(&r3, server_dh, sizeof(server_dh));
                                    if (sdh_len > 0) {
                                        found_dh = true;
                                        fprintf(stderr, "[%s] Server DH key: %zu bytes\n", TAG, sdh_len);
                                    }
                                } else {
                                    pb_skip_field(&r3, w4);
                                }
                            }
                        } else {
                            pb_skip_field(&r2, w3);
                        }
                    }
                } else {
                    pb_skip_field(&r1, w2);
                }
            }
        } else {
            pb_skip_field(&pr, w1);
        }
    }

    if (!found_dh) {
        fprintf(stderr, "[%s] Failed to extract server DH key\n", TAG);
        free(ar_data);
        pb_buf_free(&ch_buf);
        return -8;
    }

    /* ----- Step 6: Compute shared key ----- */
    uint8_t shared_key[96];
    platform_dh_compute_shared(s->dh_private, server_dh, 96, shared_key);

    /* ----- Step 7: HMAC challenge ----- */
    uint8_t challenge[100];
    compute_hmac_challenge(shared_key, 96,
                           ch_buf.data, ch_buf.size,
                           ar_data, ar_pkt_len,
                           challenge);

    /* Final HMAC: key=challenge[0:20], data=CH+AR */
    size_t cb_len = ch_buf.size + ar_pkt_len;
    uint8_t *combined = malloc(cb_len);
    memcpy(combined, ch_buf.data, ch_buf.size);
    memcpy(combined + ch_buf.size, ar_data, ar_pkt_len);

    uint8_t final_hmac[20];
    platform_hmac_sha1(challenge, 20, combined, cb_len, final_hmac);
    free(combined);

    fprintf(stderr, "[%s] HMAC challenge complete\n", TAG);

    /* Shannon keys: send = challenge[20:52], recv = challenge[52:84] */
    uint8_t send_key[32], recv_key[32];
    memcpy(send_key, challenge + 20, 32);
    memcpy(recv_key, challenge + 52, 32);

    /* ----- Step 8: Send ClientResponse (plaintext on wire) ----- */
    pb_buf_t cr_buf;
    build_client_response(&cr_buf, final_hmac);
    fprintf(stderr, "[%s] ClientResponse: %zu bytes\n", TAG, cr_buf.size);

    /* Send ClientResponse without Shannon (plaintext prefix) */
    uint8_t cr_prefix[2] = {0x00, 0x00};  /* plaintext */
    uint32_t cr_pkt_len = htonl((uint32_t)(cr_buf.size + 2));
    uint8_t cr_len_buf[4];
    memcpy(cr_len_buf, &cr_pkt_len, 4);

    size_t cr_full_len = 4 + 2 + cr_buf.size;
    uint8_t *cr_full = malloc(cr_full_len);
    memcpy(cr_full, cr_len_buf, 4);
    memcpy(cr_full + 4, cr_prefix, 2);
    memcpy(cr_full + 6, cr_buf.data, cr_buf.size);

    ret = platform_tcp_write(s->sock, cr_full, cr_full_len);
    free(cr_full);
    pb_buf_free(&cr_buf);

    if (ret != 0) {
        fprintf(stderr, "[%s] Failed to send ClientResponse\n", TAG);
        free(ar_data);
        pb_buf_free(&ch_buf);
        return -9;
    }

    /* ----- Step 9: Initialize Shannon ciphers ----- */
    uint8_t zero_nonce[4] = {0, 0, 0, 0};
    platform_shannon_key(s->send_cipher, send_key, 32);
    platform_shannon_nonce(s->send_cipher, zero_nonce, 4);
    platform_shannon_key(s->recv_cipher, recv_key, 32);
    platform_shannon_nonce(s->recv_cipher, zero_nonce, 4);

    s->send_nonce = 0;
    s->recv_nonce = 0;

    fprintf(stderr, "[%s] Shannon ciphers initialized\n", TAG);

    /* ----- Step 10: Send LoginRequest (Shannon-encrypted) ----- */
    pb_buf_t lr_buf;
    build_login_request(&lr_buf, auth_data, ad_len, auth_type,
                        username, device_id);
    fprintf(stderr, "[%s] LoginRequest: %zu bytes\n", TAG, lr_buf.size);

    ret = mercury_send(s, MERCURY_CMD_LOGIN, lr_buf.data, lr_buf.size);
    pb_buf_free(&lr_buf);

    if (ret != 0) {
        fprintf(stderr, "[%s] Failed to send LoginRequest\n", TAG);
        free(ar_data);
        pb_buf_free(&ch_buf);
        return -10;
    }

    /* ----- Step 11: Wait for APWelcome/AUTH_FAIL ----- */
    uint8_t aw_data[4096];
    size_t aw_len = 0;
    uint8_t aw_cmd = 0;

    ret = mercury_recv(s, &aw_cmd, aw_data, &aw_len, sizeof(aw_data));
    if (ret != 0) {
        fprintf(stderr, "[%s] Failed to receive auth response\n", TAG);
        free(ar_data);
        pb_buf_free(&ch_buf);
        return -11;
    }

    if (aw_cmd == MERCURY_CMD_AUTH_OK) {
        fprintf(stderr, "\n[%s] ===== AUTH SUCCESS =====\n", TAG);

        /* Parse APWelcome */
        pb_reader_t aw_reader;
        pb_reader_init(&aw_reader, aw_data, aw_len);

        uint32_t f, w;
        while (pb_read_tag(&aw_reader, &f, &w)) {
            if (f == 10 && w == PB_LENGTH_DELIM) {
                /* canonical_username */
                size_t ulen = pb_read_bytes_to(&aw_reader,
                    (uint8_t *)s->canonical_username, sizeof(s->canonical_username) - 1);
                s->canonical_username[ulen] = '\0';
                fprintf(stderr, "[%s] Canonical: %s\n", TAG, s->canonical_username);
            } else if (f == 20 && w == PB_VARINT) {
                uint64_t acc_type = pb_read_varint(&aw_reader);
                fprintf(stderr, "[%s] Account: %s\n", TAG,
                        acc_type == 0 ? "Spotify" : "Facebook");
            } else if (f == 30 && w == PB_VARINT) {
                uint64_t rt = pb_read_varint(&aw_reader);
                fprintf(stderr, "[%s] Reusable type: %llu\n", TAG,
                        (unsigned long long)rt);
            } else if (f == 40 && w == PB_LENGTH_DELIM) {
                /* stored_credential / reusable token */
                size_t cred_len = pb_read_bytes_to(&aw_reader,
                    s->stored_cred, sizeof(s->stored_cred));
                s->stored_cred_len = cred_len;
                fprintf(stderr, "[%s] Stored credential: %zu bytes\n",
                        TAG, cred_len);

                /* Print as base64 */
                char b64_out[2048];
                platform_base64_encode(s->stored_cred, cred_len,
                                       b64_out, sizeof(b64_out));
                fprintf(stderr, "[%s] Token (b64): %s\n", TAG, b64_out);
            } else if (f == 50 && w == PB_LENGTH_DELIM) {
                /* display_name */
                char dname[256] = {0};
                size_t dn_len = pb_read_bytes_to(&aw_reader,
                    (uint8_t *)dname, sizeof(dname) - 1);
                fprintf(stderr, "[%s] Display: %.*s\n", TAG, (int)dn_len, dname);
            } else {
                pb_skip_field(&aw_reader, w);
            }
        }

        s->connected = true;
        ret = 0;

    } else if (aw_cmd == MERCURY_CMD_AUTH_FAIL) {
        fprintf(stderr, "[%s] AUTH DECLINED\n", TAG);
        ret = -12;
    } else {
        fprintf(stderr, "[%s] Unknown auth response: 0x%02x\n", TAG, aw_cmd);
        ret = -13;
    }

    /* Clean up temporary data */
    free(ar_data);
    pb_buf_free(&ch_buf);

    return ret;
}

/* ================================================================== */
/*  Post-Auth Accessors                                                */
/* ================================================================== */

const char *mercury_get_canonical_username(mercury_session_t *s) {
    if (!s) return NULL;
    return s->canonical_username[0] ? s->canonical_username : NULL;
}

const uint8_t *mercury_get_stored_cred(mercury_session_t *s, size_t *out_len) {
    if (!s || !out_len) return NULL;
    if (s->stored_cred_len == 0) return NULL;
    *out_len = s->stored_cred_len;
    return s->stored_cred;
}

bool mercury_is_connected(mercury_session_t *s) {
    return s && s->connected;
}

/* ================================================================== */
/*  Lifecycle                                                          */
/* ================================================================== */

void mercury_disconnect(mercury_session_t *s) {
    if (!s) return;
    if (s->sock != PLATFORM_SOCKET_INVALID) {
        platform_tcp_close(s->sock);
        s->sock = PLATFORM_SOCKET_INVALID;
    }
    s->connected = false;
}

void mercury_destroy(mercury_session_t *s) {
    if (!s) return;
    mercury_disconnect(s);
    if (s->send_cipher) platform_shannon_free(s->send_cipher);
    if (s->recv_cipher) platform_shannon_free(s->recv_cipher);
    free(s);
}
