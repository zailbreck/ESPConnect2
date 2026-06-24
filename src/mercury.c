// mercury.c — Spotify Login5 Authentication + Mercury Protocol
// ==========================================================
// Full Login5 authentication flow with Shannon cipher and HMAC challenge.
// Based on working standalone binary: mercury_login5_v5_fix4
//
// Code sources and references:
//   Shannon cipher:      cspot (MIT) — Shannon.cpp
//                         https://github.com/feelfreelinux/cspot
//   HMAC challenge:      cspot (MIT) — AuthChallenges.cpp
//                         https://github.com/feelfreelinux/cspot/blob/master/cspot/src/AuthChallenges.cpp
//   Session auth:        cspot (MIT) — Session.cpp
//   DH group:            RFC 2409 — Oakley Group 2 (768-bit MODP)
//   Protobuf schema:     cspot (MIT) — keyexchange.proto, authentication.proto
//   APResponse parser:   Robust skipF-based — handles both authType=1 and authType=113
//
// KEY BUG FIX: HMAC challenge must use full ClientHello packet (with 0x00,0x04
// prefix + 4-byte length header), NOT proto-only bytes. This one byte difference
// caused Shannon key mismatch → server couldn't decrypt LoginRequest.
//
// License: MIT — derived from cspot & librespot

#include "internal/mercury.h"
#include "internal/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#define TAG "mercury"

/* ================================================================== */
/*  Protobuf Wire-Format Encoder (matching V5 standalone)              */
/* ================================================================== */

#define PB_VARINT    0
#define PB_LENGTH_DELIM 2

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} pb_buf_t;

static void pb_init(pb_buf_t *b, size_t cap) {
    b->data = malloc(cap);
    b->size = 0;
    b->capacity = cap;
}

static void pb_free(pb_buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->size = b->capacity = 0;
}

static void pb_grow(pb_buf_t *b, size_t need) {
    if (b->size + need > b->capacity) {
        b->capacity = (b->size + need) * 2;
        b->data = realloc(b->data, b->capacity);
    }
}

static uint8_t *pb_varint_enc(uint8_t *p, uint64_t v) {
    while (v > 0x7F) {
        *p++ = (uint8_t)((v & 0x7F) | 0x80);
        v >>= 7;
    }
    *p++ = (uint8_t)(v & 0x7F);
    return p;
}

static void pb_tag(pb_buf_t *b, uint64_t fn, uint64_t wt) {
    pb_grow(b, 10);
    b->size = pb_varint_enc(b->data + b->size, (fn << 3) | wt) - b->data;
}

static void pb_varint(pb_buf_t *b, uint64_t fn, uint64_t val) {
    pb_tag(b, fn, PB_VARINT);
    pb_grow(b, 10);
    b->size = pb_varint_enc(b->data + b->size, val) - b->data;
}

static void pb_bytes(pb_buf_t *b, uint64_t fn, const uint8_t *d, size_t len) {
    pb_tag(b, fn, PB_LENGTH_DELIM);
    pb_grow(b, 10 + len);
    b->size = pb_varint_enc(b->data + b->size, len) - b->data;
    memcpy(b->data + b->size, d, len);
    b->size += len;
}

static void pb_enum(pb_buf_t *b, uint64_t fn, uint64_t v) {
    pb_varint(b, fn, v);  /* enum = varint wire type */
}

#define pb_str(b, fn, s) pb_bytes(b, fn, (const uint8_t *)(s), strlen(s))

/* ================================================================== */
/*  Protobuf Parser (robust, skipF-based — handles both authTypes)     */
/* ================================================================== */

typedef struct {
    const uint8_t *d;
    size_t p, s;
} pb_reader_t;

static void pb_reader_init(pb_reader_t *r, const uint8_t *data, size_t len) {
    r->d = data;
    r->p = 0;
    r->s = len;
}

static void pb_reader_init_slice(pb_reader_t *r, const uint8_t *data, size_t off, size_t len) {
    r->d = data;
    r->p = off;
    r->s = len;
}

static uint64_t pb_read_varint_raw(pb_reader_t *r) {
    uint64_t v = 0;
    int sh = 0;
    while (r->p < r->s) {
        uint8_t b = r->d[r->p++];
        v |= (uint64_t)(b & 0x7F) << sh;
        if (!(b & 0x80)) break;
        sh += 7;
    }
    return v;
}

static bool pb_read_tag(pb_reader_t *r, uint32_t *fn, uint32_t *wt) {
    if (r->p >= r->s) return false;
    uint64_t t = pb_read_varint_raw(r);
    *fn = (uint32_t)(t >> 3);
    *wt = (uint32_t)(t & 7);
    return true;
}

static void pb_read_ldelim(pb_reader_t *r, pb_reader_t *sub) {
    uint64_t len = pb_read_varint_raw(r);
    if (r->p + len <= r->s) {
        sub->d = r->d + r->p;
        sub->p = 0;
        sub->s = (size_t)len;
        r->p += len;
    } else {
        sub->d = NULL;
        sub->p = 0;
        sub->s = 0;
        r->p = r->s;
    }
}

static size_t pb_read_bytes_copy(pb_reader_t *r, uint8_t *out, size_t max) {
    uint64_t len = pb_read_varint_raw(r);
    if (len > max) len = max;
    if (r->p + len <= r->s) {
        memcpy(out, r->d + r->p, len);
        r->p += len;
        return (size_t)len;
    }
    return 0;
}

/* skipF: advance past a field by wire type */
static void pb_skip(pb_reader_t *r, uint32_t wt) {
    if (wt == PB_VARINT) {
        while (r->p < r->s && (r->d[r->p - 1] & 0x80)) r->p++;
    } else if (wt == PB_LENGTH_DELIM) {
        uint64_t len = pb_read_varint_raw(r);
        if (r->p + len <= r->s) r->p += len;
        else r->p = r->s;
    }
    /* wire types 1 and 5 (64-bit/32-bit fixed) not used in Spotify handshake */
}

/* ================================================================== */
/*  Protobuf Message Builders (exact V5 algo, matching cspot fields)  */
/* ================================================================== */

/* ClientHello: matches cspot prepareClientHello + librespot ClientHello */
static void build_client_hello(pb_buf_t *out,
                                const uint8_t *dh_pub, size_t dh_pub_len,
                                const uint8_t *nonce, size_t nonce_len) {
    pb_init(out, 512);

    /* build_info (field 10) */
    pb_buf_t bi; pb_init(&bi, 64);
    pb_enum(&bi, 10, 0);   /* product = PRODUCT_CLIENT */
    pb_enum(&bi, 30, 2);   /* platform = PLATFORM_LINUX_X86 */
    pb_varint(&bi, 40, 0x10800000000ULL); /* version */
    pb_bytes(out, 10, bi.data, bi.size);
    pb_free(&bi);

    /* cryptosuites_supported (field 30 / 0x1e) */
    pb_enum(out, 30, 0);   /* CRYPTO_SUITE_SHANNON */

    /* login_crypto_hello (field 50 / 0x32) */
    pb_buf_t dh; pb_init(&dh, 256);
    pb_bytes(&dh, 10, dh_pub, dh_pub_len);  /* gc */
    pb_varint(&dh, 20, 1);                   /* server_keys_known = 1 */
    pb_buf_t un; pb_init(&un, 32);
    pb_bytes(&un, 10, dh.data, dh.size);
    pb_bytes(out, 50, un.data, un.size);
    pb_free(&dh); pb_free(&un);

    /* client_nonce (field 60 / 0x3c) */
    pb_bytes(out, 60, nonce, nonce_len);

    /* padding (field 70 / 0x46) */
    uint8_t pad = 0x1E;
    pb_bytes(out, 70, &pad, 1);

    /* feature_set (field 80 / 0x50) */
    pb_buf_t fs; pb_init(&fs, 16);
    pb_varint(&fs, 1, 1);
    pb_bytes(out, 80, fs.data, fs.size);
    pb_free(&fs);
}

/* ClientResponsePlaintext: matches librespot compute_keys + client_response */

static void raw_pb_varint(pb_buf_t *b, uint32_t tag, uint64_t val) {
    pb_grow(b, 20);
    b->data[b->size++] = (uint8_t)tag;
    b->size = pb_varint_enc(b->data + b->size, val) - b->data;
}

static void raw_pb_bytes(pb_buf_t *b, uint32_t tag, const uint8_t *d, size_t len) {
    pb_grow(b, 10 + len);
    b->data[b->size++] = (uint8_t)tag;
    b->size = pb_varint_enc(b->data + b->size, len) - b->data;
    if (len > 0) memcpy(b->data + b->size, d, len);
    b->size += len;
}

static void build_client_resp(pb_buf_t *out, const uint8_t hmac[20]) {
    pb_init(out, 128);
    pb_buf_t dh; pb_init(&dh, 32);
    pb_bytes(&dh, 10, hmac, 20); // 0xa = 10

    pb_buf_t resp; pb_init(&resp, 64);
    pb_bytes(&resp, 10, dh.data, dh.size); // 0xa = 10
    pb_free(&dh);

    pb_bytes(out, 10, resp.data, resp.size); // 0xa = 10
    /* Librespot initializes pow_response and crypto_response, but nanopb in cspot skips them.
     * We will omit them entirely to perfectly match nanopb's behavior. */
    pb_free(&resp);
}

static void build_login_request(pb_buf_t *out,
                                 const uint8_t *auth_data, size_t ad_len,
                                 int auth_type,
                                 const char *username,
                                 const char *device_id) {
    pb_init(out, 512);

    /* LoginCredentials (field 10) */
    pb_buf_t lc; pb_init(&lc, 256);
    if (username && username[0] != '\0') {
        pb_str(&lc, 10, username);         // username = field 10
    }
    pb_enum(&lc, 20, auth_type);       // typ = field 20
    pb_bytes(&lc, 30, auth_data, ad_len); // auth_data = field 30
    pb_bytes(out, 10, lc.data, lc.size);  // login_credentials = field 10
    pb_free(&lc);

    /* SystemInfo (field 50) */
    pb_buf_t si; pb_init(&si, 128);
    pb_enum(&si, 10, 0);               // cpu_family = field 10 (CPU_UNKNOWN)
    pb_enum(&si, 60, 0);               // os = field 60 (OS_UNKNOWN)
    pb_str(&si, 90, "cspot-player");   // system_information_string = field 90
    pb_str(&si, 100, device_id);       // device_id = field 100
    pb_bytes(out, 50, si.data, si.size);  // system_info = field 50
    pb_free(&si);

    /* version_string (field 70) */
    pb_str(out, 70, "cspot-1.1");      // version_string = field 70
}

/* ================================================================== */
/*  HMAC Challenge (5-round SHA1-HMAC) — cspot AuthChallenges.cpp     */
/*  KEY: Uses full ClientHello PACKET (with prefix), NOT proto-only   */
/* ================================================================== */

static void compute_auth_challenge(
    const uint8_t *shared, size_t shared_len,
    const uint8_t *hello_pkt, size_t hello_pkt_len,   /* FULL packet with 0x00 0x04 prefix! */
    const uint8_t *ap_resp, size_t ap_resp_len,
    uint8_t *result_out)   /* 100 bytes: [hmac_answer(20), send_key(32), recv_key(32)] */
{
    /* cb = hello_pkt + ap_resp */
    size_t cb_len = hello_pkt_len + ap_resp_len;
    uint8_t *cb = malloc(cb_len);
    memcpy(cb, hello_pkt, hello_pkt_len);
    memcpy(cb + hello_pkt_len, ap_resp, ap_resp_len);

    /* FIX #5 (HMAC byte order): byte counter x must be PREPENDED (at index 0),
     * not appended. cspot C++ code: vector<uint8_t>(1, i) then insert(end, cb.begin...).
     * Means layout is: [x][cb...], NOT [cb...][x]. */
    uint8_t *dst = result_out;
    for (int x = 1; x < 6; x++) {
        uint8_t *cv = malloc(cb_len + 1);
        cv[0] = (uint8_t)x;          /* x di AWAL — prepend */
        memcpy(cv + 1, cb, cb_len);  /* cb menyusul setelahnya */
        platform_hmac_sha1(shared, shared_len, cv, cb_len + 1, dst);
        free(cv);
        dst += 20;
    }

    /* Final HMAC: key = result[0:20], data = cb */
    platform_hmac_sha1(result_out, 20, cb, cb_len, result_out);
    free(cb);
}

/* ================================================================== */
/*  DH Oakley Group 2 (768-bit MODP) — RFC 2409                        */
/* ================================================================== */

/* G = 2 */
/* P = 2^768 - 2^704 - 1 + 2^64 * { [2^638 pi] + 149686 } */
/* Generated internally by platform_dh_generate_keypair */

/* ================================================================== */
/*  Mercury Session                                                    */
/* ================================================================== */

struct mercury_session_t {
    platform_socket_t sock;
    bool connected;

    /* DH secrets */
    uint8_t dh_public[96];
    uint8_t dh_private[96];
    uint8_t shared_key[96];
    size_t shared_len;

    /* Shannon ciphers */
    platform_shannon_t *send_cipher;
    platform_shannon_t *recv_cipher;
    uint32_t send_nonce;
    uint32_t recv_nonce;

    /* Auth result */
    char canonical_username[256];
    uint8_t stored_cred[2048];
    size_t stored_cred_len;
    char display_name[256];
};

/* ================================================================== */
/*  TCP Framing (matching V5 spkt/rpkt)                                */
/*  spkt: [4B BE len] [prefix] [data]                                  */
/*  rpkt: reads 4B BE len, then len bytes                              */
/* ================================================================== */

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int tcp_send_packet(platform_socket_t sock,
                           const uint8_t *prefix, size_t prefix_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t *full_pkt_out, size_t *full_len_out) {
    /* Packet format: [prefix][4B BE len][data] — matches standalone spkt */
    uint32_t total = (uint32_t)(4 + prefix_len + data_len);
    size_t full_len = prefix_len + 4 + data_len;
    uint8_t *pkt = malloc(full_len);

    if (prefix_len) memcpy(pkt, prefix, prefix_len);
    write_be32(pkt + prefix_len, total);
    if (data_len) memcpy(pkt + prefix_len + 4, data, data_len);

    int ret = platform_tcp_write(sock, pkt, full_len);

    if (full_pkt_out) {
        memcpy(full_pkt_out, pkt, full_len);
        *full_len_out = full_len;
    }

    free(pkt);
    return ret;
}

static int tcp_recv_packet(platform_socket_t sock,
                           uint8_t *out, size_t max_len, size_t *out_len) {
    uint8_t hdr[4];
    if (platform_tcp_read(sock, hdr, 4) != 0) return -1;

    uint32_t total = read_be32(hdr);
    if (total < 4 || total > max_len) return -2;

    out[0] = hdr[0]; out[1] = hdr[1]; out[2] = hdr[2]; out[3] = hdr[3];
    if (platform_tcp_read(sock, out + 4, total - 4) != 0) return -1;

    *out_len = (size_t)total;
    return 0;
}

/* ================================================================== */
/*  Shannon Framing  (cspot protocol: cmd+size+data, encrypt, MAC)    */
/* ================================================================== */

#define SHANNON_MAC_SZ 4

static void shannon_init(platform_shannon_t *snd, platform_shannon_t *rcv,
                         const uint8_t *sk, const uint8_t *rk) {
    /* Matches cspot SConn::init exactly:
     *   snd.key(sk);  → initState → loadKey(sk) → genkonst → saveState
     *   rcv.key(rk);  → initState → loadKey(rk) → genkonst → saveState
     * Each cipher starts from FRESH initState — they are completely independent.
     * Nonce is set later via mercury_send/mercury_recv. */
    platform_shannon_key(snd, sk, 32);
    platform_shannon_key(rcv, rk, 32);
}

/* ================================================================== */
/*  API Implementation                                                 */
/* ================================================================== */

mercury_session_t *mercury_init(void) {
    mercury_session_t *s = calloc(1, sizeof(*s));
    s->sock = PLATFORM_SOCKET_INVALID;
    s->send_cipher = platform_shannon_new();
    s->recv_cipher = platform_shannon_new();
    return s;
}

int mercury_login5(mercury_session_t *s,
                   const char *username,
                   const char *auth_data_b64,
                   int auth_type,
                   const char *device_id,
                   const char *ap_host,
                   int ap_port) {
    if (!s || !auth_data_b64 || !device_id || !ap_host)
        return -1;
    if (ap_port <= 0) ap_port = 443;

    uint8_t ar_buf[4096];
    size_t ar_len = 0;
    int ret;


    
    uint8_t auth_data[2048];
    size_t ad_len = 0;
    
    /* FIX #8 (auth type): AUTHENTICATION_SPOTIFY_TOKEN = 2, bukan 3.
     * 3 = AUTHENTICATION_FACEBOOK_TOKEN. */
    if (auth_type == 2) {
        // AUTHENTICATION_SPOTIFY_TOKEN (OAuth) is just the ASCII token string
        ad_len = strlen(auth_data_b64);
        if (ad_len > sizeof(auth_data)) ad_len = sizeof(auth_data);
        memcpy(auth_data, auth_data_b64, ad_len);
    } else {
        /* ---------- Decode auth data (URL-safe base64: - → +, _ → /) ---------- */
        char b64_buf[2048];
        size_t b64_len = strlen(auth_data_b64);
        if (b64_len >= sizeof(b64_buf) - 5) b64_len = sizeof(b64_buf) - 5;
        memcpy(b64_buf, auth_data_b64, b64_len);
        
        for (size_t i = 0; i < b64_len; i++) {
            if (b64_buf[i] == '-') b64_buf[i] = '+';
            if (b64_buf[i] == '_') b64_buf[i] = '/';
        }
        
        /* Add padding if needed! */
        while (b64_len % 4 != 0) {
            b64_buf[b64_len] = '=';
            b64_len++;
        }
        b64_buf[b64_len] = '\0';

        ad_len = platform_base64_decode(b64_buf,
            b64_len, auth_data, sizeof(auth_data));
    }


    if (ad_len < 10) {
        fprintf(stderr, "[%s] Bad auth data\n", TAG);
        return -2;
    }
    fprintf(stderr, "[%s] AuthData: %zu bytes, type=%d\n", TAG, ad_len, auth_type);

    /* ---------- TCP connect ---------- */
    s->sock = platform_tcp_connect(ap_host, ap_port);
    if (s->sock == PLATFORM_SOCKET_INVALID) {
        fprintf(stderr, "[%s] TCP connect fail\n", TAG);
        return -3;
    }
    platform_tcp_set_timeout(s->sock, 15);
    fprintf(stderr, "[%s] Connected: %s:%d\n", TAG, ap_host, ap_port);

    /* ---------- DH keypair ---------- */
    platform_dh_generate_keypair(s->dh_public, s->dh_private);

    /* ---------- ClientHello ---------- */
    uint8_t nonce[16];
    platform_random(nonce, 16);

    pb_buf_t ch_proto;
    build_client_hello(&ch_proto, s->dh_public, 96, nonce, 16);
    fprintf(stderr, "[%s] ClientHello proto sz=%zu hex=", TAG, ch_proto.size);
    for (size_t i = 0; i < ch_proto.size ; i++) fprintf(stderr, "%02x", ch_proto.data[i]);
    fprintf(stderr, "\n");

    uint8_t hello_pkt[512];
    size_t hello_pkt_len = 0;
    uint8_t prefix[2] = {0x00, 0x04};

    ret = tcp_send_packet(s->sock, prefix, 2,
                          ch_proto.data, ch_proto.size,
                          hello_pkt, &hello_pkt_len);

    if (ret != 0) {
        fprintf(stderr, "[%s] ClientHello send fail\n", TAG);
        return -4;
    }
    fprintf(stderr, "[%s] ClientHello sent (%zu bytes)\n", TAG, hello_pkt_len);

    /* ---------- APResponse ---------- */
    ret = tcp_recv_packet(s->sock, ar_buf, sizeof(ar_buf), &ar_len);
    if (ret != 0 || ar_len < 8) {
        fprintf(stderr, "[%s] APResponse read fail\n", TAG);
        return -5;
    }
    fprintf(stderr, "[%s] APResponse: %zu bytes\n", TAG, ar_len);

    /* ---------- Extract server DH (robust skipF parser) ---------- */
    pb_reader_t r;
    pb_reader_init_slice(&r, ar_buf, 4, ar_len); /* skip 4-byte length */
    uint32_t fn, wt;
    uint8_t server_dh[96] = {0};
    bool found = false;

    while (pb_read_tag(&r, &fn, &wt) && !found) {
        if (fn == 10 && wt == PB_LENGTH_DELIM) {
            pb_reader_t r1; pb_read_ldelim(&r, &r1);
            while (pb_read_tag(&r1, &fn, &wt) && !found) {
                if (fn == 10 && wt == PB_LENGTH_DELIM) {
                    pb_reader_t r2; pb_read_ldelim(&r1, &r2);
                    while (pb_read_tag(&r2, &fn, &wt) && !found) {
                        if (fn == 10 && wt == PB_LENGTH_DELIM) {
                            pb_reader_t r3; pb_read_ldelim(&r2, &r3);
                            while (pb_read_tag(&r3, &fn, &wt) && !found) {
                                if (fn == 10 && wt == PB_LENGTH_DELIM) {
                                    size_t dh_len = pb_read_bytes_copy(&r3,
                                        server_dh, sizeof(server_dh));
                                    if (dh_len == 96) found = true;
                                } else {
                                    pb_skip(&r3, wt);
                                }
                            }
                        } else pb_skip(&r2, wt);
                    }
                } else pb_skip(&r1, wt);
            }
        } else pb_skip(&r, wt);
    }

    if (!found) {
        fprintf(stderr, "[%s] No server DH in APResponse\n", TAG);
        return -6;
    }
    fprintf(stderr, "[%s] Server DH: 96B\n", TAG);

    /* ---------- Compute shared secret ---------- */
    platform_dh_compute_shared(s->dh_private, server_dh, 96, s->shared_key, &s->shared_len);

    /* ---------- HMAC challenge ---------- */
    /* KEY: uses ch_proto ONLY (no prefix/len header), matches standalone cb.insert(ch.begin(),ch.end()) */
    fprintf(stderr, "[%s] DBG cb=(ch_proto=%zu + ar_buf=%zu)\n", TAG, ch_proto.size, ar_len);
    fprintf(stderr, "[%s] DBG ch_proto hex=", TAG);
    for (size_t i = 0; i < ch_proto.size ; i++) fprintf(stderr, "%02x", ch_proto.data[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[%s] DBG ar_buf hex=", TAG);
    for (size_t i = 0; i < ar_len ; i++) fprintf(stderr, "%02x", ar_buf[i]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[%s] DBG shared_key hex=", TAG);
    for (size_t i = 0; i < s->shared_len; i++) fprintf(stderr, "%02x", s->shared_key[i]);
    fprintf(stderr, "\n");
    uint8_t challenge[100];
    compute_auth_challenge(s->shared_key, s->shared_len,
                           hello_pkt, hello_pkt_len,  /* FULL packet including prefix and size */
                           ar_buf, ar_len,     /* [4B len][ar_proto] */
                           challenge);
    /* Write full debug data to file for cross-verification */
    {
        FILE *__d = fopen("login5_dump.txt", "w");
        if (__d) {
            fprintf(__d, "shared_key(96)=");
            for (int i_=0; i_<96; i_++) fprintf(__d, "%02x", s->shared_key[i_]);
            fprintf(__d, "\nch_proto(%zu)=", ch_proto.size);
            for (size_t i_=0; i_<ch_proto.size; i_++) fprintf(__d, "%02x", ch_proto.data[i_]);
            fprintf(__d, "\nar_buf(%zu)=", ar_len);
            for (size_t i_=0; i_<ar_len; i_++) fprintf(__d, "%02x", ar_buf[i_]);
            fprintf(__d, "\nchallenge(100)=");
            for (int i_=0; i_<100; i_++) fprintf(__d, "%02x", challenge[i_]);
            fprintf(__d, "\n");
            fclose(__d);
        }
    }
    pb_free(&ch_proto);

    uint8_t send_key[32], recv_key[32];
    memcpy(send_key, challenge + 20, 32);
    memcpy(recv_key, challenge + 52, 32);

    fprintf(stderr, "[%s] HMAC: %02x%02x%02x%02x...\n", TAG,
            challenge[0], challenge[1], challenge[2], challenge[3]);

    /* ---------- ClientResponse (plaintext, no prefix) ---------- */
    pb_buf_t cr_buf;
    build_client_resp(&cr_buf, challenge);  /* challenge[0:20] = hmac answer */

    /* FIX #4 (ClientResponse framing): ClientResponsePlaintext harus dikirim
     * sebagai raw protobuf TANPA length prefix apapun. tcp_send_packet() selalu
     * menambahkan 4-byte BE length header yang tidak seharusnya ada di sini. */
    ret = platform_tcp_write(s->sock, cr_buf.data, cr_buf.size);
    pb_free(&cr_buf);
    if (ret != 0) {
        fprintf(stderr, "[%s] ClientResp send fail\n", TAG);
        return -7;
    }

    /* ---------- Init Shannon ---------- */
    shannon_init(s->send_cipher, s->recv_cipher, send_key, recv_key);
    s->send_nonce = 0;
    s->recv_nonce = 0;   /* Matches cspot wrapConnection htonl(0) */
    fprintf(stderr, "[%s] Shannon ready\n", TAG);
    fprintf(stderr, "[%s] KEYS sk=", TAG);
    for (int ki = 0; ki < 32; ki++) fprintf(stderr, "%02x", send_key[ki]);
    fprintf(stderr, " rk=");
    for (int ki = 0; ki < 32; ki++) fprintf(stderr, "%02x", recv_key[ki]);
    fprintf(stderr, "\n");
    fprintf(stderr, "[%s] FULL challenge(100)=", TAG);
    for (int ki = 0; ki < 100; ki++) fprintf(stderr, "%02x", challenge[ki]);
    fprintf(stderr, "\n");

    /* ---------- Build & send LoginRequest ---------- */
    pb_buf_t lr_buf;
    build_login_request(&lr_buf, auth_data, ad_len, auth_type,
                        username, device_id);

    fprintf(stderr, "[%s] LoginReq sz=%zu hex=", TAG, lr_buf.size);
    for (size_t i = 0; i < lr_buf.size ; i++)
        fprintf(stderr, "%02x", lr_buf.data[i]);
    fprintf(stderr, "\n");

    ret = mercury_send(s, MERCURY_CMD_LOGIN, lr_buf.data, lr_buf.size);
    pb_free(&lr_buf);
    if (ret != 0) {
        fprintf(stderr, "[%s] LoginReq send fail\n", TAG);
        return -8;
    }
    fprintf(stderr, "[%s] LoginReq sent\n", TAG);

    /* ---------- Wait for response (handle PINGs) ---------- */
    uint8_t rx_data[4096];
    size_t rx_len = 0;
    uint8_t cmd = 0;

    /* FIX #9 (PING cmd): PING dari server adalah 0x04, bukan 0x00.
     * 0x49 = PONG_ACK yang dikirim client — sudah benar. */
    for (int retry = 0; retry < 10; retry++) {
        if (mercury_recv(s, &cmd, rx_data, &rx_len, sizeof(rx_data)) != 0) {
            fprintf(stderr, "[%s] Recv fail\n", TAG);
            return -9;
        }
        if (cmd == 0x04) {
            /* PING dari server → balas dengan PONG_ACK */
            mercury_send(s, 0x49, NULL, 0);
            fprintf(stderr, "[%s] PING/PONG\n", TAG);
            continue;
        }
        if (cmd == MERCURY_CMD_AUTH_OK || cmd == MERCURY_CMD_AUTH_FAIL) break;
        fprintf(stderr, "[%s] Unknown cmd 0x%02x\n", TAG, cmd);
    }

    if (cmd == MERCURY_CMD_AUTH_OK) {
        fprintf(stderr, "\n[%s] ===== AUTH SUCCESS =====\n", TAG);

        /* Parse APWelcome */
        pb_reader_t aw;
        pb_reader_init(&aw, rx_data, rx_len);

        uint32_t f, w;
        /* FIX #6 (APWelcome field numbers): field numbers harus sesuai
         * keyexchange.proto / cspot APWelcome:
         *   field 1 = canonical_username (string)
         *   field 2 = account_type       (varint)
         *   field 5 = reusable_credentials_type (varint)
         *   field 6 = reusable_credentials      (bytes)
         * Sebelumnya salah: 10,20,30,40,50 */
        while (pb_read_tag(&aw, &f, &w)) {
            if (f == 1 && w == PB_LENGTH_DELIM) {
                size_t ulen = pb_read_bytes_copy(&aw,
                    (uint8_t *)s->canonical_username,
                    sizeof(s->canonical_username) - 1);
                s->canonical_username[ulen] = '\0';
                fprintf(stderr, "[%s] Canonical: %s\n", TAG, s->canonical_username);
            } else if (f == 2 && w == PB_VARINT) {
                uint64_t at = pb_read_varint_raw(&aw);
                fprintf(stderr, "[%s] Account type: %llu\n", TAG, (unsigned long long)at);
            } else if (f == 5 && w == PB_VARINT) {
                /* reusable_credentials_type */
                pb_read_varint_raw(&aw);
            } else if (f == 6 && w == PB_LENGTH_DELIM) {
                s->stored_cred_len = pb_read_bytes_copy(&aw,
                    s->stored_cred, sizeof(s->stored_cred));
                char b64[4096];
                platform_base64_encode(s->stored_cred, s->stored_cred_len,
                                       b64, sizeof(b64));
                fprintf(stderr, "[%s] Reusable: %zuB\n", TAG, s->stored_cred_len);
                fprintf(stderr, "[%s] Token: %s\n", TAG, b64);
            } else {
                pb_skip(&aw, w);
            }
        }

        s->connected = true;
        return 0;
    }

    fprintf(stderr, "[%s] AUTH FAILED cmd=0x%02x\n", TAG, cmd);
    return -10;
}

/* ================================================================== */
/*  Shannon send/recv                                                  */
/* ================================================================== */

static void uint16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void uint32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t read_u16_be(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

int mercury_send(mercury_session_t *s, uint8_t cmd,
                 const uint8_t *data, size_t len) {
    if (!s || s->sock == PLATFORM_SOCKET_INVALID) return -1;

    /* Wire: [encrypt(cmd, htons(len), data)] [MAC] */
    size_t sz = 1 + 2 + len;
    uint8_t *buf = malloc(sz + SHANNON_MAC_SZ);
    buf[0] = cmd;
    uint16_be(buf + 1, (uint16_t)len);
    if (len) memcpy(buf + 3, data, len);

    /* Set nonce before encrypting */
    uint8_t nonce[4];
    uint32_be(nonce, s->send_nonce);
    s->send_nonce++;
    platform_shannon_nonce(s->send_cipher, nonce, 4);

    platform_shannon_encrypt(s->send_cipher, buf, sz);
    
    /* Debug: hex dump first 16 encrypted bytes */
    fprintf(stderr, "[mercury] encrypted hex(first16)=");
    for (size_t __i = 0; __i < (sz < 16 ? sz : 16); __i++) fprintf(stderr, "%02x", buf[__i]);
    fprintf(stderr, "\n");
    
    if (platform_tcp_write(s->sock, buf, sz) != 0) { free(buf); return -2; }

    uint8_t mac[SHANNON_MAC_SZ];
    platform_shannon_finish(s->send_cipher, mac);
    if (platform_tcp_write(s->sock, mac, SHANNON_MAC_SZ) != 0) { free(buf); return -3; }

    free(buf);
    return 0;
}

int mercury_recv(mercury_session_t *s, uint8_t *cmd,
                 uint8_t *data, size_t *out_len, size_t max_len) {
    if (!s || s->sock == PLATFORM_SOCKET_INVALID) return -1;

    /* FIX #7 (mercury_recv header size): Shannon packet header adalah tepat 3 byte
     * [cmd(1) | len_hi(1) | len_lo(1)]. Membaca 4 byte menggeser socket buffer
     * dan menyebabkan Shannon state tidak sinkron → semua MAC mismatch. */
    uint8_t hdr[3];
    if (platform_tcp_read(s->sock, hdr, 3) != 0) {
        fprintf(stderr, "[mercury] read hdr fail\n");
        return -1;
    }
    fprintf(stderr, "[mercury] RAW hdr hex = %02x %02x %02x\n", hdr[0], hdr[1], hdr[2]);

    /* Set nonce before decrypting */
    uint8_t nonce[4];
    uint32_be(nonce, s->recv_nonce);
    s->recv_nonce++;
    platform_shannon_nonce(s->recv_cipher, nonce, 4);

    platform_shannon_decrypt(s->recv_cipher, hdr, 3);
    *cmd = hdr[0];
    uint16_t pkt_len = read_u16_be(hdr + 1);
    fprintf(stderr, "[mercury] Recv cmd=0x%02x, len=%u\n", *cmd, pkt_len);

    size_t to_read = pkt_len;
    if (to_read > max_len) to_read = max_len;
    if (to_read > 0) {
        if (platform_tcp_read(s->sock, data, to_read) != 0) {
            fprintf(stderr, "[mercury] read data fail\n");
            return -1;
        }
        platform_shannon_decrypt(s->recv_cipher, data, to_read);
    }
    *out_len = to_read;

    /* Read and check MAC */
    uint8_t recv_mac[SHANNON_MAC_SZ], our_mac[SHANNON_MAC_SZ];
    if (platform_tcp_read(s->sock, recv_mac, SHANNON_MAC_SZ) != 0) {
        fprintf(stderr, "[mercury] read mac fail\n");
        return -1;
    }
    platform_shannon_finish(s->recv_cipher, our_mac);

    if (memcmp(recv_mac, our_mac, SHANNON_MAC_SZ) != 0) {
        fprintf(stderr, "[%s] MAC MISMATCH\n", TAG);
    }
    return 0;
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
    if (!s->stored_cred_len) return NULL;
    *out_len = s->stored_cred_len;
    return s->stored_cred;
}

bool mercury_is_connected(mercury_session_t *s) {
    return s && s->connected;
}

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
    platform_shannon_free(s->send_cipher);
    platform_shannon_free(s->recv_cipher);
    free(s);
}
