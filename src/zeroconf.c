// zeroconf.c — Spotify ZeroConf Credential Extraction
// ===================================================
// Captures Spotify login credentials via mDNS + Bell HTTP + DH exchange.
//
// Code sources and references:
//   mDNS discovery:   mdns library (MIT) — https://github.com/mjansson/mdns
//   DH key exchange:  cspot (MIT) — Crypto.cpp
//   AES/CTR decrypt:  cspot (MIT) — Crypto.cpp
//   PBKDF2 + ECB:     librespot (MIT) — authentication/credentials.rs
//   Protobuf schema:  cspot (MIT) — keyexchange.proto
//   Bell HTTP:        cspot (MIT) — BellTask.cpp
//
// License: MIT — derived from cspot & librespot

#define _POSIX_C_SOURCE 200809L

#include "internal/zeroconf.h"
#include "internal/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define TAG "zeroconf"

/* Default device ID for PBKDF2 (change per device) */
#define DEFAULT_DEVICE_ID "142137fd329622137a1490161234567890123456"

/* -------- Protobuf varint reader -------- */
static uint32_t read_varint(const uint8_t *data, size_t *pos, size_t max_len) {
    if (*pos >= max_len) return 0;
    uint8_t lo = data[(*pos)++];
    if ((lo & 0x80) == 0) return lo;
    if (*pos >= max_len) return lo & 0x7f;
    uint8_t hi = data[(*pos)++];
    return (lo & 0x7f) | ((uint32_t)hi << 7);
}

/* -------- URL decode -------- */
static int hex_char_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t url_decode(const char *src, size_t src_len, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; i < src_len && j < dst_size - 1; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            int hi = hex_char_val(src[i + 1]);
            int lo = hex_char_val(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                dst[j++] = (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        if (src[i] == '+')
            dst[j++] = ' ';
        else
            dst[j++] = src[i];
    }
    dst[j] = '\0';
    return j;
}

/* Extract query param value */
static char *get_query_param(const char *query, const char *key) {
    static char val_buf[4096];
    size_t qlen = strlen(query);
    size_t klen = strlen(key);

    const char *p = query;
    while (p && (size_t)(p - query) < qlen) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            const char *end = strchr(p, '&');
            size_t vlen = end ? (size_t)(end - p) : strlen(p);
            if (vlen >= sizeof(val_buf)) vlen = sizeof(val_buf) - 1;
            url_decode(p, vlen, val_buf, sizeof(val_buf));
            return val_buf;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
    return NULL;
}

/* -------- Blob decryption -------- */

/**
 * Process the raw blob after receiving creds via Bell HTTP.
 *
 * Full pipeline:
 *   raw_blob_b64 → base64 decode → verify MAC → AES-CTR decrypt →
 *   base64 decode inner → AES-ECB decrypt → XOR post-process →
 *   protobuf parse → extract authData
 */
static int process_blob(const char *blob_b64, const char *username,
                        const char *device_id, const uint8_t *shared_secret,
                        size_t secret_len,
                        char *auth_data_b64, size_t auth_b64_size,
                        int *auth_type) {
    /* Step 1: Base64 decode outer blob */
    size_t blob_max = 8192;
    uint8_t *blob = malloc(blob_max);
    if (!blob) return -1;

    size_t blob_len = platform_base64_decode(blob_b64, strlen(blob_b64),
                                              blob, blob_max);
    if (blob_len < 36) {
        fprintf(stderr, "[%s] Blob too short: %zu bytes\n", TAG, blob_len);
        free(blob);
        return -1;
    }
    fprintf(stderr, "[%s] Outer blob: %zu bytes\n", TAG, blob_len);

    /* Extract IV, encrypted data, checksum */
    uint8_t iv[16];
    memcpy(iv, blob, 16);
    uint8_t *encrypted = blob + 16;
    size_t encrypted_len = blob_len - 16 - 20;
    uint8_t *checksum = blob + blob_len - 20;

    /* Step 2: Derive keys from shared secret
     * V13: sha1Buf(sharedSecret.data(), sharedSecret.size(), baseKey)
     *      hmacSha1(baseKey, 16, ...) ← only 16 bytes as HMAC key! */
    uint8_t base_key[20];
    platform_sha1(shared_secret, secret_len, base_key);

    uint8_t checksum_key[20], encryption_key[20];
    /* V13 uses only 16 bytes of base_key as HMAC key (not full 20!) */
    platform_hmac_sha1(base_key, 16, (const uint8_t *)"checksum", 8, checksum_key);
    platform_hmac_sha1(base_key, 16, (const uint8_t *)"encryption", 10, encryption_key);

    /* Verify MAC */
    uint8_t computed_mac[20];
    platform_hmac_sha1(checksum_key, 20, encrypted, encrypted_len, computed_mac);

    if (memcmp(computed_mac, checksum, 20) != 0) {
        fprintf(stderr, "[%s] MAC MISMATCH!\n", TAG);
        free(blob);
        return -2;
    }
    fprintf(stderr, "[%s] MAC verified OK\n", TAG);

    /* Step 3: AES-128-CTR decrypt */
    platform_aes_ctr128(encryption_key, iv, encrypted, encrypted_len);

    /* Convert CTR output (which is base64) to string and decode */
    char *ctr_str = malloc(encrypted_len + 1);
    if (!ctr_str) { free(blob); return -1; }
    memcpy(ctr_str, encrypted, encrypted_len);
    ctr_str[encrypted_len] = '\0';

    size_t inner_max = 8192;
    uint8_t *inner_blob = malloc(inner_max);
    if (!inner_blob) { free(ctr_str); free(blob); return -1; }

    size_t inner_len = platform_base64_decode(ctr_str, encrypted_len,
                                              inner_blob, inner_max);
    free(ctr_str);
    free(blob);  /* outer blob no longer needed */

    if (inner_len == 0) {
        fprintf(stderr, "[%s] Inner base64 decode failed\n", TAG);
        free(inner_blob);
        return -3;
    }
    fprintf(stderr, "[%s] Inner blob: %zu bytes\n", TAG, inner_len);

    /* Step 4: Derive AES-192-ECB key via PBKDF2
     * V13: SHA1(device_id) → PBKDF2(SHA1, username, 256) → SHA1 → + 0x00000014 */
    uint8_t secret[20];
    platform_sha1((const uint8_t *)device_id, strlen(device_id), secret);

    uint8_t pbkdf2_out[20];
    platform_pbkdf2_sha1(secret, 20,
                         (const uint8_t *)username, strlen(username),
                         256, pbkdf2_out, 20);

    uint8_t sha1_of_pbkdf2[20];
    platform_sha1(pbkdf2_out, 20, sha1_of_pbkdf2);

    uint8_t ecb_key[24];
    memcpy(ecb_key, sha1_of_pbkdf2, 20);
    ecb_key[20] = 0x00;
    ecb_key[21] = 0x00;
    ecb_key[22] = 0x00;
    ecb_key[23] = 0x14;

    fprintf(stderr, "[%s] DEBUG ECB key=", TAG);
    for (int _i = 0; _i < 24; _i++) fprintf(stderr, "%02x", ecb_key[_i]);
    fprintf(stderr, "\n");

    /* Step 5: AES-192-ECB decrypt */
    /* Pad to 16-byte boundary if needed */
    size_t padded_len = inner_len;
    if (padded_len % 16 != 0) {
        padded_len = ((padded_len / 16) + 1) * 16;
        inner_blob = realloc(inner_blob, padded_len);
        memset(inner_blob + inner_len, 0, padded_len - inner_len);
    }
    platform_aes_ecb_decrypt192(ecb_key, inner_blob, padded_len);
    {
        fprintf(stderr, "[%s] DEBUG after-ECB first32=", TAG);
        for (size_t _di = 0; _di < 32 && _di < inner_len; _di++) fprintf(stderr, "%02x", inner_blob[_di]);
        fprintf(stderr, "\n");
    }

    /* Step 6: XOR post-processing */
    for (size_t i = 0; i < inner_len && i + 16 < inner_len; i++) {
        inner_blob[inner_len - i - 1] ^= inner_blob[inner_len - i - 17];
    }
    {
        fprintf(stderr, "[%s] DEBUG after-XOR first32=", TAG);
        for (size_t _di = 0; _di < 32 && _di < inner_len; _di++)
            fprintf(stderr, "%02x", inner_blob[_di]);
        fprintf(stderr, "\n");
    }

    /* Step 7: Protobuf parse — V13 style: always advance pos */
    size_t pos = 0;

    /* Field 1: username */
    if (pos >= inner_len) { free(inner_blob); return -4; }
    uint8_t f1_tag = inner_blob[pos++];
    if (f1_tag != 0x0a) {
        fprintf(stderr, "[%s] Field1 tag 0x%02x (expected 0x0a), advancing anyway\n", TAG, f1_tag);
    }
    uint32_t name_len = read_varint(inner_blob, &pos, inner_len);
    fprintf(stderr, "[%s] Username length: %u\n", TAG, name_len);
    pos += name_len; /* skip username bytes */

    /* Field 2: authType */
    if (pos >= inner_len) { free(inner_blob); return -4; }
    uint8_t f2_tag = inner_blob[pos++];
    if (f2_tag != 0x10) {
        fprintf(stderr, "[%s] Field2 tag 0x%02x (expected 0x10), continuing\n", TAG, f2_tag);
    }
    uint32_t at = read_varint(inner_blob, &pos, inner_len);
    *auth_type = (int)at;
    fprintf(stderr, "[%s] AuthType: %d\n", TAG, *auth_type);

    /* Field 3: authData */
    if (pos >= inner_len) { free(inner_blob); return -4; }
    uint8_t f3_tag = inner_blob[pos++];
    if (f3_tag != 0x1a) {
        fprintf(stderr, "[%s] Field3 tag 0x%02x (expected 0x1a)\n", TAG, f3_tag);
    }
    uint32_t ad_len = read_varint(inner_blob, &pos, inner_len);
    fprintf(stderr, "[%s] AuthData length: %u bytes\n", TAG, ad_len);

    if (pos + ad_len <= inner_len) {
        platform_base64_encode(inner_blob + pos, ad_len,
                               auth_data_b64, auth_b64_size);
        fprintf(stderr, "[%s] AuthData (b64): %s\n", TAG, auth_data_b64);
        free(inner_blob);
        return 0;
    }

    fprintf(stderr, "[%s] WARNING: authData exceeds blob\n", TAG);
    free(inner_blob);
    return -4;
}

/* -------- Session structure -------- */

struct zeroconf_session_t {
    /* Configuration */
    char device_name[128];
    char device_id[64];
    char brand_display[64];
    char model_display[128];
    int bell_port;
    int timeout_seconds;

    /* DH keys */
    uint8_t dh_public[96];
    uint8_t dh_private[96];
    bool dh_ready;

    /* Captured credentials */
    char username[256];
    char blob_b64[4096];
    char client_key_b64[1024];
    char auth_data_b64[4096];
    int auth_type;
    bool creds_captured;

    /* Server state */
    platform_http_server_t *bell;
    platform_mdns_t *mdns;
    bool running;
};

/* -------- Bell HTTP handler -------- */

static int bell_handle_request(zeroconf_session_t *s, platform_socket_t client) {
    uint8_t buf[8192];
    int n = platform_http_server_read(client, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';

    const char *req = (const char *)buf;

    /* Parse method and path */
    char method[16] = {0}, path[512] = {0};
    sscanf(req, "%15s %511s", method, path);

    /* Extract query string */
    const char *query = strchr(path, '?');
    char path_only[512];
    if (query) {
        size_t pl = (size_t)(query - path);
        if (pl >= sizeof(path_only)) pl = sizeof(path_only) - 1;
        memcpy(path_only, path, pl);
        path_only[pl] = '\0';
        query++;
    } else {
        strncpy(path_only, path, sizeof(path_only) - 1);
    }

    if (strcmp(method, "GET") == 0 && strstr(path_only, "/spotify_info")) {
        /* GET /spotify_info?action=getInfo → return device info JSON */
        char body[2048];
        snprintf(body, sizeof(body),
            "{\"accountReq\":\"PREMIUM\",\"activeUser\":\"\","
            "\"availability\":\"\",\"brandDisplayName\":\"%s\","
            "\"deviceID\":\"%s\",\"deviceType\":\"SPEAKER\","
            "\"groupStatus\":\"NONE\",\"libraryVersion\":\"1.0.0\","
            "\"modelDisplayName\":\"%s\",\"productID\":0,"
            "\"publicKey\":\"",
            s->brand_display, s->device_id, s->model_display);

        char resp_buf[4096];
        int off = snprintf(resp_buf, sizeof(resp_buf), "%s", body);

        /* Append public key (base64) */
        char pk_b64[256];
        platform_base64_encode(s->dh_public, 96, pk_b64, sizeof(pk_b64));
        off += snprintf(resp_buf + off, sizeof(resp_buf) - off, "%s", pk_b64);

        off += snprintf(resp_buf + off, sizeof(resp_buf) - off,
            "\",\"remoteName\":\"%s\","
            "\"resolverVersion\":\"0\",\"scope\":\"streaming,client-authorization-universal\","
            "\"spotifyError\":0,\"status\":101,\"statusString\":\"OK\","
            "\"tokenType\":\"default\",\"version\":\"2.7.1\","
            "\"voiceSupport\":\"NO\"}",
            s->device_name);

        char http_resp[5120];
        int resp_len = snprintf(http_resp, sizeof(http_resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n%s", off, resp_buf);

        platform_http_server_write(client, (const uint8_t *)http_resp, resp_len);
        fprintf(stderr, "[%s] GET /spotify_info → device info sent\n", TAG);
        return 0;
    }

    if (strcmp(method, "POST") == 0 && strstr(path_only, "/spotify_info")) {
        /* Extract Content-Length and read full body (Windows recv may split) */
        const char *cl_hdr = strstr(req, "Content-Length:");
        if (cl_hdr) {
            int expected_len = atoi(cl_hdr + 15);
            const char *bs = strstr(req, "\r\n\r\n");
            if (bs) {
                int hdr_end = (int)(bs - req) + 4;
                int body_got = n - hdr_end;
                while (body_got < expected_len && body_got >= 0) {
                    int more = platform_http_server_read(client,
                        buf + n, (int)(sizeof(buf) - 1 - n));
                    if (more <= 0) break;
                    n += more; buf[n] = 0; body_got += more;
                }
            }
        }

        /* Extract body from HTTP request */
        const char *body_start = strstr(req, "\r\n\r\n");
        if (!body_start) return -1;
        body_start += 4;

        char *u = NULL, *b = NULL, *c = NULL;
        
        /* CRITICAL: get_query_param uses static buffer — must copy immediately */
        u = get_query_param(body_start, "userName");
        if (!u) u = get_query_param(body_start, "username");
        if (u) strncpy(s->username, u, sizeof(s->username) - 1);
        
        b = get_query_param(body_start, "blob");
        if (b) strncpy(s->blob_b64, b, sizeof(s->blob_b64) - 1);
        
        c = get_query_param(body_start, "clientKey");
        if (c) strncpy(s->client_key_b64, c, sizeof(s->client_key_b64) - 1);


        if (s->username[0] && s->blob_b64[0] && s->client_key_b64[0]) {
            fprintf(stderr, "\n[%s] *** Credentials POST received! ***\n", TAG);
            fprintf(stderr, "[%s] Username: %s\n", TAG, s->username);
            s->creds_captured = true;
        }

        const char *ok = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Content-Length: 42\r\n"
                         "Access-Control-Allow-Origin: *\r\n"
                         "\r\n"
                         "{\"status\":101,\"spotifyError\":0,\"statusString\":\"OK\"}";
        platform_http_server_write(client, (const uint8_t *)ok, strlen(ok));
        return 0;
    }

    /* 404 */
    const char *nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
    platform_http_server_write(client, (const uint8_t *)nf, strlen(nf));
    return 0;
}

/* -------- Public API -------- */

zeroconf_session_t *zeroconf_init(const zeroconf_config_t *config) {
    if (!config) return NULL;

    zeroconf_session_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    /* Set defaults */
    s->bell_port = config->bell_port ? config->bell_port : 7864;
    s->timeout_seconds = config->timeout_seconds;

    if (config->device_name)
        strncpy(s->device_name, config->device_name, sizeof(s->device_name) - 1);
    else
        strncpy(s->device_name, "ESPConnect", sizeof(s->device_name) - 1);

    if (config->device_id)
        strncpy(s->device_id, config->device_id, sizeof(s->device_id) - 1);
    else
        strncpy(s->device_id, DEFAULT_DEVICE_ID, sizeof(s->device_id) - 1);

    if (config->brand_display)
        strncpy(s->brand_display, config->brand_display, sizeof(s->brand_display) - 1);
    else
        strncpy(s->brand_display, "cspot", sizeof(s->brand_display) - 1);

    if (config->model_display)
        strncpy(s->model_display, config->model_display, sizeof(s->model_display) - 1);
    else
        strncpy(s->model_display, s->device_name, sizeof(s->model_display) - 1);

    /* Generate DH keypair */
    platform_dh_generate_keypair(s->dh_public, s->dh_private);
    s->dh_ready = true;

    fprintf(stderr, "[%s] Initialized (device: %s, id: %s)\n",
            TAG, s->device_name, s->device_id);

    return s;
}

int zeroconf_start(zeroconf_session_t *session) {
    if (!session || !session->dh_ready) return -1;

    /* Start Bell HTTP server */
    session->bell = platform_http_server_start(session->bell_port);
    if (!session->bell) {
        fprintf(stderr, "[%s] Failed to start Bell HTTP server on port %d\n",
                TAG, session->bell_port);
        return -2;
    }
    fprintf(stderr, "[%s] Bell HTTP server on port %d\n", TAG, session->bell_port);

    /* Start mDNS */
    session->mdns = platform_mdns_start(session->device_name);
    if (session->mdns) {
        const char *txt[] = {
            "VERSION=1.0",
            "CPath=/spotify_info",
            "Stack=SP",
            NULL
        };
        platform_mdns_register_service(session->mdns,
                                       session->device_name,
                                       "_spotify-connect._tcp.local",
                                       session->bell_port,
                                       txt);
    }

    session->running = true;
    fprintf(stderr, "[%s] Advertising as \"%s\" — open Spotify Devices to connect\n",
            TAG, session->device_name);

    return 0;
}

int zeroconf_poll(zeroconf_session_t *session, int timeout_ms) {
    if (!session || !session->running) return -1;

    /* Already have creds? */
    if (session->creds_captured) return 1;

    /* Accept one connection */
    platform_socket_t client = platform_http_server_accept(session->bell, timeout_ms);
    if (client == PLATFORM_SOCKET_INVALID) return 0;

    bell_handle_request(session, client);
    platform_tcp_close(client);

    return session->creds_captured ? 1 : 0;
}

int zeroconf_get_credentials(zeroconf_session_t *session,
                             zeroconf_credentials_t *creds) {
    if (!session || !creds) return -1;
    if (!session->creds_captured) return -2;

    memset(creds, 0, sizeof(*creds));

    /* Compute DH shared secret */
    uint8_t client_key_bin[128] = {0};
    size_t ck_len = platform_base64_decode(session->client_key_b64,
                                            strlen(session->client_key_b64),
                                            client_key_bin, sizeof(client_key_bin));
    if (ck_len == 0) return -3;

    uint8_t shared_secret[96];
    platform_dh_compute_shared(session->dh_private, client_key_bin, ck_len,
                               shared_secret);

    /* DEBUG: print key lengths and shared secret first bytes */
    for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", session->dh_private[i]);
    for (int i = 0; i < 8; i++) fprintf(stderr, "%02x", shared_secret[i]);
    fprintf(stderr, "\n");

    /* Decrypt the blob */
    char auth_data_b64[4096] = {0};
    int auth_type = 0;
    int ret = process_blob(session->blob_b64, session->username,
                           session->device_id, shared_secret, 96,
                           auth_data_b64, sizeof(auth_data_b64), &auth_type);
    if (ret != 0) {
        fprintf(stderr, "[%s] Blob decryption failed: %d\n", TAG, ret);
        return ret;
    }

    creds->username = strdup(session->username);
    creds->auth_data_b64 = strdup(auth_data_b64);
    creds->auth_type = auth_type;
    creds->success = true;

    fprintf(stderr, "[%s] Credentials extracted: user=%s, authType=%d\n",
            TAG, creds->username, creds->auth_type);

    return 0;
}

void zeroconf_free_credentials(zeroconf_credentials_t *creds) {
    if (!creds) return;
    free(creds->username);
    free(creds->auth_data_b64);
    memset(creds, 0, sizeof(*creds));
}

void zeroconf_stop(zeroconf_session_t *session) {
    if (!session) return;
    session->running = false;
    if (session->mdns) {
        platform_mdns_stop(session->mdns);
        session->mdns = NULL;
    }
    if (session->bell) {
        platform_http_server_stop(session->bell);
        session->bell = NULL;
    }
}

void zeroconf_destroy(zeroconf_session_t *session) {
    if (!session) return;
    zeroconf_stop(session);
    free(session);
}
