// spclient.c — Spotify Internal API Client
// ==========================================
// Full protocol: client token → metadata → CDN → audio download.
//
// Sources & References:
//   Client token:     librespot (MIT) — token.rs
//   Spclient HTTP:    librespot (MIT) — spclient.rs
//   CDN fetch:        librespot (MIT) — fetch.rs
//   AudioKey:         librespot (MIT) — audio_key.rs / cspot MercurySession.cpp
//
// License: MIT — derived from librespot

#include "internal/spclient.h"
#include "internal/platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define TAG "spclient"

/* ------------------------------------------------------------------ */
/*  Client Token via Mercury                                           */
/*  URI: hm://keymaster/client/token                                   */
/*  Method: SEND (0xb2) with protobuf payload                         */
/* ------------------------------------------------------------------ */

/* Minimal protobuf write helpers for client token request */
static uint8_t *varint_enc(uint8_t *p, uint64_t v) {
    while (v > 0x7F) { *p++ = (v & 0x7F) | 0x80; v >>= 7; }
    *p++ = (uint8_t)(v & 0x7F);
    return p;
}

static size_t varint_size(uint64_t v) {
    size_t sz = 1;
    while (v > 0x7F) { v >>= 7; sz++; }
    return sz;
}

/* RequestType::SEND = 0xb2, data format:
 *   [header(4)][uri_bytes][payload]
 * Mercury header: [seq(2 BE)][flags(1)][parts_count(1)]
 */
int spclient_get_client_token(mercury_session_t *sess,
                              char *token_out, size_t token_size) {
    if (!sess || !token_out || token_size < 4) return -1;

    /* Build Mercury SEND packet */
    const char *uri = "hm://keymaster/client/token";
    size_t uri_len = strlen(uri);

    /* Request payload: protobuf ClientTokenRequest */
    /* field 1: request_type = 1 (STICKY) — varint */
    /* field 2: challenge_answers — empty for now */
    uint8_t payload[128];
    uint8_t *p = payload;

    /* field 1 (varint): request_type = 1 */
    *p++ = 0x08;  /* tag: (1 << 3) | 0 */
    *p++ = 0x01;  /* value: 1 */

    /* field 2 (length-delim): challenge_answers = empty */
    *p++ = 0x12;  /* tag: (2 << 3) | 2 */
    *p++ = 0x00;  /* length: 0 */

    size_t payload_len = p - payload;

    /* Mercury header: [seq(2 BE)][flags(1)=0x04][parts=1] */
    uint8_t header[4] = {0x00, 0x01, 0x04, 0x01};

    /* Build full buffer: [header][uri][payload] */
    size_t body_len = sizeof(header) + uri_len + payload_len;
    uint8_t *body = malloc(body_len);
    memcpy(body, header, sizeof(header));
    memcpy(body + sizeof(header), uri, uri_len);
    memcpy(body + sizeof(header) + uri_len, payload, payload_len);

    fprintf(stderr, "[%s] Sending client token request...\n", TAG);
    int ret = mercury_send(sess, 0xb2, body, body_len);
    free(body);
    if (ret != 0) {
        fprintf(stderr, "[%s] Send failed: %d\n", TAG, ret);
        return -2;
    }

    /* Wait for response — keep receiving until we get a token */
    for (int i = 0; i < 20; i++) {
        uint8_t data[4096];
        size_t len = 0;
        uint8_t cmd;
        ret = mercury_recv(sess, &cmd, data, &len, sizeof(data));
        if (ret != 0) continue;

        if (cmd == 0x00 || cmd == 0x04) {
            mercury_send(sess, 0x4a, NULL, 0);
            continue;
        }

        fprintf(stderr, "[%s] Response cmd=0x%02x sz=%zu\n", TAG, cmd, len);

        /* Look for client token in Mercury response */
        /* After SEND, response comes as cmd=0xb5 (SUBRES) or similar */
        /* For keymaster token, response format varies */
        if (len > 4) {
            /* Simple heuristic: find string "{\"grantedToken\"" in JSON response */
            for (size_t j = 0; j + 15 < len; j++) {
                if (memcmp(data + j, "\"token\":\"", 9) == 0) {
                    char *start = (char *)(data + j + 9);
                    char *end = strchr(start, '"');
                    if (end) {
                        size_t tok_len = end - start;
                        if (tok_len < token_size) {
                            memcpy(token_out, start, tok_len);
                            token_out[tok_len] = '\0';
                            fprintf(stderr, "[%s] Client token obtained (%zu chars)\n",
                                    TAG, tok_len);
                            return 0;
                        }
                    }
                }
            }
        }
    }

    fprintf(stderr, "[%s] No client token in responses\n", TAG);
    return -3;
}

/* ------------------------------------------------------------------ */
/*  Track Metadata                                                     */
/* ------------------------------------------------------------------ */

/* Hex encode 16 bytes to 32 chars + NUL */
static void hex_encode(const uint8_t *in, size_t in_len, char *out) {
    for (size_t i = 0; i < in_len; i++)
        sprintf(out + i * 2, "%02x", in[i]);
    out[in_len * 2] = 0;
}

/* Hex decode 2-char hex to byte */
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Find a JSON string value by key. Returns pointer to value start, writes
 * length to *vallen. Returns NULL if not found. Simple, no full JSON parser. */
static const char *json_strval(const char *json, const char *key, size_t *vallen) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(json, search);
    if (!p) return NULL;
    p += strlen(search);
    const char *end = strchr(p, '"');
    if (!end) return NULL;
    *vallen = end - p;
    return p;
}

int spclient_get_track_metadata(const char *client_token,
                                const uint8_t track_id[16],
                                spclient_track_meta_t *meta_out) {
    if (!client_token || !track_id || !meta_out) return -1;

    memset(meta_out, 0, sizeof(*meta_out));

    /* Build Authorization header */
    char auth[1024];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", client_token);

    /* Build path */
    char track_hex[33];
    hex_encode(track_id, 16, track_hex);

    char path[256];
    snprintf(path, sizeof(path),
             "/metadata/4/track/%s?product=9&country=ID", track_hex);

    const char *headers[] = {auth, "Accept: application/json", NULL};

    fprintf(stderr, "[%s] Fetching metadata for track %s...\n", TAG, track_hex);
    platform_http_response_t resp = platform_https_get(
        "spclient.wg.spotify.com", path, headers, 10);

    if (resp.status_code != 200 || !resp.body) {
        fprintf(stderr, "[%s] HTTP %d, len=%zu\n", TAG, resp.status_code, resp.body_len);
        platform_http_response_free(&resp);
        return -2;
    }

    fprintf(stderr, "[%s] Got metadata: %zu bytes\n", TAG, resp.body_len);

    /* Simple JSON parsing: find file IDs in "file" array.
     * Expected structure: {"file": [{"file_id": "...", "format": "OGG_VORBIS_320"}, ...]} */
    const char *json = (const char *)resp.body;

    /* Count file entries */
    const char *file_search = "\"file\":[";
    const char *arr_start = strstr(json, file_search);
    if (!arr_start) {
        fprintf(stderr, "[%s] No file array in metadata\n", TAG);
        platform_http_response_free(&resp);
        return -3;
    }

    /* Count objects in array by counting "file_id" occurrences */
    int count = 0;
    const char *scan = arr_start;
    while ((scan = strstr(scan, "\"file_id\":\"") )) {
        count++;
        scan++;
    }

    meta_out->files = calloc(count > 0 ? count : 1, sizeof(spclient_file_t));
    meta_out->num_files = count;

    /* Extract each file_id and format */
    scan = arr_start;
    for (int i = 0; i < count; i++) {
        scan = strstr(scan, "\"file_id\":\"");
        if (!scan) break;
        scan += 11;
        memcpy(meta_out->files[i].file_id_hex, scan, 20);
        meta_out->files[i].file_id_hex[20] = '\0';

        /* Try to find format */
        const char *fmt = strstr(scan, "\"format\":\"");
        if (fmt) {
            fmt += 10;
            const char *fmt_end = strchr(fmt, '"');
            size_t flen = fmt_end ? (size_t)(fmt_end - fmt) : 0;
            if (flen < sizeof(meta_out->files[i].format)) {
                memcpy(meta_out->files[i].format, fmt, flen);
                meta_out->files[i].format[flen] = '\0';
            }
        }
        fprintf(stderr, "[%s]   File[%d]: %s (%s)\n", TAG, i,
                meta_out->files[i].file_id_hex,
                meta_out->files[i].format[0] ? meta_out->files[i].format : "unknown");
    }

    platform_http_response_free(&resp);
    return 0;
}

void spclient_free_track_meta(spclient_track_meta_t *meta) {
    if (meta && meta->files) {
        free(meta->files);
        meta->files = NULL;
    }
    meta->num_files = 0;
}

/* ------------------------------------------------------------------ */
/*  CDN Resolution                                                     */
/* ------------------------------------------------------------------ */

int spclient_resolve_cdn_url(const char *client_token,
                             const char *file_id_hex,
                             char *cdn_url_out, size_t url_size) {
    if (!client_token || !file_id_hex || !cdn_url_out || url_size < 256) return -1;

    char auth[1024];
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", client_token);

    char path[512];
    snprintf(path, sizeof(path),
             "/storage-resolve/files/audio/interactive/%s?product=9&alt=json",
             file_id_hex);

    const char *headers[] = {auth, "Accept: application/json", NULL};

    platform_http_response_t resp = platform_https_get(
        "spclient.wg.spotify.com", path, headers, 10);

    if (resp.status_code != 200 || !resp.body) {
        fprintf(stderr, "[%s] CDN resolve HTTP %d\n", TAG, resp.status_code);
        platform_http_response_free(&resp);
        return -2;
    }

    /* Parse "cdnurl":["..."] from JSON */
    const char *json = (const char *)resp.body;
    const char *url_start = strstr(json, "\"cdnurl\":[\"");
    if (!url_start) {
        url_start = strstr(json, "http");
        if (!url_start) {
            fprintf(stderr, "[%s] No CDN URL in response\n", TAG);
            platform_http_response_free(&resp);
            return -3;
        }
        /* URL without cdnurl key */
        const char *url_end = strchr(url_start, '"');
        size_t ulen = url_end ? (size_t)(url_end - url_start) : strlen(url_start);
        if (ulen >= url_size) ulen = url_size - 1;
        memcpy(cdn_url_out, url_start, ulen);
        cdn_url_out[ulen] = '\0';
    } else {
        url_start += 10; /* skip "cdnurl":[" */
        const char *url_end = strchr(url_start, '"');
        size_t ulen = url_end ? (size_t)(url_end - url_start) : strlen(url_start);
        if (ulen >= url_size) ulen = url_size - 1;
        memcpy(cdn_url_out, url_start, ulen);
        cdn_url_out[ulen] = '\0';
    }

    fprintf(stderr, "[%s] CDN URL: %s\n", TAG, cdn_url_out);
    platform_http_response_free(&resp);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  CDN Audio Download                                                 */
/* ------------------------------------------------------------------ */

int spclient_download_audio(const char *cdn_url,
                            size_t offset, size_t length,
                            uint8_t *buffer, size_t buffer_size) {
    if (!cdn_url || !buffer || buffer_size < length) return -1;

    /* Parse host and path from URL */
    const char *url = cdn_url;
    if (strncmp(url, "https://", 8) == 0) url += 8;

    const char *path_start = strchr(url, '/');
    if (!path_start) return -2;

    char host[256];
    size_t host_len = path_start - url;
    if (host_len >= sizeof(host)) return -2;
    memcpy(host, url, host_len);
    host[host_len] = '\0';

    /* Build Range header */
    char range_hdr[128];
    snprintf(range_hdr, sizeof(range_hdr),
             "Range: bytes=%zu-%zu", offset, offset + length - 1);

    const char *headers[] = {range_hdr, "Accept: */*", NULL};

    platform_http_response_t resp = platform_https_get(
        host, path_start, headers, 15);

    if (resp.status_code != 200 && resp.status_code != 206) {
        fprintf(stderr, "[%s] CDN download HTTP %d\n", TAG, resp.status_code);
        platform_http_response_free(&resp);
        return -3;
    }

    size_t copy_len = resp.body_len < buffer_size ? resp.body_len : buffer_size;
    memcpy(buffer, resp.body, copy_len);

    fprintf(stderr, "[%s] Downloaded %zu bytes (offset=%zu)\n",
            TAG, copy_len, offset);
    platform_http_response_free(&resp);
    return (int)copy_len;
}

/* ------------------------------------------------------------------ */
/*  AudioKey via Mercury                                               */
/* ------------------------------------------------------------------ */

static void uint16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF);
}
static void uint32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)(v);
}

int spclient_get_audio_key(mercury_session_t *sess,
                           const uint8_t track_id[16],
                           const uint8_t file_id[16],
                           uint8_t key_out[16]) {
    if (!sess || !track_id || !file_id || !key_out) return -1;

    /* Payload: [FILEID(16)] [TRACKID(16)] [SEQ(4 BE)] [0x00, 0x00]
     * Source: cspot MercurySession::requestAudioKey() */
    uint8_t payload[38];
    memcpy(payload, file_id, 16);
    memcpy(payload + 16, track_id, 16);
    uint32_be(payload + 32, 1);   /* audio key sequence = 1 */
    payload[36] = 0x00;
    payload[37] = 0x00;

    /* AUDIO_KEY_REQUEST_COMMAND = 0x0C */
    fprintf(stderr, "[%s] Requesting AudioKey...\n", TAG);
    int ret = mercury_send(sess, 0x0C, payload, sizeof(payload));
    if (ret != 0) {
        fprintf(stderr, "[%s] AudioKey send failed: %d\n", TAG, ret);
        return -2;
    }

    /* Wait for AUDIO_KEY_SUCCESS (0x0D) or FAILURE (0x0E) */
    for (int i = 0; i < 15; i++) {
        uint8_t data[256];
        size_t len = 0;
        uint8_t cmd;
        ret = mercury_recv(sess, &cmd, data, &len, sizeof(data));
        if (ret != 0) continue;

        if (cmd == 0x00 || cmd == 0x04) {
            mercury_send(sess, 0x4a, NULL, 0);
            continue;
        }

        if (cmd == 0x0D && len >= 16) {
            /* AUDIO_KEY_SUCCESS_RESPONSE: [AES_KEY(16)] */
            memcpy(key_out, data, 16);
            fprintf(stderr, "[%s] AudioKey received!\n", TAG);
            return 0;
        }

        if (cmd == 0x0E) {
            fprintf(stderr, "[%s] AudioKey request FAILED\n", TAG);
            return -3;
        }
    }

    fprintf(stderr, "[%s] AudioKey timeout\n", TAG);
    return -4;
}
