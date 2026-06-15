// DEPRECATED: uses old public OAuth API. See examples/basic_pairing/ for new flow.
/**
 * test_cdn.c — CDN resolution test tool
 * 
 * Tests the full CDN audio resolution flow:
 * 1. OAuth2 Client Credentials → access token
 * 2. Storage-resolve → CDN URLs
 * 3. CDN download → audio data
 * 
 * Compile: gcc -o test_cdn test_cdn.c -lcurl -lcjson
 * Run:     ./test_cdn <client_id> <client_secret> [file_id]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

#define MAX_RESPONSE 65536

typedef struct {
    char *data;
    size_t size;
} response_t;

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    response_t *resp = (response_t *)userdata;

    if (resp->size + total >= MAX_RESPONSE - 1) {
        total = MAX_RESPONSE - 1 - resp->size;
    }

    memcpy(resp->data + resp->size, ptr, total);
    resp->size += total;
    resp->data[resp->size] = '\0';

    return total;
}

/**
 * Step 1: Get OAuth2 token via Client Credentials
 */
static int get_oauth_token(const char *client_id, const char *client_secret, char *token) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    // Build auth header
    char credentials[256];
    snprintf(credentials, sizeof(credentials), "%s:%s", client_id, client_secret);

    char *encoded = curl_easy_escape(curl, credentials, 0);
    // Actually, for Basic auth we need base64, not URL encoding
    // Let's handle this differently
    curl_free(encoded);

    // Set up request
    char post_data[] = "grant_type=client_credentials";
    response_t resp = {.data = calloc(1, MAX_RESPONSE), .size = 0};

    curl_easy_setopt(curl, CURLOPT_URL, "https://accounts.spotify.com/api/token");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_USERNAME, client_id);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, client_secret);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
        free(resp.data);
        curl_easy_cleanup(curl);
        return -2;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    printf("[✓] Token response: HTTP %ld (%zu bytes)\n", http_code, resp.size);

    if (http_code != 200) {
        printf("[!] Error: %s\n", resp.data);
        free(resp.data);
        curl_easy_cleanup(curl);
        return -3;
    }

    // Parse JSON
    cJSON *json = cJSON_Parse(resp.data);
    if (!json) {
        printf("[!] JSON parse error\n");
        free(resp.data);
        curl_easy_cleanup(curl);
        return -4;
    }

    cJSON *access_token = cJSON_GetObjectItem(json, "access_token");
    if (!access_token || !cJSON_IsString(access_token)) {
        printf("[!] No access_token in response\n");
        cJSON_Delete(json);
        free(resp.data);
        curl_easy_cleanup(curl);
        return -5;
    }

    strncpy(token, access_token->valuestring, 511);
    token[511] = '\0';

    cJSON *expires = cJSON_GetObjectItem(json, "expires_in");
    if (expires && cJSON_IsNumber(expires)) {
        printf("[+] Token expires in: %d seconds\n", expires->valueint);
    }

    cJSON_Delete(json);
    free(resp.data);
    curl_easy_cleanup(curl);

    printf("[+] Token: %s...\n", token + (strlen(token) > 30 ? strlen(token) - 30 : 0));
    return 0;
}

/**
 * Step 2: Resolve CDN URL from storage-resolve endpoint
 */
static int resolve_cdn(const char *token, const char *file_id, cJSON **cdn_json) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[512];
    snprintf(url, sizeof(url),
             "https://api.spotify.com/v1/storage-resolve/files/audio/interactive/"
             "%s?alt=json&product=9",
             file_id);

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "User-Agent: Spotify/121000000");

    response_t resp = {.data = calloc(1, MAX_RESPONSE), .size = 0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
        free(resp.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -2;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    printf("[✓] Storage-resolve: HTTP %ld (%zu bytes)\n", http_code, resp.size);

    if (http_code != 200) {
        printf("[!] Error: %s\n", resp.data);
        free(resp.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -3;
    }

    *cdn_json = cJSON_Parse(resp.data);

    curl_slist_free_all(headers);
    free(resp.data);
    curl_easy_cleanup(curl);

    return 0;
}

/**
 * Step 3: Download first bytes from CDN URL
 */
static int download_from_cdn(const char *cdn_url, unsigned char *buffer, size_t *out_len) {
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char range[64];
    snprintf(range, sizeof(range), "bytes=0-65535");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, range);

    response_t resp = {.data = (char *)calloc(1, 65536), .size = 0};

    curl_easy_setopt(curl, CURLOPT_URL, cdn_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "CDN curl error: %s\n", curl_easy_strerror(res));
        free(resp.data);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -2;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    double content_length = 0;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &content_length);

    printf("[✓] CDN download: HTTP %ld, total file %0.f bytes, got %zu bytes\n",
           http_code, content_length, resp.size);

    if (resp.size > 0 && out_len) {
        memcpy(buffer, resp.data, resp.size);
        *out_len = resp.size;
    }

    curl_slist_free_all(headers);
    free(resp.data);
    curl_easy_cleanup(curl);

    return 0;
}

/**
 * Print CDN info
 */
static void print_cdn_info(cJSON *json, const char *file_id) {
    printf("\n=== CDN Info ===\n");

    cJSON *result = cJSON_GetObjectItem(json, "result");
    printf("Result: %s\n", result && cJSON_IsString(result) ? result->valuestring : "?");

    cJSON *fileid = cJSON_GetObjectItem(json, "fileid");
    printf("FileID: %s\n", fileid && cJSON_IsString(fileid) ? fileid->valuestring : "?");

    cJSON *ttl = cJSON_GetObjectItem(json, "ttl");
    printf("TTL: %d seconds (%d hours)\n", ttl && cJSON_IsNumber(ttl) ? ttl->valueint : 0,
           ttl && cJSON_IsNumber(ttl) ? ttl->valueint / 3600 : 0);

    cJSON *cdnurl = cJSON_GetObjectItem(json, "cdnurl");
    if (cdnurl && cJSON_IsArray(cdnurl)) {
        int n = cJSON_GetArraySize(cdnurl);
        printf("CDN URLs: %d\n", n);
        for (int i = 0; i < n && i < 3; i++) {
            cJSON *url = cJSON_GetArrayItem(cdnurl, i);
            if (url && cJSON_IsString(url)) {
                printf("  [%d] %s\n", i, url->valuestring);
            }
        }
        if (n > 3) printf("  ... and %d more\n", n - 3);
    }
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <client_id> <client_secret> [file_id]\n", argv[0]);
        printf("\nDefault file_id: 844ecdb297a87ebfee4399f28892ef85d9ba725f\n");
        printf("(a known Spotify test track)\n");
        return 1;
    }

    const char *client_id = argv[1];
    const char *client_secret = argv[2];
    const char *file_id = argc > 3 ? argv[3] : "844ecdb297a87ebfee4399f28892ef85d9ba725f";

    printf("=== esp-spotify-connect: CDN Test Tool ===\n\n");

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Step 1: Get OAuth token
    printf("Step 1: Getting OAuth2 token...\n");
    char token[512];
    int ret = get_oauth_token(client_id, client_secret, token);
    if (ret != 0) {
        printf("[!] Failed to get token (error %d)\n", ret);
        curl_global_cleanup();
        return 1;
    }

    // Step 2: Resolve CDN URL
    printf("\nStep 2: Resolving CDN for file %s...\n", file_id);
    cJSON *cdn_json = NULL;
    ret = resolve_cdn(token, file_id, &cdn_json);
    if (ret != 0) {
        printf("[!] Failed to resolve CDN (error %d)\n", ret);
        curl_global_cleanup();
        return 1;
    }

    if (!cdn_json) {
        printf("[!] No CDN info returned\n");
        curl_global_cleanup();
        return 1;
    }

    print_cdn_info(cdn_json, file_id);

    // Step 3: Download first bytes from CDN
    printf("\nStep 3: Downloading audio from CDN...\n");
    cJSON *cdnurl = cJSON_GetObjectItem(cdn_json, "cdnurl");
    if (cdnurl && cJSON_IsArray(cdnurl) && cJSON_GetArraySize(cdnurl) > 0) {
        cJSON *first_url = cJSON_GetArrayItem(cdnurl, 0);
        if (first_url && cJSON_IsString(first_url)) {
            unsigned char audio_data[65536];
            size_t audio_size = 0;

            ret = download_from_cdn(first_url->valuestring, audio_data, &audio_size);
            if (ret == 0 && audio_size > 0) {
                // Verify we got valid encrypted Ogg/Opus data
                printf("\nAudio data analysis:\n");
                printf("  First 16 bytes hex: ");
                for (size_t i = 0; i < 16 && i < audio_size; i++) {
                    printf("%02x ", audio_data[i]);
                }
                printf("\n");
                printf("  Total downloaded: %zu bytes\n", audio_size);

                // Check for OggS sync pattern (might be encrypted, but still worth checking)
                if (audio_data[0] == 'O' && audio_data[1] == 'g' && audio_data[2] == 'g') {
                    printf("  Format: OGG/Opus (not encrypted)\n");
                } else {
                    printf("  Format: Encrypted (standard Spotify)\n");
                }
            }
        }
    }

    cJSON_Delete(cdn_json);
    curl_global_cleanup();

    printf("\n=== CDN Test Complete! ===\n");
    return 0;
}
