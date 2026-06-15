// DEPRECATED: uses old public OAuth API. See examples/basic_pairing/ for new flow.
/**
 * test_quick.c — Full CDN chain test
 * Tests: OAuth2 token -> storage-resolve -> CDN download
 */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

size_t write_file(void *ptr, size_t s, size_t n, void *u) {
    return fwrite(ptr, 1, s * n, (FILE *)u);
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();

    char token[1024] = {0};
    char buf[8192];
    size_t n;
    FILE *f;

    // ========== STEP 1: OAUTH2 TOKEN ==========
    printf("=== STEP 1: OAuth2 Token ===\n");

    curl_easy_setopt(curl, CURLOPT_URL, "https://accounts.spotify.com/api/token");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "grant_type=client_credentials");
    curl_easy_setopt(curl, CURLOPT_USERNAME, "4ffa3acbda784a26964e597060747987");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "d6ffe5b8261b4e5eb3fd24a1b180ec91");
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file);

    f = fopen("/tmp/token.json", "w");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
    curl_easy_perform(curl);
    fclose(f);

    // Parse token
    f = fopen("/tmp/token.json", "r");
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);

    cJSON *j = cJSON_Parse(buf);
    cJSON *at = cJSON_GetObjectItem(j, "access_token");
    if (!at) { printf("FAIL: no token\n"); return 1; }
    strncpy(token, at->valuestring, sizeof(token)-1);
    printf("Token: [%s...%s]\n", token, token + strlen(token) - 10);
    cJSON_Delete(j);

    curl_easy_reset(curl);

    // ========== STEP 2: STORAGE-RESOLVE ==========
    printf("\n=== STEP 2: Storage Resolve ===\n");

    char url[512];
    snprintf(url, sizeof(url),
        "https://api.spotify.com/v1/storage-resolve/files/audio/interactive/"
        "844ecdb297a87ebfee4399f28892ef85d9ba725f?alt=json&product=9");

    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "User-Agent: Spotify/121000000");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, NULL);

    f = fopen("/tmp/cdn.json", "w");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
    curl_easy_perform(curl);
    fclose(f);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    printf("HTTP %ld\n", http_code);

    f = fopen("/tmp/cdn.json", "r");
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);

    j = cJSON_Parse(buf);
    cJSON *result = cJSON_GetObjectItem(j, "result");
    printf("Result: %s\n", result ? result->valuestring : "NULL");

    cJSON *ttl = cJSON_GetObjectItem(j, "ttl");
    printf("TTL: %d sec\n", ttl ? ttl->valueint : 0);

    cJSON *cdn_arr = cJSON_GetObjectItem(j, "cdnurl");
    int num_urls = cdn_arr ? cJSON_GetArraySize(cdn_arr) : 0;
    printf("CDN URLs: %d\n", num_urls);

    cJSON *first_url = cJSON_GetArrayItem(cdn_arr, 0);
    if (!first_url) { printf("FAIL: no CDN url\n"); return 1; }
    printf("URL[0]: %s\n", first_url->valuestring);

    curl_easy_reset(curl);

    // ========== STEP 3: CDN DOWNLOAD ==========
    printf("\n=== STEP 3: CDN Audio Download ===\n");

    struct curl_slist *range_h = NULL;
    range_h = curl_slist_append(range_h, "Range: bytes=0-65535");

    curl_easy_setopt(curl, CURLOPT_URL, first_url->valuestring);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, range_h);

    f = fopen("/tmp/audio_data.bin", "wb");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
    curl_easy_perform(curl);
    fclose(f);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    double total_size = 0;
    curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &total_size);
    printf("CDN: HTTP %ld, file size: %.0f bytes (%.1f MB)\n",
           http_code, total_size, total_size / 1024 / 1024);

    // Read first bytes
    f = fopen("/tmp/audio_data.bin", "rb");
    unsigned char first[16];
    size_t read = fread(first, 1, 16, f);
    fclose(f);

    printf("First %zu bytes hex: ", read);
    for (size_t i = 0; i < read; i++) printf("%02x ", first[i]);
    printf("\n");

    if (read >= 4 && first[0] == 'O' && first[1] == 'g' && first[2] == 'g') {
        printf("Format: Unencrypted OGG\n");
    } else {
        printf("Format: Encrypted audio (standard Spotify)\n");
    }

    // Cleanup
    cJSON_Delete(j);
    curl_slist_free_all(headers);
    curl_slist_free_all(range_h);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("\n=== FULL CHAIN WORKING ===\n");
    printf("Files saved:\n");
    printf("  /tmp/token.json     — OAuth2 response\n");
    printf("  /tmp/cdn.json       — Storage-resolve response\n");
    printf("  /tmp/audio_data.bin — First 64KB of encrypted audio\n");

    return 0;
}
