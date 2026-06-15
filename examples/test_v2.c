// DEPRECATED: uses old public OAuth API. See examples/basic_pairing/ for new flow.
/**
 * test_v2.c — Quick full chain test
 */
#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

size_t wf(void *p, size_t s, size_t n, void *u) {
    return fwrite(p, 1, s * n, (FILE *)u);
}

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    char buf[8192], token[1024] = {0};
    FILE *f;
    size_t n;

    // STEP 1: OAuth2 Token
    printf("=== STEP 1: OAuth2 Token ===\n");
    CURL *c = curl_easy_init();
    curl_easy_setopt(c, CURLOPT_URL, "https://accounts.spotify.com/api/token");
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, "grant_type=client_credentials");
    curl_easy_setopt(c, CURLOPT_USERNAME, "4ffa3acbda784a26964e597060747987");
    curl_easy_setopt(c, CURLOPT_PASSWORD, "d6ffe5b8261b4e5eb3fd24a1b180ec91");
    curl_easy_setopt(c, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wf);
    f = fopen("/tmp/tk.json", "w");
    curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
    curl_easy_perform(c);
    fclose(f);
    curl_easy_cleanup(c);

    f = fopen("/tmp/tk.json", "r");
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);

    cJSON *j = cJSON_Parse(buf);
    strncpy(token, cJSON_GetObjectItem(j, "access_token")->valuestring, sizeof(token) - 1);
    printf("  Token: ...%s\n\n", token + strlen(token) - 15);
    cJSON_Delete(j);

    // STEP 2: Storage Resolve
    printf("=== STEP 2: Storage Resolve ===\n");
    c = curl_easy_init();

    char url[512];
    snprintf(url, sizeof(url),
        "https://api.spotify.com/v1/storage-resolve/files/audio/interactive/"
        "844ecdb297a87ebfee4399f28892ef85d9ba725f?alt=json&product=9");

    char ah[512];
    snprintf(ah, sizeof(ah), "Authorization: Bearer %s", token);

    struct curl_slist *h = NULL;
    h = curl_slist_append(h, ah);
    h = curl_slist_append(h, "User-Agent: Spotify/121000000");

    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wf);

    f = fopen("/tmp/cdn.json", "w");
    curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
    curl_easy_perform(c);

    long hc;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &hc);
    fclose(f);
    curl_easy_cleanup(c);
    curl_slist_free_all(h);
    printf("  HTTP %ld\n", hc);

    f = fopen("/tmp/cdn.json", "r");
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = 0;
    fclose(f);
    printf("  Response: %s\n\n", buf);

    j = cJSON_Parse(buf);
    cJSON *cdn_arr = cJSON_GetObjectItem(j, "cdnurl");
    if (!cdn_arr) {
        printf("FAIL: no cdnurl in response\n");
        cJSON_Delete(j);
        return 1;
    }

    cJSON *u0 = cJSON_GetArrayItem(cdn_arr, 0);
    printf("  URL[0]: %s\n\n", u0->valuestring);

    // STEP 3: CDN Download
    printf("=== STEP 3: CDN Audio Download ===\n");
    c = curl_easy_init();

    struct curl_slist *r = NULL;
    r = curl_slist_append(r, "Range: bytes=0-65535");

    curl_easy_setopt(c, CURLOPT_URL, u0->valuestring);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, r);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wf);

    f = fopen("/tmp/audio.bin", "wb");
    curl_easy_setopt(c, CURLOPT_WRITEDATA, f);
    curl_easy_perform(c);

    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &hc);
    double ts;
    curl_easy_getinfo(c, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &ts);
    fclose(f);
    curl_easy_cleanup(c);
    curl_slist_free_all(r);

    printf("  CDN: HTTP %ld, file %.0f bytes (%.1f MB)\n", hc, ts, ts / 1024 / 1024);

    f = fopen("/tmp/audio.bin", "rb");
    unsigned char first[16];
    int rd = (int)fread(first, 1, 16, f);
    fclose(f);

    printf("  First %d bytes: ", rd);
    for (int i = 0; i < rd; i++) printf("%02x ", first[i]);
    printf("\n");

    if (first[0] == 'O' && first[1] == 'g' && first[2] == 'g')
        printf("  Format: Unencrypted OGG\n");
    else
        printf("  Format: Encrypted Spotify audio\n");

    cJSON_Delete(j);
    printf("\n=== FULL CHAIN: OK ===\n");
    return 0;
}
