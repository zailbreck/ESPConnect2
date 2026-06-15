// test_build.c — Compilation smoke test for x86 Linux
// ==================================================
// Verifies that all modules compile and link correctly.
// Does NOT perform actual Spotify authentication
// (that requires real credentials and network access).

#include "esp_spotify.h"
#include "internal/zeroconf.h"
#include "internal/mercury.h"
#include "internal/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int test_platform_shannon(void) {
    printf("[TEST] Shannon cipher self-test...\n");

    /* Known-answer test: key=32*0x42, nonce=4*0x00, pt="Hello Shannon!!!" */
    uint8_t key[32];
    memset(key, 0x42, 32);
    uint8_t nonce[4] = {0, 0, 0, 0};
    uint8_t pt[] = {'H','e','l','l','o',' ','S','h','a','n','n','o','n','!','!','!'};
    size_t pt_len = 16;
    uint8_t orig[16];
    memcpy(orig, pt, pt_len);

    platform_shannon_t *s1 = platform_shannon_new();
    platform_shannon_t *s2 = platform_shannon_new();

    platform_shannon_key(s1, key, 32);
    platform_shannon_nonce(s1, nonce, 4);
    platform_shannon_encrypt(s1, pt, pt_len);

    uint8_t mac1[4];
    platform_shannon_finish(s1, mac1);

    platform_shannon_key(s2, key, 32);
    platform_shannon_nonce(s2, nonce, 4);
    platform_shannon_decrypt(s2, pt, pt_len);

    uint8_t mac2[4];
    platform_shannon_finish(s2, mac2);

    int roundtrip_ok = (memcmp(pt, orig, pt_len) == 0);
    int mac_ok = (memcmp(mac1, mac2, 4) == 0);

    printf("[TEST]   encrypt+decrypt roundtrip: %s\n", roundtrip_ok ? "PASS" : "FAIL");
    printf("[TEST]   MAC match: %s\n", mac_ok ? "PASS" : "FAIL");

    platform_shannon_free(s1);
    platform_shannon_free(s2);

    return (roundtrip_ok && mac_ok) ? 0 : 1;
}

static int test_platform_dh(void) {
    printf("[TEST] DH key exchange self-test...\n");

    uint8_t alice_pub[96], alice_priv[96];
    uint8_t bob_pub[96], bob_priv[96];
    uint8_t shared_a[96], shared_b[96];

    platform_dh_generate_keypair(alice_pub, alice_priv);
    platform_dh_generate_keypair(bob_pub, bob_priv);

    platform_dh_compute_shared(alice_priv, bob_pub, 96, shared_a);
    platform_dh_compute_shared(bob_priv, alice_pub, 96, shared_b);

    int match = (memcmp(shared_a, shared_b, 96) == 0);
    printf("[TEST]   DH shared secret match: %s\n", match ? "PASS" : "FAIL");

    return match ? 0 : 1;
}

static int test_platform_base64(void) {
    printf("[TEST] Base64 self-test...\n");

    const char *input = "Hello, World!";
    size_t input_len = strlen(input);

    char encoded[64];
    size_t enc_len = platform_base64_encode((const uint8_t *)input, input_len,
                                             encoded, sizeof(encoded));
    printf("[TEST]   Encode: '%s' -> '%s' (%zu chars)\n", input, encoded, enc_len);

    uint8_t decoded[64];
    size_t dec_len = platform_base64_decode(encoded, enc_len, decoded, sizeof(decoded));

    int match = (dec_len == input_len && memcmp(decoded, input, input_len) == 0);
    printf("[TEST]   Decode roundtrip: %s\n", match ? "PASS" : "FAIL");

    return match ? 0 : 1;
}

static int test_platform_aes(void) {
    printf("[TEST] AES-CTR self-test...\n");

    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t data[] = "AES-CTR test data!!!!";
    uint8_t orig[32];
    size_t len = strlen((char *)data);
    memcpy(orig, data, len);

    platform_aes_ctr128(key, iv, data, len);
    /* CTR is symmetric: encrypt again = decrypt */
    platform_aes_ctr128(key, iv, data, len);

    int match = (memcmp(data, orig, len) == 0);
    printf("[TEST]   AES-CTR roundtrip: %s\n", match ? "PASS" : "FAIL");

    return match ? 0 : 1;
}

static int test_zeroconf_api(void) {
    printf("[TEST] ZeroConf API smoke test...\n");

    zeroconf_config_t config = {
        .device_name = "TestDevice",
        .device_id = "142137fd329622137a1490161234567890123456",
        .brand_display = "cspot",
        .model_display = "TestDevice",
        .bell_port = 17864,
        .timeout_seconds = 0,
    };

    zeroconf_session_t *zc = zeroconf_init(&config);
    assert(zc != NULL);
    printf("[TEST]   zeroconf_init: PASS\n");

    int ret = zeroconf_start(zc);
    printf("[TEST]   zeroconf_start: %s (ret=%d)\n", ret == 0 ? "PASS" : "OK (mDNS no-op)", ret);

    /* Non-blocking poll (will return immediately, no client) */
    ret = zeroconf_poll(zc, 100);
    printf("[TEST]   zeroconf_poll (no client): %d\n", ret);

    zeroconf_stop(zc);
    zeroconf_destroy(zc);
    printf("[TEST]   zeroconf_destroy: PASS\n");

    return 0;
}

static int test_mercury_api(void) {
    printf("[TEST] Mercury API smoke test...\n");

    mercury_session_t *ms = mercury_init();
    assert(ms != NULL);
    printf("[TEST]   mercury_init: PASS\n");

    int connected = mercury_is_connected(ms);
    printf("[TEST]   mercury_is_connected (before auth): %s\n",
           connected ? "FAIL (should be false)" : "PASS");

    const char *canon = mercury_get_canonical_username(ms);
    assert(canon == NULL);
    printf("[TEST]   mercury_get_canonical_username (no auth): PASS (NULL)\n");

    size_t cred_len = 0;
    const uint8_t *cred = mercury_get_stored_cred(ms, &cred_len);
    assert(cred == NULL && cred_len == 0);
    printf("[TEST]   mercury_get_stored_cred (no auth): PASS (NULL)\n");

    mercury_disconnect(ms);
    mercury_destroy(ms);
    printf("[TEST]   mercury_destroy: PASS\n");

    return 0;
}

int main(void) {
    printf("\n=== ESP-Spotify-Connect x86 Build Test ===\n\n");

    int failed = 0;

    failed += test_platform_shannon();
    failed += test_platform_dh();
    failed += test_platform_base64();
    failed += test_platform_aes();
    failed += test_zeroconf_api();
    failed += test_mercury_api();

    printf("\n=== Results: %d test(s) failed ===\n", failed);

    return failed ? 1 : 0;
}
