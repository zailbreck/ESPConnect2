// zeroconf.h — Spotify ZeroConf Credential Extraction API
// =======================================================
// Captures Spotify login credentials via mDNS advertisement +
// Bell HTTP server + Diffie-Hellman key exchange + blob decryption.
//
// This is the "pairing" step: the Spotify app discovers the device
// through mDNS, sends encrypted credentials via HTTP, and this module
// decrypts them to produce authData for login5.
//
// Sources & References:
//   mDNS discovery:   mdns library (MIT) — https://github.com/mjansson/mdns
//   DH key exchange:  cspot (MIT) — https://github.com/feelfreelinux/cspot/blob/master/cspot/src/Crypto.cpp
//   AES/CTR decrypt:  cspot (MIT) — Crypto.cpp
//   PBKDF2 + ECB:     librespot (MIT) — credentials.rs
//   Protobuf schema:  cspot (MIT) — keyexchange.proto
//   Bell HTTP:        cspot (MIT) — BellTask.cpp
//
// License: MIT — derived from cspot & librespot

#ifndef SPOTIFY_ZEROCONF_H
#define SPOTIFY_ZEROCONF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle for ZeroConf session
 */
typedef struct zeroconf_session_t zeroconf_session_t;

/**
 * @brief Result of credential extraction
 */
typedef struct {
    char *username;          /**< Spotify username (caller must free) */
    char *auth_data_b64;     /**< AuthData as base64 string (caller must free) */
    int auth_type;           /**< Auth type from protobuf (typically 1=stored) */
    bool success;             /**< Whether extraction was successful */
} zeroconf_credentials_t;

/**
 * @brief ZeroConf configuration
 */
typedef struct {
    const char *device_name;    /**< Display name shown in Spotify app */
    const char *device_id;      /**< 32-char hex device ID (used for PBKDF2) */
    const char *brand_display;  /**< Brand string (default: "cspot") */
    const char *model_display;  /**< Model string (default: same as device_name) */
    int bell_port;              /**< Bell HTTP port (default: 7864) */
    int timeout_seconds;        /**< How long to wait for pairing (0=indefinite) */
} zeroconf_config_t;

/**
 * @brief Initialize ZeroConf session.
 *
 * Generates DH keypair, prepares Bell HTTP server.
 *
 * @param config Configuration parameters
 * @return Session handle, NULL on error
 */
zeroconf_session_t *zeroconf_init(const zeroconf_config_t *config);

/**
 * @brief Start mDNS advertisement and Bell HTTP server.
 *
 * After this call, the device appears in the Spotify app's
 * "Devices" list. When the user selects it, credentials are
 * automatically captured and decrypted.
 *
 * @param session Session handle from zeroconf_init
 * @return 0 on success, negative on error
 */
int zeroconf_start(zeroconf_session_t *session);

/**
 * @brief Poll for incoming credentials.
 *
 * Blocks for up to timeout_ms waiting for a credential POST.
 * Call repeatedly until credentials are captured.
 *
 * @param session Session handle
 * @param timeout_ms Poll timeout in milliseconds (0=non-blocking)
 * @return 1 if credentials were captured, 0 if timeout, negative on error
 */
int zeroconf_poll(zeroconf_session_t *session, int timeout_ms);

/**
 * @brief Get the extracted credentials.
 *
 * Only valid after zeroconf_poll() returns 1.
 * The returned struct contains heap-allocated strings that the
 * caller must free with zeroconf_free_credentials().
 *
 * @param session Session handle
 * @param creds Output credentials struct (caller provides pointer)
 * @return 0 on success, negative if no credentials available
 */
int zeroconf_get_credentials(zeroconf_session_t *session,
                             zeroconf_credentials_t *creds);

/**
 * @brief Free credentials allocated by zeroconf_get_credentials
 */
void zeroconf_free_credentials(zeroconf_credentials_t *creds);

/**
 * @brief Stop mDNS and Bell server
 */
void zeroconf_stop(zeroconf_session_t *session);

/**
 * @brief Destroy session and free all resources
 */
void zeroconf_destroy(zeroconf_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* SPOTIFY_ZEROCONF_H */
