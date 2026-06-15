// mercury.h — Spotify Mercury Protocol Interface
// ================================================
// Mercury is Spotify's pub/sub messaging protocol over the AP connection.
// This module provides Login5 authentication (DH + HMAC challenge + Shannon
// cipher) and Mercury message send/receive.
//
// Sources & References:
//   Shannon cipher:      cspot (MIT) — Shannon.cpp / Shannon.h
//                        https://github.com/feelfreelinux/cspot/tree/master/cspot/src
//   Shannon connection:  cspot (MIT) — ShannonConnection.cpp
//   HMAC challenge:      librespot (MIT) — auth_challenge.rs
//   DH group:            RFC 2409 — Oakley Group 2 (768-bit MODP)
//   Protobuf schema:     cspot (MIT) — keyexchange.proto
//   Login5 flow:         librespot (MIT) — authentication/login5.rs
//   Mercury protocol:    librespot (MIT) — core/src/mercury/
//
// License: MIT — derived from cspot & librespot

#ifndef SPOTIFY_MERCURY_H
#define SPOTIFY_MERCURY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Mercury protocol constants
 */
#define MERCURY_PACKET_FLAG_SEQ     0x04
#define MERCURY_PACKET_FLAG_HEADER  0x10

/**
 * @brief Mercury method types
 */
typedef enum {
    MERCURY_METHOD_NONE  = 0,
    MERCURY_METHOD_SEND  = 0x04,
    MERCURY_METHOD_SUB   = 0x09,
    MERCURY_METHOD_UNSUB = 0x0a,
    MERCURY_METHOD_REQ   = 0x0b,
    MERCURY_METHOD_REPLY = 0x0c,
} mercury_method_t;

/**
 * @brief Shannon connection command bytes (from cspot)
 */
#define MERCURY_CMD_LOGIN     0xAB
#define MERCURY_CMD_AUTH_OK   0xAC
#define MERCURY_CMD_AUTH_FAIL 0xAD

/**
 * @brief Opaque handle for Mercury session
 */
typedef struct mercury_session_t mercury_session_t;

/**
 * @brief Mercury request structure
 */
typedef struct {
    mercury_method_t method;
    const char *uri;
    const uint8_t *payload;
    size_t payload_len;
} mercury_request_t;

/**
 * @brief Callback for state changes
 */
typedef void (*mercury_state_callback_t)(int connected, void *userdata);

/* ======== Login5 Authentication API ======== */

/**
 * @brief Initialize a Mercury session.
 *
 * The session is created in an unconnected state.
 *
 * @return Session handle, NULL on error
 */
mercury_session_t *mercury_init(void);

/**
 * @brief Perform full Login5 authentication to Spotify AP.
 *
 * Flow:
 *   1. TCP connect to AP
 *   2. DH key exchange (Oakley Group 2)
 *   3. ClientHello → APResponse
 *   4. 5-round HMAC-SHA1 challenge
 *   5. Shannon cipher initialization
 *   6. ClientResponse → server
 *   7. LoginRequest → APWelcome (or AUTH_FAIL)
 *
 * On success, the session is fully authenticated and ready for
 * Mercury messaging. The reusable token is automatically extracted
 * from APWelcome and stored internally.
 *
 * @param session       Session from mercury_init()
 * @param username      Spotify username
 * @param auth_data_b64 AuthData as base64 string (from zeroconf)
 * @param auth_type     Auth type (from zeroconf, typically 1)
 * @param device_id     32-char hex device ID string
 * @param ap_host       Spotify AP hostname (e.g., "ap-gae2.spotify.com")
 * @param ap_port       AP port (default: 443)
 * @return 0 on success, negative on error
 */
int mercury_login5(mercury_session_t *session,
                   const char *username,
                   const char *auth_data_b64,
                   int auth_type,
                   const char *device_id,
                   const char *ap_host,
                   int ap_port);

/**
 * @brief Send a Shannon-encrypted packet on the Mercury connection.
 *
 * @param session Session handle
 * @param cmd     Command byte (MERCURY_CMD_LOGIN, etc.)
 * @param data    Payload data
 * @param len     Payload length
 * @return 0 on success, negative on error
 */
int mercury_send(mercury_session_t *session, uint8_t cmd,
                 const uint8_t *data, size_t len);

/**
 * @brief Receive a Shannon-encrypted packet.
 *
 * @param session  Session handle
 * @param cmd      Output command byte
 * @param data     Output buffer for payload
 * @param len      Input: buffer capacity; Output: received length
 * @param max_len  Maximum capacity of data buffer
 * @return 0 on success, -1 on error, 1 on timeout
 */
int mercury_recv(mercury_session_t *session, uint8_t *cmd,
                 uint8_t *data, size_t *len, size_t max_len);

/* ======== Post-Auth Info ======== */

/**
 * @brief Get the canonical username from APWelcome.
 *
 * Only valid after successful mercury_login5().
 *
 * @return Canonical username string (owned by session), or NULL
 */
const char *mercury_get_canonical_username(mercury_session_t *session);

/**
 * @brief Get the reusable stored credential token.
 *
 * This token can be saved and reused for future logins
 * (auth_type = 1). Only valid after successful mercury_login5().
 *
 * @param session Session handle
 * @param out_len Output: length of stored credential
 * @return Pointer to stored credential bytes (owned by session), or NULL
 */
const uint8_t *mercury_get_stored_cred(mercury_session_t *session, size_t *out_len);

/* ======== Connection Management ======== */

/**
 * @brief Check if the session is connected and authenticated.
 */
bool mercury_is_connected(mercury_session_t *session);

/**
 * @brief Disconnect from AP and free network resources.
 */
void mercury_disconnect(mercury_session_t *session);

/**
 * @brief Destroy session and free all resources.
 */
void mercury_destroy(mercury_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* SPOTIFY_MERCURY_H */
