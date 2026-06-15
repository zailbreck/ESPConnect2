// mercury.h — Spotify Mercury Protocol Interface
// ================================================
// Mercury is Spotify's pub/sub messaging protocol over the AP connection.
// Used for AudioKey requests, track metadata, and control messages.
//
// Sources & References:
//   Mercury protocol:  librespot (MIT) — core/src/mercury/
//                      https://github.com/librespot-org/librespot/tree/dev/core/src/mercury
//   Packet constants:  cspot (MIT) — MercurySession.cpp
//                      https://github.com/feelfreelinux/cspot/blob/master/cspot/src/MercurySession.cpp
//   Method types:      librespot (MIT) — mercury/mod.rs
//
// License: MIT — derived from librespot & cspot

#ifndef SPOTIFY_MERCURY_H
#define SPOTIFY_MERCURY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Mercury protocol constants
 */
#define MERCURY_PACKET_FLAG_SEQ     0x04  /**< Packet has sequence number */
#define MERCURY_PACKET_FLAG_HEADER  0x10  /**< Packet has header (Mercury request/response) */

/**
 * @brief Mercury method types
 */
typedef enum {
    MERCURY_METHOD_NONE = 0,
    MERCURY_METHOD_SEND = 0x04,
    MERCURY_METHOD_SUB  = 0x09,
    MERCURY_METHOD_UNSUB = 0x0a,
    MERCURY_METHOD_REQ  = 0x0b,    /**< Mercury request */
    MERCURY_METHOD_REPLY = 0x0c,   /**< Mercury reply */
} mercury_method_t;

/**
 * @brief Mercury callback type
 */
typedef void (*mercury_callback_t)(int status, const uint8_t *data, size_t len, void *userdata);

/**
 * @brief Mercury request structure
 */
typedef struct {
    mercury_method_t method;
    const char *uri;
    const uint8_t *payload;
    size_t payload_len;
    mercury_callback_t callback;
    void *callback_userdata;
} mercury_request_t;

/**
 * @brief Mercury session handle
 */
typedef struct mercury_session_t mercury_session_t;

/**
 * @brief Callback when Mercury connection state changes
 */
typedef void (*mercury_state_callback_t)(int connected, void *userdata);

/**
 * @brief Initialize Mercury session
 *
 * @param device_id Unique device identifier
 * @param username Spotify username
 * @param auth_data Stored credential bytes from login5
 * @param state_cb Optional state change callback
 * @param state_cb_userdata User data for callback
 * @return Mercury session handle, NULL on error
 */
mercury_session_t *mercury_init(const char *device_id, const char *username,
                                const uint8_t *auth_data, size_t auth_data_len,
                                mercury_state_callback_t state_cb, void *state_cb_userdata);

/**
 * @brief Connect to Spotify access point
 *
 * Resolves AP address via apresolve.spotify.com, then performs
 * Diffie-Hellman handshake + Mercury session setup.
 *
 * @param session Mercury session handle from mercury_init
 * @return 0 on success, negative on error
 */
int mercury_connect(mercury_session_t *session);

/**
 * @brief Send a Mercury request
 *
 * @param session Mercury session
 * @param request Mercury request (URI, payload, callback)
 * @return 0 on success, negative on error
 */
int mercury_request(mercury_session_t *session, const mercury_request_t *request);

/**
 * @brief Subscribe to a Mercury URI
 *
 * @param session Mercury session
 * @param uri URI to subscribe to (e.g., "hm://...").
 * @return 0 on success, negative on error
 */
int mercury_subscribe(mercury_session_t *session, const char *uri);

/**
 * @brief Poll Mercury for incoming messages
 * Must be called periodically to process incoming data.
 *
 * @param session Mercury session
 * @param timeout_ms Timeout in milliseconds (0 = non-blocking)
 * @return 0 on success, 1 on timeout, negative on error
 */
int mercury_poll(mercury_session_t *session, int timeout_ms);

/**
 * @brief Close Mercury session
 */
void mercury_disconnect(mercury_session_t *session);

/**
 * @brief Destroy Mercury session and free resources
 */
void mercury_destroy(mercury_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* SPOTIFY_MERCURY_H */
