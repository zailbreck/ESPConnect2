# ESP-Spotify-Connect — Turn your ESP32 into a Smart Speaker

C library with platform abstraction layer. Zero ESP-IDF dependencies in core. Compiles on Linux x86 with OpenSSL, deploys to ESP32 with mbedtls + lwip. No cspot runtime. No librespot.

[![Status](https://img.shields.io/badge/status-active-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Spotify](https://img.shields.io/badge/spotify-v2.12.0-1DB954)]()
[![Standard](https://img.shields.io/badge/C-gnu11-lightgrey)]()

---

## Features

| Component | Description | Status |
|-----------|-------------|--------|
| **ZeroConf Pairing** | mDNS discovery + Bell HTTP + DH key exchange | ✅ |
| **Credential Decrypt** | AES-128-CTR (Layer 1) + PBKDF2/AES-192-ECB/XOR (Layer 2) | ✅ |
| **Protobuf Parse** | Manual wire-format decode, extract `authData` | ✅ |
| **Mercury Login5** | DH + HMAC challenge + Shannon encrypted channel | ✅ |
| **Client Token** | Obtain reusable bearer token via Mercury | ✅ |
| **Track Metadata** | Fetch track/file IDs via internal spclient API | ✅ |
| **CDN Resolve** | `storage-resolve` → CDN URL for audio file | ✅ |
| **AudioKey Fetch** | AES-128 key request via Mercury (0x0C) | ✅ |
| **CDN Download** | HTTP Range request for encrypted OGG chunks | ✅ |
| **Audio Decrypt** | AES-128-CTR + SHA1-based seek table | ✅ |
| **Shannon Cipher** | Exact cspot Shannon (N=16, verified) | ✅ |
| **Dual Platform** | POSIX (OpenSSL) + ESP32 (mbedtls/lwip) | ✅ |

**Tested on:** Spotify v2.12.0 — Desktop Windows, Android 15, iPhone 15 (iOS 26).

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      ESP-Spotify-Connect                         │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────┐   ┌──────────┐   ┌──────────┐   ┌─────────────┐  │
│  │ zeroconf  │   │ mercury  │   │ spclient  │   │  decrypt    │  │
│  │ .c        │──►│ .c       │──►│ .c        │──►│  .c         │  │
│  │           │   │          │   │           │   │             │  │
│  │ pairing   │   │ login5   │   │ metadata  │   │ AES-CTR     │  │
│  │ + DH      │   │ + HMAC   │   │ + cdn     │   │ OGG/Vorbis  │  │
│  │ + Layer1  │   │ + Shannon│   │ + audiokey│   │             │  │
│  │ + Layer2  │   │          │   │ + HTTP    │   │             │  │
│  └─────┬─────┘   └────┬─────┘   └─────┬─────┘   └──────┬──────┘  │
│        │              │               │                │         │
│  ┌─────┴──────────────┴───────────────┴────────────────┴─────┐   │
│  │                  Platform Abstraction                     │   │
│  │  ┌─────────────────────┐  ┌─────────────────────────┐    │   │
│  │  │ platform_posix.c    │  │ platform_esp32.c         │    │   │
│  │  │ OpenSSL + POSIX     │  │ mbedtls + lwip + ESP-IDF │    │   │
│  │  └─────────────────────┘  └─────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  Public API: esp_spotify.h                                       │
│  init → pair → login → metadata → cdn → audiokey → decrypt      │
└──────────────────────────────────────────────────────────────────┘
```

---

## Quick Start (x86 Linux)

```bash
git clone git@github.com:zailbreck/ESPConnect.git
cd ESPConnect

# Build all modules (POSIX target)
gcc -std=gnu11 -O2 -I include -I include/internal \
  src/mercury.c src/spclient.c src/zeroconf.c src/decrypt.c \
  src/esp_spotify.c src/platform_posix.c \
  test/x86/test_build.c \
  -lssl -lcrypto -lm \
  -o test_build

./test_build
```

---

## Library API

```c
#include "esp_spotify.h"

esp_spotify_handle_t spotify;
esp_spotify_config_t cfg = {
    .device_name = "ESPConnect",
    .device_id   = "142137fd329622137a14901634264e6f332e2411",
    .bell_port   = 7864,
};

esp_spotify_init(&cfg, &spotify);          // Init
esp_spotify_start(spotify);                 // mDNS + Bell
esp_spotify_pair(spotify, 300);            // Wait for Spotify app
esp_spotify_login(spotify);                 // Login5 auth

// Track metadata
spclient_track_meta_t meta;
uint8_t gid[16] = {0x06, 0xfa, ...};      // 16-byte track GID
esp_spotify_get_track_meta(spotify, gid, &meta);

// CDN
char cdn_url[512];
esp_spotify_resolve_cdn(spotify, meta.file_id, cdn_url, sizeof(cdn_url));

uint8_t audio_buf[16384];
esp_spotify_download_audio(spotify, cdn_url, 0, 16384, audio_buf, sizeof(audio_buf));

// AudioKey + Decrypt
uint8_t key[16];
esp_spotify_get_audio_key(spotify, gid, meta.file_id_bin, key);
esp_spotify_decrypt_audio(audio_buf, 16384, key, meta.file_id_bin);

esp_spotify_stop(spotify);
esp_spotify_destroy(spotify);
```

---

## Platform Abstraction

Core library files have **zero ESP-IDF dependencies**. All platform-specific code lives in two files:

| File | Platform | Crypto | Network | TLS | Lines |
|------|----------|--------|---------|-----|-------|
| `platform_posix.c` | Linux x86 | OpenSSL 3.x | POSIX sockets | OpenSSL | 756 |
| `platform_esp32.c` | ESP32 (IDF v5+) | mbedtls 3.x | lwip | mbedtls | 622 |

**Platform API** (`include/internal/platform.h`):
```
Crypto:   sha1, hmac_sha1, pbkdf2, aes_ctr128, aes_ecb_decrypt192,
          dh_generate_keypair, dh_compute_shared, random, base64
Network:  tcp_connect, tcp_read/write, tcp_close, tcp_set_timeout
HTTP:     http_server_start/stop/accept/read/write
mDNS:     mdns_start, mdns_register_service, mdns_stop
Shannon:  shannon_new/free/key/nonce/encrypt/decrypt/finish
TLS:      tls_connect, tls_read/write, tls_close
HTTPS:    https_get, http_response_free
```

---

## Dependencies

### x86 Linux
- `gcc` (gnu11) or `clang`
- `openssl` 3.x (`libssl-dev`, `libcrypto-dev`)

### ESP32
- ESP-IDF v5.0+
- Components: `mbedtls`, `esp_http_client`, `mdns`, `esp_netif`, `nvs_flash`

### Runtime
- Same local network as Spotify app for pairing
- Port 7864 open (Bell HTTP server)
- Outbound TCP to `ap-gew4.spotify.com:443`

---

## ESP32 Build (ESP-IDF)

```bash
cd ESPConnect
idf.py set-target esp32
idf.py build
idf.py flash monitor
```

---

## Protocol Flow

```
Spotify App              ESPConnect Library              Spotify AP
    │                         │                               │
    │── mDNS discover ───────►│                               │
    │◄── device JSON ──────── │                               │
    │── POST blob+clientKey ─►│                               │
    │                         │                               │
    │    ┌────────────────────┤ DH shared secret              │
    │    │ Layer 1: AES-CTR   │ HMAC-SHA1 verify             │
    │    │ Layer 2: PBKDF2+ECB│ Protobuf → authData          │
    │    └────────────────────┤                               │
    │                         │                               │
    │                         │── TCP/TLS connect ───────────►│
    │                         │── ClientHello + DH keypool ──►│
    │                         │◄── APResponse + server DH ────│
    │                         │── ClientResp + HMAC proof ───►│
    │                         │── Shannon LoginReq ──────────►│
    │                         │◄── Shannon APWelcome ─────────│
    │                         │                               │
    │                         │── Client Token (spclient) ───►│
    │                         │◄── Bearer token ──────────────│
    │                         │                               │
    │                         │── metadata/4/{gid} ──────────►│
    │                         │◄── Track JSON (file IDs) ─────│
    │                         │                               │
    │                         │── storage-resolve/{fileid} ──►│
    │                         │◄── CDN URLs ──────────────────│
    │                         │                               │
    │                         │── AudioKey (0x0C Mercury) ───►│
    │                         │◄── AES key (0x0D) ────────────│
    │                         │                               │
    │                         │── CDN Range GET ─────────────►│
    │                         │◄── Encrypted OGG chunks ──────│
    │                         │                               │
    │              AES-128-CTR decrypt → PCM audio            │
```

---

## Protocol Details

### 1. Zeroconf Pairing

mDNS advertises `_spotify-connect._tcp` with `Stack=SP`, `CPath=/spotify_info`, `VERSION=1.0`.

### 2. Diffie-Hellman (Oakley Group 2)

| Parameter | Value |
|-----------|-------|
| Prime | RFC 2409, 768-bit MODP |
| Generator | 2 |
| Key size | 96 bytes |

**Critical:** Classic DH, NOT Curve25519. Spotify app uses the classic prime.

### 3. Layer 1: AES-128-CTR

```
Blob (420 bytes): [IV:16] [CTR-payload:384] [HMAC-SHA1:20]

Key derivation:
  baseKey     = SHA1(sharedSecret[0:95])
  checksumKey = HMAC-SHA1(baseKey[0:15], "checksum")
  encryptKey  = HMAC-SHA1(baseKey[0:15], "encryption")

1. Verify: HMAC-SHA1(checksumKey, payload[0:383]) == blob[400:419]
2. Decrypt: AES-128-CTR(encryptKey, IV=blob[0:15], payload)
   → 384 bytes base64 → 288 bytes binary
```

### 4. Layer 2: PBKDF2 + AES-192-ECB + XOR

```
Key derivation:
  secret = SHA1(deviceId)
  pbkdf2 = PBKDF2-HMAC-SHA1(secret, username, iter=256, len=20)
  ecbKey = SHA1(pbkdf2) || 0x00000014  → 24 bytes (AES-192)

Decrypt: AES-192-ECB(ecbKey, 288 bytes) → XOR post-process
  → Protobuf: {loginId, username, authType, authData}
```

### 5. Mercury Login5 (Shannon Cipher)

| Parameter | Value |
|-----------|-------|
| N | 16 registers |
| INITKONST | 0x6996c53a |
| KEYP | 13 |
| FOLD | 16 |

**Source:** Exact copy from cspot Shannon.cpp.

### 6. Mercury AudioKey

Command `0x0C` payload: `[FILEID:16] [TRACKID:16] [SEQ:4 BE] [0x00, 0x00]`.
Response `0x0D` = success with AES-128 key, `0x0E` = failure.

### 7. Audio Decrypt (AES-128-CTR)

OGG pages encrypted with AES-128-CTR. Seek table built from SHA1 hashes of encrypted chunks for random access.

---

## Bugs Discovered & Fixed

| # | Bug | Impact | File |
|---|-----|--------|------|
| 1 | Shannon rotation `(-c)&c` not `(-c)&31` | Broken keystream | mercury.c |
| 2 | HMAC byte order reversed | Wrong Shannon keys | mercury.c |
| 3 | Missing protobuf required fields | Server rejected ClientResp | mercury.c |
| 4 | Missing PING/PONG handler | Connection timeout | mercury.c |
| **5** | **HMAC used proto-only bytes, not full packet** | **Auth always failed** | mercury.c |

---

## Platform Compatibility

| Platform | Spotify Version | Pairing | Decrypt | authType | authSize |
|----------|-----------------|---------|---------|----------|----------|
| Android 15 | 2.12.0 | ✅ | ✅ | 1 (STORED) | 248 |
| Windows Desktop | 2.12.0 | ✅ | ✅ | 1 (STORED) | 248 |
| iOS 26 | 2.12.0 | ✅ | ✅ | 1 (STORED) | 248 |

---

## Key Decisions

1. **Classic DH over Curve25519** — Spotify app uses classic 768-bit DH
2. **Stable deviceId** — PBKDF2 depends on `SHA1(deviceId)`, must be constant
3. **Pure C (gnu11)** — No C++ runtime, direct ESP-IDF compatibility
4. **Platform abstraction** — Core has 0 ESP-IDF deps, all OS via `platform_*` calls
5. **No codegen** — Protobuf tags written/read by hand
6. **Zeroconf only** — Every user pairs with their own Spotify app
7. **Login5** — HMAC challenge uses **full ClientHello packet** (with 0x00,0x04 prefix + 4-byte length header), NOT proto-only bytes

---

## Source Code References

All MIT-licensed.

| Component | Source |
|-----------|--------|
| Shannon cipher | [cspot](https://github.com/feelfreelinux/cspot) — Shannon.cpp |
| Login5 protocol | [librespot](https://github.com/librespot-org/librespot) — login5.rs |
| HMAC challenge | [librespot](https://github.com/librespot-org/librespot) — auth_challenge.rs |
| Spclient HTTP API | [librespot](https://github.com/librespot-org/librespot) — spclient.rs |
| Audio decrypt | [librespot](https://github.com/librespot-org/librespot) — decrypt.rs |
| DH Group 2 | [RFC 2409](https://datatracker.ietf.org/doc/html/rfc2409) Section 6.2 |
| Protobuf schema | [cspot](https://github.com/feelfreelinux/cspot) — keyexchange.proto |
| mDNS library | [mdns](https://github.com/mjansson/mdns) — mdns.c, mdnsd.c |

---

## Related Projects

- [librespot](https://github.com/librespot-org/librespot) — Open source Spotify client library (Rust)
- [cspot](https://github.com/feelfreelinux/cspot) — ESP32 Spotify Connect (C++)
- [raspotify](https://github.com/dtcooper/raspotify) — Raspberry Pi Spotify Connect
- [spotifyd](https://github.com/Spotifyd/spotifyd) — UNIX Spotify Connect daemon

---

## License

MIT — derived from [cspot](https://github.com/feelfreelinux/cspot) and [librespot](https://github.com/librespot-org/librespot), both MIT-licensed.

## Windows Test Build

Instructions to build the test Windows executable:

```bash
# Cross-compile for Windows on Linux using MinGW
x86_64-w64-mingw32-gcc -std=gnu11 -O2 -static -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600 \
  -I include -I include/internal -I /tmp/mbedtls-3.5.0-mingw/include -I thirdparty \
  src/mercury.c src/spclient.c src/zeroconf.c src/decrypt.c src/esp_spotify.c src/platform_windows.c test/x86/test_e2e.c \
  thirdparty/mdns.c thirdparty/mdnsd.c \
  /tmp/mbedtls-3.5.0-mingw/library/libmbedtls.a /tmp/mbedtls-3.5.0-mingw/library/libmbedx509.a /tmp/mbedtls-3.5.0-mingw/library/libmbedcrypto.a \
  -lws2_32 -lpthread -lbcrypt -lshlwapi -liphlpapi -lm \
  -o espconnect_e2e_v38.exe
```

This compiles a standalone `.exe` using `mbedtls` for cryptographic and TLS operations, and `winsock2` for network operations.
