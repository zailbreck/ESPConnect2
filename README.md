# ESP-Spotify-Connect — ESP32 Spotify Connect Credential Extractor & Login5 Client

**Pure C++ implementation. Zero dependencies beyond mbedtls & OpenSSL.**
No cspot runtime. No librespot. No ESP-IDF required for x86 builds.

Compiles with `g++` on Linux and `mingw-w64` on Windows. ESP32 build via ESP-IDF v5+.

[![Status](https://img.shields.io/badge/status-active-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Spotify](https://img.shields.io/badge/spotify-v2.12.0-1DB954)]()

---

## Quick Start

### Zeroconf Capture (extract credentials from Spotify app)

```bash
# Linux x86
g++ -std=c++20 -pthread -O2 \
  cspot_zeroconf_mdnssvc_v13.cpp mdns.c mdnsd.c \
  -I mbedtls-3.6.5/include \
  -lmbedtls -lmbedcrypto -lmbedx509 \
  -o cspot_extractor

./cspot_extractor
# Open Spotify on phone/desktop, tap "ESPConnect-TEST" in device list
# Credentials saved to credentials.txt
```

### Login5 Client (authenticate to Spotify AP)

```bash
g++ -std=c++20 -O2 mercury_login5_v5.cpp -lssl -lcrypto -o mercury_login5

./mercury_login5 "<authData_b64>" <authType> "<username>"
# Output: reusable token → /tmp/mercury_token_v5.bin
```

---

## Features

| Component | Description | Status |
|-----------|-------------|--------|
| **mDNS Discovery** | `_spotify-connect._tcp` advertisement with `Stack=SP` | ✅ |
| **Bell HTTP Server** | `/spotify_info` GET/POST endpoint on port 7864 | ✅ |
| **DH Key Exchange** | Classic 768-bit DH (Oakley Group 2 / RFC 2409) | ✅ |
| **Layer 1 Decrypt** | AES-128-CTR with HMAC-SHA1 verification | ✅ |
| **Layer 2 Decrypt** | PBKDF2-HMAC-SHA1 → SHA1 → AES-192-ECB → XOR | ✅ |
| **Protobuf Parse** | Manual wire-format decode, extract `authData` | ✅ |
| **Mercury Login5** | DH+HMAC+Shannon auth to Spotify AP | ✅ |
| **Shannon Cipher** | Exact cspot Shannon (N=16, verified) | ✅ |
| **AudioKey Fetch** | Authenticated Mercury session → audio keys | ⏳ |
| **CDN Stream** | Resolve CDN URLs, decrypt OGG/Vorbis | ⏳ |

**Tested on:** Spotify v2.12.0 — Desktop Windows, Android 15, iPhone 15 (iOS 26).

---

## Dependencies

### Build-time (x86 Linux)
- `g++` (C++20) or `mingw-w64-g++` (Windows cross-compile)
- `mbedtls` 3.6.5 (Zeroconf extractor — DH, AES, SHA1, PBKDF2)
- `openssl` 3.x (Login5 client — DH, HMAC, SHA1, RAND)

### Build-time (ESP32)
- ESP-IDF v5.0+ with `idf.py`
- mbedtls (bundled with ESP-IDF)
- WiFi + mDNS components

### Runtime
- Same local network as the Spotify app device
- Port 7864 open (Bell HTTP server)
- Outbound TCP to `ap-gae2.spotify.com:443` (Spotify AP)

---

## Building from Source

### Zeroconf Extractor (Linux x86)

```bash
# Clone and build mbedtls
cd mbedtls-3.6.5 && make -j$(nproc)

# Compile mDNS source (from mdns library)
gcc -c -O2 mdns.c mdnsd.c

# Compile extractor
g++ -std=c++20 -pthread -O2 \
  cspot_zeroconf_mdnssvc_v13.cpp mdns.o mdnsd.o \
  -I mbedtls-3.6.5/include \
  -L mbedtls-3.6.5/library \
  -lmbedtls -lmbedcrypto -lmbedx509 \
  -o cspot_extractor
```

### Zeroconf Extractor (Windows static .exe)

```bash
# Cross-compile mbedtls for mingw
cd mbedtls-3.6.5
CC=x86_64-w64-mingw32-gcc AR=x86_64-w64-mingw32-ar make -j$(nproc)

# Cross-compile mDNS
x86_64-w64-mingw32-gcc -c -O2 mdns.c mdnsd.c

# Cross-compile extractor (static, no DLLs)
x86_64-w64-mingw32-g++ -std=c++20 -O2 -static \
  cspot_zeroconf_mdnssvc_v13.cpp mdns.o mdnsd.o \
  -I mbedtls-3.6.5/include \
  mbedtls-3.6.5/library/libmbedcrypto.a \
  mbedtls-3.6.5/library/libmbedtls.a \
  mbedtls-3.6.5/library/libmbedx509.a \
  -lws2_32 -lpthread -lbcrypt \
  -o cspot_extractor.exe
```

### Login5 Client (Linux x86)

```bash
g++ -std=c++20 -O2 -Wno-deprecated-declarations \
  mercury_login5_v5.cpp \
  -lssl -lcrypto \
  -o mercury_login5
```

### ESP32 (ESP-IDF)

```bash
cd esp-spotify-connect
idf.py set-target esp32
idf.py build
idf.py flash monitor
```

---

## Usage

### Zeroconf Capture

```bash
# Linux
./cspot_extractor

# Windows
cspot_extractor.exe

# With explicit local IP (if auto-detection fails)
./cspot_extractor 192.168.1.100
```

1. Run the extractor on the same network as your Spotify device
2. Open Spotify app → "Connect to a device" → look for **"ESPConnect-TEST"**
3. Tap to pair
4. Credentials saved to `credentials.txt`

### Login5 Authentication

```bash
# Stored credentials (authType=1, 248 bytes)
./mercury_login5 "<base64_authData>" 1 "<username>"

# Cookie credentials (authType=113, 2693 bytes)
AUTHB64=$(cat /tmp/authData.bin | base64 -w0)
./mercury_login5 "$AUTHB64" 113 "<username>"

# Custom AP endpoint
./mercury_login5 "<authB64>" 1 "<user>" "ap-gew4.spotify.com:443"
```

**Output:**
```
=== AUTH SUCCESS ===
Canonical: 31gs6dlgp5sdrb32kznvsklgwhiy
Display: Naufal
Reusable: 195B type=1
Token saved to /tmp/mercury_token_v5.bin
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    ESP-Spotify-Connect                        │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────────┐  │
│  │ Zeroconf    │    │ Login5       │    │ Audio Pipeline │  │
│  │ Extractor   │───►│ Client       │───►│ (planned)      │  │
│  │             │    │              │    │                │  │
│  │ mDNS + Bell │    │ DH + HMAC    │    │ AudioKey fetch │  │
│  │ + HTTP      │    │ + Shannon    │    │ + CDN resolve  │  │
│  │ + Layer1/2  │    │ + Protobuf   │    │ + OGG decrypt  │  │
│  └──────┬──────┘    └──────┬───────┘    └───────┬────────┘  │
│         │                  │                    │            │
│  Output: authData    Output: reusable    Output: PCM audio  │
│  (base64, 248B)      token (195B)        (I2S/DAC)          │
└──────────────────────────────────────────────────────────────┘
```

### Protocol Flow

```
Spotify App                     Extractor                  Spotify AP
    │                              │                            │
    │──── mDNS discover ──────────►│                            │
    │◄─── device info JSON ───────│                            │
    │──── POST blob+clientKey ───►│                            │
    │                              │                            │
    │              ┌───────────────┴──────────┐                 │
    │              │ DH shared secret          │                 │
    │              │ AES-128-CTR decrypt       │                 │
    │              │ Base64 decode             │                 │
    │              │ PBKDF2 + AES-192-ECB      │                 │
    │              │ XOR post-process          │                 │
    │              │ Protobuf → authData       │                 │
    │              └───────────────┬──────────┘                 │
    │                              │                            │
    │                              │─── TCP connect ───────────►│
    │                              │─── ClientHello + DH key ──►│
    │                              │◄── APResponse + server DH ─│
    │                              │─── ClientResp HMAC ───────►│
    │                              │─── Shannon LoginReq ──────►│
    │                              │◄── Shannon APWelcome ──────│
    │                              │                            │
    │                     Output: reusable token                │
```

---

## Protocol Details

### 1. Zeroconf Pairing

The device announces itself via mDNS as `_spotify-connect._tcp` with:
- `Stack=SP` — mandatory, filters devices
- `CPath=/spotify_info` — Bell HTTP path
- `VERSION=1.0`

Spotify app discovers the device, requests device info, then POSTs encrypted credentials.

**Why mDNS (not OAuth):** For public distribution — any Spotify Premium user can pair without app registration.

### 2. Diffie-Hellman (Oakley Group 2)

| Parameter | Value |
|-----------|-------|
| Prime | RFC 2409, 768-bit MODP |
| Generator | 2 |
| Key size | 96 bytes |
| Implementation | `mbedtls_mpi` (Zeroconf) / OpenSSL `DH_*` (Login5) |

**Critical:** Classic DH, NOT Curve25519. The Spotify app uses the classic prime. Curve25519 produces mismatched keys.

### 3. Layer 1: AES-128-CTR

```
Blob structure (420 bytes):
[IV:16] [CTR-payload:384] [HMAC-SHA1:20]

Key derivation:
  baseKey = SHA1(sharedSecret[0:95])
  checksumKey = HMAC-SHA1(baseKey[0:15], "checksum")
  encryptKey  = HMAC-SHA1(baseKey[0:15], "encryption")

  1. Verify: HMAC-SHA1(checksumKey, payload[0:383]) == blob[400:419]
  2. Decrypt: AES-128-CTR(encryptKey, IV=blob[0:15], payload)
  → 384 bytes base64
```

### 4. Layer 2: PBKDF2 + AES-192-ECB + XOR

```
Key derivation:
  secret = SHA1(deviceId)
  pbkdf2 = PBKDF2-HMAC-SHA1(secret, username, iter=256, len=20)
  sha1 = SHA1(pbkdf2)
  ecbKey = sha1 || 0x00000014  → 24 bytes (AES-192)

Decrypt:
  AES-192-ECB(ecbKey, all 288 bytes)
  XOR post-process: data[len-i-1] ^= data[len-i-17]
  → Protobuf: [0x49][varint-len][username][0x50][authType][0x51][authData]
```

### 5. Shannon Cipher (N=16)

Exact copy from [cspot Shannon.cpp](https://github.com/feelfreelinux/cspot/blob/master/cspot/src/Shannon.cpp).

| Parameter | Value |
|-----------|-------|
| N | 16 registers |
| INITKONST | 0x6996c53a |
| KEYP | 13 |
| FOLD | 16 |
| Rotation | `rotl(n,c) = (n<<c) \| (n>>((-c)&31))` |

**Verified:** Roundtrip encrypt+decrypt test PASS, MAC match.

### 6. Protobuf Wire Format

All messages use manual tag-length-value encoding (no nanopb/codegen).

Key field numbers from [keyexchange.proto](https://github.com/feelfreelinux/cspot/blob/master/cspot/protobuf/keyexchange.proto):

| Message | Field | Number | Type |
|---------|-------|--------|------|
| ClientHello | build_info | 0x0a (10) | BuildInfo |
| ClientHello | login_crypto_hello | 0x32 (50) | LoginCryptoHelloUnion |
| ClientHello | client_nonce | 0x3c (60) | bytes |
| ClientHello | feature_set | 0x50 (80) | FeatureSet |
| ClientResponsePlaintext | login_crypto_response | 0x0a (10) | LoginCryptoResponseUnion |
| ClientResponsePlaintext | pow_response | 0x14 (20) | PoWResponseUnion (required!) |
| ClientResponsePlaintext | crypto_response | 0x1e (30) | CryptoResponseUnion (required!) |

---

## Platform Compatibility

| Platform | Spotify Version | Pairing | Decrypt | authType | authSize |
|----------|-----------------|---------|---------|----------|----------|
| Android 15 (Xiaomi) | 2.12.0 | ✅ | ✅ | 1 | 248 |
| Windows Desktop | 2.12.0 | ✅ | ✅ | 1 | 248 |
| iPhone 15 (iOS 26) | 2.12.0 | ✅ | ✅ | 1 | 248 |

---

## Key Decisions

1. **Classic DH over Curve25519** — Spotify app uses classic 768-bit DH, not Curve25519
2. **Stable deviceId** — `142137fd329622137a1490161234567890123456`. Must be constant; PBKDF2 depends on `SHA1(deviceId)`
3. **Pure mbedtls/OpenSSL, no cspot runtime dependency** — raw crypto APIs, no `Crypto.cpp` wrapper
4. **Manual protobuf** — field tags written/read by hand, no codegen
5. **Zeroconf only** — for public distribution, every user pairs with their own Spotify app

---

## Bugs Discovered & Fixed (Login5 v5)

### #1 Corrupted Shannon Rotation
`sh_rot(n,c)` used `(-c)&c` instead of `(-c)&31` — produced wrong rotation, broken keystream.

### #2 HMAC Byte Order Reversal
`[x][ch+ar]` vs `[ch+ar][x]` — prepend byte in wrong position, different HMAC → wrong Shannon keys.

### #3 Missing Proto Required Fields
`ClientResponsePlaintext` missing `pow_response` (field 20) and `crypto_response` (field 30) — both required.

---

## Source Code References

Code in this repository derives from the following open-source projects. All are MIT-licensed.

| Component | Source | File(s) |
|-----------|--------|---------|
| Shannon cipher | [cspot](https://github.com/feelfreelinux/cspot) | `Shannon.h`, `Shannon.cpp` |
| ShannonConnection | [cspot](https://github.com/feelfreelinux/cspot) | `ShannonConnection.h`, `ShannonConnection.cpp` |
| Protobuf schema | [cspot](https://github.com/feelfreelinux/cspot) | `keyexchange.proto` |
| HMAC challenge | [librespot](https://github.com/librespot-org/librespot) | `auth_challenge.rs` |
| DH Group 1 | [RFC 2409](https://datatracker.ietf.org/doc/html/rfc2409) | Section 6.2 |
| pack/extract utils | [cspot](https://github.com/feelfreelinux/cspot) | `Utils.h` |
| mDNS library | [mdns](https://github.com/mjansson/mdns) | `mdns.c`, `mdnsd.c` |

Each borrowed file or function includes a comment referencing its source URL and license at the top of the file.

---

## Related Projects

- [librespot](https://github.com/librespot-org/librespot) — Open source Spotify client library (Rust)
- [cspot](https://github.com/feelfreelinux/cspot) — ESP32 Spotify Connect implementation (C++)
- [raspotify](https://github.com/dtcooper/raspotify) — Raspberry Pi Spotify Connect
- [spotifyd](https://github.com/Spotifyd/spotifyd) — UNIX Spotify Connect daemon
- [ncspot](https://github.com/hrkfdn/ncspot) — ncurses Spotify client
- [Shannon Cipher](https://github.com/oleganza/Shannon-Cipher) — Reference Shannon spec

---

## License

MIT — derived from [cspot](https://github.com/feelfreelinux/cspot) and [librespot](https://github.com/librespot-org/librespot), both MIT-licensed.

Use at your own risk. Connecting to Spotify's API may violate their Terms of Service.
