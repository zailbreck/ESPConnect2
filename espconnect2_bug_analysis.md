# Diagnosa Bug ESPConnect2 — Gagal APWelcome

> Analisis berdasarkan kode di `src/mercury.c` dan `src/platform_posix.c`  
> dibandingkan dengan spesifikasi AP TCP handshake Spotify dari `lib_target.so`

---

## Ringkasan: Ditemukan 7 Bug Kritis + 4 Bug Minor

---

## 🔴 BUG KRITIS #1 — Shannon `INITKONST` Salah

**File**: `src/platform_posix.c`, line 432

```c
// KODE KAMU (SALAH):
#define SHANNON_INITKONST 0x6996c53a

// BENAR (dari Shannon referensi asli):
#define SHANNON_INITKONST 0x6996c75a
//                                ^^^ BEDA! c5 vs c7
```

**Dampak**: Seluruh Shannon key schedule menghasilkan state yang berbeda. Shannon encrypt/decrypt akan menghasilkan output yang sepenuhnya salah. Server tidak bisa membaca LoginRequest sama sekali → koneksi drop atau server kirim APLoginFailed yang juga tidak bisa kamu baca.

**Fix**:
```c
#define SHANNON_INITKONST 0x6996c75a
```

---

## 🔴 BUG KRITIS #2 — Shannon `shannon_finish()` Implementasi Salah

**File**: `src/platform_posix.c`, line 683–690

```c
// KODE KAMU (SALAH):
void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]) {
    if (s->nbuf) {
        shannon_macfunc(s, s->mbuf);
    }
    shannon_cycle(s);
    uint32_t t = s->CRC[0] ^ s->CRC[2] ^ s->CRC[15] ^ SHANNON_INITKONST;
    WORD2BYTE(t, mac);
}
```

**Masalah**:
1. Hanya memanggil `shannon_cycle()` **sekali** — implementasi Shannon yang benar memanggil siklus ekstra untuk mencampur CRC ke dalam LFSR
2. MAC dihitung dari `CRC` saja, bukan dari hasil mixing penuh antara CRC dan R
3. Referensi cspot/librespot melakukan: inject CRC ke R → clock N kali → output dari R state

**Fix (sesuai cspot Shannon.cpp):**
```c
void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]) {
    if (s->nbuf) {
        shannon_macfunc(s, s->mbuf);
        s->nbuf = 0;
    }
    // Mix CRC into R state
    s->konst = SHANNON_INITKONST;
    for (int i = 0; i < SHANNON_N; i++) {
        s->R[SHANNON_KEYP] ^= s->CRC[i];
        shannon_cycle(s);
    }
    // Extra diffusion cycles
    for (int i = 0; i < SHANNON_N / 2; i++) {
        shannon_cycle(s);
    }
    // Extract MAC from sbuf
    WORD2BYTE(s->sbuf, mac);
}
```

---

## 🔴 BUG KRITIS #3 — `shannon_init()` Salah (Key Pair Logic)

**File**: `src/mercury.c`, line 417–426

```c
// KODE KAMU:
static void shannon_init(platform_shannon_t *snd, platform_shannon_t *rcv,
                         const uint8_t *sk, const uint8_t *rk) {
    platform_shannon_key(snd, sk, 32);
    platform_shannon_key(rcv, rk, 32);
}
```

Ini memanggil `platform_shannon_key()` secara **terpisah dan independen** untuk masing-masing cipher.

**Masalah**: `platform_shannon_key_pair()` yang kamu tulis di `platform_posix.c` (line 566–593) tidak dipakai! Fungsi itu mengimplementasikan logika shared-genkonst yang lebih kompleks, tapi tidak pernah dipanggil.

Meskipun ini bisa benar jika implementasi standarnya memang terpisah, kamu perlu konsisten dengan **satu** pendekatan. Lihat cspot:

```cpp
// cspot ShannonConnection.cpp — init:
this->sendCipher.key(sendKey);
this->recvCipher.key(recvKey);
// Tiap cipher diinisialisasi independent dari scratch
```

Jika kamu menggunakan `platform_shannon_key_pair()`, **hapus** `shannon_init()` dan panggil langsung.  
Jika kamu pakai model independent, **hapus** `platform_shannon_key_pair()` agar tidak membingungkan.

---

## 🔴 BUG KRITIS #4 — Framing `ClientResponsePlaintext` Salah

**File**: `src/mercury.c`, line 622–628

```c
// KODE KAMU:
ret = tcp_send_packet(s->sock, NULL, 0, cr_buf.data, cr_buf.size, NULL, NULL);
```

Fungsi `tcp_send_packet()` menambahkan **4-byte BE length** di depan data (line 377–383):
```c
uint32_t total = (uint32_t)(4 + prefix_len + data_len);
write_be32(pkt + prefix_len, total);
```

Jadi ClientResponsePlaintext dikirim sebagai: `[4B length][protobuf]`

**Masalah**: ClientResponsePlaintext seharusnya dikirim **tanpa prefix** — hanya raw protobuf bytes saja (seperti yang diindikasikan komentar di line 626: "Send WITHOUT prefix"). Tapi fungsi `tcp_send_packet` tetap menambahkan 4-byte length header!

**Fix**: Buat fungsi send khusus untuk ClientResponse:
```c
// Kirim ClientResponse: HANYA raw protobuf, tanpa apapun
ret = platform_tcp_write(s->sock, cr_buf.data, cr_buf.size);
```

---

## 🔴 BUG KRITIS #5 — HMAC Challenge: `x` di Akhir, Bukan Awal

**File**: `src/mercury.c`, line 305–312

```c
// KODE KAMU:
for (int x = 1; x < 6; x++) {
    uint8_t *cv = malloc(cb_len + 1);
    memcpy(cv, cb, cb_len);
    cv[cb_len] = (uint8_t)x;  // x di AKHIR
    platform_hmac_sha1(shared, shared_len, cv, cb_len + 1, dst);
```

Komentar di kode sendiri bilang "x at END because C++ insert(begin) pushes..." — ini **reasoning yang salah**.

**Benar**: Berdasarkan librespot `auth_challenge.rs` dan cspot `AuthChallenges.cpp`:
```
data_i = [i_byte] + client_hello_packet + ap_response_packet
//          ^^^ byte counter DI AWAL (prepend), bukan di akhir!
```

cspot AuthChallenges.cpp:
```cpp
for (uint8_t i = 1; i < 6; i++) {
    auto data = std::vector<uint8_t>(1, i);  // i pertama
    data.insert(data.end(), cb.begin(), cb.end());  // lalu cb
    HMAC_SHA1(shared, data, dst);
}
```

**Fix**:
```c
for (int x = 1; x < 6; x++) {
    uint8_t *cv = malloc(cb_len + 1);
    cv[0] = (uint8_t)x;          // x di AWAL
    memcpy(cv + 1, cb, cb_len);  // cb setelahnya
    platform_hmac_sha1(shared, shared_len, cv, cb_len + 1, dst);
    free(cv);
    dst += 20;
}
```

---

## 🔴 BUG KRITIS #6 — APWelcome Field Parsing Salah

**File**: `src/mercury.c`, line 695–726

```c
// KODE KAMU — APWelcome parser:
while (pb_read_tag(&aw, &f, &w)) {
    if (f == 10 && w == PB_LENGTH_DELIM) { /* username */ }
    else if (f == 20 && w == PB_VARINT)  { /* account type */ }
    else if (f == 30 && w == PB_VARINT)  { /* reusable auth type */ }
    else if (f == 40 && w == PB_LENGTH_DELIM) { /* stored cred */ }
    else if (f == 50 && w == PB_LENGTH_DELIM) { /* display name */ }
```

**Masalah**: Field numbers APWelcome yang benar (dari keyexchange.proto / cspot):

| Field | Nama | Type |
|---|---|---|
| 1 | `canonical_username` | string |
| 2 | `account_type` | varint |
| 5 | `reusable_credentials_type` | varint |
| 6 | `reusable_credentials` | bytes |

Kode kamu menggunakan field 10, 20, 30, 40, 50 — **semuanya salah!** APWelcome tidak punya field dengan nomor setinggi itu.

**Fix**:
```c
while (pb_read_tag(&aw, &f, &w)) {
    if      (f == 1 && w == PB_LENGTH_DELIM) { /* canonical_username */ }
    else if (f == 2 && w == PB_VARINT)       { /* account_type */ }
    else if (f == 5 && w == PB_VARINT)       { /* reusable_credentials_type */ }
    else if (f == 6 && w == PB_LENGTH_DELIM) { /* reusable_credentials */ }
    else { pb_skip(&aw, w); }
}
```

---

## 🔴 BUG KRITIS #7 — `mercury_recv()` Baca 4 Byte Tapi Decrypt 3 Byte

**File**: `src/mercury.c`, line 794–824

```c
uint8_t hdr[4];
platform_tcp_read(s->sock, hdr, 4);   // baca 4 byte header

// ...
platform_shannon_decrypt(s->recv_cipher, hdr, 3);  // decrypt 3 byte
*cmd = hdr[0];
uint16_t pkt_len = read_u16_be(hdr + 1);
// hdr[3] tidak pernah dipakai!
```

**Masalah**: Shannon packet header hanya 3 byte `[cmd(1) | len(2)]`. Kamu membaca 4 byte tapi hanya mendecrypt 3. Byte ke-4 yang terbaca akan **menggeser state** MAC (karena data sudah dibaca dari socket), tapi Shannon state sudah dihitung untuk 3 byte.

Ini menyebabkan MAC mismatch pada semua paket yang diterima karena Shannon state tidak sinkron.

**Fix**:
```c
uint8_t hdr[3];                                    // baca tepat 3 byte
platform_tcp_read(s->sock, hdr, 3);
platform_shannon_decrypt(s->recv_cipher, hdr, 3);
*cmd = hdr[0];
uint16_t pkt_len = read_u16_be(hdr + 1);
```

---

## 🟡 BUG MINOR #8 — Auth Type Check Salah untuk OAuth Token

**File**: `src/mercury.c`, line 460

```c
if (auth_type == 3) {
    // AUTHENTICATION_SPOTIFY_TOKEN (OAuth)
```

Dari binary: `AUTHENTICATION_SPOTIFY_TOKEN = 2` (bukan 3).  
`3` = `AUTHENTICATION_FACEBOOK_TOKEN`.

**Fix**:
```c
if (auth_type == 2) {  // AUTHENTICATION_SPOTIFY_TOKEN
```

---

## 🟡 BUG MINOR #9 — PING Command Check Salah

**File**: `src/mercury.c`, line 676

```c
if (cmd == 0x00) {
    /* PING → PONG */
    mercury_send(s, 0x49, &empty, 0);
```

PING command dari AP adalah `0x04`, bukan `0x00`.  
PONG ACK yang dikirim client adalah `0x49`. Logika PONG sudah benar tapi trigger-nya salah.

**Fix**:
```c
if (cmd == 0x04) {  // PING from server
    mercury_send(s, 0x49, NULL, 0);  // PONG_ACK
```

---

## 🟡 BUG MINOR #10 — `tcp_send_packet()` Length Calculation Double-Count

**File**: `src/mercury.c`, line 377

```c
uint32_t total = (uint32_t)(4 + prefix_len + data_len);
```

`total` ini kemudian ditulis sebagai 4-byte BE length. Artinya length field **termasuk dirinya sendiri** (4 byte) + prefix + data. Ini bukan format standar Spotify — biasanya length hanya menghitung bytes setelah header.

Periksa apakah ini konsisten dengan cara AP membaca: jika AP membaca `total` bytes setelah length field, maka ini harusnya `prefix_len + data_len` saja.

---

## 🟡 BUG MINOR #11 — `pb_skip()` Untuk `PB_VARINT` Sudah Salah

**File**: `src/mercury.c`, line 171–172

```c
static void pb_skip(pb_reader_t *r, uint32_t wt) {
    if (wt == PB_VARINT) {
        while (r->p < r->s && (r->d[r->p - 1] & 0x80)) r->p++;
    }
```

Ini membaca byte **sebelum** posisi saat ini (`r->p - 1`). Seharusnya memeriksa byte **saat ini** (`r->p`) dan advance:

**Fix**:
```c
if (wt == PB_VARINT) {
    while (r->p < r->s && (r->d[r->p++] & 0x80));
}
```

---

## Urutan Prioritas Fix

| Prioritas | Bug | File | Line |
|---|---|---|---|
| 1 | `INITKONST` salah (`0x6996c53a` → `0x6996c75a`) | `platform_posix.c` | 432 |
| 2 | `shannon_finish()` tidak mixing CRC ke LFSR | `platform_posix.c` | 683 |
| 3 | HMAC challenge: byte counter di akhir, harusnya di awal | `mercury.c` | 308 |
| 4 | `mercury_recv()` baca 4 byte harusnya 3 byte | `mercury.c` | 794 |
| 5 | ClientResponsePlaintext dikirim dengan 4-byte length prefix | `mercury.c` | 627 |
| 6 | APWelcome field numbers salah (10,20,30,40 → 1,2,5,6) | `mercury.c` | 695 |
| 7 | PING cmd check 0x00 harusnya 0x04 | `mercury.c` | 676 |
| 8 | Auth type 3 harusnya 2 untuk OAuth token | `mercury.c` | 460 |

---

## Flowchart: Dimana Kamu Gagal

```
[1] TCP Connect         ✅ OK
[2] ClientHello         ✅ OK (packet format benar)
[3] APResponse          ✅ OK (diterima)
[4] DH shared secret    ✅ OK
[5] HMAC challenge      ❌ BUG #5 — byte counter di AKHIR, harusnya di AWAL
                           → send_key & recv_key SALAH
[6] ClientResponse      ❌ BUG #4 — ada 4-byte length prefix yang tidak seharusnya
[7] Shannon init        ❌ BUG #1 — INITKONST salah (0x6996c53a vs c75a)
[8] LoginRequest sent   ❌ Terenkripsi dengan key yang SALAH → server tidak bisa baca
[9] APResponse recv     ❌ BUG #7 — baca 4 byte harusnya 3 → Shannon state tidak sinkron
[10] APWelcome parse    ❌ BUG #6 — field numbers salah
```

> [!IMPORTANT]
> **Bug #1 (INITKONST) + Bug #5 (HMAC byte order) adalah root cause utama.** Fix keduanya dulu, lalu test ulang sebelum memperbaiki yang lain.

> [!TIP]
> Tambahkan dump hex di setiap tahap dan bandingkan dengan output librespot/cspot untuk verifikasi. Atau compile cspot dan run side-by-side dengan packet capture untuk melihat perbedaan bytes.
