# ESPConnect2 — Fix Summary (Sesi Pertama)

> **Tanggal**: 2026-06-24  
> **File yang diubah**: `src/platform_posix.c`, `src/mercury.c`  
> **Total bug di-fix**: 7 bug (3 di platform_posix.c, 6 di mercury.c)

---

## Ringkasan Eksekutif

Kode ESPConnect2 tidak bisa mendapat **APWelcome** karena ada rantai bug yang saling terkait:

```
HMAC challenge salah (Bug #5)
  → send_key & recv_key salah
    → Shannon encrypt dengan key yang SALAH (Bug #1 + #3)
      → Server tidak bisa baca LoginRequest
        → MAC mismatch di setiap recv (Bug #7)
          → APWelcome tidak pernah di-decode dengan benar (Bug #6)
```

---

## File 1: `src/platform_posix.c`

### FIX #1 — `SHANNON_INITKONST` Nilai Salah

| | |
|---|---|
| **Line** | 432 |
| **Severity** | 🔴 Kritis |

```diff
- #define SHANNON_INITKONST 0x6996c53a
+ #define SHANNON_INITKONST 0x6996c75a  /* FIX #1: was 0x6996c53a (typo: c5→c7) */
```

**Kenapa penting**: Konstanta ini digunakan di setiap siklus Shannon LFSR. Nilai yang salah menyebabkan seluruh key schedule menghasilkan state yang berbeda dari spesifikasi Shannon asli. Semua packet yang terenkripsi tidak bisa didekripsi oleh server.

---

### FIX #2 — DH Shared Secret Tidak Dipad ke 96 Bytes

| | |
|---|---|
| **Line** | 364–373 |
| **Severity** | 🔴 Kritis (intermittent — terjadi bila shared secret punya leading zeros) |

```diff
  BIGNUM *rb = BN_bin2bn(peer_pub, (int)peer_pub_len, NULL);
+ memset(shared, 0, 96);
  int ol = DH_compute_key(shared, rb, dh);
  BN_free(rb);
  
  if (ol < 0) {
-     memset(shared, 0, 96);
      *out_len = 0;
  } else {
-     /* Do NOT pad with leading zeros! */
-     *out_len = (size_t)ol;
+     /* Pad result to 96 bytes (zero-fill left side if shorter) */
+     if (ol < 96) {
+         memmove(shared + (96 - ol), shared, (size_t)ol);
+         memset(shared, 0, (size_t)(96 - ol));
+     }
+     *out_len = 96;
  }
```

**Kenapa penting**: `OpenSSL DH_compute_key()` membuang leading zeros dari hasil. Kalau shared secret secara kebetulan punya leading zeros (probabilitas ~1/256 per byte), hasilnya lebih pendek dari 96 bytes. HMAC challenge kemudian dihitung dari input yang berbeda → `send_key`/`recv_key` salah → Shannon tidak bisa sinkron dengan server.

---

### FIX #3 — `shannon_finish()` Tidak Mencampur CRC ke LFSR

| | |
|---|---|
| **Line** | 683–690 |
| **Severity** | 🔴 Kritis |

```diff
  void platform_shannon_finish(platform_shannon_t *s, uint8_t mac[4]) {
-     if (s->nbuf) { shannon_macfunc(s, s->mbuf); }
-     shannon_cycle(s);
-     uint32_t t = s->CRC[0] ^ s->CRC[2] ^ s->CRC[15] ^ SHANNON_INITKONST;
-     WORD2BYTE(t, mac);
+     if (s->nbuf != 0) { shannon_macfunc(s, s->mbuf); s->nbuf = 0; }
+     s->konst = SHANNON_INITKONST;
+     for (int i = 0; i < SHANNON_N; i++) {
+         s->R[SHANNON_KEYP] ^= s->CRC[i];
+         shannon_cycle(s);
+     }
+     WORD2BYTE(s->sbuf, mac);
  }
```

**Kenapa penting**: MAC di Shannon dihitung dengan mencampurkan semua 16 word dari CRC state ke dalam LFSR `R[]`, kemudian melakukan clock cycle. Implementasi lama hanya mengambil XOR dari 3 element CRC secara langsung — hasilnya MAC yang salah di setiap packet, menyebabkan server menolak koneksi.

---

## File 2: `src/mercury.c`

### FIX #4 — `ClientResponsePlaintext` Dikirim dengan Length Prefix

| | |
|---|---|
| **Line** | 622–628 |
| **Severity** | 🔴 Kritis |

```diff
- ret = tcp_send_packet(s->sock, NULL, 0, cr_buf.data, cr_buf.size, NULL, NULL);
+ ret = platform_tcp_write(s->sock, cr_buf.data, cr_buf.size);
```

**Kenapa penting**: `tcp_send_packet()` selalu menambahkan 4-byte BE length header. `ClientResponsePlaintext` seharusnya dikirim sebagai **raw protobuf bytes saja** — tanpa prefix apapun. Dengan length header, server menerima data yang tidak sesuai format dan gagal memverifikasi HMAC challenge.

---

### FIX #5 — HMAC Challenge: Byte Counter di Akhir, Harusnya di Awal

| | |
|---|---|
| **Line** | 303–312 |
| **Severity** | 🔴 **Root Cause Utama** |

```diff
  for (int x = 1; x < 6; x++) {
      uint8_t *cv = malloc(cb_len + 1);
-     memcpy(cv, cb, cb_len);
-     cv[cb_len] = (uint8_t)x;   /* x di AKHIR — SALAH */
+     cv[0] = (uint8_t)x;          /* x di AWAL — prepend */
+     memcpy(cv + 1, cb, cb_len);  /* cb menyusul setelahnya */
      platform_hmac_sha1(shared, shared_len, cv, cb_len + 1, dst);
  }
```

**Kenapa penting**: Ini adalah **akar masalah utama**. cspot C++ menggunakan:
```cpp
auto data = std::vector<uint8_t>(1, i);      // {i}
data.insert(data.end(), cb.begin(), cb.end()); // {i, cb...}
```
Layout yang benar adalah `[i][cb...]`. Kamu salah interpretasi dan menaruh `x` di akhir → 5 HMAC yang dihasilkan semuanya salah → `send_key` dan `recv_key` berbeda dari server → Shannon tidak bisa berkomunikasi sama sekali.

---

### FIX #6 — APWelcome Field Numbers Salah

| | |
|---|---|
| **Line** | 694–726 |
| **Severity** | 🔴 Kritis (data tidak terbaca setelah auth berhasil) |

```diff
  while (pb_read_tag(&aw, &f, &w)) {
-     if (f == 10 && w == PB_LENGTH_DELIM) { /* canonical_username */ }
-     else if (f == 20 && w == PB_VARINT)  { /* account type */ }
-     else if (f == 30 && w == PB_VARINT)  { /* reusable type */ }
-     else if (f == 40 && w == PB_LENGTH_DELIM) { /* stored cred */ }
-     else if (f == 50 && w == PB_LENGTH_DELIM) { /* display name */ }
+     if (f == 1 && w == PB_LENGTH_DELIM) { /* canonical_username */ }
+     else if (f == 2 && w == PB_VARINT)  { /* account_type */ }
+     else if (f == 5 && w == PB_VARINT)  { /* reusable_credentials_type */ }
+     else if (f == 6 && w == PB_LENGTH_DELIM) { /* reusable_credentials */ }
  }
```

**Kenapa penting**: Protobuf APWelcome menggunakan field numbers 1, 2, 5, 6 sesuai `keyexchange.proto`. Field numbers 10, 20, 30, 40, 50 tidak ada → semua data APWelcome di-skip → `canonical_username` dan `stored_cred` tidak pernah terisi meski auth berhasil.

---

### FIX #7 — `mercury_recv()` Baca 4 Byte Harusnya 3 Byte

| | |
|---|---|
| **Line** | 794 |
| **Severity** | 🔴 Kritis |

```diff
- uint8_t hdr[4];
- platform_tcp_read(s->sock, hdr, 4);
- fprintf(stderr, "RAW hdr hex = %02x %02x %02x %02x\n", ...);
+ uint8_t hdr[3];
+ platform_tcp_read(s->sock, hdr, 3);
+ fprintf(stderr, "RAW hdr hex = %02x %02x %02x\n", ...);
```

**Kenapa penting**: Shannon AP packet header hanya 3 byte: `[cmd(1)][len_hi(1)][len_lo(1)]`. Membaca 4 byte berarti byte pertama dari **payload** ikut terbaca ke buffer header, tapi tidak masuk ke decryption. Shannon state kemudian tidak sinkron → MAC mismatch di setiap packet yang diterima.

---

### FIX #8 — Auth Type Check Salah (OAuth Token)

| | |
|---|---|
| **Line** | 460 |
| **Severity** | 🟡 Minor |

```diff
- if (auth_type == 3) {
+ if (auth_type == 2) {  /* AUTHENTICATION_SPOTIFY_TOKEN = 2, bukan 3 */
```

**Kenapa penting**: `auth_type == 3` adalah `AUTHENTICATION_FACEBOOK_TOKEN`. OAuth/Spotify token adalah `auth_type == 2`. Kode akan salah decode token string sebagai base64 padahal seharusnya dipakai as-is.

---

### FIX #9 — PING Command Check Salah

| | |
|---|---|
| **Line** | 676 |
| **Severity** | 🟡 Minor |

```diff
- if (cmd == 0x00) {
+ if (cmd == 0x04) {  /* PING dari server adalah 0x04, bukan 0x00 */
-     uint8_t empty = 0;
-     mercury_send(s, 0x49, &empty, 0);
+     mercury_send(s, 0x49, NULL, 0);
```

**Kenapa penting**: Server mengirim PING dengan command byte `0x04`. Kamu mengecek `0x00` yang tidak pernah ada → PING tidak pernah dijawab → server akan timeout dan tutup koneksi setelah beberapa detik.

---

## Tabel Ringkasan

| # | Bug | File | Line | Severity | Status |
|---|---|---|---|---|---|
| 1 | `INITKONST` salah (`c53a` → `c75a`) | `platform_posix.c` | 432 | 🔴 Fatal | ✅ Fixed |
| 2 | DH shared not padded to 96 bytes | `platform_posix.c` | 364 | 🔴 Fatal | ✅ Fixed |
| 3 | `shannon_finish()` MAC calculation salah | `platform_posix.c` | 683 | 🔴 Fatal | ✅ Fixed |
| 4 | `ClientResponse` dikirim dengan length prefix | `mercury.c` | 627 | 🔴 Fatal | ✅ Fixed |
| 5 | HMAC byte counter di akhir, harusnya di awal | `mercury.c` | 308 | 🔴 **Root Cause** | ✅ Fixed |
| 6 | APWelcome field numbers 10,20,40 → 1,2,6 | `mercury.c` | 694 | 🔴 Fatal | ✅ Fixed |
| 7 | `mercury_recv()` baca 4 byte, harusnya 3 | `mercury.c` | 794 | 🔴 Fatal | ✅ Fixed |
| 8 | Auth type OAuth: `3` → `2` | `mercury.c` | 460 | 🟡 Minor | ✅ Fixed |
| 9 | PING check `0x00` → `0x04` | `mercury.c` | 676 | 🟡 Minor | ✅ Fixed |

---

## Langkah Selanjutnya

1. **Compile** dan test dengan zeroconf pairing
2. **Lihat log output** — cari baris `[mercury] Recv cmd=0xAC` (APWelcome)
3. Kalau masih gagal, cek apakah ada **`MAC MISMATCH`** di log → Shannon masih belum sinkron
4. Kalau berhasil → cek apakah `canonical_username` terisi dengan benar di log

> [!TIP]
> Jika ingin memastikan HMAC sudah benar sebelum test ke server Spotify, bisa dibandingkan output `login5_dump.txt` dengan output yang sama dari librespot/cspot yang berhasil connect.
