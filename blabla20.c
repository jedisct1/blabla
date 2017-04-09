#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blabla20.h"

#define crypto_stream_blabla20_ROUNDS 20

#if defined(__x86_64__) || defined(__i386__)
# undef  NATIVE_LITTLE_ENDIAN
# define NATIVE_LITTLE_ENDIAN
#endif

#define ROTR64(x, b) (uint64_t)(((x) >> (b)) | ((x) << (64 - (b))))

#define LOAD64_LE(SRC) load64_le(SRC)
static inline uint64_t load64_le(const uint8_t src[8]) {
#ifdef NATIVE_LITTLE_ENDIAN
  uint64_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  uint64_t w = (uint64_t)src[0];
  w |= (uint64_t)src[1] << 8;
  w |= (uint64_t)src[2] << 16;
  w |= (uint64_t)src[3] << 24;
  w |= (uint64_t)src[4] << 32;
  w |= (uint64_t)src[5] << 40;
  w |= (uint64_t)src[6] << 48;
  w |= (uint64_t)src[7] << 56;
  return w;
#endif
}

#define STORE64_LE(DST, W) store64_le((DST), (W))
static inline void store64_le(uint8_t dst[8], uint64_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
  memcpy(dst, &w, sizeof w);
#else
  dst[0] = (uint8_t)w;
  w >>= 8;
  dst[1] = (uint8_t)w;
  w >>= 8;
  dst[2] = (uint8_t)w;
  w >>= 8;
  dst[3] = (uint8_t)w;
  w >>= 8;
  dst[4] = (uint8_t)w;
  w >>= 8;
  dst[5] = (uint8_t)w;
  w >>= 8;
  dst[6] = (uint8_t)w;
  w >>= 8;
  dst[7] = (uint8_t)w;
#endif
}

#define HYDRO_STREAM_BLABLA20_QUARTERROUND(a, b, c, d)                         \
  a += b;                                                                      \
  d = ROTR64(d ^ a, 32);                                                       \
  c += d;                                                                      \
  b = ROTR64(b ^ c, 24);                                                       \
  a += b;                                                                      \
  d = ROTR64(d ^ a, 16);                                                       \
  c += d;                                                                      \
  b = ROTR64(b ^ c, 63)

static void crypto_stream_blabla20_rounds(uint64_t st[16]) {
  int i;

  for (i = 0; i < crypto_stream_blabla20_ROUNDS; i += 2) {
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[0], st[4], st[8], st[12]);
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[1], st[5], st[9], st[13]);
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[2], st[6], st[10], st[14]);
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[3], st[7], st[11], st[15]);
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[0], st[5], st[10], st[15]);
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[1], st[6], st[11], st[12]);
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[2], st[7], st[8], st[13]);
    HYDRO_STREAM_BLABLA20_QUARTERROUND(st[3], st[4], st[9], st[14]);
  }
}

static void crypto_stream_blabla20_update(uint64_t ks[16], uint64_t st[16]) {
  int i;

  memcpy(ks, st, 8 * 16);
  crypto_stream_blabla20_rounds(st);
  for (i = 0; i < 16; i++) {
    ks[i] += st[i];
  }
  ++st[13];
}

static void crypto_stream_blabla20_init(
    uint64_t st[16], const uint8_t nonce[crypto_stream_blabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_blabla20_KEYBYTES]) {
  int i;

  st[0] = 0x6170786593810fab;
  st[1] = 0x3320646ec7398aee;
  st[2] = 0x79622d3217318274;
  st[3] = 0x6b206574babadada;
  for (i = 0; i < 4; i++) {
    st[4 + i] = LOAD64_LE(&key[8 * i]);
  }
  st[8] = 0x2ae36e593e46ad5f;
  st[9] = 0xb68f143029225fc9;
  st[10] = 0x8da1e08468303aa6;
  st[11] = 0xa48a209acd50a4a7;
  st[12] = 0x7fdc12f23f90778c;
  st[13] = 1;
  st[14] = LOAD64_LE(&nonce[8 * 0]);
  st[15] = LOAD64_LE(&nonce[8 * 1]);
}

int crypto_stream_blabla20_xor(
    uint8_t *c, const uint8_t *m, size_t len,
    const uint8_t nonce[crypto_stream_blabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_blabla20_KEYBYTES]) {
  uint8_t tmp[crypto_stream_blabla20_BLOCKBYTES];
  uint64_t ks[16];
  uint64_t st[16];
  uint64_t x;
  int i;

  crypto_stream_blabla20_init(st, nonce, key);
  while (len >= crypto_stream_blabla20_BLOCKBYTES) {
    crypto_stream_blabla20_update(ks, st);
    for (i = 0; i < 16; i++) {
      x = ks[i] ^ LOAD64_LE(m + 8 * i);
      STORE64_LE(c + 8 * i, x);
    }
    c += crypto_stream_blabla20_BLOCKBYTES;
    m += crypto_stream_blabla20_BLOCKBYTES;
    len -= crypto_stream_blabla20_BLOCKBYTES;
  }
  if (len > 0) {
    crypto_stream_blabla20_update(ks, st);
    memset(tmp, 0, crypto_stream_blabla20_BLOCKBYTES);
    for (i = 0; i < (int)len; i++) {
      tmp[i] = m[i];
    }
    for (i = 0; i < 16; i++) {
      x = ks[i] ^ LOAD64_LE(tmp + 8 * i);
      STORE64_LE(tmp + 8 * i, x);
    }
    for (i = 0; i < (int)len; i++) {
      c[i] = tmp[i];
    }
  }
  return 0;
}

int crypto_stream_blabla20(
    uint8_t *c, size_t len,
    const uint8_t nonce[crypto_stream_blabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_blabla20_KEYBYTES]) {
  memset(c, 0, len);
  return crypto_stream_blabla20_xor(c, c, len, nonce, key);
}

void crypto_stream_blabla20_block(
    uint8_t block[crypto_stream_blabla20_BLOCKBYTES],
    const uint8_t nonce[crypto_stream_blabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_blabla20_KEYBYTES]) {
  uint64_t ks[16];
  uint64_t st[16];
  int i;

  crypto_stream_blabla20_init(st, &nonce[8], key);
  st[13] = LOAD64_LE(&nonce[0]);
  crypto_stream_blabla20_update(ks, st);
  for (i = 0; i < 16; i++) {
    STORE64_LE(block + 8 * i, ks[i]);
  }
}

static void
crypto_stream_hblabla20(uint8_t subkey[crypto_stream_hblabla20_BYTES],
                        const uint8_t nonce[crypto_stream_hblabla20_NONCEBYTES],
                        const uint8_t key[crypto_stream_hblabla20_KEYBYTES]) {
  uint64_t st[16];
  int i;

  crypto_stream_blabla20_init(st, &nonce[8], key);
  st[13] = LOAD64_LE(&nonce[0]);
  crypto_stream_blabla20_rounds(st);
  for (i = 0; i < 2; i++) {
    STORE64_LE(subkey + 8 * i, st[i]);
  }
  for (; i < 4; i++) {
    STORE64_LE(subkey + 8 * i, st[i + 12 - 4]);
  }
}

int crypto_stream_xblabla20_xor(
    uint8_t *c, const uint8_t *m, size_t len,
    const uint8_t nonce[crypto_stream_xblabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_xblabla20_KEYBYTES]) {
  uint8_t subkey[crypto_stream_blabla20_KEYBYTES];
  uint8_t subnonce[crypto_stream_blabla20_NONCEBYTES];

  crypto_stream_hblabla20(subkey, nonce, key);

  return crypto_stream_blabla20_xor(c, m, len, subnonce, subkey);
}
