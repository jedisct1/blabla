#ifndef blabla20_H
#define blabla20_H 1

#include <stddef.h>
#include <stdint.h>

#define crypto_stream_blabla20_BLOCKBYTES 128

#define crypto_stream_blabla20_KEYBYTES 32
#define crypto_stream_blabla20_NONCEBYTES 16

#define crypto_stream_xblabla20_KEYBYTES 32
#define crypto_stream_xblabla20_NONCEBYTES 24

#define crypto_stream_hblabla20_BYTES 32
#define crypto_stream_hblabla20_KEYBYTES 32
#define crypto_stream_hblabla20_NONCEBYTES 24

int crypto_stream_blabla20_xor(
    uint8_t *c, const uint8_t *m, size_t len,
    const uint8_t nonce[crypto_stream_blabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_blabla20_KEYBYTES]);

int crypto_stream_blabla20(
    uint8_t *c, size_t len,
    const uint8_t nonce[crypto_stream_blabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_blabla20_KEYBYTES]);

void crypto_stream_blabla20_block(
    uint8_t block[crypto_stream_blabla20_BLOCKBYTES],
    const uint8_t nonce[crypto_stream_blabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_blabla20_KEYBYTES]);

int crypto_stream_xblabla20_xor(
    uint8_t *c, const uint8_t *m, size_t len,
    const uint8_t nonce[crypto_stream_xblabla20_NONCEBYTES],
    const uint8_t key[crypto_stream_xblabla20_KEYBYTES]);

#endif
