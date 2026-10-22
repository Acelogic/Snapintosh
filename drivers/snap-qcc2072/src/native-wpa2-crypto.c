/* SPDX-License-Identifier: MIT */
#include "native-wpa2-crypto.h"
#include "../../../compat/aes.h"
#include <string.h>

struct sha1_state { uint32_t h[5]; uint64_t bytes; uint8_t block[64]; unsigned used; };
void snap_wpa2_clear(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}
static uint32_t rol(uint32_t v, unsigned n) { return v << n | v >> (32 - n); }
static void sha1_block(struct sha1_state *s)
{
    uint32_t w[80], a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4];
    for (unsigned i = 0; i < 16; ++i) {
        const uint8_t *p = s->block + 4 * i;
        w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
    for (unsigned i = 16; i < 80; ++i) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    for (unsigned i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
    snap_wpa2_clear(w, sizeof(w));
}
static void sha1_init(struct sha1_state *s)
{
    memset(s, 0, sizeof(*s));
    s->h[0] = 0x67452301; s->h[1] = 0xefcdab89; s->h[2] = 0x98badcfe;
    s->h[3] = 0x10325476; s->h[4] = 0xc3d2e1f0;
}
static void sha1_update(struct sha1_state *s, const uint8_t *p, size_t n)
{
    s->bytes += n;
    while (n--) {
        s->block[s->used++] = *p++;
        if (s->used == 64) { sha1_block(s); s->used = 0; }
    }
}
static void sha1_final(struct sha1_state *s, uint8_t out[20])
{
    uint64_t bits = s->bytes * 8;
    uint8_t p[8], mark = 0x80, zero = 0;
    sha1_update(s, &mark, 1);
    while (s->used != 56) sha1_update(s, &zero, 1);
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha1_update(s, p, 8);
    for (unsigned i = 0; i < 20; ++i) out[i] = (uint8_t)(s->h[i / 4] >> (24 - 8 * (i % 4)));
    snap_wpa2_clear(s, sizeof(*s));
}
void snap_wpa2_hmac(const uint8_t *key, size_t key_length,
                    const uint8_t *p, size_t n, uint8_t out[20])
{
    struct sha1_state s;
    uint8_t pad[64] = {0}, inner[20];
    if (key_length > 64) {
        sha1_init(&s); sha1_update(&s, key, key_length); sha1_final(&s, pad);
    } else memcpy(pad, key, key_length);
    for (unsigned i = 0; i < 64; ++i) pad[i] ^= 0x36;
    sha1_init(&s); sha1_update(&s, pad, 64); sha1_update(&s, p, n); sha1_final(&s, inner);
    for (unsigned i = 0; i < 64; ++i) pad[i] ^= 0x36 ^ 0x5c;
    sha1_init(&s); sha1_update(&s, pad, 64); sha1_update(&s, inner, 20); sha1_final(&s, out);
    snap_wpa2_clear(pad, sizeof(pad)); snap_wpa2_clear(inner, sizeof(inner));
}
int snap_wpa2_unwrap(const uint8_t kek[16], const uint8_t *input, size_t length, uint8_t *out)
{
    if (length < 24 || length > 256 || length % 8) return 0;
    struct aes_key key;
    uint8_t a[8], block[16];
    aes_expand(&key, kek, 16); memcpy(a, input, 8); memcpy(out, input + 8, length - 8);
    unsigned n = (unsigned)(length / 8 - 1);
    for (unsigned j = 6; j--;) for (unsigned i = n; i; --i) {
        uint64_t t = (uint64_t)n * j + i;
        for (unsigned k = 0; k < 8; ++k) block[k] = a[k] ^ (uint8_t)(t >> (56 - 8 * k));
        memcpy(block + 8, out + 8 * (i - 1), 8);
        aes_block(&key, block, block, 1);
        memcpy(a, block, 8); memcpy(out + 8 * (i - 1), block + 8, 8);
    }
    unsigned different = 0;
    for (unsigned i = 0; i < 8; ++i) different |= a[i] ^ 0xa6;
    snap_wpa2_clear(&key, sizeof(key)); snap_wpa2_clear(a, sizeof(a));
    snap_wpa2_clear(block, sizeof(block));
    if (different) snap_wpa2_clear(out, length - 8);
    return !different;
}
