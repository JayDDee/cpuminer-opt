/*
 * Equihash internal shared primitives.
 *
 * Included by the arch-neutral core (equihash.c) AND by every solver backend
 * (equihash-ref.c, and later equihash-simd.c). These are the small, hot,
 * byte-layout primitives that the kernels and the verifier MUST agree on
 * exactly. Keeping them `static inline` here lets each translation unit inline
 * them (important for the Wagner inner loop) while guaranteeing the reference
 * backend and the verifier stay bit-identical.
 */
#ifndef EQUIHASH_IMPL_H
#define EQUIHASH_IMPL_H

#include "equihash.h"
#include "../blake/sph_blake2b.h"
#include <stdint.h>
#include <string.h>

/* ── Parameter helpers ───────────────────────────────────────────── */

static inline int eh_indices_per_hash(int wn)
{
    return 512 / wn;   /* IndicesPerHashOutput = 512/N (integer division) */
}

static inline int eh_hash_output(int wn)
{
    /* HashOutput = IndicesPerHashOutput * N/8  (non-ZelHash)
     * ZelHash (N=125): IndicesPerHashOutput * ceil(N/8)           */
    int iph = eh_indices_per_hash(wn);
    if (wn == 125) return iph * ((wn + 7) / 8);
    return iph * (wn / 8);
}

/* ── Blake2b with personalization ────────────────────────────────── */

static inline uint64_t eh_load64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8*i);
    return v;
}

static inline void blake2b_init_pers(sph_blake2b_ctx *ctx, size_t outlen,
                                     const uint8_t *personal)
{
    static const uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    memset(ctx, 0, sizeof(*ctx));
    ctx->outlen = outlen;
    for (int i = 0; i < 8; i++) ctx->h[i] = iv[i];
    ctx->h[0] ^= (uint64_t)outlen | (1ULL << 16) | (1ULL << 24);
    if (personal) {
        ctx->h[6] ^= eh_load64le(personal);
        ctx->h[7] ^= eh_load64le(personal + 8);
    }
}

/* ── ExpandArray (reference algorithm) ───────────────────────────── */
/* Converts raw hash bytes to collision-aligned expanded format.
 * Matches CompressArray/ExpandArray from equihash.cpp (byte_pad = 0).        */
static inline void expand_hash(const uint8_t *in, int in_len,
                               uint8_t *out, int out_len, int bit_len)
{
    int out_width = (bit_len + 7) / 8;

    /* Byte-aligned fast path (96/5 cbl=2, 144/5 / 192/7 cbl=3): when bit_len is
     * a multiple of 8 each extracted value is just `out_width` consecutive raw
     * bytes, so ExpandArray degenerates to a straight copy of whole groups. The
     * bit-extraction loop below is pure overhead there. Bit-identical: same
     * group count, same bytes. The bit path stays for 200/9 (20) and 125/4 (25). */
    if ((bit_len & 7) == 0) {
        int groups     = in_len  / out_width;   /* full input groups */
        int max_groups = out_len / out_width;
        if (groups > max_groups) groups = max_groups;
        memcpy(out, in, (size_t)groups * out_width);
        return;
    }

    uint32_t mask = ((uint32_t)1 << bit_len) - 1;
    uint32_t acc  = 0;
    int acc_bits  = 0;
    int j         = 0;
    for (int i = 0; i < in_len && j < out_len; i++) {
        acc = (acc << 8) | in[i];
        acc_bits += 8;
        if (acc_bits >= bit_len) {
            acc_bits -= bit_len;
            uint32_t val = (acc >> acc_bits) & mask;
            /* Write val big-endian into out_width bytes */
            for (int x = out_width - 1; x >= 0; x--) {
                out[j + x] = (uint8_t)(val & 0xFF);
                val >>= 8;
            }
            j += out_width;
        }
    }
}

/* ── Slot accessors ──────────────────────────────────────────────── */

/* Minimum leaf index stored at slot[hash_length..hash_length+3] (LE32) */
static inline uint32_t slot_get_min(const uint8_t *slot, int hash_length)
{
    const uint8_t *p = slot + hash_length;
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

static inline void slot_set_min(uint8_t *slot, int hash_length, uint32_t v)
{
    uint8_t *p = slot + hash_length;
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

/* Bucket key: top min(collision_bits,20) bits of the collision group, which
 * begins at slot[0] (MSB). This reads exactly 3 bytes, so slot[0] is the MSB
 * at bit 23 and shift = 24 - bkt_bits, INDEPENDENT of cbl. coll_match re-checks
 * the full cbl bytes, so the bucket is a correct superset for cbl = 2, 3, 4.  */
static inline uint32_t bucket_key_be(const uint8_t *slot, int cbl,
                                     int collision_bits)
{
    (void)cbl;
    int bkt_bits = collision_bits < 20 ? collision_bits : 20;
    uint32_t v = ((uint32_t)slot[0] << 16) |
                 ((uint32_t)slot[1] <<  8) |
                  (uint32_t)slot[2];
    int shift = 24 - bkt_bits;
    return (v >> shift) & ((1u << bkt_bits) - 1);
}

/* Check full collision: first cbl bytes must be equal (big-endian match) */
static inline int coll_match(const uint8_t *a, const uint8_t *b, int cbl)
{
    return memcmp(a, b, cbl) == 0;
}

/* XOR first hash_length bytes (NOT the min_idx at the end). Word-at-a-time
 * (8-byte) with a byte tail; XOR is bytewise so this is endian-independent and
 * bit-identical to the scalar loop. hash_length is 12-30 B across variants, so
 * this is 2-4 word ops instead of up to 30 byte ops.                          */
static inline void xor_hash(uint8_t *dst, const uint8_t *src, int hash_length)
{
    int i = 0;
    for (; i + 8 <= hash_length; i += 8) {
        uint64_t a, b;
        memcpy(&a, dst + i, 8);
        memcpy(&b, src + i, 8);
        a ^= b;
        memcpy(dst + i, &a, 8);
    }
    for (; i < hash_length; i++) dst[i] ^= src[i];
}

/* Shift expanded hash left by one CollisionByteLength group (cbl bytes). */
static inline void shift_hash(uint8_t *slot, int hash_length, int cbl)
{
    int remaining = hash_length - cbl;
    if (remaining > 0)
        memmove(slot, slot + cbl, remaining);
    memset(slot + remaining, 0, cbl);
}

/* True iff the leading cbl bytes of the slot hash are all zero. */
static inline int slot_zero(const uint8_t *slot, int cbl)
{
    for (int i = 0; i < cbl; i++) if (slot[i]) return 0;
    return 1;
}

#endif /* EQUIHASH_IMPL_H */
