/*
 * Copyright 2009 Colin Percival, 2014 savale
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "simd-utils.h"
#include <algo/yespower/crypto/sph_types.h>
#include "blake2b-yp.h"

// Cyclic right rotation.
//#ifndef ROTR64
//#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))
//#endif

#define ROTR64(x, y) ror64( x, y )

// Little-endian byte access.
#define B2B_GET64(p)                            \
    (((uint64_t) ((uint8_t *) (p))[0]) ^        \
    (((uint64_t) ((uint8_t *) (p))[1]) << 8) ^  \
    (((uint64_t) ((uint8_t *) (p))[2]) << 16) ^ \
    (((uint64_t) ((uint8_t *) (p))[3]) << 24) ^ \
    (((uint64_t) ((uint8_t *) (p))[4]) << 32) ^ \
    (((uint64_t) ((uint8_t *) (p))[5]) << 40) ^ \
    (((uint64_t) ((uint8_t *) (p))[6]) << 48) ^ \
    (((uint64_t) ((uint8_t *) (p))[7]) << 56))

// G Mixing function.
#define B2B_G(a, b, c, d, x, y) {   \
    v[a] = v[a] + v[b] + x;      \
    v[d] = ROTR64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d];          \
    v[b] = ROTR64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + y;      \
    v[d] = ROTR64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d];          \
    v[b] = ROTR64(v[b] ^ v[c], 63); }

// Initialization Vector.
static const uint64_t blake2b_iv[8] = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

// Compression function. "last" flag indicates last block.
static void blake2b_compress(blake2b_yp_ctx *ctx, int last)
{
    const uint8_t sigma[12][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };
    int i;
    uint64_t v[16], m[16];

    // init work variables
    for (i = 0; i < 8; i++) {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }

    v[12] ^= ctx->t[0]; // low 64 bits of offset
    v[13] ^= ctx->t[1]; // high 64 bits

    // last block flag set ?
    if (last) { 
        v[14] = ~v[14];
    }

    // get little-endian words
    for (i = 0; i < 16; i++) {
        m[i] = B2B_GET64(&ctx->b[8 * i]);
    }

    // twelve rounds
    for (i = 0; i < 12; i++) {
        B2B_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
        B2B_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
        B2B_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
        B2B_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
        B2B_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
        B2B_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
        B2B_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
        B2B_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
    }

    for(i = 0; i < 8; ++i) {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

// Initialize the hashing context "ctx" with optional key "key".
// 1 <= outlen <= 64 gives the digest size in bytes.
// Secret key (also <= 64 bytes) is optional (keylen = 0).
int blake2b_yp_init(blake2b_yp_ctx *ctx, size_t outlen,
    const void *key, size_t keylen) // (keylen=0: no key)
{
    size_t i;

    // illegal parameters
    if (outlen == 0 || outlen > 64 || keylen > 64) {
        return -1;
    }

    // state, "param block"
    for (i = 0; i < 8; i++) {
        ctx->h[i] = blake2b_iv[i];
    }

    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    ctx->t[0] = 0; // input count low word
    ctx->t[1] = 0; // input count high word
    ctx->c = 0; // pointer within buffer
    ctx->outlen = outlen;

    // zero input block
    for (i = keylen; i < 128; i++) {
        ctx->b[i] = 0;
    }

    if (keylen > 0) {
        blake2b_yp_update(ctx, key, keylen);
        ctx->c = 128; // at the end
    }

    return 0;
}

// Add "inlen" bytes from "in" into the hash.
void blake2b_yp_update(blake2b_yp_ctx *ctx,
    const void *in, size_t inlen) // data bytes
{
    size_t i;
    for (i = 0; i < inlen; i++) {
        if (ctx->c == 128) { // buffer full ?
            ctx->t[0] += ctx->c; // add counters
            if (ctx->t[0] < ctx->c) // carry overflow ?
                ctx->t[1]++; // high word
            blake2b_compress(ctx, 0); // compress (not last)
            ctx->c = 0; // counter to zero
        }
        ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
    }
}

// Generate the message digest (size given in init).
// Result placed in "out".
void blake2b_yp_final(blake2b_yp_ctx *ctx, void *out)
{
    size_t i;

    ctx->t[0] += ctx->c; // mark last block offset
    // carry overflow
    if (ctx->t[0] < ctx->c) {
        ctx->t[1]++; // high word
    }

    // fill up with zeros
    while (ctx->c < 128) {
        ctx->b[ctx->c++] = 0;
    }

    blake2b_compress(ctx, 1); // final block flag = 1

    // little endian convert and store
    for (i = 0; i < ctx->outlen; i++) {
        ((uint8_t *) out)[i] =
            (ctx->h[i >> 3] >> (8 * (i & 7))) & 0xFF;
    }
}

// inlen = number of bytes
void blake2b_yp_hash(void *out, const void *in, size_t inlen) {
    blake2b_yp_ctx ctx;
    blake2b_yp_init(&ctx, 32, NULL, 0);
    blake2b_yp_update(&ctx, in, inlen);
    blake2b_yp_final(&ctx, out);
}

// // keylen = number of bytes
void hmac_blake2b_yp_init(hmac_yp_ctx *hctx, const void *_key, size_t keylen) {
    const uint8_t *key = _key;
    uint8_t keyhash[32];
    uint8_t pad[64];
    uint64_t i;

    if (keylen > 64) {
        blake2b_yp_hash(keyhash, key, keylen);
        key = keyhash;
        keylen = 32;
    }

    blake2b_yp_init(&hctx->inner, 32, NULL, 0);
    memset(pad, 0x36, 64);
    for (i = 0; i < keylen; ++i) {
        pad[i] ^= key[i];
    }

    blake2b_yp_update(&hctx->inner, pad, 64);
    blake2b_yp_init(&hctx->outer, 32, NULL, 0);
    memset(pad, 0x5c, 64);
    for (i = 0; i < keylen; ++i) {
        pad[i] ^= key[i];
    }

    blake2b_yp_update(&hctx->outer, pad, 64);
    memset(keyhash, 0, 32);
}

// datalen = number of bits
void hmac_blake2b_yp_update(hmac_yp_ctx *hctx, const void *data, size_t datalen) {
    // update the inner state
    blake2b_yp_update(&hctx->inner, data, datalen);
}

void hmac_blake2b_yp_final(hmac_yp_ctx *hctx, uint8_t *digest) {
    uint8_t ihash[32];
    blake2b_yp_final(&hctx->inner, ihash);
    blake2b_yp_update(&hctx->outer, ihash, 32);
    blake2b_yp_final(&hctx->outer, digest);
    memset(ihash, 0, 32);
}

// // keylen = number of bytes; inlen = number of bytes
void hmac_blake2b_yp_hash(void *out, const void *key, size_t keylen, const void *in, size_t inlen) {
    hmac_yp_ctx hctx;
    hmac_blake2b_yp_init(&hctx, key, keylen);
    hmac_blake2b_yp_update(&hctx, in, inlen);
    hmac_blake2b_yp_final(&hctx, out);
}

void pbkdf2_blake2b_yp(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    hmac_yp_ctx PShctx, hctx;
    size_t i;
    uint32_t ivec;
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_blake2b_yp_init(&PShctx, passwd, passwdlen);
    hmac_blake2b_yp_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        ivec = bswap_32( i+1 );

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_yp_ctx));
        hmac_blake2b_yp_update(&hctx, &ivec, 4);
        hmac_blake2b_yp_final(&hctx, U);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_blake2b_yp_init(&hctx, passwd, passwdlen);
            hmac_blake2b_yp_update(&hctx, U, 32);
            hmac_blake2b_yp_final(&hctx, U);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32) {
            clen = 32;
        }

        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(hmac_yp_ctx));
}
