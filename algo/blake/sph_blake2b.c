/*
 * Copyright 2009 Colin Percival, 2014 savale
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
#include "compat/sph_types.h"
#include "sph_blake2b.h"

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

#if defined(__AVX2__)

#define BLAKE2B_G( Sa, Sb, Sc, Sd, Se, Sf, Sg, Sh ) \
{ \
  V[0] = _mm256_add_epi64( V[0], _mm256_add_epi64( V[1], \
              _mm256_set_epi64x( m[ sigmaR[ Sg ] ], m[ sigmaR[ Se ] ], \
                                 m[ sigmaR[ Sc ] ], m[ sigmaR[ Sa ] ] ) ) ); \
  V[3] = mm256_ror_64( _mm256_xor_si256( V[3], V[0] ), 32 ); \
  V[2] = _mm256_add_epi64( V[2], V[3] ); \
  V[1] = mm256_ror_64( _mm256_xor_si256( V[1], V[2] ), 24 ); \
\
  V[0] = _mm256_add_epi64( V[0], _mm256_add_epi64( V[1], \
              _mm256_set_epi64x( m[ sigmaR[ Sh ] ], m[ sigmaR[ Sf ] ], \
                                 m[ sigmaR[ Sd ] ], m[ sigmaR[ Sb ] ] ) ) ); \
  V[3] = mm256_ror_64( _mm256_xor_si256( V[3], V[0] ), 16 ); \
  V[2] = _mm256_add_epi64( V[2], V[3] ); \
  V[1] = mm256_ror_64( _mm256_xor_si256( V[1], V[2] ), 63 ); \
}

// Pivot about V[1] instead of V[0] reduces latency.
#define BLAKE2B_ROUND( R ) \
{ \
  __m256i *V = (__m256i*)v; \
  const uint8_t *sigmaR = sigma[R]; \
  BLAKE2B_G(  0,  1,  2,  3,  4,  5,  6,  7 ); \
  V[0] = mm256_shufll_64( V[0] ); \
  V[3] = mm256_swap_128( V[3] ); \
  V[2] = mm256_shuflr_64( V[2] ); \
  BLAKE2B_G( 14, 15,  8,  9, 10, 11, 12, 13 ); \
  V[0] = mm256_shuflr_64( V[0] ); \
  V[3] = mm256_swap_128( V[3] ); \
  V[2] = mm256_shufll_64( V[2] ); \
}

/*
#define BLAKE2B_ROUND( R ) \
{ \
  __m256i *V = (__m256i*)v; \
  const uint8_t *sigmaR = sigma[R]; \
  BLAKE2B_G(  0,  1,  2,  3,  4,  5,  6,  7 ); \
  V[3] = mm256_shufll_64( V[3] ); \
  V[2] = mm256_swap_128( V[2] ); \
  V[1] = mm256_shuflr_64( V[1] ); \
  BLAKE2B_G(  8,  9, 10, 11, 12, 13, 14, 15 ); \
  V[3] = mm256_shuflr_64( V[3] ); \
  V[2] = mm256_swap_128( V[2] ); \
  V[1] = mm256_shufll_64( V[1] ); \
}
*/

#elif defined(__SSE2__) || defined(__ARM_NEON)

#define BLAKE2B_G( Va, Vb, Vc, Vd, Sa, Sb, Sc, Sd ) \
{ \
   Va = v128_add64( Va, v128_add64( Vb, \
                 v128_set64( m[ sigmaR[ Sc ] ], m[ sigmaR[ Sa ] ] ) ) ); \
   Vd = v128_ror64( v128_xor( Vd, Va ), 32 ); \
   Vc = v128_add64( Vc, Vd ); \
   Vb = v128_ror64( v128_xor( Vb, Vc ), 24 ); \
\
   Va = v128_add64( Va, v128_add64( Vb, \
                 v128_set64( m[ sigmaR[ Sd ] ], m[ sigmaR[ Sb ] ] ) ) ); \
   Vd = v128_ror64( v128_xor( Vd, Va ), 16 ); \
   Vc = v128_add64( Vc, Vd ); \
   Vb = v128_ror64( v128_xor( Vb, Vc ), 63 ); \
}

#define BLAKE2B_ROUND( R ) \
{ \
   v128_t *V = (v128_t*)v; \
   v128_t V2, V3, V6, V7; \
   const uint8_t *sigmaR = sigma[R]; \
   BLAKE2B_G( V[0], V[2], V[4], V[6], 0, 1, 2, 3 ); \
   BLAKE2B_G( V[1], V[3], V[5], V[7], 4, 5, 6, 7 ); \
   V2 = v128_alignr64( V[3], V[2], 1 ); \
   V3 = v128_alignr64( V[2], V[3], 1 ); \
   V6 = v128_alignr64( V[6], V[7], 1 ); \
   V7 = v128_alignr64( V[7], V[6], 1 ); \
   BLAKE2B_G( V[0], V2, V[5], V6,  8,  9, 10, 11 ); \
   BLAKE2B_G( V[1], V3, V[4], V7, 12, 13, 14, 15 ); \
   V[2] = v128_alignr64( V2, V3, 1 ); \
   V[3] = v128_alignr64( V3, V2, 1 ); \
   V[6] = v128_alignr64( V7, V6, 1 ); \
   V[7] = v128_alignr64( V6, V7, 1 ); \
}

#else

#ifndef ROTR64
#define ROTR64(x, y)  (((x) >> (y)) ^ ((x) << (64 - (y))))
#endif

#define BLAKE2B_G( R, Va, Vb, Vc, Vd, Sa, Sb ) \
{ \
   Va = Va + Vb + m[ sigma[R][Sa] ]; \
   Vd = ROTR64( Vd ^ Va, 32 ); \
   Vc = Vc + Vd; \
   Vb = ROTR64( Vb ^ Vc, 24 ); \
\
   Va = Va + Vb + m[ sigma[R][Sb] ]; \
   Vd = ROTR64( Vd ^ Va, 16 ); \
   Vc = Vc + Vd; \
   Vb = ROTR64( Vb ^ Vc, 63 ); \
}

#define BLAKE2B_ROUND( R ) \
{ \
   BLAKE2B_G( R, v[ 0], v[ 4], v[ 8], v[12],  0,  1 ); \
   BLAKE2B_G( R, v[ 1], v[ 5], v[ 9], v[13],  2,  3 ); \
   BLAKE2B_G( R, v[ 2], v[ 6], v[10], v[14],  4,  5 ); \
   BLAKE2B_G( R, v[ 3], v[ 7], v[11], v[15],  6,  7 ); \
   BLAKE2B_G( R, v[ 0], v[ 5], v[10], v[15],  8,  9 ); \
   BLAKE2B_G( R, v[ 1], v[ 6], v[11], v[12], 10, 11 ); \
   BLAKE2B_G( R, v[ 2], v[ 7], v[ 8], v[13], 12, 13 ); \
   BLAKE2B_G( R, v[ 3], v[ 4], v[ 9], v[14], 14, 15 ); \
}

#endif

// Initialization Vector.

static const uint64_t blake2b_iv[8] __attribute__ ((aligned (32))) =
{
	0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
	0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

static const uint8_t sigma[12][16] __attribute__ ((aligned (32))) =
{
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

// Compression function. "last" flag indicates last block.

static void blake2b_compress( sph_blake2b_ctx *ctx, int last )
{
	uint64_t v[16] __attribute__ ((aligned (32)));
   uint64_t m[16] __attribute__ ((aligned (32)));
   int i;

	for (i = 0; i < 8; i++) {           // init work variables
		v[i] = ctx->h[i];
		v[i + 8] = blake2b_iv[i];
	}

	v[12] ^= ctx->t[0];                 // low 64 bits of offset
	v[13] ^= ctx->t[1];                 // high 64 bits
	if (last)                           // last block flag set ?
		v[14] = ~v[14];
	for (i = 0; i < 16; i++)            // get little-endian words
		m[i] = B2B_GET64(&ctx->b[8 * i]);

	for (i = 0; i < 12; i++)
      BLAKE2B_ROUND( i );   

	for( i = 0; i < 8; ++i )
		ctx->h[i] ^= v[i] ^ v[i + 8];
}

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 64 gives the digest size in bytes.
//      Secret key (also <= 64 bytes) is optional (keylen = 0).

int sph_blake2b_init( sph_blake2b_ctx *ctx, size_t outlen, const void *key,
                      size_t keylen )        // (keylen=0: no key)
{
	size_t i;

	if (outlen == 0 || outlen > 64 || keylen > 64)
		return -1;                      // illegal parameters

	for (i = 0; i < 8; i++)             // state, "param block"
		ctx->h[i] = blake2b_iv[i];
	ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

	ctx->t[0] = 0;                      // input count low word
	ctx->t[1] = 0;                      // input count high word
	ctx->c = 0;                         // pointer within buffer
	ctx->outlen = outlen;

	for (i = keylen; i < 128; i++)      // zero input block
		ctx->b[i] = 0;
	if (keylen > 0) {
		sph_blake2b_update(ctx, key, keylen);
		ctx->c = 128;                   // at the end
	}

	return 0;
}

// Add "inlen" bytes from "in" into the hash.

void sph_blake2b_update( sph_blake2b_ctx *ctx, const void *in, size_t inlen )  
{
	size_t i;

	for (i = 0; i < inlen; i++) {
		if (ctx->c == 128) {            // buffer full ?
			ctx->t[0] += ctx->c;        // add counters
			if (ctx->t[0] < ctx->c)     // carry overflow ?
				ctx->t[1]++;            // high word
			blake2b_compress(ctx, 0);   // compress (not last)
			ctx->c = 0;                 // counter to zero
		}
		ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
	}
}

// Generate the message digest (size given in init).
//      Result placed in "out".

void sph_blake2b_final( sph_blake2b_ctx *ctx, void *out )
{
	size_t i;

	ctx->t[0] += ctx->c;                // mark last block offset
	if (ctx->t[0] < ctx->c)             // carry overflow
		ctx->t[1]++;                    // high word

	while (ctx->c < 128)                // fill up with zeros
		ctx->b[ctx->c++] = 0;

   blake2b_compress(ctx, 1);           // final block flag = 1

	// little endian convert and store
	for (i = 0; i < ctx->outlen; i++) {
		((uint8_t *) out)[i] =
			(ctx->h[i >> 3] >> (8 * (i & 7))) & 0xFF;
	}
}

