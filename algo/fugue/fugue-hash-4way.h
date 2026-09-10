#ifndef FUGUE_HASH_4WAY_H__
#define FUGUE_HASH_4WAY_H__ 1

#include "simd-utils.h"

/* 4-lane fugue512. Each lane occupies one 128-bit sublane of a 512-bit
 * register, so every round op stays 128-bit-lane-local and the AES step is
 * _mm512_aesenclast_epi128 (VAES). Hence "4x128": the element is 128 bits.
 *
 * The API takes four separate lane buffers, not an interleaved one, so it drops
 * into the sites that already de-interleave and call fugue512_full per lane.
 * in* may alias out*, lane for lane; cross-lane aliasing is not supported.
 */

/* -DFUGUE_NO_NWAY disables both widths; every caller falls back to per-lane
 * fugue512_full. */
#if defined(SIMD512) && defined(__VAES__) && !defined(FUGUE_NO_NWAY)

#define FUGUE_4X128 1

typedef struct
{
   __m512i state[12];
   unsigned int base;
} fugue512_4x128_context __attribute__ ((aligned (64)));

void fugue512_4x128_full( fugue512_4x128_context *ctx,
                          void *out0, void *out1, void *out2, void *out3,
                          const void *in0, const void *in1,
                          const void *in2, const void *in3,
                          uint64_t len );

#endif // SIMD512 && VAES

/* 2-lane variant for VAES machines without AVX-512 (Zen 2 / Zen 3), where x17
 * and friends select their 4-way width and already use 2-lane groestl/echo.
 * Same structure, __m256i, _mm256_aesenclast_epi128. */
#if defined(__AVX2__) && defined(__VAES__) && !defined(FUGUE_NO_NWAY)

#define FUGUE_2X128 1

typedef struct
{
   __m256i state[12];
   unsigned int base;
} fugue512_2x128_context __attribute__ ((aligned (64)));

void fugue512_2x128_full( fugue512_2x128_context *ctx,
                          void *out0, void *out1,
                          const void *in0, const void *in1, uint64_t len );

#endif // AVX2 && VAES
#endif // FUGUE_HASH_4WAY_H__
