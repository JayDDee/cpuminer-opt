/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef BLAKE_ROUND_MKA_OPT_H
#define BLAKE_ROUND_MKA_OPT_H

#include "blake2-impl.h"
#include "simd-utils.h"

#if !defined(SIMD512)

#if !defined(__AVX2__)

static BLAKE2_INLINE v128_t fBlaMka(v128_t x, v128_t y)
{
    const v128u64_t z = v128_mulw32( x, y );
    return (v128u32_t)v128_add64( v128_add64( (v128u64_t)x, (v128u64_t)y ),
                                  v128_add64( z, z ) );
}

#define G1( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
   A0 = fBlaMka( A0, B0 ); \
   A1 = fBlaMka( A1, B1 ); \
   D0 = v128_xor( D0, A0 ); \
   D1 = v128_xor( D1, A1 ); \
   D0 = v128_ror64( D0, 32 ); \
   D1 = v128_ror64( D1, 32 ); \
   C0 = fBlaMka( C0, D0 ); \
   C1 = fBlaMka( C1, D1 ); \
   B0 = v128_xor( B0, C0 ); \
   B1 = v128_xor( B1, C1 ); \
   B0 = v128_ror64( B0, 24 ); \
   B1 = v128_ror64( B1, 24 ); \
} 

#define G2( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
   A0 = fBlaMka( A0, B0 ); \
   A1 = fBlaMka( A1, B1 ); \
   D0 = v128_xor( D0, A0 ); \
   D1 = v128_xor( D1, A1 ); \
   D0 = v128_ror64( D0, 16 ); \
   D1 = v128_ror64( D1, 16 ); \
   C0 = fBlaMka( C0, D0 ); \
   C1 = fBlaMka( C1, D1 ); \
   B0 = v128_xor( B0, C0 ); \
   B1 = v128_xor( B1, C1 ); \
   B0 = v128_ror64( B0, 63 ); \
   B1 = v128_ror64( B1, 63 ); \
}

#if defined(__SSSE3__)  || defined(__ARM_NEON)

#define DIAGONALIZE( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
   v128_t t = v128_alignr8( B1, B0, 8 ); \
   B1 = v128_alignr8( B0, B1, 8 ); \
   B0 = t; \
   t = v128_alignr8( D1, D0, 8 ); \
   D0 = v128_alignr8( D0, D1, 8 ); \
   D1 = t; \
}

#define UNDIAGONALIZE( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
    v128_t t = v128_alignr8( B0, B1, 8 ); \
    B1 = v128_alignr8( B1, B0, 8 ); \
    B0 = t; \
    t = v128_alignr8( D0, D1, 8 ); \
    D0 = v128_alignr8( D1, D0, 8 ); \
    D1 = t; \
}

#else /* SSE2 */

#define DIAGONALIZE( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
    v128_t t = D0; \
    D0 = v128_unpackhi64( D1, v128_unpacklo64( D0, D0 ) ); \
    D1 = v128_unpackhi64( t, v128_unpacklo64( D1, D1 ) ); \
    t = B0; \
    B0 = v128_unpackhi64( B0, v128_unpacklo64( B1, B1 ) ); \
    B1 = v128_unpackhi64( B1, v128_unpacklo64( t, t ) ); \
}

#define UNDIAGONALIZE( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
    v128_t t = B0; \
    B0 = v128_unpackhi64( B1, v128_unpacklo64( B0, B0 ) ); \
    B1 = v128_unpackhi64( t, v128_unpacklo64( B1, B1 ) ); \
    t = D0; \
    D0 = v128_unpackhi64( D0, v128_unpacklo64( D1, D1 ) ); \
    D1 = v128_unpackhi64( D1, v128_unpacklo64( t, t ) ); \
}

#endif

#define BLAKE2_ROUND( A0, A1, B0, B1, C0, C1, D0, D1 ) \
{ \
    G1( A0, B0, C0, D0, A1, B1, C1, D1 ); \
    G2( A0, B0, C0, D0, A1, B1, C1, D1 ); \
    DIAGONALIZE( A0, B0, C0, D0, A1, B1, C1, D1 ); \
    G1( A0, B0, C1, D0, A1, B1, C0, D1 ); \
    G2( A0, B0, C1, D0, A1, B1, C0, D1 ); \
    UNDIAGONALIZE( A0, B0, C0, D0, A1, B1, C1, D1 ); \
}

#else /* __AVX2__ */

#include <immintrin.h>

#define  rotr32( x )  mm256_ror_64( x, 32 )
#define  rotr24( x )  mm256_ror_64( x, 24 )
#define  rotr16( x )  mm256_ror_64( x, 16 )
#define  rotr63( x )  mm256_rol_64( x,  1 )

//#define rotr32(x)   _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1))
//#define rotr24(x)   _mm256_shuffle_epi8(x, _mm256_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10))
//#define rotr16(x)   _mm256_shuffle_epi8(x, _mm256_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9))
//#define rotr63(x)   _mm256_xor_si256(_mm256_srli_epi64((x), 63), _mm256_add_epi64((x), (x)))

#define G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i ml0, ml1; \
        ml0 = _mm256_mul_epu32(A0, B0); \
        ml1 = _mm256_mul_epu32(A1, B1); \
        ml0 = _mm256_add_epi64(ml0, ml0); \
        ml1 = _mm256_add_epi64(ml1, ml1); \
        A0 = _mm256_add_epi64(A0, _mm256_add_epi64(B0, ml0)); \
        A1 = _mm256_add_epi64(A1, _mm256_add_epi64(B1, ml1)); \
        D0 = _mm256_xor_si256(D0, A0); \
        D1 = _mm256_xor_si256(D1, A1); \
        D0 = rotr32(D0); \
        D1 = rotr32(D1); \
        ml0 = _mm256_mul_epu32(C0, D0); \
        ml1 = _mm256_mul_epu32(C1, D1); \
        ml0 = _mm256_add_epi64(ml0, ml0); \
        ml1 = _mm256_add_epi64(ml1, ml1); \
        C0 = _mm256_add_epi64(C0, _mm256_add_epi64(D0, ml0)); \
        C1 = _mm256_add_epi64(C1, _mm256_add_epi64(D1, ml1)); \
        B0 = _mm256_xor_si256(B0, C0); \
        B1 = _mm256_xor_si256(B1, C1); \
        B0 = rotr24(B0); \
        B1 = rotr24(B1); \
    } while((void)0, 0);

#define G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i ml0, ml1; \
        ml0 = _mm256_mul_epu32(A0, B0); \
        ml1 = _mm256_mul_epu32(A1, B1); \
        ml0 = _mm256_add_epi64(ml0, ml0); \
        ml1 = _mm256_add_epi64(ml1, ml1); \
        A0 = _mm256_add_epi64(A0, _mm256_add_epi64(B0, ml0)); \
        A1 = _mm256_add_epi64(A1, _mm256_add_epi64(B1, ml1)); \
        D0 = _mm256_xor_si256(D0, A0); \
        D1 = _mm256_xor_si256(D1, A1); \
        D0 = rotr16(D0); \
        D1 = rotr16(D1); \
        ml0 = _mm256_mul_epu32(C0, D0); \
        ml1 = _mm256_mul_epu32(C1, D1); \
        ml0 = _mm256_add_epi64(ml0, ml0); \
        ml1 = _mm256_add_epi64(ml1, ml1); \
        C0 = _mm256_add_epi64(C0, _mm256_add_epi64(D0, ml0)); \
        C1 = _mm256_add_epi64(C1, _mm256_add_epi64(D1, ml1)); \
        B0 = _mm256_xor_si256(B0, C0); \
        B1 = _mm256_xor_si256(B1, C1); \
        B0 = rotr63(B0); \
        B1 = rotr63(B1); \
    } while((void)0, 0);

#define DIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm256_permute4x64_epi64(B0, _MM_SHUFFLE(0, 3, 2, 1)); \
        C0 = _mm256_permute4x64_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        D0 = _mm256_permute4x64_epi64(D0, _MM_SHUFFLE(2, 1, 0, 3)); \
        B1 = _mm256_permute4x64_epi64(B1, _MM_SHUFFLE(0, 3, 2, 1)); \
        C1 = _mm256_permute4x64_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        D1 = _mm256_permute4x64_epi64(D1, _MM_SHUFFLE(2, 1, 0, 3)); \
    } while((void)0, 0);

#define DIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i tmp1 = _mm256_blend_epi32(B0, B1, 0x33); \
        __m256i tmp2 = _mm256_blend_epi32(B0, B1, 0xCC); \
        B0 = _mm256_shuffle_epi32( tmp1, 0x4e ); \
        B1 = _mm256_shuffle_epi32( tmp2, 0x4e ); \
        tmp1 = _mm256_blend_epi32(D0, D1, 0xCC); \
        tmp2 = _mm256_blend_epi32(D0, D1, 0x33); \
        D0 = _mm256_shuffle_epi32( tmp1, 0x4e ); \
        D1 = _mm256_shuffle_epi32( tmp2, 0x4e ); \
    } while(0);

#define UNDIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm256_permute4x64_epi64(B0, _MM_SHUFFLE(2, 1, 0, 3)); \
        C0 = _mm256_permute4x64_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        D0 = _mm256_permute4x64_epi64(D0, _MM_SHUFFLE(0, 3, 2, 1)); \
        B1 = _mm256_permute4x64_epi64(B1, _MM_SHUFFLE(2, 1, 0, 3)); \
        C1 = _mm256_permute4x64_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        D1 = _mm256_permute4x64_epi64(D1, _MM_SHUFFLE(0, 3, 2, 1)); \
    } while((void)0, 0);

#define UNDIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i tmp1 = _mm256_blend_epi32(B0, B1, 0xCC); \
        __m256i tmp2 = _mm256_blend_epi32(B0, B1, 0x33); \
        B0 = _mm256_shuffle_epi32( tmp1, 0x4e ); \
        B1 = _mm256_shuffle_epi32( tmp2, 0x4e ); \
        tmp2 = _mm256_blend_epi32(D0, D1, 0xCC); \
        tmp1 = _mm256_blend_epi32(D0, D1, 0x33); \
        D1 = _mm256_shuffle_epi32( tmp2, 0x4e ); \
        D0 = _mm256_shuffle_epi32( tmp1, 0x4e ); \
    } while((void)0, 0);

#define BLAKE2_ROUND_1(A0, A1, B0, B1, C0, C1, D0, D1) \
    do{ \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        DIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        UNDIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
    } while((void)0, 0);

#define BLAKE2_ROUND_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do{ \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        DIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G1_AVX2(A0, A1, B0, B1, C1, C0, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C1, C0, D0, D1) \
        UNDIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    } while((void)0, 0);

#endif /* __AVX2__ */

#else /* __AVX512F__ */

#include <immintrin.h>

/*
static inline __m512i muladd(__m512i x, __m512i y)
{
    __m512i z = _mm512_mul_epu32(x, y);
    return _mm512_add_epi64(_mm512_add_epi64(x, y), _mm512_add_epi64(z, z));
}
*/

#define G1( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
  __m512i z0, z1; \
  z0 = _mm512_mul_epu32( A0, B0 ); \
  z1 = _mm512_mul_epu32( A1, B1 ); \
  A0 = _mm512_add_epi64( A0, B0 ); \
  A1 = _mm512_add_epi64( A1, B1 ); \
  z0 = _mm512_add_epi64( z0, z0 ); \
  z1 = _mm512_add_epi64( z1, z1 ); \
  A0 = _mm512_add_epi64( A0, z0 ); \
  A1 = _mm512_add_epi64( A1, z1 ); \
  D0 = _mm512_xor_si512(D0, A0); \
  D1 = _mm512_xor_si512(D1, A1); \
  D0 = _mm512_ror_epi64(D0, 32); \
  D1 = _mm512_ror_epi64(D1, 32); \
  z0 = _mm512_mul_epu32( C0, D0 ); \
  z1 = _mm512_mul_epu32( C1, D1 ); \
  C0 = _mm512_add_epi64( C0, D0 ); \
  C1 = _mm512_add_epi64( C1, D1 ); \
  z0 = _mm512_add_epi64( z0, z0 ); \
  z1 = _mm512_add_epi64( z1, z1 ); \
  C0 = _mm512_add_epi64( C0, z0 ); \
  C1 = _mm512_add_epi64( C1, z1 ); \
  B0 = _mm512_xor_si512(B0, C0); \
  B1 = _mm512_xor_si512(B1, C1); \
  B0 = _mm512_ror_epi64(B0, 24); \
  B1 = _mm512_ror_epi64(B1, 24); \
}

#define G2( A0, B0, C0, D0, A1, B1, C1, D1 ) \
{ \
  __m512i z0, z1; \
  z0 = _mm512_mul_epu32( A0, B0 ); \
  z1 = _mm512_mul_epu32( A1, B1 ); \
  A0 = _mm512_add_epi64( A0, B0 ); \
  A1 = _mm512_add_epi64( A1, B1 ); \
  z0 = _mm512_add_epi64( z0, z0 ); \
  z1 = _mm512_add_epi64( z1, z1 ); \
  A0 = _mm512_add_epi64( A0, z0 ); \
  A1 = _mm512_add_epi64( A1, z1 ); \
  D0 = _mm512_xor_si512(D0, A0); \
  D1 = _mm512_xor_si512(D1, A1); \
  D0 = _mm512_ror_epi64(D0, 16); \
  D1 = _mm512_ror_epi64(D1, 16); \
  z0 = _mm512_mul_epu32( C0, D0 ); \
  z1 = _mm512_mul_epu32( C1, D1 ); \
  C0 = _mm512_add_epi64( C0, D0 ); \
  C1 = _mm512_add_epi64( C1, D1 ); \
  z0 = _mm512_add_epi64( z0, z0 ); \
  z1 = _mm512_add_epi64( z1, z1 ); \
  C0 = _mm512_add_epi64( C0, z0 ); \
  C1 = _mm512_add_epi64( C1, z1 ); \
  B0 = _mm512_xor_si512(B0, C0); \
  B1 = _mm512_xor_si512(B1, C1); \
  B0 = _mm512_ror_epi64(B0, 63); \
  B1 = _mm512_ror_epi64(B1, 63); \
}

/*
#define G1(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        A0 = muladd(A0, B0); \
        A1 = muladd(A1, B1); \
\
        D0 = _mm512_xor_si512(D0, A0); \
        D1 = _mm512_xor_si512(D1, A1); \
\
        D0 = _mm512_ror_epi64(D0, 32); \
        D1 = _mm512_ror_epi64(D1, 32); \
\
        C0 = muladd(C0, D0); \
        C1 = muladd(C1, D1); \
\
        B0 = _mm512_xor_si512(B0, C0); \
        B1 = _mm512_xor_si512(B1, C1); \
\
        B0 = _mm512_ror_epi64(B0, 24); \
        B1 = _mm512_ror_epi64(B1, 24); \
    } while ((void)0, 0)
*/
/* 
#define G2(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        A0 = muladd(A0, B0); \
        A1 = muladd(A1, B1); \
\
        D0 = _mm512_xor_si512(D0, A0); \
        D1 = _mm512_xor_si512(D1, A1); \
\
        D0 = _mm512_ror_epi64(D0, 16); \
        D1 = _mm512_ror_epi64(D1, 16); \
\
        C0 = muladd(C0, D0); \
        C1 = muladd(C1, D1); \
\
        B0 = _mm512_xor_si512(B0, C0); \
        B1 = _mm512_xor_si512(B1, C1); \
\
        B0 = _mm512_ror_epi64(B0, 63); \
        B1 = _mm512_ror_epi64(B1, 63); \
    } while ((void)0, 0)
*/

#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm512_permutex_epi64(B0, _MM_SHUFFLE(0, 3, 2, 1)); \
        B1 = _mm512_permutex_epi64(B1, _MM_SHUFFLE(0, 3, 2, 1)); \
        C0 = _mm512_permutex_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        C1 = _mm512_permutex_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        D0 = _mm512_permutex_epi64(D0, _MM_SHUFFLE(2, 1, 0, 3)); \
        D1 = _mm512_permutex_epi64(D1, _MM_SHUFFLE(2, 1, 0, 3)); \
    } while ((void)0, 0)

#define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm512_permutex_epi64(B0, _MM_SHUFFLE(2, 1, 0, 3)); \
        B1 = _mm512_permutex_epi64(B1, _MM_SHUFFLE(2, 1, 0, 3)); \
        C0 = _mm512_permutex_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        C1 = _mm512_permutex_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        D0 = _mm512_permutex_epi64(D0, _MM_SHUFFLE(0, 3, 2, 1)); \
        D1 = _mm512_permutex_epi64(D1, _MM_SHUFFLE(0, 3, 2, 1)); \
    } while ((void)0, 0)

#define BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        G1(A0, B0, C0, D0, A1, B1, C1, D1); \
        G2(A0, B0, C0, D0, A1, B1, C1, D1); \
        DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1); \
        G1(A0, B0, C0, D0, A1, B1, C1, D1); \
        G2(A0, B0, C0, D0, A1, B1, C1, D1); \
        UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1); \
    } while ((void)0, 0)

static const __m512i swap_q0  = { 0,1,  8,9,  2,3,  10,11 }; 
static const __m512i swap_q1  = { 4,5, 12,13, 6,7,  14,15 };
static const __m512i uswap_q0 = { 0,1,  4,5,  8,9,  12,13 };
static const __m512i uswap_q1 = { 2,3,  6,7, 10,11, 14,15 };

#define SWAP_HALVES(A0, A1) \
    do { \
        __m512i t; \
        t = _mm512_shuffle_i64x2(A0, A1, _MM_SHUFFLE(1, 0, 1, 0)); \
        A1 = _mm512_shuffle_i64x2(A0, A1, _MM_SHUFFLE(3, 2, 3, 2)); \
        A0 = t; \
    } while((void)0, 0)

#define SWAP_QUARTERS(A0, A1) \
{ \
   __m512i t = _mm512_permutex2var_epi64( A0, swap_q0, A1 ); \
   A1 = _mm512_permutex2var_epi64( A0, swap_q1, A1 ); \
   A0 = t; \
}   

#define UNSWAP_QUARTERS(A0, A1) \
{ \
   __m512i t = _mm512_permutex2var_epi64( A0, uswap_q0, A1 ); \
   A1 = _mm512_permutex2var_epi64( A0, uswap_q1, A1 ); \
   A0 = t; \
}   
   
/*
#define SWAP_QUARTERS(A0, A1) \
    do { \
        SWAP_HALVES(A0, A1); \
        A0 = _mm512_shuffle_i64x2( A0, A0, 0xd8 ); \
        A1 = _mm512_shuffle_i64x2( A1, A1, 0xd8 ); \
    } while((void)0, 0)
*/
/*
#define UNSWAP_QUARTERS(A0, A1) \
    do { \
        A0 = _mm512_shuffle_i64x2( A0, A0, 0xd8 ); \
        A1 = _mm512_shuffle_i64x2( A1, A1, 0xd8 ); \
        SWAP_HALVES(A0, A1); \
    } while((void)0, 0)
*/

#define BLAKE2_ROUND_1(A0, C0, B0, D0, A1, C1, B1, D1) \
    do { \
        SWAP_HALVES(A0, B0); \
        SWAP_HALVES(C0, D0); \
        SWAP_HALVES(A1, B1); \
        SWAP_HALVES(C1, D1); \
        BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1); \
        SWAP_HALVES(A0, B0); \
        SWAP_HALVES(C0, D0); \
        SWAP_HALVES(A1, B1); \
        SWAP_HALVES(C1, D1); \
    } while ((void)0, 0)

#define BLAKE2_ROUND_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        SWAP_QUARTERS(A0, A1); \
        SWAP_QUARTERS(B0, B1); \
        SWAP_QUARTERS(C0, C1); \
        SWAP_QUARTERS(D0, D1); \
        BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1); \
        UNSWAP_QUARTERS(A0, A1); \
        UNSWAP_QUARTERS(B0, B1); \
        UNSWAP_QUARTERS(C0, C1); \
        UNSWAP_QUARTERS(D0, D1); \
    } while ((void)0, 0)

#endif /* __AVX512F__ */

#endif /* BLAKE_ROUND_MKA_OPT_H */
