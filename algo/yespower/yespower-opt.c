/*-
 * Copyright 2009 Colin Percival
 * Copyright 2012-2018 Alexander Peslyak
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
 *
 * This is a proof-of-work focused fork of yescrypt, including optimized and
 * cut-down implementation of the obsolete yescrypt 0.5 (based off its first
 * submission to PHC back in 2014) and a new proof-of-work specific variation
 * known as yespower 1.0.  The former is intended as an upgrade for
 * cryptocurrencies that already use yescrypt 0.5 and the latter may be used
 * as a further upgrade (hard fork) by those and other cryptocurrencies.  The
 * version of algorithm to use is requested through parameters, allowing for
 * both algorithms to co-exist in client and miner implementations (such as in
 * preparation for a hard-fork).
 */

#ifndef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 1
#endif

#if _YESPOWER_OPT_C_PASS_ == 1
/*
 * AVX and especially XOP speed up Salsa20 a lot, but needlessly result in
 * extra instruction prefixes for pwxform (which we make more use of).  While
 * no slowdown from the prefixes is generally observed on AMD CPUs supporting
 * XOP, some slowdown is sometimes observed on Intel CPUs with AVX.
 */
/*
#ifdef __XOP__
#warning "Note: XOP is enabled.  That's great."
#elif defined(__AVX__)
#warning "Note: AVX is enabled.  That's OK."
#elif defined(__SSE2__)
#warning "Note: AVX and XOP are not enabled.  That's OK."
#elif defined(__x86_64__) || defined(__i386__)
#warning "SSE2 not enabled.  Expect poor performance."
#else
#warning "Note: building generic code for non-x86.  That's OK."
#endif
*/

/*
 * The SSE4 code version has fewer instructions than the generic SSE2 version,
 * but all of the instructions are SIMD, thereby wasting the scalar execution
 * units.  Thus, the generic SSE2 version below actually runs faster on some
 * CPUs due to its balanced mix of SIMD and scalar instructions.
 */
#undef USE_SSE4_FOR_32BIT

// AVX512 is slow. There isn't enough AVX512 code to make up
// for the reduced clock. AVX512VL, used for rotate & ternary logic on smaller
// vectors, is exempt.
//#define YESPOWER_USE_AVX512 1

#ifdef __SSE2__
/*
 * GCC before 4.9 would by default unnecessarily use store/load (without
 * SSE4.1) or (V)PEXTR (with SSE4.1 or AVX) instead of simply (V)MOV.
 * This was tracked as GCC bug 54349.
 * "-mtune=corei7" works around this, but is only supported for GCC 4.6+.
 * We use inline asm for pre-4.6 GCC, further down this file.
 */
#if __GNUC__ == 4 && __GNUC_MINOR__ >= 6 && __GNUC_MINOR__ < 9 && \
    !defined(__clang__) && !defined(__ICC)
#pragma GCC target ("tune=corei7")
#endif
#include <emmintrin.h>
#ifdef __XOP__
#include <x86intrin.h>
#endif
#elif defined(__SSE__)
#include <xmmintrin.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "algo/sha/hmac-sha256-hash.h"
#include "algo/sha/hmac-sha256-hash-4way.h"

#include "yespower.h"
#include "yespower-platform.c"

#if __STDC_VERSION__ >= 199901L
/* Have restrict */
#elif defined(__GNUC__)
#define restrict __restrict
#else
#define restrict
#endif

/*
#ifdef __GNUC__
#define unlikely(exp) __builtin_expect(exp, 0)
#else
#define unlikely(exp) (exp)
#endif
*/

#ifdef __SSE__
#define PREFETCH(x, hint) _mm_prefetch((const char *)(x), (hint));
#else
#undef PREFETCH
#endif

typedef union {
	uint32_t d[16];
	uint64_t q[8];
#ifdef __SSE2__
	__m128i m128[4];
#endif
#if defined(__AVX2__)
   __m256i m256[2];
#endif
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
   __m512i m512;
#endif
} salsa20_blk_t;

#if defined(YESPOWER_USE_AVX512) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
// Slow

static const __m512i simd_shuffle_index = 
   { 0x0000000500000000, 0x0000000f0000000a,
     0x0000000900000004, 0x000000030000000e,
     0x0000000d00000008, 0x0000000700000002,
     0x000000010000000c, 0x0000000b00000006 };
static const __m512i simd_unshuffle_index =
   { 0x0000000d00000000, 0x000000070000000a,
     0x0000000100000004, 0x0000000b0000000e,
     0x0000000500000008, 0x0000000f00000002,
     0x000000090000000c, 0x0000000300000006 };

#elif defined(__AVX2__)

#if defined(__AVX512VL__)
// alternative when not using 512 bit vectors

static const __m256i simd_shuffle_index =
   { 0x0000000500000000, 0x0000000f0000000a,
     0x0000000900000004, 0x000000030000000e };
static const __m256i simd_unshuffle_index =
   { 0x0000000d00000000, 0x000000070000000a,
     0x0000000100000004, 0x0000000b0000000e };

#else

static const __m256i simd_shuffle_index =
   { 0x0000000500000000, 0x0000000700000002,
     0x0000000100000004, 0x0000000300000006 };
// same index for unshuffle

#endif

#endif

static inline void salsa20_simd_shuffle(const salsa20_blk_t *Bin,
    salsa20_blk_t *Bout)
{
#if defined(YESPOWER_USE_AVX512) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  
  Bout->m512 = _mm512_permutexvar_epi32( simd_shuffle_index, Bin->m512 );

#elif defined(__AVX2__)

#if defined(__AVX512VL__)

  Bout->m256[0] = _mm256_permutex2var_epi32( Bin->m256[0], simd_shuffle_index,
                                             Bin->m256[1] );
  Bout->m256[1] = _mm256_permutex2var_epi32( Bin->m256[1], simd_shuffle_index,
                                             Bin->m256[0] );
  
#else

  __m256i t0 = _mm256_permutevar8x32_epi32( Bin->m256[0], simd_shuffle_index );
  __m256i t1 = _mm256_permutevar8x32_epi32( Bin->m256[1], simd_shuffle_index );
  Bout->m256[0] = _mm256_blend_epi32( t1, t0, 0x93 );
  Bout->m256[1] = _mm256_blend_epi32( t1, t0, 0x6c );
  
#endif
  
#elif defined(__SSE4_1__)

  __m128i t0 = _mm_blend_epi16( Bin->m128[0], Bin->m128[1], 0xcc );
  __m128i t1 = _mm_blend_epi16( Bin->m128[0], Bin->m128[1], 0x33 );
  __m128i t2 = _mm_blend_epi16( Bin->m128[2], Bin->m128[3], 0xcc );
  __m128i t3 = _mm_blend_epi16( Bin->m128[2], Bin->m128[3], 0x33 );
  Bout->m128[0] = _mm_blend_epi16( t0, t2, 0xf0 );
  Bout->m128[1] = _mm_blend_epi16( t1, t3, 0x3c );
  Bout->m128[2] = _mm_blend_epi16( t0, t2, 0x0f );
  Bout->m128[3] = _mm_blend_epi16( t1, t3, 0xc3 );

#else

#define COMBINE(out, in1, in2) \
	Bout->q[out] = Bin->d[in1 * 2] | ((uint64_t)Bin->d[in2 * 2 + 1] << 32);
	COMBINE(0, 0, 2)
	COMBINE(1, 5, 7)
	COMBINE(2, 2, 4)
	COMBINE(3, 7, 1)
	COMBINE(4, 4, 6)
	COMBINE(5, 1, 3)
	COMBINE(6, 6, 0)
	COMBINE(7, 3, 5)
#undef COMBINE

#endif   
}

static inline void salsa20_simd_unshuffle(const salsa20_blk_t *Bin,
    salsa20_blk_t *Bout)
{
#if defined(YESPOWER_USE_AVX512) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

  Bout->m512 = _mm512_permutexvar_epi32( simd_unshuffle_index, Bin->m512 );    

#elif defined(__AVX2__)
  
#if defined(__AVX512VL__)
  
  Bout->m256[0] = _mm256_permutex2var_epi32( Bin->m256[0], simd_unshuffle_index,
                                             Bin->m256[1] );
  Bout->m256[1] = _mm256_permutex2var_epi32( Bin->m256[1], simd_unshuffle_index,
                                             Bin->m256[0] );

#else  

  __m256i t0 = _mm256_permutevar8x32_epi32( Bin->m256[0], simd_shuffle_index );
  __m256i t1 = _mm256_permutevar8x32_epi32( Bin->m256[1], simd_shuffle_index );
  Bout->m256[0] = _mm256_blend_epi32( t1, t0, 0x39 );
  Bout->m256[1] = _mm256_blend_epi32( t1, t0, 0xc6 );

#endif

#elif defined(__SSE4_1__)

  __m128i t0 = _mm_blend_epi16( Bin->m128[0], Bin->m128[2], 0xf0 );
  __m128i t1 = _mm_blend_epi16( Bin->m128[0], Bin->m128[2], 0x0f );
  __m128i t2 = _mm_blend_epi16( Bin->m128[1], Bin->m128[3], 0x3c );
  __m128i t3 = _mm_blend_epi16( Bin->m128[1], Bin->m128[3], 0xc3 );
  Bout->m128[0] = _mm_blend_epi16( t0, t2, 0xcc );
  Bout->m128[1] = _mm_blend_epi16( t0, t2, 0x33 );
  Bout->m128[2] = _mm_blend_epi16( t1, t3, 0xcc );
  Bout->m128[3] = _mm_blend_epi16( t1, t3, 0x33 );

#else

#define UNCOMBINE(out, in1, in2) \
	Bout->d[out * 2] = Bin->q[in1]; \
	Bout->d[out * 2 + 1] = Bin->q[in2] >> 32;
	UNCOMBINE(0, 0, 6)
	UNCOMBINE(1, 5, 3)
	UNCOMBINE(2, 2, 0)
	UNCOMBINE(3, 7, 5)
	UNCOMBINE(4, 4, 2)
	UNCOMBINE(5, 1, 7)
	UNCOMBINE(6, 6, 4)
	UNCOMBINE(7, 3, 1)
#undef UNCOMBINE

#endif
}

#define WRITE_X(out) \
 (out).m128[0] = X0; (out).m128[1] = X1; (out).m128[2] = X2; (out).m128[3] = X3;

// Bit rotation optimization
#if defined(__AVX512VL__)

#define ARX(out, in1, in2, s) \
   out = _mm_xor_si128(out, _mm_rol_epi32(_mm_add_epi32(in1, in2), s));

#elif defined(__XOP__)

#define ARX(out, in1, in2, s) \
	out = _mm_xor_si128(out, _mm_roti_epi32(_mm_add_epi32(in1, in2), s));

#else

#define ARX(out, in1, in2, s) { \
	__m128i tmp = _mm_add_epi32(in1, in2); \
	out = _mm_xor_si128(out, _mm_slli_epi32(tmp, s)); \
	out = _mm_xor_si128(out, _mm_srli_epi32(tmp, 32 - s)); \
}

#endif

#define SALSA20_2ROUNDS \
	/* Operate on "columns" */ \
	ARX(X1, X0, X3, 7) \
	ARX(X2, X1, X0, 9) \
	ARX(X3, X2, X1, 13) \
	ARX(X0, X3, X2, 18) \
	/* Rearrange data */ \
	X1 = _mm_shuffle_epi32(X1, 0x93); \
   X3 = _mm_shuffle_epi32(X3, 0x39); \
	X2 = _mm_shuffle_epi32(X2, 0x4E); \
	/* Operate on "rows" */ \
	ARX(X3, X0, X1, 7) \
	ARX(X2, X3, X0, 9) \
	ARX(X1, X2, X3, 13) \
	ARX(X0, X1, X2, 18) \
	/* Rearrange data */ \
   X3 = _mm_shuffle_epi32(X3, 0x93); \
	X1 = _mm_shuffle_epi32(X1, 0x39); \
	X2 = _mm_shuffle_epi32(X2, 0x4E);

/**
 * Apply the Salsa20 core to the block provided in (X0 ... X3).
 */
#define SALSA20_wrapper(out, rounds) { \
	__m128i Z0 = X0, Z1 = X1, Z2 = X2, Z3 = X3; \
	rounds \
	(out).m128[0] = X0 = _mm_add_epi32( X0, Z0 ); \
	(out).m128[1] = X1 = _mm_add_epi32( X1, Z1 ); \
	(out).m128[2] = X2 = _mm_add_epi32( X2, Z2 ); \
	(out).m128[3] = X3 = _mm_add_epi32( X3, Z3 ); \
}

/**
 * Apply the Salsa20/2 core to the block provided in X.
 */
// Not called explicitly, aliased to SALSA20
#define SALSA20_2(out) \
	SALSA20_wrapper(out, SALSA20_2ROUNDS)

/**
 * Apply the Salsa20/8 core to the block provided in X.
 */
#define SALSA20_8ROUNDS \
   SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS SALSA20_2ROUNDS

#define SALSA20_8(out) \
	SALSA20_wrapper(out, SALSA20_8ROUNDS)

#define XOR_X(in) \
	X0 = _mm_xor_si128( X0, (in).m128[0] ); \
	X1 = _mm_xor_si128( X1, (in).m128[1] ); \
	X2 = _mm_xor_si128( X2, (in).m128[2] ); \
	X3 = _mm_xor_si128( X3, (in).m128[3] );

#define XOR_X_WRITE_XOR_Y_2(out, in) \
	(out).m128[0] = Y0 = _mm_xor_si128( (out).m128[0], (in).m128[0] ); \
	(out).m128[1] = Y1 = _mm_xor_si128( (out).m128[1], (in).m128[1] ); \
	(out).m128[2] = Y2 = _mm_xor_si128( (out).m128[2], (in).m128[2] ); \
	(out).m128[3] = Y3 = _mm_xor_si128( (out).m128[3], (in).m128[3] ); \
	X0 = _mm_xor_si128( X0, Y0 ); \
	X1 = _mm_xor_si128( X1, Y1 ); \
	X2 = _mm_xor_si128( X2, Y2 ); \
	X3 = _mm_xor_si128( X3, Y3 );

#define INTEGERIFY( X ) _mm_cvtsi128_si32( X )

// AVX512 ternary logic optimization
#if defined(__AVX512VL__)

#define XOR_X_XOR_X( in1, in2 ) \
 X0 =  _mm_ternarylogic_epi32( X0, (in1).m128[0], (in2).m128[0], 0x96 ); \
 X1 =  _mm_ternarylogic_epi32( X1, (in1).m128[1], (in2).m128[1], 0x96 ); \
 X2 =  _mm_ternarylogic_epi32( X2, (in1).m128[2], (in2).m128[2], 0x96 ); \
 X3 =  _mm_ternarylogic_epi32( X3, (in1).m128[3], (in2).m128[3], 0x96 ); 

#else

#define XOR_X_XOR_X( in1, in2 ) \
  XOR_X( in1 ) \
  XOR_X( in2 )

#endif

// General vectored optimizations
#if defined(YESPOWER_USE_AVX512) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define READ_X( in ) \
  X.m512 = (in).m512;

#define XOR_X_2_XOR_X( in1, in2, in3 ) \
 X.m512 = _mm512_ternarylogic_epi32( (in1).m512, (in2).m512, (in3).m512, 0x96 );

#define XOR_X_SALSA20_XOR_MEM( in1, in2, out) \
{ \
 __m128i X0, X1, X2, X3; \
 X.m512 = _mm512_ternarylogic_epi32( X.m512, (in1).m512, (in2).m512, 0x96 ); \
 X0 = X.m128[0]; \
 X1 = X.m128[1]; \
 X2 = X.m128[2]; \
 X3 = X.m128[3]; \
 SALSA20( out ); \
 X.m128[0] = X0; \
 X.m128[1] = X1; \
 X.m128[2] = X2; \
 X.m128[3] = X3; \
}

#define SALSA20_XOR_MEM(in, out) \
{ \
 __m128i X0, X1, X2, X3; \
 X.m512 = _mm512_xor_si512( X.m512, (in).m512 ); \
 X0 = X.m128[0]; \
 X1 = X.m128[1]; \
 X2 = X.m128[2]; \
 X3 = X.m128[3]; \
 SALSA20( out ); \
 X.m128[0] = X0; \
 X.m128[1] = X1; \
 X.m128[2] = X2; \
 X.m128[3] = X3; \
}

#elif defined(__AVX2__)

#define READ_X( in ) \
  X.m256[0] = (in).m256[0]; \
  X.m256[1] = (in).m256[1];

#if defined(__AVX512VL__)

#define XOR_X_2_XOR_X( in1, in2, in3 ) \
   X.m256[0] = _mm256_ternarylogic_epi32( (in1).m256[0], (in2).m256[0], \
                                          (in3).m256[0], 0x96 ); \
   X.m256[1] = _mm256_ternarylogic_epi32( (in1).m256[1], (in2).m256[1], \
                                          (in3).m256[1], 0x96 );

#define XOR_X_SALSA20_XOR_MEM( in1, in2, out) \
{ \
   __m128i X0, X1, X2, X3; \
   X.m256[0] = _mm256_ternarylogic_epi32( X.m256[0], (in1).m256[0], \
                                      (in2).m256[0], 0x96 ); \
   X.m256[1] = _mm256_ternarylogic_epi32( X.m256[1], (in1).m256[1], \
                                      (in2).m256[1], 0x96 ); \
   X0 = X.m128[0]; \
   X1 = X.m128[1]; \
   X2 = X.m128[2]; \
   X3 = X.m128[3]; \
   SALSA20( out ); \
   X.m128[0] = X0; \
   X.m128[1] = X1; \
   X.m128[2] = X2; \
   X.m128[3] = X3; \
}

#else  // AVX2

#define XOR_X_2_XOR_X( in1, in2, in3 ) \
   X.m256[0] = _mm256_xor_si256( (in1).m256[0], \
                       _mm256_xor_si256( (in2).m256[0], (in3).m256[0] ) ); \
   X.m256[1] = _mm256_xor_si256( (in1).m256[1], \
                       _mm256_xor_si256( (in2).m256[1], (in3).m256[1] ) );

#define XOR_X_SALSA20_XOR_MEM( in1, in2, out) \
{ \
   __m128i X0, X1, X2, X3; \
   X.m256[0] = _mm256_xor_si256( X.m256[0], \
                       _mm256_xor_si256( (in1).m256[0], (in2).m256[0] ) ); \
   X.m256[1] = _mm256_xor_si256( X.m256[1], \
                       _mm256_xor_si256( (in1).m256[1], (in2).m256[1] ) ); \
   X0 = X.m128[0]; \
   X1 = X.m128[1]; \
   X2 = X.m128[2]; \
   X3 = X.m128[3]; \
   SALSA20( out ); \
   X.m128[0] = X0; \
   X.m128[1] = X1; \
   X.m128[2] = X2; \
   X.m128[3] = X3; \
}  

#endif // AVX512VL else

#define SALSA20_XOR_MEM( in, out ) \
{ \
   __m128i X0, X1, X2, X3; \
   X.m256[0] = _mm256_xor_si256( X.m256[0], (in).m256[0] ); \
   X.m256[1] = _mm256_xor_si256( X.m256[1], (in).m256[1] ); \
   X0 = X.m128[0]; \
   X1 = X.m128[1]; \
   X2 = X.m128[2]; \
   X3 = X.m128[3]; \
   SALSA20( out ) \
   X.m128[0] = X0; \
   X.m128[1] = X1; \
   X.m128[2] = X2; \
   X.m128[3] = X3; \
}

#else   // SSE2

#define READ_X(in) \
   X.m128[0] = (in).m128[0]; \
   X.m128[1] = (in).m128[1]; \
   X.m128[2] = (in).m128[2]; \
   X.m128[3] = (in).m128[3];

#define XOR_X_2_XOR_X( in1, in2, in3 ) \
   X.m128[0] = _mm_xor_si128( (in1).m128[0], \
                     _mm_xor_si128( (in2).m128[0], (in3).m128[0] ) ); \
   X.m128[1] = _mm_xor_si128( (in1).m128[1], \
                     _mm_xor_si128( (in2).m128[1], (in3).m128[1] ) ); \
   X.m128[2] = _mm_xor_si128( (in1).m128[2], \
                     _mm_xor_si128( (in2).m128[2], (in3).m128[2] ) ); \
   X.m128[3] = _mm_xor_si128( (in1).m128[3], \
                     _mm_xor_si128( (in2).m128[3], (in3).m128[3] ) );


#define XOR_X_SALSA20_XOR_MEM( in1, in2, out) \
{ \
   __m128i X0 = _mm_xor_si128( X.m128[0], \
                         _mm_xor_si128( (in1).m128[0], (in2).m128[0] ) ); \
   __m128i X1 = _mm_xor_si128( X.m128[1], \
                         _mm_xor_si128( (in1).m128[1], (in2).m128[1] ) ); \
   __m128i X2 = _mm_xor_si128( X.m128[2], \
                         _mm_xor_si128( (in1).m128[2], (in2).m128[2] ) ); \
   __m128i X3 = _mm_xor_si128( X.m128[3], \
                         _mm_xor_si128( (in1).m128[3], (in2).m128[3] ) ); \
   SALSA20( out ); \
   X.m128[0] = X0; \
   X.m128[1] = X1; \
   X.m128[2] = X2; \
   X.m128[3] = X3; \
}   
     
// Apply the Salsa20 core to the block provided in X ^ in.
#define SALSA20_XOR_MEM(in, out) \
{ \
   __m128i X0 = _mm_xor_si128( X.m128[0], (in).m128[0] ); \
   __m128i X1 = _mm_xor_si128( X.m128[1], (in).m128[1] ); \
   __m128i X2 = _mm_xor_si128( X.m128[2], (in).m128[2] ); \
   __m128i X3 = _mm_xor_si128( X.m128[3], (in).m128[3] ); \
   SALSA20( out ) \
   X.m128[0] = X0; \
   X.m128[1] = X1; \
   X.m128[2] = X2; \
   X.m128[3] = X3; \
} 

#endif   // AVX512 elif AVX2 else

#define SALSA20 SALSA20_8
#else /* pass 2 */
#undef SALSA20
#define SALSA20 SALSA20_2
#endif

/*
 * blockmix_salsa(Bin, Bout):
 * Compute Bout = BlockMix_{salsa20, 1}(Bin).  The input Bin must be 128
 * bytes in length; the output Bout must also be the same size.
 */
static inline void blockmix_salsa(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout)
{
   salsa20_blk_t X;

   READ_X( Bin[1] );
   SALSA20_XOR_MEM(Bin[0], Bout[0]);
	SALSA20_XOR_MEM(Bin[1], Bout[1]);
}

static inline uint32_t blockmix_salsa_xor(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout)
{
   salsa20_blk_t X;

   XOR_X_2_XOR_X( Bin1[1], Bin2[1], Bin1[0] );   
	SALSA20_XOR_MEM( Bin2[0], Bout[0] );
   XOR_X_SALSA20_XOR_MEM( Bin1[1], Bin2[1], Bout[1] );

   return X.d[0];
}

#if _YESPOWER_OPT_C_PASS_ == 1
/* This is tunable, but it is part of what defines a yespower version */
/* Version 0.5 */
#define Swidth_0_5 8
/* Version 1.0 */
#define Swidth_1_0 11

/* Not tunable in this implementation, hard-coded in a few places */
#define PWXsimple 2
#define PWXgather 4

/* Derived value.  Not tunable on its own. */
#define PWXbytes (PWXgather * PWXsimple * 8)

/* (Maybe-)runtime derived values.  Not tunable on their own. */
#define Swidth_to_Sbytes1(Swidth) ((1 << (Swidth)) * PWXsimple * 8)
#define Swidth_to_Smask(Swidth) (((1 << (Swidth)) - 1) * PWXsimple * 8)
#define Smask_to_Smask2(Smask) (((uint64_t)(Smask) << 32) | (Smask))

/* These should be compile-time derived */
#define Smask2_0_5 Smask_to_Smask2(Swidth_to_Smask(Swidth_0_5))
#define Smask2_1_0 Smask_to_Smask2(Swidth_to_Smask(Swidth_1_0))

typedef struct {
	uint8_t *S0, *S1, *S2;
	size_t w;
	uint32_t Sbytes;
} pwxform_ctx_t;

#define DECL_SMASK2REG /* empty */
#define MAYBE_MEMORY_BARRIER /* empty */

/*
 * (V)PSRLDQ and (V)PSHUFD have higher throughput than (V)PSRLQ on some CPUs
 * starting with Sandy Bridge.  Additionally, PSHUFD uses separate source and
 * destination registers, whereas the shifts would require an extra move
 * instruction for our code when building without AVX.  Unfortunately, PSHUFD
 * is much slower on Conroe (4 cycles latency vs. 1 cycle latency for PSRLQ)
 * and somewhat slower on some non-Intel CPUs (luckily not including AMD
 * Bulldozer and Piledriver).
 */
#ifdef __AVX__
#define HI32(X) \
	_mm_srli_si128((X), 4)
#elif 1 /* As an option, check for __SSE4_1__ here not to hurt Conroe */
#define HI32(X) \
	_mm_shuffle_epi32((X), _MM_SHUFFLE(2,3,0,1))
#else
#define HI32(X) \
	_mm_srli_epi64((X), 32)
#endif

#if defined(__x86_64__) && \
    __GNUC__ == 4 && __GNUC_MINOR__ < 6 && !defined(__ICC)

#ifdef __AVX__

#define MOVQ "vmovq"

#else
/* "movq" would be more correct, but "movd" is supported by older binutils
 * due to an error in AMD's spec for x86-64. */

#define MOVQ "movd"

#endif

#define EXTRACT64(X) ({ \
	uint64_t result; \
	__asm__(MOVQ " %1, %0" : "=r" (result) : "x" (X)); \
	result; \
})

#elif defined(__x86_64__) && !defined(_MSC_VER) && !defined(__OPEN64__)
/* MSVC and Open64 had bugs */

#define EXTRACT64(X) _mm_cvtsi128_si64(X)

#elif defined(__x86_64__) && defined(__SSE4_1__)
/* No known bugs for this intrinsic */

#include <smmintrin.h>
#define EXTRACT64(X) _mm_extract_epi64((X), 0)

#elif defined(USE_SSE4_FOR_32BIT) && defined(__SSE4_1__)
/* 32-bit */
#include <smmintrin.h>

#if 0
/* This is currently unused by the code below, which instead uses these two
 * intrinsics explicitly when (!defined(__x86_64__) && defined(__SSE4_1__)) */
#define EXTRACT64(X) \
	((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | \
	((uint64_t)(uint32_t)_mm_extract_epi32((X), 1) << 32))
#endif

#else
/* 32-bit or compilers with known past bugs in _mm_cvtsi128_si64() */

#define EXTRACT64(X) \
	((uint64_t)(uint32_t)_mm_cvtsi128_si32(X) | \
	((uint64_t)(uint32_t)_mm_cvtsi128_si32(HI32(X)) << 32))

#endif

#if defined(__x86_64__) && (defined(__AVX__) || !defined(__GNUC__))
/* 64-bit with AVX */
/* Force use of 64-bit AND instead of two 32-bit ANDs */

#undef DECL_SMASK2REG

#if defined(__GNUC__) && !defined(__ICC)

#define DECL_SMASK2REG uint64_t Smask2reg = Smask2;
/* Force use of lower-numbered registers to reduce number of prefixes, relying
 * on out-of-order execution and register renaming. */
#define FORCE_REGALLOC_1 \
	__asm__("" : "=a" (x), "+d" (Smask2reg), "+S" (S0), "+D" (S1));
#define FORCE_REGALLOC_2 \
	__asm__("" : : "c" (lo));

#else   // not GNUC

static volatile uint64_t Smask2var = Smask2;
#define DECL_SMASK2REG uint64_t Smask2reg = Smask2var;
#define FORCE_REGALLOC_1 /* empty */
#define FORCE_REGALLOC_2 /* empty */

#endif

#define PWXFORM_SIMD(X) { \
	uint64_t x; \
	FORCE_REGALLOC_1 \
	uint32_t lo = x = EXTRACT64(X) & Smask2reg; \
	FORCE_REGALLOC_2 \
	uint32_t hi = x >> 32; \
	X = _mm_mul_epu32(HI32(X), X); \
	X = _mm_add_epi64(X, *(__m128i *)(S0 + lo)); \
	X = _mm_xor_si128(X, *(__m128i *)(S1 + hi)); \
}

#elif defined(__x86_64__)
/* 64-bit without AVX.  This relies on out-of-order execution and register
 * renaming.  It may actually be fastest on CPUs with AVX(2) as well - e.g.,
 * it runs great on Haswell. */
//#warning "Note: using x86-64 inline assembly for pwxform.  That's great."

#undef MAYBE_MEMORY_BARRIER

#define MAYBE_MEMORY_BARRIER \
	__asm__("" : : : "memory");

#define PWXFORM_SIMD(X) { \
	__m128i H; \
	__asm__( \
	    "movd %0, %%rax\n\t" \
	    "pshufd $0xb1, %0, %1\n\t" \
	    "andq %2, %%rax\n\t" \
	    "pmuludq %1, %0\n\t" \
	    "movl %%eax, %%ecx\n\t" \
	    "shrq $0x20, %%rax\n\t" \
	    "paddq (%3,%%rcx), %0\n\t" \
	    "pxor (%4,%%rax), %0\n\t" \
	    : "+x" (X), "=x" (H) \
	    : "d" (Smask2), "S" (S0), "D" (S1) \
	    : "cc", "ax", "cx"); \
}

#elif defined(USE_SSE4_FOR_32BIT) && defined(__SSE4_1__)
/* 32-bit with SSE4.1 */

#define PWXFORM_SIMD(X) { \
	__m128i x = _mm_and_si128(X, _mm_set1_epi64x(Smask2)); \
	__m128i s0 = *(__m128i *)(S0 + (uint32_t)_mm_cvtsi128_si32(x)); \
	__m128i s1 = *(__m128i *)(S1 + (uint32_t)_mm_extract_epi32(x, 1)); \
	X = _mm_mul_epu32(HI32(X), X); \
	X = _mm_add_epi64(X, s0); \
	X = _mm_xor_si128(X, s1); \
}

#else
/* 32-bit without SSE4.1 */

#define PWXFORM_SIMD(X) { \
	uint64_t x = EXTRACT64(X) & Smask2; \
	__m128i s0 = *(__m128i *)(S0 + (uint32_t)x); \
	__m128i s1 = *(__m128i *)(S1 + (x >> 32)); \
	X = _mm_mul_epu32(HI32(X), X); \
	X = _mm_add_epi64(X, s0); \
	X = _mm_xor_si128(X, s1); \
}

#endif

#define PWXFORM_SIMD_WRITE(X, Sw) \
	PWXFORM_SIMD(X) \
	MAYBE_MEMORY_BARRIER \
	*(__m128i *)(Sw + w) = X; \
	MAYBE_MEMORY_BARRIER

#define PWXFORM_ROUND \
	PWXFORM_SIMD(X0) \
	PWXFORM_SIMD(X1) \
	PWXFORM_SIMD(X2) \
	PWXFORM_SIMD(X3)

#define PWXFORM_ROUND_WRITE4 \
	PWXFORM_SIMD_WRITE(X0, S0) \
	PWXFORM_SIMD_WRITE(X1, S1) \
	w += 16; \
	PWXFORM_SIMD_WRITE(X2, S0) \
	PWXFORM_SIMD_WRITE(X3, S1) \
	w += 16;

#define PWXFORM_ROUND_WRITE2 \
	PWXFORM_SIMD_WRITE(X0, S0) \
	PWXFORM_SIMD_WRITE(X1, S1) \
	w += 16; \
	PWXFORM_SIMD(X2) \
	PWXFORM_SIMD(X3)

#define PWXFORM \
	PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND \
	PWXFORM_ROUND PWXFORM_ROUND PWXFORM_ROUND

#define Smask2 Smask2_0_5

#else // pass 2

#undef PWXFORM
#define PWXFORM \
	PWXFORM_ROUND_WRITE4 PWXFORM_ROUND_WRITE2 PWXFORM_ROUND_WRITE2 \
	w &= Smask2; \
	{ \
		uint8_t *Stmp = S2; \
		S2 = S1; \
		S1 = S0; \
		S0 = Stmp; \
	}

#undef Smask2
#define Smask2 Smask2_1_0

#endif

/**
 * blockmix_pwxform(Bin, Bout, r, S):
 * Compute Bout = BlockMix_pwxform{salsa20, r, S}(Bin).  The input Bin must
 * be 128r bytes in length; the output Bout must also be the same size.
 */
static void blockmix(const salsa20_blk_t *restrict Bin,
    salsa20_blk_t *restrict Bout, size_t r, pwxform_ctx_t *restrict ctx)
{
	if ( unlikely(!ctx) )
   {
		blockmix_salsa(Bin, Bout);
		return;
	}

   __m128i X0, X1, X2, X3;
	uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
	uint8_t *S2 = ctx->S2;
	size_t w = ctx->w;
#endif
	size_t i;

	/* Convert count of 128-byte blocks to max index of 64-byte block */
	r = r * 2 - 1;

   X0 = Bin[r].m128[0];
   X1 = Bin[r].m128[1];
   X2 = Bin[r].m128[2];
   X3 = Bin[r].m128[3];

	DECL_SMASK2REG

	i = 0;
	do {
		XOR_X(Bin[i])
		PWXFORM
		if (unlikely(i >= r))
			break;
		WRITE_X(Bout[i])
		i++;
	} while (1);

#if _YESPOWER_OPT_C_PASS_ > 1
	ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2;
	ctx->w = w;
#endif

	SALSA20(Bout[i])
}

static uint32_t blockmix_xor(const salsa20_blk_t *restrict Bin1,
    const salsa20_blk_t *restrict Bin2, salsa20_blk_t *restrict Bout,
    size_t r, pwxform_ctx_t *restrict ctx)
{
	if (unlikely(!ctx))
		return blockmix_salsa_xor(Bin1, Bin2, Bout);

   __m128i X0, X1, X2, X3;
	uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
	uint8_t *S2 = ctx->S2;
	size_t w = ctx->w;
#endif
	size_t i;

	/* Convert count of 128-byte blocks to max index of 64-byte block */
	r = r * 2 - 1;

#ifdef PREFETCH
	PREFETCH(&Bin2[r], _MM_HINT_T0)
	for (i = 0; i < r; i++) {
		PREFETCH(&Bin2[i], _MM_HINT_T0)
	}
#endif

   X0 = _mm_xor_si128( Bin1[r].m128[0], Bin2[r].m128[0] );
   X1 = _mm_xor_si128( Bin1[r].m128[1], Bin2[r].m128[1] );
   X2 = _mm_xor_si128( Bin1[r].m128[2], Bin2[r].m128[2] );
   X3 = _mm_xor_si128( Bin1[r].m128[3], Bin2[r].m128[3] );

	DECL_SMASK2REG

	i = 0;
	r--;
	do {
      XOR_X_XOR_X( Bin1[i], Bin2[i] )
		PWXFORM
		WRITE_X(Bout[i])
      XOR_X_XOR_X( Bin1[ i+1 ], Bin2[ i+1 ] )     
		PWXFORM
		if (unlikely(i >= r))
			break;
		WRITE_X(Bout[i + 1])
		i += 2;
	} while (1);
	i++;

#if _YESPOWER_OPT_C_PASS_ > 1
	ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2;
	ctx->w = w;
#endif

	SALSA20(Bout[i])

	return INTEGERIFY( X0 );
}

static uint32_t blockmix_xor_save( salsa20_blk_t *restrict Bin1out,
        salsa20_blk_t *restrict Bin2,  size_t r, pwxform_ctx_t *restrict ctx )
{
   __m128i X0, X1, X2, X3;
   __m128i Y0, Y1, Y2, Y3;
	uint8_t *S0 = ctx->S0, *S1 = ctx->S1;
#if _YESPOWER_OPT_C_PASS_ > 1
	uint8_t *S2 = ctx->S2;
	size_t w = ctx->w;
#endif
	size_t i;

	/* Convert count of 128-byte blocks to max index of 64-byte block */
	r = r * 2 - 1;

#ifdef PREFETCH
	PREFETCH(&Bin2[r], _MM_HINT_T0)
	for (i = 0; i < r; i++) {
		PREFETCH(&Bin2[i], _MM_HINT_T0)
	}
#endif

   X0 = _mm_xor_si128( Bin1out[r].m128[0], Bin2[r].m128[0] );
   X1 = _mm_xor_si128( Bin1out[r].m128[1], Bin2[r].m128[1] );
   X2 = _mm_xor_si128( Bin1out[r].m128[2], Bin2[r].m128[2] );
   X3 = _mm_xor_si128( Bin1out[r].m128[3], Bin2[r].m128[3] );

	DECL_SMASK2REG

	i = 0;
	r--;
	do {
		XOR_X_WRITE_XOR_Y_2(Bin2[i], Bin1out[i])
		PWXFORM
		WRITE_X(Bin1out[i])
		XOR_X_WRITE_XOR_Y_2(Bin2[i + 1], Bin1out[i + 1])
		PWXFORM
		if ( unlikely(i >= r) )
         break;
		WRITE_X(Bin1out[i + 1])
		i += 2;
	} while (1);
	i++;

#if _YESPOWER_OPT_C_PASS_ > 1
	ctx->S0 = S0; ctx->S1 = S1; ctx->S2 = S2;
	ctx->w = w;
#endif

	SALSA20(Bin1out[i])

	return INTEGERIFY( X0 );
}

#if _YESPOWER_OPT_C_PASS_ == 1
/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static inline uint32_t integerify(const salsa20_blk_t *B, size_t r)
{
/*
 * Our 64-bit words are in host byte order, which is why we don't just read
 * w[0] here (would be wrong on big-endian).  Also, our 32-bit words are
 * SIMD-shuffled, but we only care about the least significant 32 bits anyway.
 */
	return (uint32_t)B[2 * r - 1].q[0];
}
#endif

/**
 * smix1(B, r, N, V, XY, S):
 * Compute first loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 128r+64 bytes in length.  N must be even and at least 4.
 * The array V must be aligned to a multiple of 64 bytes, and arrays B and XY
 * to a multiple of at least 16 bytes.
 */
static void smix1(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
	size_t s = 2 * r;
	salsa20_blk_t *X = V, *Y = &V[s], *V_j;
	uint32_t i, j, n;

#if _YESPOWER_OPT_C_PASS_ == 1
	for (i = 0; i < 2 * r; i++) {
#else
	for (i = 0; i < 2; i++) {
#endif
		const salsa20_blk_t *src = (salsa20_blk_t *)&B[i * 64];
		salsa20_blk_t *tmp = Y;
		salsa20_blk_t *dst = &X[i];
		size_t k;
		for (k = 0; k < 16; k++)
         tmp->d[k] = src->d[k];
		salsa20_simd_shuffle(tmp, dst);
	}

#if _YESPOWER_OPT_C_PASS_ > 1
	for (i = 1; i < r; i++)
		blockmix(&X[(i - 1) * 2], &X[i * 2], 1, ctx);
#endif

	blockmix(X, Y, r, ctx);
	X = Y + s;
	blockmix(Y, X, r, ctx);
	j = integerify(X, r);

	for (n = 2; n < N; n <<= 1) {
		uint32_t m = (n < N / 2) ? n : (N - 1 - n);
		for (i = 1; i < m; i += 2) {
			Y = X + s;
			j &= n - 1;
			j += i - 1;
			V_j = &V[j * s];
			j = blockmix_xor(X, V_j, Y, r, ctx);
			j &= n - 1;
			j += i;
			V_j = &V[j * s];
			X = Y + s;
			j = blockmix_xor(Y, V_j, X, r, ctx);
		}
	}
	n >>= 1;

	j &= n - 1;
	j += N - 2 - n;
	V_j = &V[j * s];
	Y = X + s;
	j = blockmix_xor(X, V_j, Y, r, ctx);
	j &= n - 1;
	j += N - 1 - n;
	V_j = &V[j * s];
	blockmix_xor(Y, V_j, XY, r, ctx);

	for (i = 0; i < 2 * r; i++) {
		const salsa20_blk_t *src = &XY[i];
		salsa20_blk_t *tmp = &XY[s];
		salsa20_blk_t *dst = (salsa20_blk_t *)&B[i * 64];
		size_t k;
		for (k = 0; k < 16; k++)
         tmp->d[k] = src->d[k];
		salsa20_simd_unshuffle(tmp, dst);
	}
}

/**
 * smix2(B, r, N, Nloop, V, XY, S):
 * Compute second loop of B = SMix_r(B, N).  The input B must be 128r bytes in
 * length; the temporary storage V must be 128rN bytes in length; the temporary
 * storage XY must be 256r bytes in length.  N must be a power of 2 and at
 * least 2.  Nloop must be even.  The array V must be aligned to a multiple of
 * 64 bytes, and arrays B and XY to a multiple of at least 16 bytes.
 */
static void smix2(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
	size_t s = 2 * r;
	salsa20_blk_t *X = XY, *Y = &XY[s];
	uint32_t i, j;

	for (i = 0; i < 2 * r; i++) {
		const salsa20_blk_t *src = (salsa20_blk_t *)&B[i * 64];
		salsa20_blk_t *tmp = Y;
		salsa20_blk_t *dst = &X[i];
		size_t k;
		for (k = 0; k < 16; k++)
			tmp->d[k] = src->d[k];
		salsa20_simd_shuffle(tmp, dst);
	}

	j = integerify(X, r) & (N - 1);

#if _YESPOWER_OPT_C_PASS_ == 1
	if (Nloop > 2) {
#endif
		do {
			salsa20_blk_t *V_j = &V[j * s];
			j = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
			V_j = &V[j * s];
			j = blockmix_xor_save(X, V_j, r, ctx) & (N - 1);
		} while (Nloop -= 2);
#if _YESPOWER_OPT_C_PASS_ == 1
	} else {
		do {
			const salsa20_blk_t * V_j = &V[j * s];
			j = blockmix_xor(X, V_j, Y, r, ctx) & (N - 1);
			V_j = &V[j * s];
			j = blockmix_xor(Y, V_j, X, r, ctx) & (N - 1);
		} while (Nloop -= 2);
	}
#endif

	for (i = 0; i < 2 * r; i++) {
		const salsa20_blk_t *src = &X[i];
		salsa20_blk_t *tmp = Y;
		salsa20_blk_t *dst = (salsa20_blk_t *)&B[i * 64];
		size_t k;
		for (k = 0; k < 16; k++)
			tmp->d[k]  = src->d[k];
		salsa20_simd_unshuffle(tmp, dst);
	}
}

/**
 * smix(B, r, N, V, XY, S):
 * Compute B = SMix_r(B, N).  The input B must be 128rp bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  N must be a power of 2 and at least 16.
 * The array V must be aligned to a multiple of 64 bytes, and arrays B and XY
 * to a multiple of at least 16 bytes (aligning them to 64 bytes as well saves
 * cache lines, but it might also result in cache bank conflicts).
 */
static void smix(uint8_t *B, size_t r, uint32_t N,
    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)
{
#if _YESPOWER_OPT_C_PASS_ == 1
	uint32_t Nloop_all = (N + 2) / 3; /* 1/3, round up */
	uint32_t Nloop_rw = Nloop_all;

	Nloop_all++; Nloop_all &= ~(uint32_t)1; /* round up to even */
	Nloop_rw &= ~(uint32_t)1; /* round down to even */
#else
	uint32_t Nloop_rw = (N + 2) / 3; /* 1/3, round up */
	Nloop_rw++; Nloop_rw &= ~(uint32_t)1; /* round up to even */
#endif

	smix1(B, 1, ctx->Sbytes / 128, (salsa20_blk_t *)ctx->S0, XY, NULL);
	smix1(B, r, N, V, XY, ctx);
	smix2(B, r, N, Nloop_rw /* must be > 2 */, V, XY, ctx);
#if _YESPOWER_OPT_C_PASS_ == 1
	if (Nloop_all > Nloop_rw)
		smix2(B, r, N, 2, V, XY, ctx);
#endif
}

#if _YESPOWER_OPT_C_PASS_ == 1
#undef _YESPOWER_OPT_C_PASS_
#define _YESPOWER_OPT_C_PASS_ 2
#define blockmix_salsa blockmix_salsa_1_0
#define blockmix_salsa_xor blockmix_salsa_xor_1_0
#define blockmix blockmix_1_0
#define blockmix_xor blockmix_xor_1_0
#define blockmix_xor_save blockmix_xor_save_1_0
#define smix1 smix1_1_0
#define smix2 smix2_1_0
#define smix smix_1_0
#include "yespower-opt.c"
#undef smix

/**
 * yespower(local, src, srclen, params, dst):
 * Compute yespower(src[0 .. srclen - 1], N, r), to be checked for "< target".
 * local is the thread-local data structure, allowing to preserve and reuse a
 * memory allocation across calls, thereby reducing its overhead.
 *
 * Return 0 on success; or -1 on error.
 */
int yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params,
    yespower_binary_t *dst, int thrid )
{
   yespower_version_t version = params->version;
   uint32_t N = params->N;
   uint32_t r = params->r;
   const uint8_t *pers = params->pers;
   size_t perslen = params->perslen;
   uint32_t Swidth;
   size_t B_size, V_size, XY_size, need;
   uint8_t *B, *S;
   salsa20_blk_t *V, *XY;
   pwxform_ctx_t ctx;
   uint8_t sha256[32];
   sha256_context sha256_ctx;

   /* Sanity-check parameters */
   if ( (version != YESPOWER_0_5 && version != YESPOWER_1_0)
      || N < 1024 || N > 512 * 1024 || r < 8 || r > 32
      || (N & (N - 1)) != 0 || ( !pers && perslen ) )
   {
      errno = EINVAL;
      return -1;
   }

   /* Allocate memory */
   B_size = (size_t)128 * r;
   V_size = B_size * N;
   if ( version == YESPOWER_0_5 )
   {
      XY_size = B_size * 2;
      Swidth = Swidth_0_5;
      ctx.Sbytes = 2 * Swidth_to_Sbytes1( Swidth );
   }
   else
   {
      XY_size = B_size + 64;
      Swidth = Swidth_1_0;
      ctx.Sbytes = 3 * Swidth_to_Sbytes1( Swidth );
   }
   need = B_size + V_size + XY_size + ctx.Sbytes;
   if ( local->aligned_size < need )
   {
      if ( free_region( local ) )
         return -1;
      if ( !alloc_region( local, need ) )
         return -1;
   }
   B = (uint8_t *)local->aligned;
   V = (salsa20_blk_t *)((uint8_t *)B + B_size);
   XY = (salsa20_blk_t *)((uint8_t *)V + V_size);
   S = (uint8_t *)XY + XY_size;
   ctx.S0 = S;
   ctx.S1 = S + Swidth_to_Sbytes1( Swidth );

   if ( srclen == 80 )   // assume 64 byte prehash was done
   {
     memcpy( &sha256_ctx, &sha256_prehash_ctx, sizeof sha256_ctx );
     sha256_update( &sha256_ctx, src+64, srclen-64 );
     sha256_final( &sha256_ctx, sha256 );
   }
   else
     sha256_full( sha256, src, srclen );
   
   if ( version == YESPOWER_0_5 )
   {
      PBKDF2_SHA256( sha256, sizeof(sha256), src, srclen, 1, B, B_size );

      if ( work_restart[thrid].restart ) return 0;
   
      memcpy( sha256, B, sizeof(sha256) );
      smix( B, r, N, V, XY, &ctx );

      if ( work_restart[thrid].restart ) return 0;

      PBKDF2_SHA256( sha256, sizeof(sha256), B, B_size, 1, (uint8_t *)dst,
                     sizeof(*dst) );

      if ( work_restart[thrid].restart ) return 0;

      if ( pers )
      {
         src = pers;
         srclen = perslen;
      }

      HMAC_SHA256_Buf( dst, sizeof(*dst), src, srclen, sha256 );
      SHA256_Buf( sha256, sizeof(sha256), (uint8_t *)dst );
      
   }
   else
   {
      ctx.S2 = S + 2 * Swidth_to_Sbytes1( Swidth );
      ctx.w = 0;
      if ( pers )
      {
         src = pers;
         srclen = perslen;
      }
      else
         srclen = 0;

      PBKDF2_SHA256( sha256, sizeof(sha256), src, srclen, 1, B, 128 );
      memcpy( sha256, B, sizeof(sha256) );

      if ( work_restart[thrid].restart ) return 0;

      smix_1_0( B, r, N, V, XY, &ctx );

      if ( work_restart[thrid].restart ) return 0;

      HMAC_SHA256_Buf( B + B_size - 64, 64, sha256, sizeof(sha256),
                       (uint8_t *)dst );
   }

   /* Success! */
   return 1;
}

/**
 * yespower_tls(src, srclen, params, dst):
 * Compute yespower(src[0 .. srclen - 1], N, r), to be checked for "< target".
 * The memory allocation is maintained internally using thread-local storage.
 *
 * Return 0 on success; or -1 on error.
 */
int yespower_tls(const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst, int thrid )
{
	static __thread int initialized = 0;
	static __thread yespower_local_t local;

	if (!initialized) {
		if (yespower_init_local(&local))
			return -1;
		initialized = 1;
	}

	return yespower( &local, src, srclen, params, dst, thrid );
}

int yespower_init_local(yespower_local_t *local)
{
	init_region(local);
	return 0;
}

int yespower_free_local(yespower_local_t *local)
{
	return free_region(local);
}
#endif
