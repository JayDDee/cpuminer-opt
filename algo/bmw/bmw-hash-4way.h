/* $Id: sph_bmw.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * BMW interface. BMW (aka "Blue Midnight Wish") is a family of
 * functions which differ by their output size; this implementation
 * defines BMW for output sizes 224, 256, 384 and 512 bits.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_bmw.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef BMW_HASH_H__
#define BMW_HASH_H__

#ifdef __cplusplus
extern "C"{
#endif

#include <stddef.h>

#include "algo/sha/sph_types.h"
#include "simd-utils.h"

#define SPH_SIZE_bmw256   256

#define SPH_SIZE_bmw512   512

#if defined(__SSE2__)

// BMW-256 4 way 32

typedef struct {
   __m128i buf[64];
   __m128i H[16];
   size_t ptr;
   sph_u32 bit_count;  // assume bit_count fits in 32 bits
} bmw_4way_small_context;

typedef bmw_4way_small_context bmw256_4way_context;

void bmw256_4way_init( bmw256_4way_context *ctx );

void bmw256_4way_update(void *cc, const void *data, size_t len);
#define bmw256_4way bmw256_4way_update

void bmw256_4way_close(void *cc, void *dst);

void bmw256_4way_addbits_and_close(
        void *cc, unsigned ub, unsigned n, void *dst);

#endif  // __SSE2__

#if defined(__AVX2__)

// BMW-256 8 way 32

typedef struct {
   __m256i buf[16];
   __m256i H[16];
   size_t ptr;
   uint32_t bit_count;  // assume bit_count fits in 32 bits
} bmw_8way_small_context __attribute__ ((aligned (64)));

typedef bmw_8way_small_context bmw256_8way_context;

void bmw256_8way_init( bmw256_8way_context *ctx );
void bmw256_8way_update( bmw256_8way_context *ctx, const void *data,
                         size_t len );
#define bmw256_8way bmw256_8way_update
void bmw256_8way_close( bmw256_8way_context *ctx, void *dst );

#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// BMW-256 16 way 32

typedef struct {
   __m512i buf[16];
   __m512i H[16];
   size_t ptr;
   uint32_t bit_count;  // assume bit_count fits in 32 bits
} bmw_16way_small_context __attribute__ ((aligned (128)));

typedef bmw_16way_small_context bmw256_16way_context;

void bmw256_16way_init( bmw256_16way_context *ctx );
void bmw256_16way_update( bmw256_16way_context *ctx, const void *data,
                          size_t len );
void bmw256_16way_close( bmw256_16way_context *ctx, void *dst );

#endif


#if defined(__SSE2__)

// BMW-512 2 way 64

typedef struct {
   __m128i buf[16];
   __m128i H[16];
   size_t ptr;
   uint64_t bit_count; 
} bmw_2way_big_context __attribute__ ((aligned (64)));

typedef bmw_2way_big_context bmw512_2way_context;

void bmw512_2way_init( bmw512_2way_context *ctx );
void bmw512_2way_update( bmw512_2way_context *ctx, const void *data,
                         size_t len );
void bmw512_2way_close( bmw512_2way_context *ctx, void *dst );

#endif // __SSE2__

#if defined(__AVX2__)

// BMW-512 64 bit 4 way

typedef struct {
   __m256i buf[16];
   __m256i H[16];
   size_t ptr;
   sph_u64 bit_count;
} bmw_4way_big_context __attribute__((aligned(128)));

typedef bmw_4way_big_context bmw512_4way_context;

void bmw512_4way_init(void *cc);

void bmw512_4way_update(void *cc, const void *data, size_t len);
#define bmw512_4way bmw512_4way_update

void bmw512_4way_close(void *cc, void *dst);

void bmw512_4way_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

#endif  // __AVX2__

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// BMW-512 64 bit 8 way
typedef struct {
   __m512i buf[16];
   __m512i H[16];
   size_t ptr;
   uint64_t bit_count;
} bmw512_8way_context __attribute__((aligned(128)));

void bmw512_8way_full( bmw512_8way_context *ctx, void *out, const void *data,
                         size_t len );
void bmw512_8way_init( bmw512_8way_context *ctx );
void bmw512_8way_update( bmw512_8way_context *ctx, const void *data,
                         size_t len );
void bmw512_8way_close( bmw512_8way_context *ctx, void *dst );

#endif // AVX512

#ifdef __cplusplus
}
#endif

#endif // BMW_HASH_H__
