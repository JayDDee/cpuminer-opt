/* $Id: sph_shabal.h 175 2010-05-07 16:03:20Z tp $ */
/**
 * Shabal interface. Shabal is a family of functions which differ by
 * their output size; this implementation defines Shabal for output
 * sizes 192, 224, 256, 384 and 512 bits.
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
 * @file     sph_shabal.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SHABAL_HASH_4WAY_H__
#define SHABAL_HASH_4WAY_H__ 1

#ifdef __SSE4_1__

#include <stddef.h>
#include "algo/sha/sph_types.h"
#include "simd-utils.h"

#ifdef __cplusplus
extern "C"{
#endif

#define SPH_SIZE_shabal256   256

#define SPH_SIZE_shabal512   512

#if defined(__AVX2__)

typedef struct {
   __m256i buf[16];
   __m256i A[12], B[16], C[16];
   sph_u32 Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_8way_context __attribute__ ((aligned (64)));

typedef shabal_8way_context shabal256_8way_context;
typedef shabal_8way_context shabal512_8way_context;

void shabal256_8way_init( void *cc );
void shabal256_8way_update( void *cc, const void *data, size_t len );
void shabal256_8way_close( void *cc, void *dst );
void shabal256_8way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

void shabal512_8way_init( void *cc );
void shabal512_8way_update( void *cc, const void *data, size_t len );
void shabal512_8way_close( void *cc, void *dst );
void shabal512_8way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );


#endif

typedef struct {
	__m128i buf[16] __attribute__ ((aligned (64)));
	__m128i A[12], B[16], C[16];
	sph_u32 Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_4way_context;

typedef shabal_4way_context shabal256_4way_context;
typedef shabal_4way_context shabal512_4way_context;

void shabal256_4way_init( void *cc );
void shabal256_4way_update( void *cc, const void *data, size_t len );
void shabal256_4way_close( void *cc, void *dst );
void shabal256_4way_addbits_and_close(	void *cc, unsigned ub, unsigned n,
                                       void *dst );

void shabal512_4way_init( void *cc );
void shabal512_4way_update( void *cc, const void *data, size_t len );
//#define shabal512_4way shabal512_4way_update
void shabal512_4way_close( void *cc, void *dst );
void shabal512_4way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

#ifdef __cplusplus
}
#endif

#endif

#endif

