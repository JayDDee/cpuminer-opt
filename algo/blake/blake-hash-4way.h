/* $Id: sph_blake.h 252 2011-06-07 17:55:14Z tp $ */
/**
 * BLAKE interface. BLAKE is a family of functions which differ by their
 * output size; this implementation defines BLAKE for output sizes 224,
 * 256, 384 and 512 bits. This implementation conforms to the "third
 * round" specification.
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
 * @file     sph_blake.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef __BLAKE_HASH_4WAY__
#define __BLAKE_HASH_4WAY___

#ifdef __cplusplus
extern "C"{
#endif

#include <stddef.h>
#include "algo/sha/sph_types.h"
#include "avxdefs.h"

/**
 * Output size (in bits) for BLAKE-256.
 */
#define SPH_SIZE_blake256   256

#if SPH_64

/**
 * Output size (in bits) for BLAKE-512.
 */
#define SPH_SIZE_blake512   512

#endif

#ifdef __AVX__
typedef struct {
        __m128i buf[16] __attribute__ ((aligned (64)));
	size_t ptr;
        __m128i H[8];
        __m128i S[4];    
	sph_u32 T0, T1;
} blake_4way_small_context;

typedef blake_4way_small_context blake256_4way_context;

void blake256_4way_init(void *cc);
void blake256_4way(void *cc, const void *data, size_t len);
void blake256_4way_close(void *cc, void *dst);
void blake256_4way_addbits_and_close(
        void *cc, unsigned ub, unsigned n, void *dst);

#endif

#ifdef __AVX2__

typedef struct {
        __m256i buf[16] __attribute__ ((aligned (64)));
	size_t ptr;
        __m256i H[8];
        __m256i S[4];   
	sph_u64 T0, T1;
} blake_4way_big_context;

typedef blake_4way_big_context blake512_avx2_context;

void blake512_4way_init(void *cc);
void blake512_4way(void *cc, const void *data, size_t len);
void blake512_4way_close(void *cc, void *dst);
void blake512_4way_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

#endif

#ifdef __cplusplus
}
#endif

#endif
