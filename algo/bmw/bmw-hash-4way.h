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
#ifdef __AVX2__

#include "algo/sha/sph_types.h"
#include "avxdefs.h"

/**
 * Output size (in bits) for BMW-224.
 */
#define SPH_SIZE_bmw224   224

/**
 * Output size (in bits) for BMW-256.
 */
#define SPH_SIZE_bmw256   256

#if SPH_64

/**
 * Output size (in bits) for BMW-384.
 */
#define SPH_SIZE_bmw384   384

/**
 * Output size (in bits) for BMW-512.
 */
#define SPH_SIZE_bmw512   512

#endif

/**
 * This structure is a context for BMW-224 and BMW-256 computations:
 * it contains the intermediate values and some data from the last
 * entered block. Once a BMW computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running BMW
 * computation can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[64];    /* first field, for alignment */
	size_t ptr;
	sph_u32 H[16];
#if SPH_64
	sph_u64 bit_count;
#else
	sph_u32 bit_count_high, bit_count_low;
#endif
#endif
} bmw_4way_small_context;

typedef bmw_4way_small_context bmw256_4way_context;

#if SPH_64

/**
 * This structure is a context for BMW-384 and BMW-512 computations:
 * it contains the intermediate values and some data from the last
 * entered block. Once a BMW computation has been performed, the
 * context can be reused for another computation.
 *
 * The contents of this structure are private. A running BMW
 * computation can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
   __m256i buf[16];
   __m256i H[16];

//	unsigned char buf[128];    /* first field, for alignment */
	size_t ptr;
//	sph_u64 H[16];
	sph_u64 bit_count;
#endif
} bmw_4way_big_context;

typedef bmw_4way_big_context bmw512_4way_context;

#endif

void bmw256_4way_init(void *cc);

void bmw256_4way(void *cc, const void *data, size_t len);

void bmw256_4way_close(void *cc, void *dst);

void bmw256_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

#if SPH_64

void bmw512_4way_init(void *cc);

void bmw512_4way(void *cc, const void *data, size_t len);

void bmw512_4way_close(void *cc, void *dst);

void bmw512_4way_addbits_and_close(
	void *cc, unsigned ub, unsigned n, void *dst);

#endif

#ifdef __cplusplus
}
#endif

#endif

#endif
