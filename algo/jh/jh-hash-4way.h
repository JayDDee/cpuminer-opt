/* $Id: sph_jh.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * JH interface. JH is a family of functions which differ by
 * their output size; this implementation defines JH for output
 * sizes 224, 256, 384 and 512 bits.
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
 * @file     sph_jh.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef JH_HASH_4WAY_H__
#define JH_HASH_4WAY_H__

#ifdef __AVX2__

#ifdef __cplusplus
extern "C"{
#endif

#include <stddef.h>
#include "simd-utils.h"

#define SPH_SIZE_jh256   256

#define SPH_SIZE_jh512   512

/**
 * This structure is a context for JH computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a JH computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running JH computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */

 
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct {
    __m512i buf[8];
    __m512i H[16];
    size_t ptr;
    uint64_t block_count;
} jh_8way_context __attribute__ ((aligned (128)));

typedef jh_8way_context jh256_8way_context;

typedef jh_8way_context jh512_8way_context;

void jh256_8way_init( jh_8way_context *sc);

void jh256_8way_update(void *cc, const void *data, size_t len);

void jh256_8way_close(void *cc, void *dst);

void jh512_8way_init( jh_8way_context *sc );

void jh512_8way_update(void *cc, const void *data, size_t len);

void jh512_8way_close(void *cc, void *dst);

#endif

typedef struct {
    __m256i buf[8];
    __m256i H[16];
    size_t ptr;
    uint64_t block_count;
} jh_4way_context __attribute__ ((aligned (128)));

typedef jh_4way_context jh256_4way_context;

typedef jh_4way_context jh512_4way_context;

void jh256_4way_init( jh_4way_context *sc);

void jh256_4way_update(void *cc, const void *data, size_t len);

void jh256_4way_close(void *cc, void *dst);

void jh512_4way_init( jh_4way_context *sc );

void jh512_4way_update(void *cc, const void *data, size_t len);

void jh512_4way_close(void *cc, void *dst);

#ifdef __cplusplus
}
#endif

#endif // AVX2

#endif
