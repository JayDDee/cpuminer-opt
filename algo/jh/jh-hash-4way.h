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

typedef struct
{
    __m512i buf[8];
    __m512i H[16];
    size_t ptr;
    uint64_t block_count;
} jh_8x64_context __attribute__ ((aligned (128)));

typedef jh_8x64_context jh256_8x64_context;
typedef jh_8x64_context jh512_8x64_context;
#define jh256_8way_context jh256_8x64_context
#define jh512_8way_context jh512_8x64_context

void jh256_8x64_init( jh_8x64_context *sc);
void jh256_8x64_update(void *cc, const void *data, size_t len);
void jh256_8x64_close(void *cc, void *dst);
void jh256_8x64_ctx( jh_8x64_context *cc, void *dst, const void *data, size_t len );

void jh512_8x64_init( jh_8x64_context *sc );
void jh512_8x64_update(void *cc, const void *data, size_t len);
void jh512_8x64_close(void *cc, void *dst);
void jh512_8x64_ctx( jh_8x64_context *cc, void *dst, const void *data, size_t len );

#define jh256_8way_init     jh256_8x64_init
#define jh256_8way_update   jh256_8x64_update
#define jh256_8way_close    jh256_8x64_close

#define jh512_8way_init     jh512_8x64_init
#define jh512_8way_update   jh512_8x64_update
#define jh512_8way_close    jh512_8x64_close

#endif

#if defined(__AVX2__)

typedef struct
{
    __m256i buf[8];
    __m256i H[16];
    size_t ptr;
    uint64_t block_count;
} jh_4x64_context __attribute__ ((aligned (128)));

typedef jh_4x64_context jh256_4x64_context;
typedef jh_4x64_context jh512_4x64_context;
#define jh256_4way_context jh256_4x64_context
#define jh512_4way_context jh512_4x64_context

void jh256_4x64_init( jh_4x64_context *sc );
void jh256_4x64_update( void *cc, const void *data, size_t len );
void jh256_4x64_close( void *cc, void *dst );
void jh256_4x64_ctx( jh_4x64_context *cc, void *dst, const void *data,
                     size_t len );

void jh512_4x64_init( jh_4x64_context *sc );
void jh512_4x64_update( void *cc, const void *data, size_t len );
void jh512_4x64_close( void *cc, void *dst );
void jh512_4x64_ctx( jh_4x64_context *cc, void *dst, const void *data, size_t len );

#define jh256_4way_init     jh256_4x64_init
#define jh256_4way_update   jh256_4x64_update 
#define jh256_4way_close    jh256_4x64_close

#define jh512_4way_init     jh512_4x64_init
#define jh512_4way_update   jh512_4x64_update 
#define jh512_4way_close    jh512_4x64_close

#endif // AVX2

typedef struct
{
    v128u64_t buf[8];
    v128u64_t H[16];
    size_t ptr;
    uint64_t block_count;
} jh_2x64_context __attribute__ ((aligned (128)));

typedef jh_2x64_context jh256_2x64_context;
typedef jh_2x64_context jh512_2x64_context;

void jh256_2x64_init( jh256_2x64_context *cc );
void jh256_2x64_update( jh256_2x64_context *cc, const void *data, size_t len );
void jh256_2x64_close( jh256_2x64_context *cc, void *dst );
void jh256_2x64_ctx( jh256_2x64_context *cc, void *dst, const void *data, size_t len );

void jh512_2x64_init( jh512_2x64_context *cc );
void jh512_2x64_update( jh256_2x64_context *cc, const void *data, size_t len );
void jh512_2x64_close( jh256_2x64_context *cc, void *dst );
void jh512_2x64_ctx( jh256_2x64_context *cc, void *dst, const void *data, size_t len );

#endif
