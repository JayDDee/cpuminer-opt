/* $Id: sph_hamsi.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * Hamsi interface. This code implements Hamsi with the recommended
 * parameters for SHA-3, with outputs of 224, 256, 384 and 512 bits.
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
 * @file     sph_hamsi.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef HAMSI_4WAY_H__
#define HAMSI_4WAY_H__

#include <stddef.h>
#include "simd-utils.h"

#if defined(__SSE4_2__) || defined(__ARM_NEON)

typedef struct
{
   v128_t h[8];
   v128_t buf[1];
   size_t partial_len;
   uint32_t count_high, count_low;
} hamsi_2x64_context;
typedef hamsi_2x64_context hamsi512_2x64_context;

void hamsi512_2x64_init( hamsi512_2x64_context *sc );
void hamsi512_2x64_update( hamsi512_2x64_context *sc, const void *data,
      size_t len );
void hamsi512_2x64_close( hamsi512_2x64_context *sc, void *dst );
void hamsi512_2x64_ctx( hamsi512_2x64_context *sc, void *dst, const void *data,
                        size_t len );
void hamsi512_2x64( void *dst, const void *data, size_t len );

#endif

#if defined (__AVX2__)

// Hamsi-512 4x64

// Partial is only scalar but needs pointer ref for hamsi-helper
// deprecate partial_len
typedef struct
{
   __m256i h[8];
   __m256i buf[1];
   size_t partial_len;
   uint32_t count_high, count_low;
} hamsi_4way_big_context;
typedef hamsi_4way_big_context hamsi512_4x64_context;

void hamsi512_4x64_init( hamsi512_4x64_context *sc );
void hamsi512_4x64_update( hamsi512_4x64_context *sc, const void *data,
      size_t len );
void hamsi512_4x64_close( hamsi512_4x64_context *sc, void *dst );

#define hamsi512_4way_context   hamsi512_4x64_context
#define hamsi512_4way_init      hamsi512_4x64_init
#define hamsi512_4way_update    hamsi512_4x64_update
#define hamsi512_4way_close     hamsi512_4x64_close

// Hamsi-512 8x32

typedef struct
{
   __m256i h[16];
   __m256i buf[2];
   size_t partial_len;
   uint32_t count_high, count_low;
} hamsi_8x32_big_context;
typedef hamsi_8x32_big_context hamsi512_8x32_context;

void hamsi512_8x32_init( hamsi512_8x32_context *sc );
void hamsi512_8x32_update( hamsi512_8x32_context *sc, const void *data,
      size_t len );
void hamsi512_8x32_close( hamsi512_8x32_context *sc, void *dst );
void hamsi512_8x32_full( hamsi512_8x32_context *sc, void *dst, const void *data,
      size_t len );

#endif

#if defined(SIMD512)

// Hamsi-512 8x64

typedef struct
{
   __m512i h[8];
   __m512i buf[1];
   size_t partial_len;
   uint32_t count_high, count_low;
} hamsi_8way_big_context;
typedef hamsi_8way_big_context hamsi512_8x64_context;

void hamsi512_8x64_init( hamsi512_8x64_context *sc );
void hamsi512_8x64_update( hamsi512_8x64_context *sc, const void *data,
                           size_t len );
void hamsi512_8x64_close( hamsi512_8x64_context *sc, void *dst );

#define hamsi512_8way_context   hamsi512_8x64_context
#define hamsi512_8way_init      hamsi512_8x64_init
#define hamsi512_8way_update    hamsi512_8x64_update
#define hamsi512_8way_close     hamsi512_8x64_close

// Hamsi-512 16x32

typedef struct
{
   __m512i h[16];
   __m512i buf[2];
   size_t partial_len;
   uint32_t count_high, count_low;
} hamsi_16x32_big_context;
typedef hamsi_16x32_big_context hamsi512_16x32_context;

void hamsi512_16x32_init( hamsi512_16x32_context *sc );
void hamsi512_16x32_update( hamsi512_16x32_context *sc, const void *data,
                           size_t len );
void hamsi512_16way_close( hamsi512_16x32_context *sc, void *dst );
void hamsi512_16x32_full( hamsi512_16x32_context *sc, void *dst,
                          const void *data, size_t len );

#endif   // AVX512

#endif
