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
#include "algo/sha/sph_types.h"

#if defined (__AVX2__)

#include "simd-utils.h"

#ifdef __cplusplus
extern "C"{
#endif

#define SPH_SIZE_hamsi512   512

// Partial is only scalar but needs pointer ref for hamsi-helper
// deprecate partial_len
typedef struct {
   __m256i h[8];
   __m256i buf[1];
   size_t partial_len;
   sph_u32 count_high, count_low;
} hamsi_4way_big_context;

typedef hamsi_4way_big_context hamsi512_4way_context;

void hamsi512_4way_init( hamsi512_4way_context *sc );
void hamsi512_4way_update( hamsi512_4way_context *sc, const void *data,
      size_t len );
//#define hamsi512_4way hamsi512_4way_update
void hamsi512_4way_close( hamsi512_4way_context *sc, void *dst );

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct {
   __m512i h[8];
   __m512i buf[1];
   size_t partial_len;
   sph_u32 count_high, count_low;
} hamsi_8way_big_context;

typedef hamsi_8way_big_context hamsi512_8way_context;

void hamsi512_8way_init( hamsi512_8way_context *sc );
void hamsi512_8way_update( hamsi512_8way_context *sc, const void *data,
                           size_t len );
void hamsi512_8way_close( hamsi512_8way_context *sc, void *dst );



#endif


#ifdef __cplusplus
}
#endif

#endif

#endif
