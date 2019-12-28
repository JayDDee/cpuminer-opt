/* $Id: sph_haval.h 218 2010-06-08 17:06:34Z tp $ */
/**
 * HAVAL interface.
 *
 * HAVAL is actually a family of 15 hash functions, depending on whether
 * the internal computation uses 3, 4 or 5 passes, and on the output
 * length, which is 128, 160, 192, 224 or 256 bits. This implementation
 * provides interface functions for all 15, which internally map to
 * three cores (depending on the number of passes). Note that output
 * lengths other than 256 bits are not obtained by a simple truncation
 * of a longer result; the requested length is encoded within the
 * padding data.
 *
 * HAVAL was published in: Yuliang Zheng, Josef Pieprzyk and Jennifer
 * Seberry: "HAVAL -- a one-way hashing algorithm with variable length
 * of output", Advances in Cryptology -- AUSCRYPT'92, Lecture Notes in
 * Computer Science, Vol.718, pp.83-104, Springer-Verlag, 1993.
 *
 * This paper, and a reference implementation, are available on the
 * Calyptix web site: http://labs.calyptix.com/haval.php
 *
 * The HAVAL reference paper is quite unclear on the data encoding
 * details, i.e. endianness (both byte order within a 32-bit word, and
 * word order within a message block). This implementation has been
 * made compatible with the reference implementation referenced above.
 *
 * @warning   A collision for HAVAL-128/3 (HAVAL with three passes and
 * 128-bit output) has been published; this function is thus considered
 * as cryptographically broken. The status for other variants is unclear;
 * use only with care.
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
 * @file     sph_haval.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef HAVAL_HASH_4WAY_H__
#define HAVAL_HASH_4WAY_H__ 1

#if defined(__AVX__)

#ifdef __cplusplus
extern "C"{
#endif

#include <stddef.h>
#include "algo/sha/sph_types.h"
#include "simd-utils.h"

#define SPH_SIZE_haval256_5   256

typedef struct {
   __m128i buf[32];
   __m128i s0, s1, s2, s3, s4, s5, s6, s7;
   unsigned olen, passes;
   sph_u32 count_high, count_low;
} haval_4way_context;

typedef haval_4way_context haval256_5_4way_context;

void haval256_5_4way_init( void *cc );

void haval256_5_4way_update( void *cc, const void *data, size_t len );
//#define haval256_5_4way haval256_5_4way_update

void haval256_5_4way_close( void *cc, void *dst );

#if defined(__AVX2__)

typedef struct {
   __m256i buf[32];
   __m256i s0, s1, s2, s3, s4, s5, s6, s7;
   unsigned olen, passes;
   uint32_t count_high, count_low;
} haval_8way_context __attribute__ ((aligned (64)));

typedef haval_8way_context haval256_5_8way_context;

void haval256_5_8way_init( void *cc );

void haval256_5_8way_update( void *cc, const void *data, size_t len );

void haval256_5_8way_close( void *cc, void *dst );

#endif // AVX2

#ifdef __cplusplus
}
#endif
#endif
#endif
