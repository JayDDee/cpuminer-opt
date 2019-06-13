/* $Id: sph_sha2.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * SHA-224, SHA-256, SHA-384 and SHA-512 interface.
 *
 * SHA-256 has been published in FIPS 180-2, now amended with a change
 * notice to include SHA-224 as well (which is a simple variation on
 * SHA-256). SHA-384 and SHA-512 are also defined in FIPS 180-2. FIPS
 * standards can be found at:
 *    http://csrc.nist.gov/publications/fips/
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
 * @file     sph_sha2.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SHA2_HASH_4WAY_H__
#define SHA2_HASH_4WAY_H__ 1

#include <stddef.h>
#include "sph_types.h"
#include "simd-utils.h"

#if defined(__SSE2__)
//#if defined(__SSE4_2__)

//#define SPH_SIZE_sha256   256

// SHA-256 4 way

typedef struct {
   __m128i buf[64>>2];
   __m128i val[8];
   uint32_t count_high, count_low;
} sha256_4way_context;

void sha256_4way_init( sha256_4way_context *sc );
void sha256_4way( sha256_4way_context *sc, const void *data, size_t len );
void sha256_4way_close( sha256_4way_context *sc, void *dst );

/*
// SHA-256 7 way hybrid
// Combines SSE, MMX and scalar data to do 8 + 2 + 1 parallel.
typedef struct {
   __m128i  bufx[64>>2];
   __m128i  valx[8];
   __m64    bufy[64>>2];
   __m64    valy[8];
   uint32_t bufz[64>>2];
   uint32_t valz[8];
   uint32_t count_high, count_low;
} sha256_7way_context;

void sha256_7way_init( sha256_7way_context *ctx );
void sha256_7way( sha256_7way_context *ctx, const void *datax,
                         void *datay, void *dataz, size_t len );
void sha256_7way_close( sha256_7way_context *ctx, void *dstx, void *dstyx,
                         void *dstz  );
*/

#if defined (__AVX2__)

// SHA-256 8 way

typedef struct {
   __m256i buf[64>>2];
   __m256i val[8];
   uint32_t count_high, count_low;
} sha256_8way_context;

void sha256_8way_init( sha256_8way_context *sc );
void sha256_8way( sha256_8way_context *sc, const void *data, size_t len );
void sha256_8way_close( sha256_8way_context *sc, void *dst );

//#define SPH_SIZE_sha512   512

// SHA-512 4 way

typedef struct {
   __m256i buf[128>>3];
   __m256i val[8];
   uint64_t count;
} sha512_4way_context;

void sha512_4way_init( sha512_4way_context *sc);
void sha512_4way( sha512_4way_context *sc, const void *data, size_t len );
void sha512_4way_close( sha512_4way_context *sc, void *dst );

// SHA-256 11 way hybrid
// Combines AVX2, MMX and scalar data to do 8 + 2 + 1 parallel.
typedef struct {
   __m256i  bufx[64>>2];
   __m256i  valx[8];
   __m64    bufy[64>>2];
   __m64    valy[8];
   uint32_t bufz[64>>2];
   uint32_t valz[8];
   uint32_t count_high, count_low;
} sha256_11way_context;

void sha256_11way_init( sha256_11way_context *ctx );
void sha256_11way_update( sha256_11way_context *ctx, const void *datax,
	                 const void *datay, const void *dataz, size_t len );
void sha256_11way_close( sha256_11way_context *ctx, void *dstx, void *dstyx,
	                 void *dstz  );

#endif  // __AVX2__
#endif  // __SSE2__
#endif  // SHA256_4WAY_H__
