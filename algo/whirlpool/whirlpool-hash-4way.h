/* $Id: sph_whirlpool.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * WHIRLPOOL interface.
 *
 * WHIRLPOOL knows three variants, dubbed "WHIRLPOOL-0" (original
 * version, published in 2000, studied by NESSIE), "WHIRLPOOL-1"
 * (first revision, 2001, with a new S-box) and "WHIRLPOOL" (current
 * version, 2003, with a new diffusion matrix, also described as "plain
 * WHIRLPOOL"). All three variants are implemented here.
 *
 * The original WHIRLPOOL (i.e. WHIRLPOOL-0) was published in: P. S. L.
 * M. Barreto, V. Rijmen, "The Whirlpool Hashing Function", First open
 * NESSIE Workshop, Leuven, Belgium, November 13--14, 2000.
 *
 * The current WHIRLPOOL specification and a reference implementation
 * can be found on the WHIRLPOOL web page:
 * http://paginas.terra.com.br/informatica/paulobarreto/WhirlpoolPage.html
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
 * @file     sph_whirlpool.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef WHIRLPOOL_HASH_4WAY_H__
#define WHIRLPOOL_HASH_4WAY_H__

#ifdef __AVX2__

#include <stddef.h>
#include "algo/sha/sph_types.h"
#include "simd-utils.h"

/**
 * Output size (in bits) for WHIRLPOOL.
 */
#define SPH_SIZE_whirlpool   512

/**
 * Output size (in bits) for WHIRLPOOL-0.
 */
#define SPH_SIZE_whirlpool0   512

/**
 * Output size (in bits) for WHIRLPOOL-1.
 */
#define SPH_SIZE_whirlpool1   512

typedef struct {
    __m256i buf[8] __attribute__ ((aligned (64)));
    __m256i state[8];
    sph_u64 count;
} whirlpool_4way_context;

void whirlpool_4way_init( void *cc );

void whirlpool_4way( void *cc, const void *data, size_t len );

void whirlpool_4way_close( void *cc, void *dst );

/**
 * WHIRLPOOL-0 uses the same structure than plain WHIRLPOOL.
 */
typedef whirlpool_4way_context whirlpool0_4way_context;

#define whirlpool0_4way_init whirlpool_4way_init

void whirlpool0_4way( void *cc, const void *data, size_t len );

void whirlpool0_4way_close( void *cc, void *dst );

/**
 * WHIRLPOOL-1 uses the same structure than plain WHIRLPOOL.
 */
typedef whirlpool_4way_context whirlpool1_4way_context;

#define whirlpool1_4way_init whirlpool_4way_init

void whirlpool1_4way(void *cc, const void *data, size_t len);

void whirlpool1_4way_close(void *cc, void *dst);

#endif

#endif
