/* $Id: sph_skein.h 253 2011-06-07 18:33:10Z tp $ */
/**
 * Skein interface. The Skein specification defines three main
 * functions, called Skein-256, Skein-512 and Skein-1024, which can be
 * further parameterized with an output length. For the SHA-3
 * competition, Skein-512 is used for output sizes of 224, 256, 384 and
 * 512 bits; this is what this code implements. Thus, we hereafter call
 * Skein-224, Skein-256, Skein-384 and Skein-512 what the Skein
 * specification defines as Skein-512-224, Skein-512-256, Skein-512-384
 * and Skein-512-512, respectively.
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
 * @file     sph_skein.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef __SKEIN_HASH_4WAY_H__
#define __SKEIN_HASH_4WAY_H__ 1

#ifdef __AVX2__

#ifdef __cplusplus
extern "C"{
#endif

#include <stddef.h>
#include "algo/sha/sph_types.h"
#include "avxdefs.h"

// Output size in bits
#define SPH_SIZE_skein256   256
#define SPH_SIZE_skein512   512

typedef struct {
        __m256i buf[8] __attribute__ ((aligned (32)));
        __m256i h0, h1, h2, h3, h4, h5, h6, h7;
        size_t ptr;
	sph_u64 bcount;
} sph_skein_4way_big_context;

typedef sph_skein_4way_big_context skein512_4way_context;
typedef sph_skein_4way_big_context skein256_4way_context;

void skein512_4way_init(void *cc);
void skein512_4way(void *cc, const void *data, size_t len);
void skein512_4way_close(void *cc, void *dst);
//void sph_skein512_addbits_and_close(
//        void *cc, unsigned ub, unsigned n, void *dst);

void skein256_4way_init(void *cc);
void skein256_4way(void *cc, const void *data, size_t len);
void skein256_4way_close(void *cc, void *dst);
//void sph_skein256_addbits_and_close(
//	void *cc, unsigned ub, unsigned n, void *dst);


#ifdef __cplusplus
}
#endif
#endif
#endif
