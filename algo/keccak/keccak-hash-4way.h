/* $Id: sph_keccak.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * Keccak interface. This is the interface for Keccak with the
 * recommended parameters for SHA-3, with output lengths 224, 256,
 * 384 and 512 bits.
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
 * @file     sph_keccak.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef KECCAK_HASH_4WAY_H__
#define KECCAK_HASH_4WAY_H__

#ifdef __cplusplus
extern "C"{
#endif

#ifdef  __AVX2__

#include <stddef.h>
#include "algo/sha/sph_types.h"
#include "avxdefs.h"

#define SPH_SIZE_keccak256   256

/**
 * Output size (in bits) for Keccak-512.
 */
#define SPH_SIZE_keccak512   512

/**
 * This structure is a context for Keccak computations: it contains the
 * intermediate values and some data from the last entered block. Once a
 * Keccak computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running Keccak computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */

typedef struct {
        __m256i buf[144*8];    /* first field, for alignment */
        __m256i w[25];
        size_t ptr, lim;
//        sph_u64 wide[25];
} keccak64_ctx_m256i;

typedef keccak64_ctx_m256i keccak256_4way_context;
typedef keccak64_ctx_m256i keccak512_4way_context;

void keccak256_4way_init(void *cc);
void keccak256_4way(void *cc, const void *data, size_t len);
void keccak256_4way_close(void *cc, void *dst);


void keccak512_4way_init(void *cc);
void keccak512_4way(void *cc, const void *data, size_t len);
void keccak512_4way_close(void *cc, void *dst);
void keccak512_4way_addbits_and_close(
        void *cc, unsigned ub, unsigned n, void *dst);

#endif

#ifdef __cplusplus
}
#endif

#endif
