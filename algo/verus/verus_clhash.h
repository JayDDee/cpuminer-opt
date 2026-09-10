/*
 * This uses veriations of the clhash algorithm for Verus Coin, licensed
 * with the Apache-2.0 open source license.
 * 
 * Copyright (c) 2018 Michael Toutonghi
 * Distributed under the Apache 2.0 software license, available in the original form for clhash
 * here: https://github.com/lemire/clhash/commit/934da700a2a54d8202929a826e2763831bd43cf7#diff-9879d6db96fd29134fc802214163b95a
 * 
 * CLHash is a very fast hashing function that uses the
 * carry-less multiplication and SSE instructions.
 *
 * Original CLHash code (C) 2017, 2018 Daniel Lemire and Owen Kaser
 * Faster 64-bit universal hashing
 * using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
 *
 * Best used on recent x64 processors (Haswell or better).
 *
 **/

#ifndef INCLUDE_VERUS_CLHASH_H
#define INCLUDE_VERUS_CLHASH_H


//#include <intrin.h>

#include "verus-simd.h"   /* immintrin.h on x86, verus-neon.h on aarch64 */
#ifdef _WIN32
#include <intrin.h>
#endif


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>   /* EDIT: header uses bool/false; implicit in C++, not in C */
#include <stddef.h>
#include <assert.h>
//#include <boost/thread.hpp>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)

#endif
#include "haraka.h"
#include "haraka_portable.h"


uint64_t verusclhashv2_2(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *fixrand, uint32_t *fixrandex,
	u128 *g_prand, u128 *g_prandex);

/* in verus_clhash.c; declared for verus_clhash_2way.c */
__m128i  lazyLengthHash(uint64_t keylength, uint64_t length);
uint64_t precompReduction64(__m128i A);

/* two nonces interleaved; each lane needs its own mutable key and journal */
void verusclhash_2way(void *random0, const unsigned char buf0[64],
	void *random1, const unsigned char buf1[64], uint64_t keymask,
	uint32_t *fixrand0, uint32_t *fixrandex0, u128 *g_prand0, u128 *g_prandex0,
	uint32_t *fixrand1, uint32_t *fixrandex1, u128 *g_prand1, u128 *g_prandex1,
	uint64_t out[2]);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // INCLUDE_VERUS_CLHASH_H
