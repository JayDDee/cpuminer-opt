/* Uses hardware AES/CLMUL; compiles to nothing without them so a plain -O3
 * build of the tree still works (same convention as algo/echo/aes_ni). */
#include "verus-simd.h"
#if defined(VERUS_HAVE_SIMD)

/*
* This uses veriations of the clhash algorithm for Verus Coin, licensed
* with the Apache-2.0 open source license.
*
* Copyright (c) 2018 Michael Toutonghi
* Distributed under the Apache 2.0 software license, available in the original form for clhash
* here: https://github.com/lemire/clhash/commit/934da700a2a54d8202929a826e2763831bd43cf7#diff-9879d6db96fd29134fc802214163b95a
*
* Original CLHash code and any portions herein, (C) 2017, 2018 Daniel Lemire and Owen Kaser
* Faster 64-bit universal hashing
* using carry-less multiplications, Journal of Cryptographic Engineering (to appear)
*
* Best used on recent x64 processors (Haswell or better).
*
* This implements an intermediate step in the last part of a Verus block hash. The intent of this step
* is to more effectively equalize FPGAs over GPUs and CPUs.
*
**/


#include "verus_clhash.h"


#include <assert.h>
#include <string.h>
//#include <intrin.h>
//#include "cpu_verushash.hpp"

#ifdef _WIN32
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif


// multiply the length and the some key, no modulo
__m128i lazyLengthHash(uint64_t keylength, uint64_t length) {
	const __m128i lengthvector = _mm_set_epi64x(keylength, length);
	const __m128i clprod1 = _mm_clmulepi64_si128(lengthvector, lengthvector, 0x10);
	return clprod1;
}

// modulo reduction to 64-bit value. The high 64 bits contain garbage, see precompReduction64
__m128i precompReduction64_si128(__m128i A) {

	//const __m128i C = _mm_set_epi64x(1U,(1U<<4)+(1U<<3)+(1U<<1)+(1U<<0)); // C is the irreducible poly. (64,4,3,1,0)
#if defined(VERUS_PMULL_EMULATED)
	/* by a 5-bit constant is a few shifts against ~55 ops for an emulated
	 * clmul. Identical result; see VRS_CLMUL_X1B. */
	const  __m128i Q2 = VRS_CLMUL_X1B(A);
#else
	const __m128i C = _mm_cvtsi64_si128((1U << 4) + (1U << 3) + (1U << 1) + (1U << 0));
	const  __m128i Q2 = _mm_clmulepi64_si128(A, C, 0x01);
#endif
	const __m128i Q3 = _mm_shuffle_epi8(_mm_setr_epi8(0, 27, 54, 45, 108, 119, 90, 65, (char)216, (char)195, (char)238, (char)245, (char)180, (char)175, (char)130, (char)153),
		_mm_srli_si128(Q2, 8));
	const __m128i Q4 = _mm_xor_si128(Q2, A);
	const __m128i final = _mm_xor_si128(Q3, Q4);
	return final;/// WARNING: HIGH 64 BITS CONTAIN GARBAGE
}

uint64_t precompReduction64(__m128i A) {
	return _mm_cvtsi128_si64(precompReduction64_si128(A));
}

__m128i __verusclmulwithoutreduction64alignedrepeatv2_2(__m128i *randomsource, const __m128i buf[4], uint64_t keyMask,
	uint32_t *fixrand, uint32_t *fixrandex, u128 *g_prand, u128 *g_prandex)
{
	const __m128i pbuf_copy[4] = { _mm_xor_si128(buf[0], buf[2]), _mm_xor_si128(buf[1], buf[3]), buf[2], buf[3] };

	// divide key mask by 16 from bytes to __m128i
	//keyMask >>= 4;

	// the random buffer must have at least 32 16 byte dwords after the keymask to work with this
	// algorithm. we take the value from the last element inside the keyMask + 2, as that will never
	// be used to xor into the accumulator before it is hashed with other values first
	__m128i acc = _mm_load_si128(randomsource + (keyMask + 2));

	for (int64_t i = 0; i < 32; i++)
	{
#     include "verus_clhash_iter.h"
	}

	return acc;
}

// hashes 64 bytes only by doing a carryless multiplication and reduction of the repeated 64 byte sequence 16 times, 
// returning a 64 bit hash value

uint64_t verusclhashv2_2(void * random, const unsigned char buf[64], uint64_t keyMask, uint32_t *fixrand, uint32_t *fixrandex,
	u128 *g_prand, u128 *g_prandex) {
	__m128i  acc = __verusclmulwithoutreduction64alignedrepeatv2_2((__m128i *)random, (const __m128i *)buf, 511, fixrand, fixrandex, g_prand, g_prandex);
	acc = _mm_xor_si128(acc, lazyLengthHash(1024, 64));


	return precompReduction64(acc);
}

#ifdef _WIN32

#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif
#endif /* VERUS_HAVE_SIMD */
