#pragma once
#ifndef __BLAKE2B_HASH_4WAY_H__
#define __BLAKE2B_HASH_4WAY_H__

#include "simd-utils.h"
#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#include <inttypes.h>
#define inline __inline
#define ALIGN(x) __declspec(align(x))
#else
#define ALIGN(x) __attribute__((aligned(x)))
#endif


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct ALIGN( 64 ) {
   __m512i b[16]; // input buffer
   __m512i h[8];  // chained state
   uint64_t t[2];  // total number of bytes
   size_t c;       // pointer for b[]
   size_t outlen;  // digest size
} blake2b_8way_ctx;

int blake2b_8way_init( blake2b_8way_ctx *ctx );
void blake2b_8way_update( blake2b_8way_ctx *ctx, const void *input,
                          size_t inlen );
void blake2b_8way_final( blake2b_8way_ctx *ctx, void *out );

#endif

#if defined(__AVX2__)

// state context
typedef struct ALIGN( 64 ) {
	__m256i b[16]; // input buffer
	__m256i h[8];  // chained state
	uint64_t t[2];  // total number of bytes
	size_t c;       // pointer for b[]
	size_t outlen;  // digest size
} blake2b_4way_ctx;

int blake2b_4way_init( blake2b_4way_ctx *ctx );
void blake2b_4way_update( blake2b_4way_ctx *ctx, const void *input,
                          size_t inlen );
void blake2b_4way_final( blake2b_4way_ctx *ctx, void *out );

#endif

#endif
