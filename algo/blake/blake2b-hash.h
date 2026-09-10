#pragma once
#ifndef BLAKE2B_HASH_4WAY_H__
#define BLAKE2B_HASH_4WAY_H__

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

#if defined(SIMD512)

typedef struct ALIGN( 64 ) {
   __m512i b[16]; // input buffer
   __m512i h[8];  // chained state
   uint64_t t[2];  // total number of bytes
   size_t c;       // pointer for b[]
   size_t outlen;  // digest size
} blake2b_8x64_ctx;

int blake2b_8x64_init( blake2b_8x64_ctx *ctx );
void blake2b_8x64_update( blake2b_8x64_ctx *ctx, const void *input,
                          size_t inlen );
void blake2b_8x64_final( blake2b_8x64_ctx *ctx, void *out );

// See the 4x64 pair below. digest_length other than 32, and a final emitting
// all 8 state words (64 B per lane, still interleaved).
int blake2b_8x64_init_len( blake2b_8x64_ctx *ctx, size_t outlen );
void blake2b_8x64_final_full( blake2b_8x64_ctx *ctx, void *out );

#endif

#if defined(__AVX2__)

// state context
typedef struct ALIGN( 64 ) {
	__m256i b[16]; // input buffer
	__m256i h[8];  // chained state
	uint64_t t[2];  // total number of bytes
	size_t c;       // pointer for b[]
	size_t outlen;  // digest size
} blake2b_4x64_ctx;

int blake2b_4x64_init( blake2b_4x64_ctx *ctx );
void blake2b_4x64_update( blake2b_4x64_ctx *ctx, const void *input,
                          size_t inlen );
void blake2b_4x64_final( blake2b_4x64_ctx *ctx, void *out );

// digest_length other than 32, and a final that emits all 8 state words
// (64 B per lane, still interleaved), as argon2's blake2b_long chain needs.
int blake2b_4x64_init_len( blake2b_4x64_ctx *ctx, size_t outlen );
void blake2b_4x64_final_full( blake2b_4x64_ctx *ctx, void *out );

#endif

#endif
