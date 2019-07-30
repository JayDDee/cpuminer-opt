#pragma once
#ifndef __BLAKE2B_HASH_4WAY_H__
#define __BLAKE2B_HASH_4WAY_H__

#if defined(__AVX2__)

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

// state context
ALIGN(64) typedef struct {
	__m256i b[16]; // input buffer
	__m256i h[8];  // chained state
	uint64_t t[2];  // total number of bytes
	size_t c;       // pointer for b[]
	size_t outlen;  // digest size
} blake2b_4way_ctx __attribute__((aligned(64)));

int blake2b_4way_init( blake2b_4way_ctx *ctx );
void blake2b_4way_update( blake2b_4way_ctx *ctx, const void *input,
                          size_t inlen );
void blake2b_4way_final( blake2b_4way_ctx *ctx, void *out );

#endif

#endif
