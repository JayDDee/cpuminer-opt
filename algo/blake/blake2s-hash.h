/**
 * BLAKE2 reference source code package - reference C implementations
 *
 * Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
//#pragma once
#ifndef BLAKE2S_HASH_4WAY_H__
#define BLAKE2S_HASH_4WAY_H__ 1

#if defined(__SSE2__) || defined(__ARM_NEON)

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

typedef struct __blake2s_nway_param
{
   uint8_t  digest_length; // 1
   uint8_t  key_length;    // 2
   uint8_t  fanout;        // 3
   uint8_t  depth;         // 4
   uint32_t leaf_length;   // 8
   uint8_t  node_offset[6];// 14
   uint8_t  node_depth;    // 15
   uint8_t  inner_length;  // 16
   // uint8_t  reserved[0];
   uint8_t  salt[8]; // 24
   uint8_t  personal[8];  // 32
} blake2s_nway_param;

typedef struct ALIGN( 64 ) __blake2s_4way_state
{
   v128_t h[8];
   uint8_t  buf[ 64 * 4 ];
   uint32_t t[2];
   uint32_t f[2];
   size_t   buflen;
   uint8_t  last_node;
} blake2s_4way_state ;

int blake2s_4way_init( blake2s_4way_state *S, const uint8_t outlen );
int blake2s_4way_update( blake2s_4way_state *S, const void *in,
                         uint64_t inlen );
int blake2s_4way_final( blake2s_4way_state *S, void *out, uint8_t outlen );
int blake2s_4way_full_blocks( blake2s_4way_state *S, void *out,
                              const void *input, uint64_t inlen );

#define blake2s_4x32_state       blake2s_4way_state
#define blake2s_4x32_init        blake2s_4way_init
#define blake2s_4x32_update      blake2s_4way_update
#define blake2s_4x32_final       blake2s_4way_final
#define blake2s_4x32_full_blocks blake2s_4way_full_blocks

#if defined(__AVX2__)

typedef struct ALIGN( 64 ) __blake2s_8way_state
{
   __m256i h[8];
   uint8_t  buf[ 64 * 8 ];
   uint32_t t[2];
   uint32_t f[2];
   size_t   buflen;
   uint8_t  last_node;
} blake2s_8way_state ;

int blake2s_8way_init( blake2s_8way_state *S, const uint8_t outlen );
int blake2s_8way_update( blake2s_8way_state *S, const void *in,
                         uint64_t inlen );
int blake2s_8way_final( blake2s_8way_state *S, void *out, uint8_t outlen );
int blake2s_8way_full_blocks( blake2s_8way_state *S, void *out,
                              const void *input, uint64_t inlen );

#define blake2s_8x32_state       blake2s_8way_state
#define blake2s_8x32_init        blake2s_8way_init
#define blake2s_8x32_update      blake2s_8way_update
#define blake2s_8x32_final       blake2s_8way_final
#define blake2s_8x32_full_blocks blake2s_8way_full_blocks

#endif

#if defined(SIMD512)

typedef struct ALIGN( 64 ) __blake2s_16way_state
{
   __m512i h[8];
   uint8_t  buf[ 64 * 16 ];
   uint32_t t[2];
   uint32_t f[2];
   size_t   buflen;
   uint8_t  last_node;
} blake2s_16way_state ;

int blake2s_16way_init( blake2s_16way_state *S, const uint8_t outlen );
int blake2s_16way_update( blake2s_16way_state *S, const void *in,
                         uint64_t inlen );
int blake2s_16way_final( blake2s_16way_state *S, void *out, uint8_t outlen );

#define blake2s_16x32_state       blake2s_16way_state
#define blake2s_16x32_init        blake2s_16way_init
#define blake2s_16x32_update      blake2s_16way_update
#define blake2s_16x32_final       blake2s_16way_final

#endif

#if 0
	// Simple API
//	int blake2s( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen );

	// Direct Hash Mining Helpers
	#define blake2s_salt32(out, in, inlen, key32) blake2s(out, in, key32, 32, inlen, 32) /* neoscrypt */
	#define blake2s_simple(out, in, inlen) blake2s(out, in, NULL, 32, inlen, 0)
#endif

#endif  // __SSE2__

#endif
