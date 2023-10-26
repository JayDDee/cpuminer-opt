#ifndef X17_GATE_H__
#define X17_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X17_8WAY 1
//  #define X17_16X32 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X17_4WAY 1
  #define X17_8X32 1
#elif defined(__SSE2__) || defined(__ARM_NEON)
  #define X17_2X64 1
#endif

bool register_x17_algo( algo_gate_t* gate );

#if defined(X17_8WAY) || defined(X17_16X32)

int scanhash_x17_16x32( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );
#define scanhash_x17_16way scanhash_x17_16x32

//int x17_16way_hash( void *state, const void *input, int thr_id );

int scanhash_x17_8x64( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );
#define scanhash_x17_8way scanhash_x17_8x64

int x17_8x64_hash( void *state, const void *input, int thr_id );
#define x17_8way_hash     x17_8x64_hash

#elif defined(X17_4WAY)

int scanhash_x17_4x64( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );
#define scanhash_x17_4way scanhash_x17_4x64

int x17_4x64_hash( void *state, const void *input, int thr_id );
#define x17_4way_hash     x17_4x64_hash

#elif defined(X17_2X64)

int scanhash_x17_2x64( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );

int x17_2x64_hash( void *state, const void *input, int thr_id );

#endif

int x17_hash( void *state, const void *input, int thr_id );

#endif

