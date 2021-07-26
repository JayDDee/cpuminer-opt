#ifndef __BLAKE2S_GATE_H__
#define __BLAKE2S_GATE_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

#if defined(__SSE2__)
  #define BLAKE2S_4WAY
#endif

#if defined(__AVX2__)
  #define BLAKE2S_8WAY
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define BLAKE2S_16WAY
#endif

bool register_blake2s_algo( algo_gate_t* gate );

#if defined(BLAKE2S_16WAY)

void blake2s_16way_hash( void *state, const void *input );
int scanhash_blake2s_16way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined (BLAKE2S_8WAY)

void blake2s_8way_hash( void *state, const void *input );
int scanhash_blake2s_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined (BLAKE2S_4WAY)

void blake2s_4way_hash( void *state, const void *input );
int scanhash_blake2s_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
#else

void blake2s_hash( void *state, const void *input );
int scanhash_blake2s( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif
