#ifndef __BLAKE2S_GATE_H__
#define __BLAKE2S_GATE_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

#if defined(__SSE4_2__)
  #define BLAKE2S_4WAY
#endif
#if defined(__AVX2__)
  #define BLAKE2S_8WAY
#endif

bool register_blake2s_algo( algo_gate_t* gate );

#if defined(BLAKE2S_8WAY)

void blake2s_8way_hash( void *state, const void *input );
int scanhash_blake2s_8way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

#elif defined (BLAKE2S_4WAY)

void blake2s_4way_hash( void *state, const void *input );
int scanhash_blake2s_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
#else

void blake2s_hash( void *state, const void *input );
int scanhash_blake2s( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done );

#endif

#endif
