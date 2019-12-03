#ifndef __BLAKE2B_GATE_H__
#define __BLAKE2B_GATE_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define BLAKE2B_8WAY
#elif defined(__AVX2__)
  #define BLAKE2B_4WAY
#endif

bool register_blake2b_algo( algo_gate_t* gate );

#if defined(BLAKE2B_8WAY)

//void blake2b_8way_hash( void *state, const void *input );
int scanhash_blake2b_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(BLAKE2B_4WAY)

void blake2b_4way_hash( void *state, const void *input );
int scanhash_blake2b_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
#else

void blake2b_hash( void *state, const void *input );
int scanhash_blake2b( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif
