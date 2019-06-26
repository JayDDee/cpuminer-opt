#ifndef VELTOR_GATE_H__
#define VELTOR_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define VELTOR_4WAY
#endif

bool register_veltor_algo( algo_gate_t* gate );

#if defined(VELTOR_4WAY)

void veltor_4way_hash( void *state, const void *input );

int scanhash_veltor_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );

void init_veltor_4way_ctx();

#endif

void veltor_hash( void *state, const void *input );

int scanhash_veltor( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );

void init_veltor_ctx();

#endif

