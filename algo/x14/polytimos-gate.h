#ifndef POLYTIMOS_GATE_H__
#define POLYTIMOS_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define POLYTIMOS_4WAY
#endif

bool register_polytimos_algo( algo_gate_t* gate );

#if defined(POLYTIMOS_4WAY)

void polytimos_4way_hash( void *state, const void *input );

int scanhash_polytimos_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

void init_polytimos_4way_ctx();

#endif

void polytimos_hash( void *state, const void *input );

int scanhash_polytimos( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

void init_polytimos_ctx();

#endif

