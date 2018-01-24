#ifndef X15_GATE_H__
#define X15_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X15_4WAY
#endif

bool register_x15_algo( algo_gate_t* gate );

#if defined(X15_4WAY)

void x15_4way_hash( void *state, const void *input );

int scanhash_x15_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

void init_x15_4way_ctx();

#endif

void x15hash( void *state, const void *input );

int scanhash_x15( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

void init_x15_ctx();

#endif

