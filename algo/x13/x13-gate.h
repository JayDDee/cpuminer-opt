#ifndef X13_GATE_H__
#define X13_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X13_4WAY
#endif

bool register_x13_algo( algo_gate_t* gate );

#if defined(X13_4WAY)

void x13_4way_hash( void *state, const void *input );

int scanhash_x13_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

void init_x13_4way_ctx();

#endif

void x13hash( void *state, const void *input );

int scanhash_x13( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

void init_x13_ctx();

#endif

