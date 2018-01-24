#ifndef X14_GATE_H__
#define X14_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X14_4WAY
#endif

bool register_x14_algo( algo_gate_t* gate );

#if defined(X14_4WAY)

void x14_4way_hash( void *state, const void *input );

int scanhash_x14_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

void init_x14_4way_ctx();

#endif

void x14hash( void *state, const void *input );

int scanhash_x14( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

void init_x14_ctx();

#endif

