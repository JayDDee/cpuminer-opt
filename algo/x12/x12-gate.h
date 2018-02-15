#ifndef X12_GATE_H__
#define X12_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X12_4WAY
#endif

bool register_x12_algo( algo_gate_t* gate );

#if defined(X12_4WAY)

void x12_4way_hash( void *state, const void *input );

int scanhash_x12_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

void init_x12_4way_ctx();

#endif

void x12hash( void *state, const void *input );

int scanhash_x12( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

void init_x12_ctx();

#endif

