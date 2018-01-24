#ifndef X13SM3_GATE_H__
#define X13SM3_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X13SM3_4WAY
#endif

bool register_x13sm3_algo( algo_gate_t* gate );

#if defined(X13SM3_4WAY)

void x13sm3_4way_hash( void *state, const void *input );

int scanhash_x13sm3_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

void init_x13sm3_4way_ctx();

#endif

void x13sm3_hash( void *state, const void *input );

int scanhash_x13sm3( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

void init_x13sm3_ctx();

#endif

