#ifndef XEVAN_GATE_H__
#define XEVAN_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define XEVAN_4WAY
#endif

bool register_xevan_algo( algo_gate_t* gate );

#if defined(XEVAN_4WAY)

void xevan_4way_hash( void *state, const void *input );

int scanhash_xevan_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

void init_xevan_4way_ctx();

#endif

void xevan_hash( void *state, const void *input );

int scanhash_xevan( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

void init_xevan_ctx();

#endif

