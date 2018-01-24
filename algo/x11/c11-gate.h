#ifndef C11_GATE_H__
#define C11_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define C11_4WAY
#endif

bool register_c11_algo( algo_gate_t* gate );

#if defined(C11_4WAY)

void c11_4way_hash( void *state, const void *input );

int scanhash_c11_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

void init_c11_4way_ctx();

#endif

void c11_hash( void *state, const void *input );

int scanhash_c11( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_c11_ctx();

#endif

