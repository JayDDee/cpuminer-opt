#ifndef QUARK_GATE_H__
#define QUARK_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define QUARK_4WAY
#endif

bool register_quark_algo( algo_gate_t* gate );

#if defined(QUARK_4WAY)

void quark_4way_hash( void *state, const void *input );

int scanhash_quark_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

void init_quark_4way_ctx();

#endif

void quark_hash( void *state, const void *input );

int scanhash_quark( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_quark_ctx();

#endif

