#ifndef QUBIT_GATE_H__
#define QUBIT_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define QUBIT_2WAY
#endif

bool register_qubit_algo( algo_gate_t* gate );

#if defined(QUBIT_2WAY)

void qubit_2way_hash( void *state, const void *input );

int scanhash_qubit_2way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

void init_qubit_2way_ctx();

#endif

void qubit_hash( void *state, const void *input );

int scanhash_qubit( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_qubit_ctx();

#endif

