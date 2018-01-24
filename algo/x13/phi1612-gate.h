#ifndef PHI1612_GATE_H__
#define PHI1612_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define PHI1612_4WAY
#endif

bool register_phi1612_algo( algo_gate_t* gate );

#if defined(PHI1612_4WAY)

void phi1612_4way_hash( void *state, const void *input );

int scanhash_phi1612_4way( int thr_id, struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done );

void init_phi1612_4way_ctx();

#endif

void phi1612_hash( void *state, const void *input );

int scanhash_phi1612( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_phi1612_ctx();

#endif

