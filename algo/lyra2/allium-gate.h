#ifndef ALLIUM_GATE_H__
#define ALLIUM_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
#include "lyra2.h"

#if defined(__AVX2__) && defined(__AES__)
  #define ALLIUM_4WAY
#endif

bool register_allium_algo( algo_gate_t* gate );

#if defined(ALLIUM_4WAY)

void allium_4way_hash( void *state, const void *input );
int scanhash_allium_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done );
bool init_allium_4way_ctx();

#endif

void allium_hash( void *state, const void *input );
int scanhash_allium( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done );
bool init_allium_ctx();

#endif

