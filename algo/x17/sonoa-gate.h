#ifndef SONOA_GATE_H__
#define SONOA_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define SONOA_4WAY
#endif

bool register_sonoa_algo( algo_gate_t* gate );

#if defined(SONOA_4WAY)

void sonoa_4way_hash( void *state, const void *input );

int scanhash_sonoa_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

//void init_sonoa_4way_ctx();

#endif

void sonoa_hash( void *state, const void *input );

int scanhash_sonoa( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );

void init_sonoa_ctx();

#endif

