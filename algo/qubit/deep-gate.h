#ifndef DEEP_GATE_H__
#define DEEP_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define DEEP_2WAY
#endif

bool register_deep_algo( algo_gate_t* gate );

#if defined(DEEP_2WAY)

void deep_2way_hash( void *state, const void *input );
int scanhash_deep_2way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_deep_2way_ctx();

#endif

void deep_hash( void *state, const void *input );
int scanhash_deep( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_deep_ctx();

#endif

