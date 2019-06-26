#ifndef X17_GATE_H__
#define X17_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X17_4WAY
#endif

bool register_x17_algo( algo_gate_t* gate );

#if defined(X17_4WAY)

void x17_4way_hash( void *state, const void *input );
int scanhash_x17_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );

#endif

void x17_hash( void *state, const void *input );
int scanhash_x17( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );

#endif

