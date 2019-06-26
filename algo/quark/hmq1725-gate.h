#ifndef HMQ1725_GATE_H__
#define HMQ1725_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
//  #define HMQ1725_4WAY
#endif

bool register_hmq1725_algo( algo_gate_t* gate );

#if defined(HMQ1725_4WAY)

void hmq1725_4way_hash( void *state, const void *input );
int scanhash_hmq1725_4way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );

#else

void hmq1725hash( void *state, const void *input );
int scanhash_hmq1725( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );
void init_hmq1725_ctx();

#endif

#endif  // HMQ1725_GATE_H__
