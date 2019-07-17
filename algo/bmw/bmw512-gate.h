#ifndef BMW512_GATE_H__
#define BMW512_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)
  #define BMW512_4WAY 1
#endif

#if defined(BMW512_4WAY)

void bmw512hash_4way( void *state, const void *input );
int scanhash_bmw512_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#endif

void bmw512hash( void *state, const void *input );
int scanhash_bmw512( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif
