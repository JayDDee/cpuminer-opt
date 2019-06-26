#ifndef __NIST5_GATE_H__
#define __NIST5_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define NIST5_4WAY
#endif

#if defined(NIST5_4WAY)

void nist5hash_4way( void *state, const void *input );

int scanhash_nist5_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#else

void nist5hash( void *state, const void *input );

int scanhash_nist5( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_nist5_ctx();
#endif

#endif
