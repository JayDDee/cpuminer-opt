#ifndef __SKEIN_GATE_H__
#define __SKEIN_GATE_H__
#include <stdint.h>
#include "algo-gate-api.h"

#if defined(__AVX2__)
  #define SKEIN_4WAY
#endif

#if defined(SKEIN_4WAY)

void skeinhash_4way( void *output, const void *input );

int scanhash_skein_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
#endif

void skeinhash( void *output, const void *input );

int scanhash_skein( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif
