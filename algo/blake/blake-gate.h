#ifndef __BLAKE_GATE_H__
#define __BLAKE_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)
  #define BLAKE_4WAY
#endif

#if defined (BLAKE_4WAY)
void blakehash_4way(void *state, const void *input);
int scanhash_blake_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
#endif

void blakehash( void *state, const void *input );
int scanhash_blake( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done );

#endif
