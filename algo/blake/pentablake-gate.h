#ifndef __PENTABLAKE_GATE_H__
#define __PENTABLAKE_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)
  #define PENTABLAKE_4WAY
#endif

#if defined(PENTABLAKE_4WAY)
void pentablakehash_4way( void *state, const void *input );
int scanhash_pentablake_4way( int thr_id, struct work *work,
                              uint32_t max_nonce, uint64_t *hashes_done );
#endif

void pentablakehash( void *state, const void *input );
int scanhash_pentablake( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
#endif

