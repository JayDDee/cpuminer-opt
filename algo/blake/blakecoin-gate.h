#ifndef __BLAKECOIN_GATE_H__
#define __BLAKECOIN_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)
  #define BLAKECOIN_4WAY
#endif

#if defined (BLAKECOIN_4WAY)
void blakecoin_4way_hash(void *state, const void *input);
int scanhash_blakecoin_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
#endif

void blakecoinhash( void *state, const void *input );
int scanhash_blakecoin( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done );

#endif
