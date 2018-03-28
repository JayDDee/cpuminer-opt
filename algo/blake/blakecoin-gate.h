#ifndef __BLAKECOIN_GATE_H__
#define __BLAKECOIN_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__SSE4_2__)
  #define BLAKECOIN_4WAY
#endif
#if defined(__AVX2__)
  #define BLAKECOIN_8WAY
#endif

#if defined (BLAKECOIN_8WAY)
void blakecoin_8way_hash(void *state, const void *input);
int scanhash_blakecoin_8way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
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
