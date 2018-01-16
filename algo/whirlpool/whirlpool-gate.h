#ifndef WHIRLPOOL_GATE_H__
#define WHIRLPOOL_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

/*
#if defined(FOUR_WAY) && defined(__AVX2__)
  #define WHIRLPOOL_4WAY
#endif
*/

#if defined (WHIRLPOOL_4WAY) 

void whirlpool_hash_4way(void *state, const void *input);

int scanhash_whirlpool_4way( int thr_id, struct work *work, uint32_t max_nonce,
                              uint64_t *hashes_done );
#else

void whirlpool_hash( void *state, const void *input );

int scanhash_whirlpool( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done );
void init_whirlpool_ctx();
#endif

#endif
