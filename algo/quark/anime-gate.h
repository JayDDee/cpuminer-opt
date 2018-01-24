#ifndef ANIME_GATE_H__
#define ANIME_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define ANIME_4WAY
#endif

bool register_anime_algo( algo_gate_t* gate );

#if defined(ANIME_4WAY)

void anime_4way_hash( void *state, const void *input );

int scanhash_anime_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

void init_anime_4way_ctx();

#endif

void anime_hash( void *state, const void *input );

int scanhash_anime( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_anime_ctx();

#endif

