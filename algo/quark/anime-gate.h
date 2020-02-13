#ifndef ANIME_GATE_H__
#define ANIME_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define ANIME_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define ANIME_4WAY 1
#endif

bool register_anime_algo( algo_gate_t* gate );

#if defined(ANIME_8WAY)

void anime_8way_hash( void *state, const void *input );
int scanhash_anime_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(ANIME_4WAY)

void anime_4way_hash( void *state, const void *input );
int scanhash_anime_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#endif

void anime_hash( void *state, const void *input );
int scanhash_anime( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_anime_ctx();

#endif

