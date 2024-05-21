#ifndef BLAKECOIN_GATE_H__
#define BLAKECOIN_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(SIMD512)
  #define BLAKECOIN_16WAY
#elif defined(__AVX2__)
  #define BLAKECOIN_8WAY
#elif defined(__SSE2__)  // always true
  #define BLAKECOIN_4WAY
#endif

#if defined (BLAKECOIN_16WAY)
int scanhash_blakecoin_16way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined (BLAKECOIN_8WAY)
//void blakecoin_8way_hash(void *state, const void *input);
int scanhash_blakecoin_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined (BLAKECOIN_4WAY)
void blakecoin_4way_hash(void *state, const void *input);
int scanhash_blakecoin_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
#else  // never used

void blakecoinhash( void *state, const void *input );
int scanhash_blakecoin( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif
