#ifndef BMW512_GATE_H__
#define BMW512_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define BMW512_8WAY 1
#elif defined(__AVX2__)
  #define BMW512_4WAY 1
#endif

#if defined(BMW512_8WAY)

void bmw512hash_8way( void *state, const void *input );
int scanhash_bmw512_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(BMW512_4WAY)

void bmw512hash_4way( void *state, const void *input );
int scanhash_bmw512_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#else

void bmw512hash( void *state, const void *input );
int scanhash_bmw512( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif
