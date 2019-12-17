#ifndef X14_GATE_H__
#define X14_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X14_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X14_4WAY 1
#endif

bool register_x14_algo( algo_gate_t* gate );

#if defined(X14_8WAY)

void x14_8way_hash( void *state, const void *input );
int scanhash_x14_8way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
void init_x14_8way_ctx();

#elif defined(X14_4WAY)

void x14_4way_hash( void *state, const void *input );
int scanhash_x14_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
void init_x14_4way_ctx();

#else

void x14hash( void *state, const void *input );
int scanhash_x14( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );
void init_x14_ctx();

#endif

#endif
