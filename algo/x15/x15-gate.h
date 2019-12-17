#ifndef X15_GATE_H__
#define X15_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X15_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X15_4WAY 1
#endif


bool register_x15_algo( algo_gate_t* gate );

#if defined(X15_8WAY)

void x15_8way_hash( void *state, const void *input );
int scanhash_x15_8way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
void init_x15_8way_ctx();

#elif defined(X15_4WAY)

void x15_4way_hash( void *state, const void *input );
int scanhash_x15_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
void init_x15_4way_ctx();

#else

void x15hash( void *state, const void *input );
int scanhash_x15( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );
void init_x15_ctx();

#endif

#endif

