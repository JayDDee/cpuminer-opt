#ifndef XEVAN_GATE_H__
#define XEVAN_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define XEVAN_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define XEVAN_4WAY 1
#endif

bool register_xevan_algo( algo_gate_t* gate );

#if defined(XEVAN_8WAY)

int xevan_8way_hash( void *state, const void *input );
int scanhash_xevan_8way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
#elif defined(XEVAN_4WAY)

int xevan_4way_hash( void *state, const void *input );
int scanhash_xevan_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );

//void init_xevan_4way_ctx();

#else

int xevan_hash( void *state, const void *input, int trh_id );
void init_xevan_ctx();

#endif

#endif
