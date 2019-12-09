#ifndef C11_GATE_H__
#define C11_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define C11_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define C11_4WAY 1
#endif


bool register_c11_algo( algo_gate_t* gate );
#if defined(C11_8WAY)

void c11_8way_hash( void *state, const void *input );
int scanhash_c11_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_c11_8way_ctx();

#elif defined(C11_4WAY)

void c11_4way_hash( void *state, const void *input );
int scanhash_c11_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_c11_4way_ctx();

#else

void c11_hash( void *state, const void *input );
int scanhash_c11( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_c11_ctx();

#endif

#endif

