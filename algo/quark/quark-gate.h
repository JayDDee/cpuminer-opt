#ifndef QUARK_GATE_H__
#define QUARK_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define QUARK_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define QUARK_4WAY 1
#endif

bool register_quark_algo( algo_gate_t* gate );

#if defined(QUARK_8WAY)

void quark_8way_hash( void *state, const void *input );
int scanhash_quark_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_quark_8way_ctx();

#elif defined(QUARK_4WAY)

void quark_4way_hash( void *state, const void *input );
int scanhash_quark_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_quark_4way_ctx();

#else

void quark_hash( void *state, const void *input );
int scanhash_quark( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif
#endif
