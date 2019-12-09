#ifndef PHI1612_GATE_H__
#define PHI1612_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define PHI1612_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define PHI1612_4WAY 1
#endif

bool register_phi1612_algo( algo_gate_t* gate );

#if defined(PHI1612_8WAY)

void phi1612_8way_hash( void *state, const void *input );
int scanhash_phi1612_8way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
void init_phi1612_8way_ctx();

#elif defined(PHI1612_4WAY)

void phi1612_4way_hash( void *state, const void *input );
int scanhash_phi1612_4way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
void init_phi1612_4way_ctx();

#else

void phi1612_hash( void *state, const void *input );
int scanhash_phi1612( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_phi1612_ctx();

#endif
#endif

