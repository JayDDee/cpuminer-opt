#ifndef QUBIT_GATE_H__
#define QUBIT_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define QUBIT_4WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define QUBIT_2WAY 1
#endif

bool register_qubit_algo( algo_gate_t* gate );

#if defined(QUBIT_4WAY)

void qubit_4way_hash( void *state, const void *input );
int scanhash_qubit_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_qubit_4way_ctx();

#elif defined(QUBIT_2WAY)

void qubit_2way_hash( void *state, const void *input );
int scanhash_qubit_2way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_qubit_2way_ctx();

#endif

void qubit_hash( void *state, const void *input );
int scanhash_qubit( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_qubit_ctx();

#endif

