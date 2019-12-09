#ifndef SKUNK_GATE_H__
#define SKUNK_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define SKUNK_8WAY 1
#elif defined(__AVX2__)
  #define SKUNK_4WAY 1
#endif

bool register_skunk_algo( algo_gate_t* gate );

#if defined(SKUNK_8WAY)

void skunk_8way_hash( void *state, const void *input );
int scanhash_skunk_8way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
bool skunk_8way_thread_init();

#elif defined(SKUNK_4WAY)

void skunk_4way_hash( void *state, const void *input );
int scanhash_skunk_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
bool skunk_4way_thread_init();

#endif

void skunkhash( void *state, const void *input );
int scanhash_skunk( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );
bool skunk_thread_init();

#endif

