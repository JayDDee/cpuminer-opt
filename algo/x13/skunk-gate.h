#ifndef SKUNK_GATE_H__
#define SKUNK_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)
  #define SKUNK_4WAY
#endif

bool register_skunk_algo( algo_gate_t* gate );

#if defined(SKUNK_4WAY)

void skunk_4way_hash( void *state, const void *input );

int scanhash_skunk_4way( int thr_id, struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done );

bool skunk_4way_thread_init();
//void init_skunk_4way_ctx();

#endif

void skunkhash( void *state, const void *input );

int scanhash_skunk( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );

bool skunk_thread_init();

#endif

