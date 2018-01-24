#ifndef TRIBUS_GATE_H__
#define TRIBUS_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define TRIBUS_4WAY
#endif

#if defined(TRIBUS_4WAY)

//void init_tribus_4way_ctx();

void tribus_hash_4way( void *state, const void *input );

int scanhash_tribus_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done );

#else

void tribus_hash( void *state, const void *input );

int scanhash_tribus( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done );

bool tribus_thread_init();

#endif

#endif
