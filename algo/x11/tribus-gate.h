#ifndef TRIBUS_GATE_H__
#define TRIBUS_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define TRIBUS_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define TRIBUS_4WAY 1
#endif

#if defined(TRIBUS_8WAY)

void tribus_hash_8way( void *state, const void *input );

int scanhash_tribus_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(TRIBUS_4WAY)

void tribus_hash_4way( void *state, const void *input );

int scanhash_tribus_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#else

void tribus_hash( void *state, const void *input );

int scanhash_tribus( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );

bool tribus_thread_init();

#endif

#endif
