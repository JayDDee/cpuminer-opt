#ifndef NIST5_GATE_H__
#define NIST5_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define NIST5_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define NIST5_4WAY 1
#endif

#if defined(NIST5_8WAY)

void nist5hash_8way( void *state, const void *input );

int scanhash_nist5_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(NIST5_4WAY)

void nist5hash_4way( void *state, const void *input );

int scanhash_nist5_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#else

void nist5hash( void *state, const void *input );

int scanhash_nist5( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif
