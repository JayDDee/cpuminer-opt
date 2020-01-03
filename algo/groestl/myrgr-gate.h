#ifndef MYRGR_GATE_H__
#define MYRGR_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__VAES__) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define MYRGR_8WAY 1
#elif defined(__AVX2__) && defined(__AES__) && !defined(__SHA__)
  #define MYRGR_4WAY 1
#endif

#if defined(MYRGR_8WAY)

void myriad_8way_hash( void *state, const void *input );
int scanhash_myriad_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_myrgr_8way_ctx();

#elif defined(MYRGR_4WAY)

void myriad_4way_hash( void *state, const void *input );
int scanhash_myriad_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_myrgr_4way_ctx();

#else

void myriad_hash( void *state, const void *input );
int scanhash_myriad( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_myrgr_ctx();

#endif
#endif
