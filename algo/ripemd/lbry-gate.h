#ifndef LBRY_GATE_H__
#define LBRY_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define LBRY_16WAY 1
#elif defined(__AVX2__)
  #define LBRY_8WAY 1
#endif
/*
#if !defined(__SHA__)
 #if defined(__AVX2__)
  #define LBRY_8WAY
 #endif
#endif
*/

#define LBRY_NTIME_INDEX 25
#define LBRY_NBITS_INDEX 26
#define LBRY_NONCE_INDEX 27
#define LBRY_WORK_DATA_SIZE 192
#define LBRY_WORK_CMP_SIZE 76  // same as default

bool register_lbry_algo( algo_gate_t* gate );

#if defined(LBRY_16WAY)

void lbry_16way_hash( void *state, const void *input );
int scanhash_lbry_16way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
#elif defined(LBRY_8WAY)

void lbry_8way_hash( void *state, const void *input );
int scanhash_lbry_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(LBRY_4WAY)

void lbry_4way_hash( void *state, const void *input );
int scanhash_lbry_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

#else

void lbry_hash( void *state, const void *input );
int scanhash_lbry( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
#endif
#endif
