#ifndef __DECRED_GATE_H__
#define __DECRED_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#define DECRED_NBITS_INDEX 29
#define DECRED_NTIME_INDEX 34
#define DECRED_NONCE_INDEX 35
#define DECRED_XNONCE_INDEX 36
#define DECRED_DATA_SIZE 192
#define DECRED_WORK_COMPARE_SIZE 140
#define DECRED_MIDSTATE_LEN 128

#if defined (__AVX2__) 
//void blakehash_84way(void *state, const void *input);
//int scanhash_blake_8way( struct work *work, uint32_t max_nonce,
//                         uint64_t *hashes_done );
#endif

#if defined(__SSE4_2__)
  #define DECRED_4WAY
#endif

#if defined (DECRED_4WAY)
void decred_hash_4way(void *state, const void *input);
int scanhash_decred_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );
#endif

void decred_hash( void *state, const void *input );
int scanhash_decred( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );

#endif

