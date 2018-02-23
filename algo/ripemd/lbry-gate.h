#ifndef LBRY_GATE_H__
#define LBRY_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// need sha512 2 way AVX x2 or 1 way scalar x4 to support 4way AVX.
#if defined(__AVX2__)
  #define LBRY_8WAY
#endif

#define LBRY_NTIME_INDEX 25
#define LBRY_NBITS_INDEX 26
#define LBRY_NONCE_INDEX 27
#define LBRY_WORK_DATA_SIZE 192
#define LBRY_WORK_CMP_SIZE 76  // same as default

bool register_lbry_algo( algo_gate_t* gate );

#if defined(LBRY_8WAY)

void lbry_8way_hash( void *state, const void *input );
int scanhash_lbry_8way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

#elif defined(LBRY_4WAY)

void lbry_4way_hash( void *state, const void *input );
int scanhash_lbry_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
#else

void lbry_hash( void *state, const void *input );
int scanhash_lbry( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );
#endif
#endif
