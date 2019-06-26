#ifndef TIMETRAVEL_GATE_H__
#define TIMETRAVEL_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define TIMETRAVEL_4WAY
#endif

// Machinecoin Genesis Timestamp
#define TT8_FUNC_BASE_TIMESTAMP 1389040865

#define TT8_FUNC_COUNT 8
#define TT8_FUNC_COUNT_PERMUTATIONS 40320

void tt8_next_permutation( int *pbegin, int *pend );

bool register_timetravel_algo( algo_gate_t* gate );

#if defined(TIMETRAVEL_4WAY)

void timetravel_4way_hash( void *state, const void *input );

int scanhash_timetravel_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

void init_tt8_4way_ctx();

#endif

void timetravel_hash( void *state, const void *input );

int scanhash_timetravel( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

void init_tt8_ctx();

#endif

