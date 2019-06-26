#ifndef TIMETRAVEL10_GATE_H__
#define TIMETRAVEL10_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define TIMETRAVEL10_4WAY
#endif

// BitCore Genesis Timestamp
#define TT10_FUNC_BASE_TIMESTAMP 1492973331U
#define TT10_FUNC_COUNT 10
#define TT10_FUNC_COUNT_PERMUTATIONS 40320

void tt10_next_permutation( int *pbegin, int *pend );

bool register_timetravel10_algo( algo_gate_t* gate );

#if defined(TIMETRAVEL10_4WAY)

void timetravel10_4way_hash( void *state, const void *input );

int scanhash_timetravel10_4way( struct work *work,
           uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr );

void init_tt10_4way_ctx();

#endif

void timetravel10_hash( void *state, const void *input );

int scanhash_timetravel10( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

void init_tt10_ctx();

#endif

