#ifndef KECCAK_GATE_H__
#define KECCAK_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)
  #define KECCAK_4WAY
#endif

#if defined(KECCAK_4WAY)

void keccakhash_4way( void *state, const void *input );
int scanhash_keccak_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

#endif

void keccakhash( void *state, const void *input );
int scanhash_keccak( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

#endif
