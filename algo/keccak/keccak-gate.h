#ifndef __KECCAK_GATE_H__
#define __KECCAK_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)

void keccakhash_4way( void *state, const void *input );
int scanhash_keccak_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

#endif

void keccakhash( void *state, const void *input );
int scanhash_keccak( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

#endif
