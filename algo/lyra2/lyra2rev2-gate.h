#ifndef LYRA2REV2_GATE_H__
#define LYRA2REV2_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
#include "lyra2.h"

#if defined(__AVX2__)
  #define LYRA2REV2_4WAY
#endif

extern __thread uint64_t* l2v2_wholeMatrix;

bool register_lyra2rev2_algo( algo_gate_t* gate );

#if defined(LYRA2REV2_4WAY)

void lyra2rev2_4way_hash( void *state, const void *input );

int scanhash_lyra2rev2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

void init_lyra2rev2_4way_ctx();

#endif

void lyra2rev2_hash( void *state, const void *input );

int scanhash_lyra2rev2( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_lyra2rev2_ctx();

#endif

