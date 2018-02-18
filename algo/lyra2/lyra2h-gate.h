#ifndef LYRA2H_GATE_H__
#define LYRA2H_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__)
  #define LYRA2H_4WAY
#endif

#define LYRA2H_MATRIX_SIZE  BLOCK_LEN_INT64 * 16 * 16 * 8

#if defined(LYRA2H_4WAY)

void lyra2h_4way_hash( void *state, const void *input );

int scanhash_lyra2h_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

bool lyra2h_4way_thread_init();

#endif

void lyra2h_hash( void *state, const void *input );

int scanhash_lyra2h( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

bool lyra2h_thread_init();

#endif

