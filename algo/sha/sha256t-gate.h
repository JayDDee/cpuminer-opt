#ifndef __SHA256T_GATE_H__
#define __SHA256T_GATE_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

#if defined(__SSE4_2__)
  #define SHA256T_4WAY
#endif
#if defined(__AVX2__)
  #define SHA256T_8WAY
#endif

bool register_blake2s_algo( algo_gate_t* gate );

#if defined(SHA256T_8WAY)

void sha256t_8way_hash( void *output, const void *input );
int scanhash_sha256t_8way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

#elif defined (SHA256T_4WAY)

void sha256t_4way_hash( void *output, const void *input );
int scanhash_sha256t_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
#else

void sha256t_hash( void *output, const void *input );
int scanhash_sha256t( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done );

#endif

#endif

