#ifndef X22I_GATE_H__
#define X22I_GATE_H__ 1

#include "algo-gate-api.h"
#include "simd-utils.h"
#include <stdint.h>
#include <unistd.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X22I_4WAY
#endif

bool register_x22i__algo( algo_gate_t* gate );

#if defined(X22I_4WAY)

void x22i_4way_hash( void *state, const void *input );
int scanhash_x22i_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

void x25x_4way_hash( void *state, const void *input );
int scanhash_x25x_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#endif

void x22i_hash( void *state, const void *input );
int scanhash_x22i( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

void x25x_hash( void *state, const void *input );
int scanhash_x25x( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif  // X22I_GATE_H__
