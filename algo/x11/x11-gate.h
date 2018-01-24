#ifndef X11_GATE_H__
#define X11_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X11_4WAY
#endif

bool register_x11_algo( algo_gate_t* gate );

#if defined(X11_4WAY)

void x11_4way_hash( void *state, const void *input );

int scanhash_x11_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

void init_x11_4way_ctx();

#endif

void x11_hash( void *state, const void *input );

int scanhash_x11( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_x11_ctx();

#endif

