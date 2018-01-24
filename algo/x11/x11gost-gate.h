#ifndef X11GOST_GATE_H__
#define X11GOST_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X11GOST_4WAY
#endif

bool register_x11gost_algo( algo_gate_t* gate );

#if defined(X11GOST_4WAY)

void x11gost_4way_hash( void *state, const void *input );

int scanhash_x11gost_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );

void init_x11gost_4way_ctx();

#endif

void x11gost_hash( void *state, const void *input );

int scanhash_x11gost( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

void init_x11gost_ctx();

#endif

