#ifndef X11EVO_GATE_H__
#define X11EVO_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X11EVO_4WAY
#endif

#define X11EVO_INITIAL_DATE 1462060800
#define X11EVO_FUNC_COUNT 11

extern int s_seq;

bool register_x11evo_algo( algo_gate_t* gate );

#if defined(X11EVO_4WAY)

void x11evo_4way_hash( void *state, const void *input );

int scanhash_x11evo_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

void init_x11evo_4way_ctx();

#endif

void x11evo_hash( void *state, const void *input );

int scanhash_x11evo( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

void init_x11evo_ctx();

void evo_twisted_code( uint32_t ntime, char *permstr );

#endif

