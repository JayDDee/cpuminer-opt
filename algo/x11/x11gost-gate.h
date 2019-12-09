#ifndef X11GOST_GATE_H__
#define X11GOST_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X11GOST_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X11GOST_4WAY 1
#endif

bool register_x11gost_algo( algo_gate_t* gate );

#if defined(X11GOST_8WAY)

void x11gost_8way_hash( void *state, const void *input );
int scanhash_x11gost_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_x11gost_8way_ctx();

#elif defined(X11GOST_4WAY)

void x11gost_4way_hash( void *state, const void *input );
int scanhash_x11gost_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
void init_x11gost_4way_ctx();

#else

void x11gost_hash( void *state, const void *input );
int scanhash_x11gost( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_x11gost_ctx();

#endif

#endif

