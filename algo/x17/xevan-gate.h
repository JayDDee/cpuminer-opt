#ifndef XEVAN_GATE_H__
#define XEVAN_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define XEVAN_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define XEVAN_4WAY 1
#endif

bool register_xevan_algo( algo_gate_t* gate );

#if defined(XEVAN_8WAY)

int xevan_8way_hash( void *state, const void *input, int thr_id );

#elif defined(XEVAN_4WAY)

int xevan_4way_hash( void *state, const void *input, int thr_id );

#else

int xevan_hash( void *state, const void *input, int trh_id );
void init_xevan_ctx();

#endif

#endif
