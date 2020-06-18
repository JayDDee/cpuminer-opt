#ifndef X17_GATE_H__
#define X17_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X17_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X17_4WAY 1
#endif

bool register_x17_algo( algo_gate_t* gate );

#if defined(X17_8WAY)

int x17_8way_hash( void *state, const void *input, int thr_id );

#elif defined(X17_4WAY)

int x17_4way_hash( void *state, const void *input, int thr_id );

#endif

int x17_hash( void *state, const void *input, int thr_id );

#endif

