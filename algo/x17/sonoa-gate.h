#ifndef SONOA_GATE_H__
#define SONOA_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define SONOA_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define SONOA_4WAY 1
#endif

bool register_sonoa_algo( algo_gate_t* gate );

#if defined(SONOA_8WAY)

int sonoa_8way_hash( void *state, const void *input, int thr_id );

#elif defined(SONOA_4WAY)

int sonoa_4way_hash( void *state, const void *input, int thr_id );

#else

int sonoa_hash( void *state, const void *input, int thr_id );
void init_sonoa_ctx();

#endif

#endif
