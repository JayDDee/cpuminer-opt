#ifndef GROESTL_GATE_H__
#define GROESTL_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__VAES__) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define GROESTL_4WAY_VAES 1
#endif

bool register_dmd_gr_algo( algo_gate_t* gate );

bool register_groestl_algo( algo_gate_t* gate );

#if defined(GROESTL_4WAY_VAES)

void groestl_4way_hash( void *state, const void *input );
int scanhash_groestl_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#else

void groestlhash( void *state, const void *input );
int scanhash_groestl( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );
void init_groestl_ctx();

#endif

#endif

