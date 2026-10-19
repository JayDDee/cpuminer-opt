#ifndef SKYDOGE_GATE_H__
#define SKYDOGE_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// SkyDoge width dispatch: AVX-512 -> 8x64 (8 nonces), AVX2 -> 4x64 (4 nonces),
// otherwise the scalar path.
#if defined(SIMD512)
  #define SKYDOGE_8WAY 1
#elif defined(__AVX2__)
  #define SKYDOGE_4WAY 1
#endif

bool register_skydoge_algo( algo_gate_t *gate );

// Scalar reference path (always compiled; also the consensus reference).
int  skydoge_hash( void *output, const void *input, int thr_id );
int  scanhash_skydoge( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );
bool skydoge_self_test( void );

// Consensus KAT (from a pool-accepted share), shared by both paths' self-tests.
extern const uint8_t skydoge_test_input[80];
extern const uint8_t skydoge_test_expected[32];

#if defined(SKYDOGE_8WAY)
int  skydoge_8x64_hash( void *output, const void *input, int thr_id );
int  scanhash_skydoge_8x64( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr );
bool skydoge_8way_self_test( void );
#elif defined(SKYDOGE_4WAY)
int  skydoge_4x64_hash( void *output, const void *input, int thr_id );
int  scanhash_skydoge_4x64( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr );
bool skydoge_4way_self_test( void );
#endif

#endif // SKYDOGE_GATE_H__
