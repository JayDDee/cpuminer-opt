#ifndef X22I_GATE_H__
#define X22I_GATE_H__ 1

#include "algo-gate-api.h"
#include "simd-utils.h"
#include <stdint.h>
#include <unistd.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X22I_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X22I_4WAY 1
#endif

bool register_x22i_algo( algo_gate_t* gate );

#if defined(X22I_8WAY)

void x22i_8way_hash( void *state, const void *input );
int scanhash_x22i_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(X22I_4WAY)

void x22i_4way_hash( void *state, const void *input );
int scanhash_x22i_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

void x22i_hash( void *state, const void *input );
int scanhash_x22i( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif


// Big problems with x25x 8 way. It blows up just by increasing the
// buffer sizes and nothing else. It may have to do with accessing 2 dim arrays.

//#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
//  #define X25X_8WAY 1
#if defined(__AVX2__) && defined(__AES__)
  #define X25X_4WAY 1
#endif

bool register_x25i_algo( algo_gate_t* gate );

#if defined(X25X_8WAY)

void x25x_8way_hash( void *state, const void *input );
int scanhash_x25x_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(X25X_4WAY)

void x25x_4way_hash( void *state, const void *input );
int scanhash_x25x_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

void x25x_hash( void *state, const void *input );
int scanhash_x25x( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif  // X22I_GATE_H__
