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

#if defined(__SHA__)
//  #define X22I_8WAY_SHA 1
  #define X22I_4WAY_SHA 1
#endif

bool register_x22i_algo( algo_gate_t* gate );

#if defined(X22I_8WAY)

int x22i_8way_hash( void *state, const void *input, int thrid );
#if defined(X22I_8WAY_SHA)
int scanhash_x22i_8way_sha( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
#else
int scanhash_x22i_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
#endif

#elif defined(X22I_4WAY)

int x22i_4way_hash( void *state, const void *input, int thrid );
#if defined(X22I_4WAY_SHA)
int scanhash_x22i_4way_sha( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr );
#else
int scanhash_x22i_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
#endif

#else

int x22i_hash( void *state, const void *input, int thrid );
int scanhash_x22i( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X25X_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X25X_4WAY 1
#endif

#if defined(__SHA__)
//  #define X25X_8WAY_SHA 1
  #define X25X_4WAY_SHA 1
#endif

bool register_x25i_algo( algo_gate_t* gate );

#if defined(X25X_8WAY)

int x25x_8way_hash( void *state, const void *input, int thrid );
int scanhash_x25x_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(X25X_4WAY)

int x25x_4way_hash( void *state, const void *input, int thrid );
int scanhash_x25x_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

int x25x_hash( void *state, const void *input, int thrif );
int scanhash_x25x( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif  // X22I_GATE_H__
