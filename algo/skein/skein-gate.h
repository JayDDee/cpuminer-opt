#ifndef __SKEIN_GATE_H__
#define __SKEIN_GATE_H__ 1
#include <stdint.h>
#include "algo-gate-api.h"

#if defined(SIMD512)
  #define SKEIN_8WAY 1
#elif defined(__AVX2__)
  #define SKEIN_4WAY 1
#elif defined(__SSE2__) || defined(__ARM_NEON)
  #define SKEIN_2WAY 1
#endif

#if defined(SKEIN_8WAY)

void skeinhash_8way( void *output, const void *input );
int scanhash_skein_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

void skein2hash_8way( void *output, const void *input );
int scanhash_skein2_8way( struct work *work, uint32_t max_nonce,
                          uint64_t* hashes_done, struct thr_info *mythr );

#elif defined(SKEIN_4WAY)

void skeinhash_4way( void *output, const void *input );
int scanhash_skein_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

void skein2hash_4way( void *output, const void *input );
int scanhash_skein2_4way( struct work *work, uint32_t max_nonce,
                          uint64_t* hashes_done, struct thr_info *mythr );

#elif defined(SKEIN_2WAY)

void skeinhash_2x64( void *output, const void *input );
int scanhash_skein_2x64( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

void skein2hash_2x64( void *output, const void *input );
int scanhash_skein2_2x64( struct work *work, uint32_t max_nonce,
                          uint64_t* hashes_done, struct thr_info *mythr );

#else

void skeinhash( void *output, const void *input );
int scanhash_skein( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

void skein2hash( void *output, const void *input );
int scanhash_skein2( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif
