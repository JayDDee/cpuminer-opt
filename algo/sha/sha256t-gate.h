#ifndef __SHA256T_GATE_H__
#define __SHA256T_GATE_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

#if defined(SIMD512)
  #define SHA256T_16WAY 1
#elif defined(__SHA__)
  #define SHA256T_SHA 1
#elif defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)
  #define SHA256T_NEON_SHA2 1
#elif defined(__AVX2__)
  #define SHA256T_8WAY 1
#else
  #define SHA256T_4WAY 1
#endif

bool register_sha256t_algo( algo_gate_t* gate );
bool register_sha256q_algo( algo_gate_t* gate );

#if defined(SHA256T_16WAY)

int scanhash_sha256t_16way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
void sha256q_16way_hash( void *output, const void *input );
int scanhash_sha256q_16way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256T_8WAY)

int scanhash_sha256t_8way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
void sha256q_8way_hash( void *output, const void *input );
int scanhash_sha256q_8way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256T_4WAY)

int scanhash_sha256t_4way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
void sha256q_4way_hash( void *output, const void *input );
int scanhash_sha256q_4way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256T_SHA)

int scanhash_sha256t_sha( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

#endif

#if defined(SHA256T_NEON_SHA2)

int scanhash_sha256t_neon_sha2( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

#endif

int sha256t_hash( void *output, const void *input );
int scanhash_sha256t( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

int sha256q_hash( void *output, const void *input );
int scanhash_sha256q( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

#endif

