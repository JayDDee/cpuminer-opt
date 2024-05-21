#ifndef __SHA256D_4WAY_H__
#define __SHA256D_4WAY_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

#if defined(SIMD512)
  #define SHA256D_16WAY 1
#elif defined(__SHA__)
  #define SHA256D_SHA 1
#elif defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)
  #define SHA256D_NEON_SHA2 1
#elif defined(__AVX2__)
  #define SHA256D_8WAY 1
#else
  #define SHA256D_4WAY 1
#endif

bool register_sha256d_algo( algo_gate_t* gate );

#if defined(SHA256D_16WAY)

int scanhash_sha256d_16way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256D_8WAY)

int scanhash_sha256d_8way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256D_4WAY)

int scanhash_sha256d_4way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256D_SHA)

int scanhash_sha256d_sha( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#endif

#if defined(SHA256D_NEON_SHA2)

int scanhash_sha256d_neon_sha2( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#endif

#endif

