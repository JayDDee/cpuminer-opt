#ifndef KECCAK_GATE_H__
#define KECCAK_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define KECCAK_8WAY 1
#elif defined(__AVX2__)
  #define KECCAK_4WAY 1
#endif

extern int hard_coded_eb;

#if defined(KECCAK_8WAY)

void keccakhash_8way( void *state, const void *input );
int scanhash_keccak_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

void sha3d_hash_8way( void *state, const void *input );
int scanhash_sha3d_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(KECCAK_4WAY)

void keccakhash_4way( void *state, const void *input );
int scanhash_keccak_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

void sha3d_hash_4way( void *state, const void *input );
int scanhash_sha3d_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#else

void keccakhash( void *state, const void *input );
int scanhash_keccak( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

void sha3d_hash( void *state, const void *input );
int scanhash_sha3d( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif
#endif
