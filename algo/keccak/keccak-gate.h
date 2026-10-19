#ifndef KECCAK_GATE_H__
#define KECCAK_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

#if defined(SIMD512)
  #define KECCAK_8WAY 1
#elif defined(__AVX2__)
  #define KECCAK_4WAY 1
#elif defined(__SSE2__) || defined(__ARM_NEON)
  #define KECCAK_2WAY 1
#endif

#if defined(SIMD512)
  #define SHA3D_8WAY 1
#elif defined(__AVX2__)
  #define SHA3D_4WAY 1
#elif defined(__SSE2__) || defined(__ARM_NEON)
  #define SHA3D_2WAY 1
#endif

// NOTE: Narrower NEON arm than the sha3d/keccak ladders above, deliberately.
// Without the ARMv8.2 SHA3 extension the 2x64 NEON path loses to scalar: NEON
// has no 64-bit rotate, so v128_rol64 is a shift plus SLI (destructive,
// 2-cycle, single-issue), while scalar folds a 1-cycle ROR into the XOR
// (EOR Xd,Xn,Xm,ROR #n). Measured on RK3588S: scalar +35% on in-order A55,
// +3% on A76, +12% device-wide. FEAT_SHA3 should swing it back (EOR3, BCAX),
// so gate on the extension, not on "is this ARM". x86 SSE2 keeps 2x64.
//
// -DSHA3T_FORCE_SCALAR selects the scalar path on any target, so its driver
// and differential stay testable on x86 (which always defines __SSE2__).
// Test hatch only, never a release flag.
#if defined(SHA3T_FORCE_SCALAR)
  // deliberately empty: no SHA3T_*WAY, so the ladders below fall to scalar
#elif defined(SIMD512)
  #define SHA3T_8WAY 1
#elif defined(__AVX2__)
  #define SHA3T_4WAY 1
#elif defined(__SSE2__)
  #define SHA3T_2WAY 1
#elif defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA3)
  #define SHA3T_2WAY 1
#endif

// SHA3T_NO_PREPAD selects between the two scalar drivers only, so on a batched
// build it does nothing. Say so rather than letting it pass silently.
#if defined(SHA3T_NO_PREPAD) && \
    ( defined(SHA3T_8WAY) || defined(SHA3T_4WAY) || defined(SHA3T_2WAY) )
  #warning "SHA3T_NO_PREPAD has no effect: a batched sha3t width was selected. Add -DSHA3T_FORCE_SCALAR to reach the scalar drivers."
#endif

extern int hard_coded_eb;

#if defined(KECCAK_8WAY)

void keccakhash_8way( void *state, const void *input );
int scanhash_keccak_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(KECCAK_4WAY)

void keccakhash_4way( void *state, const void *input );
int scanhash_keccak_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(KECCAK_2WAY)

void keccakhash_2x64( void *state, const void *input );
int scanhash_keccak_2x64( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#else

void keccakhash( void *state, const void *input );
int scanhash_keccak( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );

#endif

#if defined(SHA3D_8WAY)

void sha3d_hash_8way( void *state, const void *input );
int scanhash_sha3d_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(SHA3D_4WAY)

void sha3d_hash_4way( void *state, const void *input );
int scanhash_sha3d_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(SHA3D_2WAY)

void sha3d_hash_2x64( void *state, const void *input );
int scanhash_sha3d_2x64( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );

#else

void sha3d_hash( void *state, const void *input );
int scanhash_sha3d( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif

// sha3t: scalar hash and KAT anchor are always available; the batched
// self-tests use them as differential oracle.
void sha3t_hash( void *state, const void *input );
bool sha3t_kat_check( void );

#if defined(SHA3T_8WAY)

void sha3t_hash_8way( void *state, const void *input );
int scanhash_sha3t_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
bool sha3t_8way_self_test( void );

#elif defined(SHA3T_4WAY)

void sha3t_hash_4way( void *state, const void *input );
int scanhash_sha3t_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
bool sha3t_4way_self_test( void );

#elif defined(SHA3T_2WAY)

void sha3t_hash_2x64( void *state, const void *input );
int scanhash_sha3t_2x64( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr );
bool sha3t_2way_self_test( void );

#else

// Shipped scalar driver (pre-padded) and its differential against sha3t_hash.
void sha3t_hash_prepad( void *state, const void *input );
bool sha3t_1way_self_test( void );

// -DSHA3T_NO_PREPAD mines with the ctx chain instead: escape hatch, and the
// second arm for timing the two against each other. Not a second digest
// producer -- the self-test diffs both either way and logs which one mines.
#if defined(SHA3T_NO_PREPAD)
  #define SHA3T_SCALAR_HASH       sha3t_hash
  #define SHA3T_SCALAR_HASH_NAME  "ctx chain"
#else
  #define SHA3T_SCALAR_HASH       sha3t_hash_prepad
  #define SHA3T_SCALAR_HASH_NAME  "pre-padded"
#endif

int scanhash_sha3t( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif
#endif
