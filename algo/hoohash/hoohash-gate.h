#ifndef HOOHASH_GATE_H__
#define HOOHASH_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
#include <stdbool.h>

// HoohashV110 (PePePoW) — single 80-byte block-header PoW.
//
//   firstPass  = BLAKE3(header80)                       (nonce-dependent)
//   matrixSeed = BLAKE3(header80 with nNonce zeroed)    (nonce-independent)
//   mat[64][64]= xoshiro256**(matrixSeed) -> doubles
//   digest     = BLAKE3( firstPass ^ matrix*vector(firstPass, nonce) )
//
// The matrix multiply uses double-precision transcendentals (sin/cos/exp/sqrt)
// with a NaN/Inf rejection step, so hoohash.c MUST be compiled without
// -ffast-math / -Ofast (it pins -fno-fast-math via a pragma) or the digest
// diverges from consensus. Portable BLAKE3 only, matching upstream PePePoW.

#define HOOHASH_HASH_SIZE 32

// Hashes the 80-byte serialized header `input` into the 32-byte `output`.
int hoohashv110_hash( void *output, const void *input, int thr_id );

int scanhash_hoohashv110( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

bool register_hoohashv110_algo( algo_gate_t *gate );

bool hoohashv110_self_test( void );

#endif // HOOHASH_GATE_H__
