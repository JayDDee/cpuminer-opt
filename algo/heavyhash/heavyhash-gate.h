#ifndef HEAVYHASH_GATE_H__
#define HEAVYHASH_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
#include <stdbool.h>

// HeavyHash (Optical Bitcoin / OBTC, Ursula / URSA) - 80-byte header PoW.
// SHA3-256, then a 64x64 4-bit matrix-vector product, then SHA3-256; the matrix
// comes from xoshiro256++ seeded with SHA3-256 of the prev block hash. See
// heavyhash.c for the full spec.

#define HEAVYHASH_HASH_SIZE 32

// xoshiro256++ state, seeded from the matrix seed as 4 little-endian uint64.
struct heavyhash_xoshiro_state { uint64_t s[4]; };

// Job-constant half: 64x64 matrix from header bytes 4..35, nonce-independent.
void heavyhash_matrix_gen( const void *header80, uint32_t matrix[64][64] );

// Nonce-dependent half. `output` is 32 bytes in the little-endian uint32 word
// order valid_hash expects, so no byte reversal is needed.
void heavyhash_core( const uint32_t matrix[64][64], const void *header80,
                     void *output );
void heavyhash_core_len( const uint32_t matrix[64][64], const void *data,
                         size_t len, void *output );

// Both halves over an 80-byte header. Reference/oracle path.
void heavyhash_hash( void *output, const void *input );

int scanhash_heavyhash( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

bool register_heavyhash_algo( algo_gate_t *gate );

bool heavyhash_self_test( void );

#endif // HEAVYHASH_GATE_H__
