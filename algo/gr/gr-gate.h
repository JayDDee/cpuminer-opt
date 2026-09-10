#ifndef GR_GATE_H__
#define GR_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// Consensus GhostRider (Raptoreum) hash: 15 core rounds (x16 set minus SHA)
// interleaved with 3 of 6 CryptoNight-v1 variants, both orders derived from
// the block header. `output` receives 32 bytes.
void gr_hash( void *output, const void *input );

/* Shared with `mike` (algo/mike/mike-gate.c), which is GhostRider with an
 * 11-wide core pool. Exported rather than duplicated so there is one copy of
 * each consensus table.
 *
 * gr_get_algo_string() returns a permutation of 0..algoCount-1, walking the
 * nibbles of `mem` (low nibble of each byte first) and reducing each one
 * % algoCount. For mike that is % 11, which is NOT the first 11 entries of
 * the 15-permutation.
 *
 * Core table order (gr_do_core_algo): 0 blake, 1 bmw, 2 groestl, 3 jh,
 *   4 keccak, 5 skein, 6 luffa, 7 cubehash, 8 shavite, 9 simd, 10 echo,
 *   11 hamsi, 12 fugue, 13 shabal, 14 whirlpool.        (mike uses 0..10)
 * CN table order (gr_do_cn_algo): 0 dark, 1 darklite, 2 fast, 3 lite,
 *   4 turtle, 5 turtlelite.                             (mike uses all six)
 */
#define GR_CORE_ALGO_COUNT 15
#define GR_CN_ALGO_COUNT    6

void gr_get_algo_string( const void *mem, unsigned int size,
                         uint8_t *selectedAlgoOutput, int algoCount );
void gr_do_core_algo( uint8_t algo, const void *in, void *hash, int size );
void gr_do_cn_algo  ( uint8_t algo, const void *in, void *hash, int size );

// Known-answer self-test; returns true on success. Run once per process.
bool gr_self_test( void );

int scanhash_gr( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                 struct thr_info *mythr );

bool register_gr_algo( algo_gate_t *gate );

#endif /* GR_GATE_H__ */
