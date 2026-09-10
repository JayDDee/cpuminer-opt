#ifndef CURVEHASH_GATE_H__
#define CURVEHASH_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

/* curvehash (Pulsar, PLSR) -- the only public-key PoW in this tree.
 *
 *   phash = SHA256( header80 )
 *   for round in 0..7:
 *       phash = SHA256( uncompressed_pubkey( phash ) )   // phash IS the privkey
 *
 * `input` is the 80-byte little-endian wire header, i.e. what v128_bswap32_80()
 * produces from work->data.
 *
 * Returns false on an invalid secret key (phash == 0 or >= n, ~2^-128): skip
 * that nonce, never submit a fabricated digest. */
bool curvehash_hash( void *output, const void *input );

/* CURVEHASH_LANES nonces in lockstep so their inversions batch. Bits of *active
 * mark live lanes on entry and are cleared for any lane whose scalar turned out
 * invalid; a cleared lane's digest is meaningless. */
void curvehash_hash_batch( unsigned char out[][32], const unsigned char in[][80],
                           int lanes, uint32_t *active );

/* NULL on success, else the name of the failed check. */
const char *curvehash_self_test( void );

int scanhash_curvehash( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

bool register_curvehash_algo( algo_gate_t *gate );

#endif
