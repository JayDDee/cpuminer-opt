#ifndef RINHASH_GATE_H__
#define RINHASH_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

/* RinHash -- RinCoin (RIN) proof of work.
 *
 *   digest = SHA3-256( Argon2d( BLAKE3( header80 ) ) )
 *
 * Consensus, from rincoin src/crypto/rinhash.cpp: BLAKE3 over the serialized
 * 80-byte header, then Argon2d with pwd = that digest and a FIXED ASCII salt
 * "RinCoinSalt", then SHA3-256 (0x06 padding, not Keccak) of the 32-byte
 * Argon2d output. rincoin's primitives/block.cpp defines GetHash() and
 * GetPoWHash() both as RinHash, so a block hash is also its PoW hash.
 */

#define RINHASH_M_COST   64      /* KiB */
#define RINHASH_T_COST   2
#define RINHASH_LANES    1
#define RINHASH_SALT     "RinCoinSalt"

void rinhash_hash( void *state, const void *input );

int scanhash_rinhash( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

bool register_rinhash_algo( algo_gate_t *gate );

#endif // RINHASH_GATE_H__
