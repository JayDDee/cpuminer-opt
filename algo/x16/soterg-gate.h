#ifndef SOTERG_GATE_H__
#define SOTERG_GATE_H__ 1

#include "algo-gate-api.h"
#include "simd-utils.h"
#include <stdint.h>

/* SoterG -- Soteria (SOTER) proof of work, PoW type 0 of a four-type chain.
 *
 * A 12-stage variable-order cascade. The order is derived from the block time
 * alone, so it is constant for every nonce in a job:
 *
 *   seed     = sha256d( (int32_t)( nTime & SOTERG_TIME_MASK ) )
 *   order[i] = rejection-sampled nibble of seed, i = 0..11
 *   h[0]     = f(order[0])( header80 );  h[i] = f(order[i])( h[i-1], 64 )
 *   powhash  = low 256 bits of h[11]
 *
 * Soteria selects its PoW function from version bits -- (nVersion >> 16) & 0xFF
 * over { soterg, soterc, soterhash, X8S } -- and gates changes on consensus
 * timestamps. This implements the soterg path, which is what live blocks use.
 */

#define SOTERG_FUNC_COUNT   12
#define SOTERG_TIME_MASK    0xFFFFFFA0u   /* 96-second bucket */

/* Stage ids. This order is consensus: it is the daemon's switch in
 * src/algo/soterg/soterg.h, and it is NOT the order of that file's includes. */
enum soterg_algo
{
   SOTERG_BLAKE = 0, SOTERG_SHABAL, SOTERG_GROESTL, SOTERG_JH,
   SOTERG_KECCAK,    SOTERG_SKEIN,  SOTERG_LUFFA,   SOTERG_CUBEHASH,
   SOTERG_SIMD,      SOTERG_ECHO,   SOTERG_HAMSI,   SOTERG_SHA512
};

void soterg_getAlgoString( uint32_t ntime, char *output );
void soterg_order_to_x16r_ids( const char *src, char *dst );
int  soterg_hash( void *output, const void *input, int thrid );

int scanhash_soterg( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );

/* The cascade is a subset of x16r's, so the interleaved widths reuse x16r's
 * chain via an id translation (soterg-4way.c). Guarded on X16R_* because those
 * are exactly the conditions under which the reused functions exist. */
int scanhash_soterg_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );
int scanhash_soterg_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );
int scanhash_soterg_2x64( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

bool register_soterg_algo( algo_gate_t *gate );

#endif // SOTERG_GATE_H__
