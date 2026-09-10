#ifndef VERUS_GATE_H__
#define VERUS_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
#include <stdbool.h>

// VerusHash 2.2 (Verus Coin / PBaaS).
//
// Preimage is the serialised CBlockHeader: 140-byte header || CompactSize(1344)
// || 1344-byte solution = 1487 bytes, and 1487 = 46*32 + 15. Upstream sizes the
// solution so the total is always 15 (mod 32), which leaves exactly one partial
// Haraka512 block. So:
//
//   VerusHashHalf   46 x haraka512 over bytes 0..1471   ] job-constant,
//   GenNewCLKey     276 x haraka256 -> 8832-byte key    ] cached per job
//   ---- per nonce: only the last 15 bytes change --------------------------
//   Verus2hash      FillExtra, install 15-byte nonce, verusclhashv2_2 (32
//                   CLMUL/AES/MULHRS/idiv rounds mutating 2 key slots each),
//                   keyed haraka512 with round constants read from the mutated
//                   key at a data-dependent offset, then FixKey to undo the
//                   mutations from the journal.


#define VERUS_KEY_SIZE      8832   /* 1024*8 mutable + 40*16 haraka headroom */
#define VERUS_KEY_SIZE128    552   /* 8832/16 */
#define VERUS_SCRATCH_U128    64   /* 32 prand + 32 prandex save slots        */
#define VERUS_HEADER_SIZE    140
#define VERUS_BASE_SIZE      143   /* 140 header + 3-byte CompactSize          */
#define VERUS_SOLUTION_MAX  2048   /* buffer capacity, not a protocol constant */
#define VERUS_PREIMAGE_MAX  ( VERUS_BASE_SIZE + VERUS_SOLUTION_MAX )
#define VERUS_NONCE_SPACE     15   /* the last 15 bytes of the preimage        */

#define VERUS_SOLUTION_FIXED 1344  /* VRSC SOLUTION_SIZE (SOLUTION_SIZE_FIXED) */

/* opt_target_factor: Verus reports difficulty against powLimit = 2^256/17 while
 * nbits_to_diff() uses Bitcoin's diff-1, so every displayed diff is short by the
 * ratio of the two. Display only -- the share target comes verbatim from
 * mining.set_target. Calibration against block 4174000: docs/algorithms/verus.md. */
#define VRS_DIFF_SCALE  ( 281474976710656.0 / ( 17.0 * 65535.0 ) )  /* 2^48/(17*0xffff) */

/* The pool sends only descriptor + PBaaS headers + extra data (281 bytes on
 * pool.verus.io) and the miner zero-pads it. Two things pin the padded size:
 *
 *   1. base+solution must be 15 (mod 32), leaving exactly one partial Haraka
 *      block with 15 free bytes for the nonce -- upstream's
 *      GetRequiredSolutionSize() computes the SMALLEST such size (281 -> 320).
 *   2. But the mod-32 rule does not pin it: adding any multiple of 32 also
 *      satisfies it. The chain constant does. VRSC is SOLUTION_SIZE_FIXED at
 *      1344, and the pool rejects anything else outright:
 *        "Incorrect size of solution (646), expected 2694"   (646 = 3+320 hex,
 *                                                             2694 = 3+1344)
 *
 * So pad to the fixed size, falling back to the formula's minimum only for a
 * chain whose solution is larger than the fixed constant. */
static inline int verus_padded_solution_size( int received )
{
   if ( received <= VERUS_SOLUTION_FIXED ) return VERUS_SOLUTION_FIXED;
   return received + ( 47 - ( ( received + VERUS_BASE_SIZE ) % 32 ) );
}

/* Header word indices, shared with the equihash family (same 140-byte layout). */
#define VRS_NTIME_INDEX      25
#define VRS_NBITS_INDEX      26
/* std_get_new_work() and scanhash both write work->data[nonce_index], so it must
 * alias neither the pool's extranonce1 (data[27..28], same trap as
 * EQH_NONCE_INDEX in algo-gate-api.h) nor word 32, which PBaaS relocates into
 * nonceSpace[7..10] -- the write-back lands after nonceSpace is captured and the
 * submitted header would then contradict the submitted solution. Word 30 is read
 * by neither; it is also the reference's EQNONCE_OFFSET. */
#define VRS_NONCE_INDEX      30
#define VRS_NONCESPACE_INDEX 32    /* -> nonceSpace[7..10], never written */
#define VRS_WORK_CMP_SIZE   108    /* version+prevhash+merkle+reserved */

int  verushash_full( void *output, const void *preimage, int pre_len );
int  scanhash_verus( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );
bool register_verus_algo( algo_gate_t *gate );
bool verus_self_test( void );

#endif // VERUS_GATE_H__
