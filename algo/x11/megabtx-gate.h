#ifndef MEGABTX_GATE_H__
#define MEGABTX_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

/* megabtx -- BitCore (BTX); megamec -- Megacoin (MEC).
 * Consensus: BitCore src/crypto/mega-btx.h @ ee07eac6, reached from
 * primitives/block.cpp GetPoWHash() as Mega_Btx( header80, nTime ) for blocks
 * at or after HASH_FORK_TIME_1 = 1598961600. Megacoin src/crypto/mega-mec.h
 * @ 53dca5fb is the same code with two constants changed, so megamec is a
 * second registration, not a second implementation.
 *
 * 23 slots. Slot 0 is blake512( header80 ); slots 1-22 each run one or two
 * 512-bit hashes over the previous slot's 64-byte output. The slots form three
 * independently permuted groups, so every case body runs exactly once per nonce
 * and only the order varies -- unlike x16r the cost per nonce is constant.
 * Order depends on nTime alone, so it is per-job state.
 */

#define MEGA_FUNC_COUNT_1        8
#define MEGA_FUNC_COUNT_2        8
#define MEGA_FUNC_COUNT_3        7
#define MEGA_SLOTS              23   // 8 + 8 + 7
#define MEGA_PERMUTATIONS_7   5040   // 7!
#define MEGA_PERMUTATIONS_8  40320   // 8!

#define MEGABTX_BASE_TIMESTAMP  1492973331U   // BitCore genesis
#define MEGAMEC_BASE_TIMESTAMP  1370079299U   // Megacoin block 1
#define MEGABTX_VAR_1                 3333U
#define MEGAMEC_VAR_1                 2100U
#define MEGA_VAR_2                    2100U   // same for both coins

/* 4x64 needs AVX2, plus AES for the per-lane groestl/echo/fugue fallbacks this
 * tree has no n-way kernel for. -DMEGABTX_FORCE_1WAY selects the scalar path
 * anyway, so both can be A/B'd in one binary with identical -march flags. */
#if defined(__AVX2__) && defined(__AES__) && !defined(MEGABTX_FORCE_1WAY)
  #define MEGABTX_4WAY 1
#endif

// Which coin's constants mega_permutation() uses. Set at registration.
extern uint32_t mega_base_timestamp;
extern uint32_t mega_var_1;

// Fill perm[MEGA_SLOTS] with the slot order for this nTime.
void mega_permutation_ex( int *perm, uint32_t ntime, uint32_t base_timestamp,
                          uint32_t var_1 );
void mega_permutation( int *perm, uint32_t ntime );

// The hash proper. perm[] must come from mega_permutation*().
void megabtx_hash_perm( void *output, const void *input, const int *perm );

int  megabtx_hash( void *output, const void *input, int thr_id );
int  scanhash_megabtx( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );

// Hard-fail startup self-test against real BTX blocks. See megabtx-kat.h.
bool megabtx_kat( void );

#if defined(MEGABTX_4WAY)
void megabtx_4x64_hash( void *state, const void *vinput, const int *perm );
int  scanhash_megabtx_4x64( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr );
// Differential check of the 4-way against the 1-way. Hard fail.
bool megabtx_4way_selftest( void );
#endif

bool register_megabtx_algo( algo_gate_t *gate );
bool register_megamec_algo( algo_gate_t *gate );

#endif
