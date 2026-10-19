#include "megabtx-gate.h"
#include "timetravel10-gate.h"   // tt10_next_permutation

uint32_t mega_base_timestamp = MEGABTX_BASE_TIMESTAMP;
uint32_t mega_var_1          = MEGABTX_VAR_1;

/* Order derivation, mega-btx.h:74-103. Three groups permuted independently,
 * step counts from nTime, all arithmetic uint32_t and wrapping as upstream's
 * does. tt10_next_permutation() is timetravel10's -- same chain, and the same
 * std::next_permutation the reference calls.
 *
 * Group 1's permute range is [0,8) but only slots 1-7 are ever consumed. Not a
 * typo: upstream's Init1 starts at 1 and never writes slot 0, so slot 0 holds
 * the minimum and -- step count being mod 7! not 8! -- stays put while 1-7
 * cycle through every ordering of {1..7}. It must be 0 for that to hold;
 * megabtx-kat.h confirms it against real blocks. Narrowing the range to perm+1,
 * or planting anything else in slot 0, changes every digest.
 */
void mega_permutation_ex( int *perm, uint32_t ntime, uint32_t base_timestamp,
                          uint32_t var_1 )
{
   uint32_t i, steps;

   for ( i = 0; i < MEGA_SLOTS; i++ ) perm[i] = i;

   steps = ( ntime - base_timestamp ) % MEGA_PERMUTATIONS_7;
   for ( i = 0; i < steps; i++ )
      tt10_next_permutation( perm, perm + MEGA_FUNC_COUNT_1 );

   steps = ( ntime + var_1 - base_timestamp ) % MEGA_PERMUTATIONS_8;
   for ( i = 0; i < steps; i++ )
      tt10_next_permutation( perm + MEGA_FUNC_COUNT_1,
                             perm + MEGA_FUNC_COUNT_1 + MEGA_FUNC_COUNT_2 );

   steps = ( ntime + MEGA_VAR_2 - base_timestamp ) % MEGA_PERMUTATIONS_7;
   for ( i = 0; i < steps; i++ )
      tt10_next_permutation( perm + MEGA_FUNC_COUNT_1 + MEGA_FUNC_COUNT_2,
                             perm + MEGA_SLOTS );
}

void mega_permutation( int *perm, uint32_t ntime )
{
   mega_permutation_ex( perm, ntime, mega_base_timestamp, mega_var_1 );
}

static bool register_mega_common( algo_gate_t *gate )
{
#if defined(MEGABTX_4WAY)
   if ( !megabtx_4way_selftest() ) return false;
   gate->scanhash      = (void*)&scanhash_megabtx_4x64;
#else
   gate->scanhash      = (void*)&scanhash_megabtx;
#endif
   gate->hash          = (void*)&megabtx_hash;
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;

   /* No gen_merkle_root override: both chains are unmodified Bitcoin forks
    * here, and sha256d of every KAT header reproduces its published block id.
    *
    * opt_target_factor stays at the 1.0 default, measured rather than assumed:
    * displayed net_diff matches the explorer, and observed share diffs sit just
    * above the stratum diff. Note timetravel10 -- BitCore's previous algo, same
    * chain -- sets 256.0; the two disagree and this one is the measured side. */
   return true;
}

bool register_megabtx_algo( algo_gate_t *gate )
{
   mega_base_timestamp = MEGABTX_BASE_TIMESTAMP;
   mega_var_1          = MEGABTX_VAR_1;
   if ( !megabtx_kat() ) return false;
   return register_mega_common( gate );
}

bool register_megamec_algo( algo_gate_t *gate )
{
   mega_base_timestamp = MEGAMEC_BASE_TIMESTAMP;
   mega_var_1          = MEGAMEC_VAR_1;

   /* The KAT vectors are BTX blocks run with BTX constants explicitly, so they
    * still cover every line megamec shares with megabtx -- all of it but the
    * two constants set above. Those two have no offline test of their own (no
    * Megacoin explorer survives) and rest on pool acceptance. */
   if ( !megabtx_kat() ) return false;
   return register_mega_common( gate );
}
