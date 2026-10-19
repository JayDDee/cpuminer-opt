#include "groestl-gate.h"
#include <string.h>
#include "groestl-kat.h"

void groestlhash( void *state, const void *input );
void init_groestl_ctx( void );

/* Hard gate: six headers whose digests a pool accepted (groestl-kat.h).
 * Registration fails rather than let a broken build mine rejects.
 *
 * Scope: this drives the 1-way groestlhash, compiled on every tier. On a VAES
 * build the shipped path is groestl_4way_hash, which this does not reach, nor
 * the merkle/header assembly. */
static bool groestl_selftest( void )
{
   uint8_t out[32];

   /* groestlhash() reads the global context, and the VAES arm of
    * register_dmd_gr_algo never initialises it -- do it here rather than
    * depend on call order. */
   init_groestl_ctx();

   for ( int i = 0; i < GROESTL_KAT_COUNT; i++ )
   {
      groestlhash( out, groestl_kat[i].header );
      if ( memcmp( out, groestl_kat[i].digest, 32 ) )
      {
         applog( LOG_ERR, "groestl: KAT vector %d does not match a "
                          "pool-accepted digest", i );
         return false;
      }
   }

   /* Non-vacuity: a broken compare must not read as a pass. */
   {
      uint8_t hdr[80] __attribute__ ((aligned (64)));
      memcpy( hdr, groestl_kat[0].header, 80 );
      hdr[79] ^= 0x01;
      groestlhash( out, hdr );
      if ( !memcmp( out, groestl_kat[0].digest, 32 ) )
      {
         applog( LOG_ERR, "groestl: KAT is vacuous -- a flipped nonce bit "
                          "produced the same digest" );
         return false;
      }
   }
   return true;
}


bool register_dmd_gr_algo( algo_gate_t *gate )
{
#if defined (GROESTL_4WAY_VAES)
  gate->scanhash  = (void*)&scanhash_groestl_4way;
  gate->hash      = (void*)&groestl_4way_hash;
#else
  init_groestl_ctx();
  gate->scanhash  = (void*)&scanhash_groestl;
  gate->hash      = (void*)&groestlhash;
#endif
  gate->optimizations = AES_OPT | VAES_OPT;
  return true;
};

bool register_groestl_algo( algo_gate_t* gate )
{
    register_dmd_gr_algo( gate );
    gate->gen_merkle_root = (void*)&sha256_gen_merkle_root;
    if ( !groestl_selftest() ) return false;
    /* The pool states groestl difficulty on a 256x scale: a stated difficulty of
     * 4 accepts shares of Bitcoin-scale difficulty 4/256. Without this the internal
     * target is 256x too strict and almost every creditable share is discarded.
     * Same value the lyra2 family uses. NOT applied to dmd-gr or myr-gr, which
     * were measured separately and are plain 1.0. */
    opt_target_factor = 256.0;
    return true;
};

