#include "lyra2z-gate.h"

#ifdef LYRA2Z_4WAY

#include <memory.h>
#include <mm_malloc.h>
#include "lyra2.h"
#include "algo/blake/sph_blake.h"
#include "algo/blake/blake-hash-4way.h"

__thread uint64_t* lyra2z_4way_matrix;

bool lyra2z_4way_thread_init()
{
 return ( lyra2z_4way_matrix = _mm_malloc( LYRA2Z_MATRIX_SIZE, 64 ) );
}

static __thread blake256_4way_context l2z_4way_blake_mid;

void lyra2z_4way_midstate( const void* input )
{
       blake256_4way_init( &l2z_4way_blake_mid );
       blake256_4way( &l2z_4way_blake_mid, input, 64 );
}

void lyra2z_4way_hash( void *state, const void *input )
{
     uint32_t hash0[8] __attribute__ ((aligned (64)));
     uint32_t hash1[8] __attribute__ ((aligned (64)));
     uint32_t hash2[8] __attribute__ ((aligned (64)));
     uint32_t hash3[8] __attribute__ ((aligned (64)));
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
     blake256_4way_context ctx_blake __attribute__ ((aligned (64)));

     memcpy( &ctx_blake, &l2z_4way_blake_mid, sizeof l2z_4way_blake_mid );
     blake256_4way( &ctx_blake, input + (64*4), 16 );
     blake256_4way_close( &ctx_blake, vhash );

     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 256 );

     LYRA2Z( lyra2z_4way_matrix, hash0, 32, hash0, 32, hash0, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash1, 32, hash1, 32, hash1, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash2, 32, hash2, 32, hash2, 32, 8, 8, 8 );
     LYRA2Z( lyra2z_4way_matrix, hash3, 32, hash3, 32, hash3, 32, 8, 8, 8 );

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_lyra2z_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;
   uint32_t *noncep0 = vdata + 76; // 19*4
   uint32_t *noncep1 = vdata + 77;
   uint32_t *noncep2 = vdata + 78;
   uint32_t *noncep3 = vdata + 79;

   if ( opt_benchmark )
      ptarget[7] = 0x0000ff;

   for ( int i=0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   lyra2z_4way_midstate( vdata );

   do {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep0, n   );
      be32enc( noncep1, n+1 );
      be32enc( noncep2, n+2 );
      be32enc( noncep3, n+3 );

      lyra2z_4way_hash( hash, vdata );
      pdata[19] = n;

      if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
      {
          found[0] = true;
          num_found++;
          nonces[0] = pdata[19] = n;
          work_set_target_ratio( work, hash );
      }
      if ( (hash+8)[7] <= Htarg && fulltest( hash+8, ptarget ) )
      {
          found[1] = true;
          num_found++;
          nonces[1] = n+1;
          work_set_target_ratio( work, hash+8 );
      }
      if ( (hash+16)[7] <= Htarg && fulltest( hash+16, ptarget ) )
      {
          found[2] = true;
          num_found++;
          nonces[2] = n+2;
          work_set_target_ratio( work, hash+16 );
      }
      if ( (hash+24)[7] <= Htarg && fulltest( hash+24, ptarget ) )
      {
          found[3] = true;
          num_found++;
          nonces[3] = n+3;
          work_set_target_ratio( work, hash+24 );
      }
      n += 4;
   } while ( (num_found == 0) && (n < max_nonce-4)
                   && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif

