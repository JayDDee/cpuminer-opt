#include "lyra2h-gate.h"

#ifdef LYRA2H_4WAY

#include <memory.h>
#include <mm_malloc.h>
#include "lyra2.h"
#include "algo/blake/sph_blake.h"
#include "algo/blake/blake-hash-4way.h"

__thread uint64_t* lyra2h_4way_matrix;

bool lyra2h_4way_thread_init()
{
 return ( lyra2h_4way_matrix = _mm_malloc( LYRA2H_MATRIX_SIZE, 64 ) );
}

static __thread blake256_4way_context l2h_4way_blake_mid;

void lyra2h_4way_midstate( const void* input )
{
       blake256_4way_init( &l2h_4way_blake_mid );
       blake256_4way( &l2h_4way_blake_mid, input, 64 );
}

void lyra2h_4way_hash( void *state, const void *input )
{
     uint32_t hash0[8] __attribute__ ((aligned (64)));
     uint32_t hash1[8] __attribute__ ((aligned (64)));
     uint32_t hash2[8] __attribute__ ((aligned (64)));
     uint32_t hash3[8] __attribute__ ((aligned (64)));
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
     blake256_4way_context ctx_blake __attribute__ ((aligned (64)));

     memcpy( &ctx_blake, &l2h_4way_blake_mid, sizeof l2h_4way_blake_mid );
     blake256_4way( &ctx_blake, input + (64*4), 16 );
     blake256_4way_close( &ctx_blake, vhash );

     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 256 );

     LYRA2Z( lyra2h_4way_matrix, hash0, 32, hash0, 32, hash0, 32, 16, 16, 16 );
     LYRA2Z( lyra2h_4way_matrix, hash1, 32, hash1, 32, hash1, 32, 16, 16, 16 );
     LYRA2Z( lyra2h_4way_matrix, hash2, 32, hash2, 32, hash2, 32, 16, 16, 16 );
     LYRA2Z( lyra2h_4way_matrix, hash3, 32, hash3, 32, hash3, 32, 16, 16, 16 );

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_lyra2h_4way( int thr_id, struct work *work, uint32_t max_nonce,
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
   int num_found = 0;
   uint32_t *noncep= vdata + 76; // 19*4

   if ( opt_benchmark )
      ptarget[7] = 0x0000ff;

   for ( int i=0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   lyra2h_4way_midstate( vdata );

   do {
      be32enc( noncep,   n   );
      be32enc( noncep+1, n+1 );
      be32enc( noncep+2, n+2 );
      be32enc( noncep+3, n+3 );

      be32enc( &edata[19], n );
      lyra2h_4way_hash( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
      {
          pdata[19] = n+i;         
          nonces[ num_found++ ] = n+i;
          work_set_target_ratio( work, hash+(i<<3) );
      }
      n += 4;
   } while ( (num_found == 0) && (n < max_nonce-4)
                   && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif

