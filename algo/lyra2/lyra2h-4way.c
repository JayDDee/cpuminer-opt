#include "lyra2-gate.h"

#ifdef LYRA2H_4WAY

#include <memory.h>
#include <mm_malloc.h>
#include "lyra2.h"
//#include "algo/blake/sph_blake.h"
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
       blake256_4way_update( &l2h_4way_blake_mid, input, 64 );
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
     blake256_4way_update( &ctx_blake, input + (64*4), 16 );
     blake256_4way_close( &ctx_blake, vhash );

     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 256 );

     LYRA2Z( lyra2h_4way_matrix, state, 32, hash0, 32, hash0, 32,
             16, 16, 16 );
     LYRA2Z( lyra2h_4way_matrix, state+32, 32, hash1, 32, hash1,
             32, 16, 16, 16 );
     LYRA2Z( lyra2h_4way_matrix, state+64, 32, hash2, 32, hash2,
             32, 16, 16, 16 );
     LYRA2Z( lyra2h_4way_matrix, state+96, 32, hash3, 32, hash3,
             32, 16, 16, 16 );
}

int scanhash_lyra2h_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ptarget[7] = 0x0000ff;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   lyra2h_4way_midstate( vdata );

   do {
     *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );
      lyra2h_4way_hash( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget )
           && !opt_benchmark )
      {
          pdata[19] = n+i;         
          submit_solution( work, hash+(i<<3), mythr );
      }
      n += 4;
   } while (  (n < max_nonce-4) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif

