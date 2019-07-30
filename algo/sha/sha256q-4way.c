#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha-hash-4way.h"

#if defined(SHA256T_8WAY)

static __thread sha256_8way_context sha256_ctx8 __attribute__ ((aligned (64)));

void sha256q_8way_hash( void* output, const void* input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (64)));
   sha256_8way_context ctx;
   memcpy( &ctx, &sha256_ctx8, sizeof ctx );

   sha256_8way( &ctx, input + (64<<3), 16 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, output );
}

int scanhash_sha256q_8way( struct work *work, uint32_t max_nonce,
	                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t hash[8*8] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   const uint64_t htmax[] = {          0,
                                     0xF,
                                    0xFF,
                                   0xFFF,
                                  0xFFFF,
                              0x10000000 };
   const uint32_t masks[] = {  0xFFFFFFFF,
                               0xFFFFFFF0,
                               0xFFFFFF00,
                               0xFFFFF000,
                               0xFFFF0000,
                                        0 };

   // Need big endian data
   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   sha256_8way_init( &sha256_ctx8 );
   sha256_8way( &sha256_ctx8, vdata, 64 );

   for ( int m = 0; m < 6; m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do
      {
         *noncev = mm256_bswap_32(
		            _mm256_set_epi32( n+7, n+6, n+5, n+4, n+3, n+2, n+1, n ) );

	      pdata[19] = n;
         sha256q_8way_hash( hash, vdata );

         uint32_t *hash7 = &(hash[7<<3]); 
	 
         for ( int lane = 0; lane < 8; lane++ )
         if ( !( hash7[ lane ] & mask ) )
         { 
            // deinterleave hash for lane
	         extr_lane_8x32( lane_hash, hash, lane, 256 );

	         if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
            {
	           pdata[19] = n + lane;
              submit_lane_solution( work, lane_hash, mythr, lane );
            }
	      }
         n += 8;
      } while ( (n < max_nonce-10) && !work_restart[thr_id].restart );
      break;
   }
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif

#if defined(SHA256T_4WAY)

static __thread sha256_4way_context sha256_ctx4 __attribute__ ((aligned (64)));

void sha256q_4way_hash( void* output, const void* input )
{
   uint32_t vhash[8*4] __attribute__ ((aligned (64)));
   sha256_4way_context ctx;
   memcpy( &ctx, &sha256_ctx4, sizeof ctx );

   sha256_4way( &ctx, input + (64<<2), 16 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way( &ctx, vhash, 32 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way( &ctx, vhash, 32 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way( &ctx, vhash, 32 );
   sha256_4way_close( &ctx, output );
}

int scanhash_sha256q_4way( struct work *work, uint32_t max_nonce,
	                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   const uint64_t htmax[] = {          0,
                                     0xF,
                                    0xFF,
                                   0xFFF,
                                  0xFFFF,
                              0x10000000 };
   const uint32_t masks[] = {  0xFFFFFFFF,
                               0xFFFFFFF0,
                               0xFFFFFF00,
                               0xFFFFF000,
                               0xFFFF0000,
                                        0 };

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   sha256_4way_init( &sha256_ctx4 );
   sha256_4way( &sha256_ctx4, vdata, 64 );

   for ( int m = 0; m < 6; m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do {
         *noncev = mm128_bswap_32( _mm_set_epi32( n+3,n+2,n+1,n ) );
         pdata[19] = n;

         sha256q_4way_hash( hash, vdata );

         for ( int lane = 0; lane < 4; lane++ )
         if ( !( hash7[ lane ] & mask ) )
         {
            extr_lane_4x32( lane_hash, hash, lane, 256 );

            if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
            {
              pdata[19] = n + lane;
              submit_lane_solution( work, lane_hash, mythr, lane );
            }
         }
         n += 4;
      } while ( (n < max_nonce - 4) && !work_restart[thr_id].restart );
      break;
   }
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif

