#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha-hash-4way.h"

#if defined(SHA256T_11WAY)

static __thread sha256_11way_context sha256_ctx11 __attribute__ ((aligned (64)));

void sha256t_11way_hash( void *outx, void *outy, void *outz, const void *inpx,
	                 const void *inpy, const void*inpz )
{
   uint32_t hashx[8*8] __attribute__ ((aligned (64)));
   uint32_t hashy[8*2] __attribute__ ((aligned (64)));
   uint32_t hashz[8]   __attribute__ ((aligned (64)));
   sha256_11way_context ctx;
   const void *inpx64 = inpx+(64<<3);
   const void *inpy64 = inpy+(64<<1);
   const void *inpz64 = inpz+ 64;

   memcpy( &ctx, &sha256_ctx11, sizeof ctx );
   sha256_11way_update( &ctx, inpx64, inpy64, inpz64,  16 );
   sha256_11way_close( &ctx, hashx, hashy, hashz );

   sha256_11way_init( &ctx );
   sha256_11way_update( &ctx, hashx, hashy, hashz, 32 );
   sha256_11way_close( &ctx, hashx, hashy, hashz );

   sha256_11way_init( &ctx );
   sha256_11way_update( &ctx, hashx, hashy, hashz, 32 );
   sha256_11way_close( &ctx, outx, outy, outz );
}

int scanhash_sha256t_11way( struct work *work, uint32_t max_nonce,
	                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t datax[20*8]  __attribute__ ((aligned (64)));
   uint32_t datay[20*2]  __attribute__ ((aligned (32)));
   uint32_t dataz[20]    __attribute__ ((aligned (32)));
   uint32_t hashx[8*8]   __attribute__ ((aligned (32)));
   uint32_t hashy[8*2]   __attribute__ ((aligned (32)));
   uint32_t hashz[8]     __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7;
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m256i  *noncex = (__m256i*) datax + 19;
   __m64    *noncey = (__m64*)   datay + 19;
   uint32_t *noncez = (uint32_t*)dataz + 19;
   int thr_id = mythr->id;  // thr_id arg is deprecated
   int i;
   const uint64_t htmax[] = {           0,
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

   // Use dataz (scalar) to stage bswapped data for the vectors.
   casti_m256i( dataz, 0 ) = mm256_bswap_32( casti_m256i( pdata, 0 ) );
   casti_m256i( dataz, 1 ) = mm256_bswap_32( casti_m256i( pdata, 1 ) );
   casti_m128i( dataz, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

   intrlv_8x32( datax, dataz, dataz, dataz, dataz,
                                 dataz, dataz, dataz, dataz, 640 );
   mm64_interleave_2x32( datay, dataz, dataz, 640 );

   sha256_11way_init( &sha256_ctx11 );
   sha256_11way_update( &sha256_ctx11, datax, datay, dataz, 64 );

   for ( int m = 0; m < 6; m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do
      {
        *noncex = mm256_bswap_32(
         _mm256_set_epi32( n+7, n+6, n+5, n+4, n+3, n+2, n+1, n ) );
        *noncey = mm64_bswap_32( _mm_set_pi32( n+9, n+8 ) );
        *noncez = bswap_32( n+10 );

        pdata[19] = n;

        sha256t_11way_hash( hashx, hashy, hashz, datax, datay, dataz );

        if ( opt_benchmark ) { n += 11; continue; }

        hash7 = &(hashx[7<<3]); 
        for ( i = 0; i < 8; i++ ) if ( !( hash7[ i ] & mask ) )
        { 
            // deinterleave hash for lane
            extr_lane_8x32( lane_hash, hashx, i, 256 );
            if ( fulltest( lane_hash, ptarget ) )
            {
	            pdata[19] = n + i;
               submit_lane_solution( work, lane_hash, mythr, i );
            }
        }

        hash7 = &(hashy[7<<1]);
        for( i = 0; i < 2; i++ ) if ( !(hash7[ 0] & mask ) )
 
        {
            mm64_extr_lane_2x32( lane_hash, hashy, i, 256 );
           if ( fulltest( lane_hash, ptarget ) )
           {
               pdata[19] = n + 8 + i;
               submit_lane_solution( work, lane_hash, mythr, i+8 );
           }
	     }

        if ( !(hashz[7] & mask ) && fulltest( hashz, ptarget ) )
        {
            pdata[19] = n+10;
            submit_lane_solution( work, hashz, mythr, 10 );
        }
        n += 11;

      } while ( (n < max_nonce-12) && !work_restart[thr_id].restart );
      break;
   }
    
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif

#if defined(SHA256T_8WAY)

static __thread sha256_8way_context sha256_ctx8 __attribute__ ((aligned (64)));

void sha256t_8way_hash( void* output, const void* input )
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
   sha256_8way_close( &ctx, output );
}

int scanhash_sha256t_8way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*8]  __attribute__ ((aligned (64)));
   uint32_t hash[8*8]    __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<3]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   const int thr_id = mythr->id;

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
      const uint32_t mask = masks[m];
      do
      {
        *noncev = mm256_bswap_32( _mm256_set_epi32(
                                          n+7,n+6,n+5,n+4,n+3,n+2,n+1,n ) );
         pdata[19] = n;
         sha256t_8way_hash( hash, vdata );
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

void sha256t_4way_hash( void* output, const void* input )
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
   sha256_4way_close( &ctx, output );
}

int scanhash_sha256t_4way( struct work *work, const uint32_t max_nonce,
	                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   const int thr_id = mythr->id;

   const uint64_t htmax[] = {          0,
                                     0xF,
                                    0xFF,
                                   0xFFF,
                                  0xFFFF,
                              0x10000000 };
   const uint32_t masks[] = { 0xFFFFFFFF,
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
      const uint32_t mask = masks[m];
      do {
         *noncev = mm128_bswap_32( _mm_set_epi32( n+3,n+2,n+1,n ) );
         pdata[19] = n;

         sha256t_4way_hash( hash, vdata );

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

