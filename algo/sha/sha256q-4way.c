#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha-hash-4way.h"

#if defined(SHA256T_16WAY)

static __thread sha256_16way_context sha256_ctx16 __attribute__ ((aligned (64)));

void sha256q_16way_hash( void* output, const void* input )
{
   uint32_t vhash[8*16] __attribute__ ((aligned (64)));
   sha256_16way_context ctx;
   memcpy( &ctx, &sha256_ctx16, sizeof ctx );

   sha256_16way_update( &ctx, input + (64<<4), 16 );
   sha256_16way_close( &ctx, vhash );

   sha256_16way_init( &ctx );
   sha256_16way_update( &ctx, vhash, 32 );
   sha256_16way_close( &ctx, vhash );

   sha256_16way_init( &ctx );
   sha256_16way_update( &ctx, vhash, 32 );
   sha256_16way_close( &ctx, vhash );

   sha256_16way_init( &ctx );
   sha256_16way_update( &ctx, vhash, 32 );
   sha256_16way_close( &ctx, output );
}

int scanhash_sha256q_16way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*16] __attribute__ ((aligned (64)));
   uint32_t hash32[8*16] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 = &(hash32[7<<4]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 16;
   uint32_t n = first_nonce;
   __m512i  *noncev = (__m512i*)vdata + 19;   // aligned
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   mm512_bswap32_intrlv80_16x32( vdata, pdata );
   *noncev = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+9, n+8,
                               n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );
   sha256_16way_init( &sha256_ctx16 );
   sha256_16way_update( &sha256_ctx16, vdata, 64 );

   do
   {
     pdata[19] = n;
     sha256q_16way_hash( hash32, vdata );
     for ( int lane = 0; lane < 16; lane++ )
     if ( unlikely( hash32_d7[ lane ] <= targ32_d7 ) )
     {
        extr_lane_16x32( lane_hash, hash32, lane, 256 );
        if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
        {
           pdata[19] = bswap_32( n + lane );
           submit_solution( work, lane_hash, mythr );
        }
      }
      *noncev = _mm512_add_epi32( *noncev, m512_const1_32( 16 ) );
      n += 16;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

#if defined(SHA256T_8WAY)

static __thread sha256_8way_context sha256_ctx8 __attribute__ ((aligned (64)));

void sha256q_8way_hash( void* output, const void* input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (64)));
   sha256_8way_context ctx;
   memcpy( &ctx, &sha256_ctx8, sizeof ctx );

   sha256_8way_update( &ctx, input + (64<<3), 16 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way_update( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way_update( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way_update( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, output );
}

int scanhash_sha256q_8way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*8]  __attribute__ ((aligned (64)));
   uint32_t hash32[8*8]    __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 = &(hash32[7<<3]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   *noncev = _mm256_set_epi32( n+7, n+6, n+5, n+4, n+3, n+2, n+1, n );
   sha256_8way_init( &sha256_ctx8 );
   sha256_8way_update( &sha256_ctx8, vdata, 64 );

   do
   {
     pdata[19] = n;
     sha256q_8way_hash( hash32, vdata );
     for ( int lane = 0; lane < 8; lane++ )
     if ( unlikely( hash32_d7[ lane ] <= targ32_d7 ) )
     {
        extr_lane_8x32( lane_hash, hash32, lane, 256 );
        if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
        {
           pdata[19] = bswap_32( n + lane );
           submit_solution( work, lane_hash, mythr );
        }
      }
      *noncev = _mm256_add_epi32( *noncev, m256_const1_32( 8 ) );
      n += 8;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
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

   sha256_4way_update( &ctx, input + (64<<2), 16 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way_update( &ctx, vhash, 32 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way_update( &ctx, vhash, 32 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way_update( &ctx, vhash, 32 );
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
   sha256_4way_update( &sha256_ctx4, vdata, 64 );

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
              submit_solution( work, lane_hash, mythr );
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

