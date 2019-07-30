#include "lbry-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/sha/sha-hash-4way.h"
#include "ripemd-hash-4way.h"

#define LBRY_INPUT_SIZE 112
#define LBRY_MIDSTATE    64
#define LBRY_TAIL (LBRY_INPUT_SIZE) - (LBRY_MIDSTATE)

#if defined(LBRY_8WAY)

static __thread sha256_8way_context sha256_8w_mid;

void lbry_8way_hash( void* output, const void* input )
{
   uint32_t _ALIGN(64) vhashA[16<<3];
   uint32_t _ALIGN(64) vhashB[16<<3];
   uint32_t _ALIGN(64) vhashC[16<<3];
   uint32_t _ALIGN(32) h0[32];
   uint32_t _ALIGN(32) h1[32];
   uint32_t _ALIGN(32) h2[32];
   uint32_t _ALIGN(32) h3[32];
   uint32_t _ALIGN(32) h4[32];
   uint32_t _ALIGN(32) h5[32];
   uint32_t _ALIGN(32) h6[32];
   uint32_t _ALIGN(32) h7[32];
   sha256_8way_context     ctx_sha256 __attribute__ ((aligned (64)));
   sha512_4way_context     ctx_sha512;
   ripemd160_8way_context  ctx_ripemd;

   memcpy( &ctx_sha256, &sha256_8w_mid, sizeof(ctx_sha256) );
   sha256_8way( &ctx_sha256, input + (LBRY_MIDSTATE<<3), LBRY_TAIL );
   sha256_8way_close( &ctx_sha256, vhashA );

   sha256_8way_init( &ctx_sha256 );
   sha256_8way( &ctx_sha256, vhashA, 32 );
   sha256_8way_close( &ctx_sha256, vhashA );

   // reinterleave to do sha512 4-way 64 bit twice.
   dintrlv_8x32( h0, h1, h2, h3, h4, h5, h6, h7, vhashA, 256 );
   intrlv_4x64( vhashA, h0, h1, h2, h3, 256 );
   intrlv_4x64( vhashB, h4, h5, h6, h7, 256 );

   sha512_4way_init( &ctx_sha512 );
   sha512_4way( &ctx_sha512, vhashA, 32 );
   sha512_4way_close( &ctx_sha512, vhashA );

   sha512_4way_init( &ctx_sha512 );
   sha512_4way( &ctx_sha512, vhashB, 32 );
   sha512_4way_close( &ctx_sha512, vhashB );

   // back to 8-way 32 bit
   dintrlv_4x64( h0, h1, h2, h3, vhashA, 512 );
   dintrlv_4x64( h4, h5, h6, h7, vhashB, 512 );
   intrlv_8x32( vhashA, h0, h1, h2, h3, h4, h5, h6, h7, 512 );

   ripemd160_8way_init( &ctx_ripemd );
   ripemd160_8way( &ctx_ripemd, vhashA, 32 );
   ripemd160_8way_close( &ctx_ripemd, vhashB );

   ripemd160_8way_init( &ctx_ripemd );
   ripemd160_8way( &ctx_ripemd, vhashA+(8<<3), 32 );
   ripemd160_8way_close( &ctx_ripemd, vhashC );

   sha256_8way_init( &ctx_sha256 );
   sha256_8way( &ctx_sha256, vhashB, 20 );
   sha256_8way( &ctx_sha256, vhashC, 20 );
   sha256_8way_close( &ctx_sha256, vhashA );

   sha256_8way_init( &ctx_sha256 );
   sha256_8way( &ctx_sha256, vhashA, 32 );
   sha256_8way_close( &ctx_sha256, output );
}

int scanhash_lbry_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (64)));
   uint32_t vdata[32*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<3]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[27];
   const uint32_t first_nonce = pdata[27];
   const uint32_t Htarg = ptarget[7];
   uint32_t edata[32] __attribute__ ((aligned (64)));
   __m256i  *noncev = (__m256i*)vdata + 27;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   uint64_t htmax[] = {          0,        0xF,       0xFF,
                             0xFFF,     0xFFFF, 0x10000000 };
   uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                        0xFFFFF000, 0xFFFF0000,          0 };

   // we need bigendian data...
   casti_m128i( edata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( edata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( edata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( edata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( edata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );
   casti_m128i( edata, 5 ) = mm128_bswap_32( casti_m128i( pdata, 5 ) );
   casti_m128i( edata, 6 ) = mm128_bswap_32( casti_m128i( pdata, 6 ) );
   casti_m128i( edata, 7 ) = mm128_bswap_32( casti_m128i( pdata, 7 ) );
   intrlv_8x32( vdata, edata, edata, edata, edata,
                             edata, edata, edata, edata, 1024 );
   sha256_8way_init( &sha256_8w_mid );
   sha256_8way( &sha256_8w_mid, vdata, LBRY_MIDSTATE );

   for ( int m = 0; m < sizeof(masks); m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do
      {
        *noncev = mm256_bswap_32( _mm256_set_epi32(
                                          n+7,n+6,n+5,n+4,n+3,n+2,n+1,n ) );
         lbry_8way_hash( hash, vdata );

         for ( int i = 0; i < 8; i++ )  if ( !( hash7[ i ] & mask ) )
         {
            // deinterleave hash for lane
            extr_lane_8x32( lane_hash, hash, i, 256 );
            if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
            {
              pdata[27] = n + i;
              submit_lane_solution( work, lane_hash, mythr, i );
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
