#include "blake2s-gate.h"
#include "blake2s-hash-4way.h"
#include <string.h>
#include <stdint.h>

#if defined(BLAKE2S_8WAY)

static __thread blake2s_8way_state blake2s_8w_ctx;

void blake2s_8way_hash( void *output, const void *input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (64)));
   blake2s_8way_state ctx;
   memcpy( &ctx, &blake2s_8w_ctx, sizeof ctx );

   blake2s_8way_update( &ctx, input + (64<<3), 16 );
   blake2s_8way_final( &ctx, vhash, BLAKE2S_OUTBYTES );

   dintrlv_8x32( output,     output+ 32, output+ 64, output+ 96,
                 output+128, output+160, output+192, output+224,
                 vhash, 256 );
}

int scanhash_blake2s_8way( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t hash[8*8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   uint32_t n = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   blake2s_8way_init( &blake2s_8w_ctx, BLAKE2S_OUTBYTES );
   blake2s_8way_update( &blake2s_8w_ctx, vdata, 64 );

   do {
      *noncev = mm256_bswap_32( _mm256_set_epi32( n+7, n+6, n+5, n+4,
                                                  n+3, n+2, n+1, n ) );
      pdata[19] = n;

      blake2s_8way_hash( hash, vdata );


      for ( int i = 0; i < 8; i++ )
      if (  (hash+(i<<3))[7] <= Htarg )
      if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
      {
          pdata[19] = n+i;
          submit_lane_solution( work, hash+(i<<3), mythr, i );
      }
      n += 8;

   } while ( (n < max_nonce) && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#elif defined(BLAKE2S_4WAY)

static __thread blake2s_4way_state blake2s_4w_ctx;

void blake2s_4way_hash( void *output, const void *input )
{
   uint32_t vhash[8*4] __attribute__ ((aligned (64)));
   blake2s_4way_state ctx;
   memcpy( &ctx, &blake2s_4w_ctx, sizeof ctx );

   blake2s_4way_update( &ctx, input + (64<<2), 16 );
   blake2s_4way_final( &ctx, vhash, BLAKE2S_OUTBYTES );

   dintrlv_4x32( output, output+32, output+64, output+96,
		            vhash, 256 );
}

int scanhash_blake2s_4way( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   uint32_t n = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   blake2s_4way_init( &blake2s_4w_ctx, BLAKE2S_OUTBYTES );
   blake2s_4way_update( &blake2s_4w_ctx, vdata, 64 );

   do {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );
      pdata[19] = n;

      blake2s_4way_hash( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= Htarg )
      if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
      {
          pdata[19] = n+i;
          submit_lane_solution( work, hash+(i<<3), mythr, i );
      }
      n += 4;

   } while ( (n < max_nonce) && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
