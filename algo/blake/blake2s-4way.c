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

   mm256_dintrlv_8x32( output,     output+ 32, output+ 64, output+ 96,
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
   uint32_t _ALIGN(64) edata[20];
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *noncep = vdata + 152;   // 19*8
   int thr_id = mythr->id;  // thr_id arg is deprecated

   swab32_array( edata, pdata, 20 );
   mm256_intrlv_8x32( vdata, edata, edata, edata, edata,
                                 edata, edata, edata, edata, 640 );
   blake2s_8way_init( &blake2s_8w_ctx, BLAKE2S_OUTBYTES );
   blake2s_8way_update( &blake2s_8w_ctx, vdata, 64 );

   do {
      be32enc( noncep,    n   );
      be32enc( noncep +1, n+1 );
      be32enc( noncep +2, n+2 );
      be32enc( noncep +3, n+3 );
      be32enc( noncep +4, n+4 );
      be32enc( noncep +5, n+5 );
      be32enc( noncep +6, n+6 );
      be32enc( noncep +7, n+7 );
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
   uint32_t _ALIGN(64) edata[20];
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *noncep = vdata + 76;   // 19*4
   int thr_id = mythr->id;  // thr_id arg is deprecated

   swab32_array( edata, pdata, 20 );
   mm128_intrlv_4x32( vdata, edata, edata, edata, edata, 640 );
   blake2s_4way_init( &blake2s_4w_ctx, BLAKE2S_OUTBYTES );
   blake2s_4way_update( &blake2s_4w_ctx, vdata, 64 );

   do {
      be32enc( noncep,    n   );
      be32enc( noncep +1, n+1 );
      be32enc( noncep +2, n+2 );
      be32enc( noncep +3, n+3 );
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
