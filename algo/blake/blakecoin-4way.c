#include "blakecoin-gate.h"
#include "blake-hash-4way.h"
#include <string.h>
#include <stdint.h>
#include <memory.h>

#if defined (BLAKECOIN_4WAY)

blake256r8_4way_context blakecoin_4w_ctx;

void blakecoin_4way_hash(void *state, const void *input)
{
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
     blake256r8_4way_context ctx;

     memcpy( &ctx, &blakecoin_4w_ctx, sizeof ctx );
     blake256r8_4way( &ctx, input + (64<<2), 16 );
     blake256r8_4way_close( &ctx, vhash );

     mm_deinterleave_4x32( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_blakecoin_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t HTarget = ptarget[7];
   uint32_t _ALIGN(32) edata[20];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   if ( opt_benchmark )
      HTarget = 0x7f;

   swab32_array( edata, pdata, 20 );
   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );
   blake256r8_4way_init( &blakecoin_4w_ctx );
   blake256r8_4way( &blakecoin_4w_ctx, vdata, 64 );

   uint32_t *noncep = vdata + 76;   // 19*4
   do {
      be32enc( noncep,    n   );
      be32enc( noncep +1, n+1 );
      be32enc( noncep +2, n+2 );
      be32enc( noncep +3, n+3 );
      pdata[19] = n;
      blakecoin_4way_hash( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if (  (hash+(i<<3))[7] <= HTarget && fulltest( hash+(i<<3), ptarget ) )
      {
          pdata[19] = n+i;
          nonces[ num_found++ ] = n+i;
          work_set_target_ratio( work, hash+(i<<3) );
      }
      n += 4;

   } while ( (num_found == 0) && (n < max_nonce) 
             && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif

#if defined(BLAKECOIN_8WAY)

blake256r8_8way_context blakecoin_8w_ctx;

void blakecoin_8way_hash( void *state, const void *input )
{
     uint32_t vhash[8*8] __attribute__ ((aligned (64)));
     blake256r8_8way_context ctx;

     memcpy( &ctx, &blakecoin_8w_ctx, sizeof ctx );
     blake256r8_8way( &ctx, input + (64<<3), 16 );
     blake256r8_8way_close( &ctx, vhash );

     mm256_deinterleave_8x32( state,     state+ 32, state+ 64, state+ 96,
                              state+128, state+160, state+192, state+224,
                              vhash, 256 );
}

int scanhash_blakecoin_8way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done )
{
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t hash[8*8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t HTarget = ptarget[7];
   uint32_t _ALIGN(32) edata[20];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   uint32_t *noncep = vdata + 152;   // 19*8
   int num_found = 0;
   if ( opt_benchmark )
      HTarget = 0x7f;

   // we need big endian data...
   swab32_array( edata, pdata, 20 );
   mm256_interleave_8x32( vdata, edata, edata, edata, edata,
                                 edata, edata, edata, edata, 640 );
   blake256r8_8way_init( &blakecoin_8w_ctx );
   blake256r8_8way( &blakecoin_8w_ctx, vdata, 64 );

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
      blakecoin_8way_hash( hash, vdata );

      for ( int i = 0; i < 8; i++ )
      if (  (hash+(i<<3))[7] <= HTarget && fulltest( hash+(i<<3), ptarget ) )
      {
          pdata[19] = n+i;
          nonces[ num_found++ ] = n+i;
          work_set_target_ratio( work, hash+(i<<3) );
      }
      n += 8;
   } while ( (num_found == 0) && (n < max_nonce)
             && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif

