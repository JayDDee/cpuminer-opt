#include "blake-gate.h"
#include "blake-hash-4way.h"
#include <string.h>
#include <stdint.h>
#include <memory.h>

#if defined (BLAKE_4WAY)

blake256r14_4way_context blake_4w_ctx;

void blakehash_4way(void *state, const void *input)
{
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
     blake256r14_4way_context ctx;
     memcpy( &ctx, &blake_4w_ctx, sizeof ctx );
     blake256r14_4way_update( &ctx, input + (64<<2), 16 );
     blake256r14_4way_close( &ctx, vhash );
     dintrlv_4x32( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_blake_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t HTarget = ptarget[7];
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   uint32_t n = first_nonce;
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if (opt_benchmark)
      HTarget = 0x7f;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   blake256r14_4way_init( &blake_4w_ctx );
   blake256r14_4way_update( &blake_4w_ctx, vdata, 64 );

   do {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );

      blakehash_4way( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= HTarget )
      if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
      {
          pdata[19] = n+i;
          submit_solution( work, hash+(i<<3), mythr );
      }
      n += 4;

   } while ( (n < max_nonce) && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif

#if defined(BLAKE_8WAY)

blake256r14_8way_context blake_8w_ctx;

void blakehash_8way( void *state, const void *input )
{
     uint32_t vhash[8*8] __attribute__ ((aligned (64)));
     blake256r14_8way_context ctx;
     memcpy( &ctx, &blake_8w_ctx, sizeof ctx );
     blake256r14_8way( &ctx, input + (64<<3), 16 );
     blake256r14_8way_close( &ctx, vhash );
     _dintrlv_8x32( state,     state+ 32, state+ 64, state+ 96,
                    state+128, state+160, state+192, state+224,
                    vhash, 256 );
}

int scanhash_blake_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t hash[8*8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t HTarget = ptarget[7];
   uint32_t n = first_nonce;
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if (opt_benchmark)
      HTarget = 0x7f;

   mm256_bswap32_intrlv80_8x32( vdata, pdata );

   blake256r14_8way_init( &blake_8w_ctx );
   blake256r14_8way( &blake_8w_ctx, vdata, 64 );

   do {
      *noncev = mm256_bswap_32( _mm256_set_epi32( n+7, n+6, n+5, n+4,
                                                  n+3, n+2, n+1, n ) );
      pdata[19] = n;

      blakehash_8way( hash, vdata );

      for ( int i = 0; i < 8; i++ )
      if ( (hash+i)[7] <= HTarget && fulltest( hash+i, ptarget ) )
      {
          pdata[19] = n+i;
          submit_solution( work, hash+(i<<3), mythr );
      }
      n += 8;

   } while ( (n < max_nonce) !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
