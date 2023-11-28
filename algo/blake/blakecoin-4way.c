#include "blakecoin-gate.h"
#include "blake256-hash.h"
#include <string.h>
#include <stdint.h>
#include <memory.h>

#define rounds 8

#if defined (BLAKECOIN_16WAY)

int scanhash_blakecoin_16way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8*16] __attribute__ ((aligned (64)));
   uint32_t midstate_vars[16*16] __attribute__ ((aligned (64)));
   __m512i block0_hash[8] __attribute__ ((aligned (64)));
   __m512i block_buf[16] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 =  (uint32_t*)&( ((__m512i*)hash32)[7] );
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   uint32_t phash[8] __attribute__ ((aligned (64))) =
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t n = pdata[19];
   const uint32_t first_nonce = (const uint32_t) n;
   const uint32_t last_nonce = max_nonce - 16;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m512i sixteen = v512_32( 16 );

   // Prehash first block
   blake256_transform_le( phash, pdata, 512, 0, rounds );

   block0_hash[0] = v512_32( phash[0] );
   block0_hash[1] = v512_32( phash[1] );
   block0_hash[2] = v512_32( phash[2] );
   block0_hash[3] = v512_32( phash[3] );
   block0_hash[4] = v512_32( phash[4] );
   block0_hash[5] = v512_32( phash[5] );
   block0_hash[6] = v512_32( phash[6] );
   block0_hash[7] = v512_32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[0] = v512_32( pdata[16] );
   block_buf[1] = v512_32( pdata[17] );
   block_buf[2] = v512_32( pdata[18] );
   block_buf[3] =
             _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+ 9, n+ 8,
                               n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n +1, n );

   // Partialy prehash second block without touching nonces in block_buf[3].
   blake256_16way_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
      blake256_16way_final_rounds_le( hash32, midstate_vars, block0_hash,
                                      block_buf, rounds );
      for ( int lane = 0; lane < 16; lane++ )
      if ( unlikely( hash32_d7[ lane ] <= targ32_d7 ) )
      {
         extr_lane_16x32( lane_hash, hash32, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      block_buf[3] = _mm512_add_epi32( block_buf[3], sixteen );
      n += 16;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (BLAKECOIN_8WAY)

int scanhash_blakecoin_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8*8] __attribute__ ((aligned (64)));
   uint32_t midstate_vars[16*8] __attribute__ ((aligned (32)));
   __m256i block0_hash[8] __attribute__ ((aligned (32)));
   __m256i block_buf[16] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 =  (uint32_t*)&( ((__m256i*)hash32)[7] );
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   uint32_t phash[8] __attribute__ ((aligned (32))) =
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t n = pdata[19];
   const uint32_t first_nonce = (const uint32_t) n;
   const uint32_t last_nonce = max_nonce - 8;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m256i eight = v256_32( 8 );

   // Prehash first block
   blake256_transform_le( phash, pdata, 512, 0, rounds );

   block0_hash[0] = v256_32( phash[0] );
   block0_hash[1] = v256_32( phash[1] );
   block0_hash[2] = v256_32( phash[2] );
   block0_hash[3] = v256_32( phash[3] );
   block0_hash[4] = v256_32( phash[4] );
   block0_hash[5] = v256_32( phash[5] );
   block0_hash[6] = v256_32( phash[6] );
   block0_hash[7] = v256_32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[0] = v256_32( pdata[16] );
   block_buf[1] = v256_32( pdata[17] );
   block_buf[2] = v256_32( pdata[18] );
   block_buf[3] = _mm256_set_epi32( n+7, n+6, n+5, n+4, n+3, n+2, n+1, n );

   // Partialy prehash second block without touching nonces in block_buf[3].
   blake256_8way_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
      blake256_8way_final_rounds_le( hash32, midstate_vars, block0_hash,
                                     block_buf, rounds );
      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( hash32_d7[ lane ] <= targ32_d7 ) )
      {
         extr_lane_8x32( lane_hash, hash32, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      block_buf[3] = _mm256_add_epi32( block_buf[3], eight );
      n += 8;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}
   
#elif defined (BLAKECOIN_4WAY)

blake256r8_4way_context blakecoin_4w_ctx;

void blakecoin_4way_hash(void *state, const void *input)
{
     uint32_t vhash[8*4] __attribute__ ((aligned (64)));
     blake256r8_4way_context ctx;

     memcpy( &ctx, &blakecoin_4w_ctx, sizeof ctx );
     blake256r8_4way_update( &ctx, input + (64<<2), 16 );
     blake256r8_4way_close( &ctx, vhash );

     dintrlv_4x32( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_blakecoin_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t HTarget = ptarget[7];
   uint32_t n = first_nonce;
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated
   if ( opt_benchmark )
      HTarget = 0x7f;

   v128_bswap32_intrlv80_4x32( vdata, pdata );
   blake256r8_4way_init( &blakecoin_4w_ctx );
   blake256r8_4way_update( &blakecoin_4w_ctx, vdata, 64 );

   do {
      *noncev = v128_bswap32( _mm_set_epi32( n+3, n+2, n+1, n ) );
      pdata[19] = n;
      blakecoin_4way_hash( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if (  (hash+(i<<3))[7] <= HTarget && fulltest( hash+(i<<3), ptarget )
           && !opt_benchmark )
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

