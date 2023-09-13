#include "sha256d-4way.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha256-hash.h"
#include "sha-hash-4way.h"

static const uint32_t sha256_iv[8] __attribute__ ((aligned (32))) =
{
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

#if defined(SHA256D_SHA)

int scanhash_sha256d_sha( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t block0[16]   __attribute__ ((aligned (64)));
   uint32_t block1[16]   __attribute__ ((aligned (64)));
   uint32_t hash0[8]     __attribute__ ((aligned (32)));
   uint32_t hash1[8]     __attribute__ ((aligned (32)));
   uint32_t mstate[8]  __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m128i shuf_bswap32 =
           _mm_set_epi64x( 0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL );

   // hash first 64 bytes of data
   sha256_opt_transform_le( mstate, pdata, sha256_iv );

   do
   {
      // 1. final 16 bytes of data, with padding
      memcpy( block0, pdata + 16, 16 );
      memcpy( block1, pdata + 16, 16 );
      block0[ 3] = n;
      block1[ 3] = n+1;
      block0[ 4] = block1[ 4] = 0x80000000;
      memset( block0 + 5, 0, 40 );
      memset( block1 + 5, 0, 40 );
      block0[15] = block1[15] = 80*8; // bit count
      sha256_ni2way_transform_le( hash0, hash1, block0, block1,
                                  mstate, mstate );

      // 2. 32 byte hash from 1.
      memcpy( block0, hash0, 32 );
      memcpy( block1, hash1, 32 );
      block0[ 8] = block1[ 8] = 0x80000000;
      memset( block0 + 9, 0, 24 );
      memset( block1 + 9, 0, 24 );
      block0[15] = block1[15] = 32*8; // bit count
      sha256_ni2way_transform_le( hash0, hash1, block0, block1,
                                  sha256_iv, sha256_iv );

      if ( unlikely( bswap_32( hash0[7] ) <= ptarget[7] ) )
      {
          casti_m128i( hash0, 0 ) =
               _mm_shuffle_epi8( casti_m128i( hash0, 0 ), shuf_bswap32 );
          casti_m128i( hash0, 1 ) =
               _mm_shuffle_epi8( casti_m128i( hash0, 1 ), shuf_bswap32 );
          if ( likely( valid_hash( hash0, ptarget ) && !bench ) )
          {
             pdata[19] = n;
             submit_solution( work, hash0, mythr );
          }
      }

      if ( unlikely( bswap_32( hash1[7] ) <= ptarget[7] ) )
      {
         casti_m128i( hash1, 0 ) =
               _mm_shuffle_epi8( casti_m128i( hash1, 0 ), shuf_bswap32 );
         casti_m128i( hash1, 1 ) =
               _mm_shuffle_epi8( casti_m128i( hash1, 1 ), shuf_bswap32 );
         if ( likely( valid_hash( hash1, ptarget ) && !bench ) )
         {
            pdata[19] = n+1;
            submit_solution( work, hash1, mythr );
         }
      }
      n += 2;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

#if defined(SHA256D_16WAY)

int scanhash_sha256d_16way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m512i  hash32[8]    __attribute__ ((aligned (128)));
   __m512i  block[16]    __attribute__ ((aligned (64)));
   __m512i  buf[16]      __attribute__ ((aligned (64)));
   __m512i  mstate1[8]   __attribute__ ((aligned (64)));
   __m512i  mstate2[8]   __attribute__ ((aligned (64)));
   __m512i  istate[8]    __attribute__ ((aligned (64)));
   __m512i  mexp_pre[8]  __attribute__ ((aligned (64)));
   uint32_t phash[8]     __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t *hash32_d7 = (uint32_t*)&(hash32[7]);
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 16;
   const __m512i last_byte = _mm512_set1_epi32( 0x80000000 );
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const __m512i sixteen = _mm512_set1_epi32( 16 );
   const bool bench = opt_benchmark;
   const __m256i bswap_shuf = mm256_bcast_m128( _mm_set_epi64x(
                                0x0c0d0e0f08090a0b, 0x0405060700010203 ) );

   // prehash first block directly from pdata
   sha256_transform_le( phash, pdata, sha256_iv );

   // vectorize block 0 hash for second block
   mstate1[0] = _mm512_set1_epi32( phash[0] );
   mstate1[1] = _mm512_set1_epi32( phash[1] );
   mstate1[2] = _mm512_set1_epi32( phash[2] );
   mstate1[3] = _mm512_set1_epi32( phash[3] );
   mstate1[4] = _mm512_set1_epi32( phash[4] );
   mstate1[5] = _mm512_set1_epi32( phash[5] );
   mstate1[6] = _mm512_set1_epi32( phash[6] );
   mstate1[7] = _mm512_set1_epi32( phash[7] );

   // second message block data, with nonce & padding   
   buf[0] = _mm512_set1_epi32( pdata[16] );
   buf[1] = _mm512_set1_epi32( pdata[17] );
   buf[2] = _mm512_set1_epi32( pdata[18] );
   buf[3] = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+ 9, n+ 8,
                              n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n +1, n );
   buf[4] = last_byte;
   memset_zero_512( buf+5, 10 );
   buf[15] = _mm512_set1_epi32( 80*8 ); // bit count

   // partially pre-expand & prehash second message block, avoiding the nonces
   sha256_16way_prehash_3rounds( mstate2, mexp_pre, buf, mstate1 );

   // vectorize IV for 2nd & 3rd sha256
   istate[0] = _mm512_set1_epi32( sha256_iv[0] );
   istate[1] = _mm512_set1_epi32( sha256_iv[1] );
   istate[2] = _mm512_set1_epi32( sha256_iv[2] );
   istate[3] = _mm512_set1_epi32( sha256_iv[3] );
   istate[4] = _mm512_set1_epi32( sha256_iv[4] );
   istate[5] = _mm512_set1_epi32( sha256_iv[5] );
   istate[6] = _mm512_set1_epi32( sha256_iv[6] );
   istate[7] = _mm512_set1_epi32( sha256_iv[7] );

   // initialize padding for 2nd sha256
   block[ 8] = last_byte;
   memset_zero_512( block + 9, 6 );
   block[15] = _mm512_set1_epi32( 32*8 ); // bit count

   do
   {
      sha256_16way_final_rounds( block, buf, mstate1, mstate2, mexp_pre );

      if ( sha256_16way_transform_le_short( hash32, block, istate, ptarget ) )
      {
         for ( int lane = 0; lane < 16; lane++ )
         if ( bswap_32( hash32_d7[ lane ] ) <= targ32_d7 )
         {
            extr_lane_16x32( phash, hash32, lane, 256 );
            casti_m256i( phash, 0 ) =
                _mm256_shuffle_epi8( casti_m256i( phash, 0 ), bswap_shuf );
            if ( likely( valid_hash( phash, ptarget ) && !bench ) )
            {
               pdata[19] = n + lane;
               submit_solution( work, phash, mythr );
            }
         }
      }
      buf[3] = _mm512_add_epi32( buf[3], sixteen );
      n += 16;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}


/*
int scanhash_sha256d_16way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m512i  vdata[32]    __attribute__ ((aligned (128)));
   __m512i  block[16]    __attribute__ ((aligned (64)));
   __m512i  hash32[8]    __attribute__ ((aligned (64)));
   __m512i  initstate[8] __attribute__ ((aligned (64)));
   __m512i  midstate1[8] __attribute__ ((aligned (64)));
   __m512i  midstate2[8] __attribute__ ((aligned (64)));
   __m512i  mexp_pre[16] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash32_d7 =  (uint32_t*)&( hash32[7] );
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 16;
   uint32_t n = first_nonce;
   __m512i *noncev = vdata + 19;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m512i last_byte = _mm512_set1_epi32( 0x80000000 );
   const __m512i sixteen = _mm512_set1_epi32( 16 );

   for ( int i = 0; i < 19; i++ )
       vdata[i] = _mm512_set1_epi32( pdata[i] );

   *noncev = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+9, n+8,
                               n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );

   vdata[16+4] = last_byte;
   memset_zero_512( vdata+16 + 5, 10 );
   vdata[16+15] = _mm512_set1_epi32( 80*8 ); // bit count

   block[ 8] = last_byte;
   memset_zero_512( block + 9, 6 );
   block[15] = _mm512_set1_epi32( 32*8 ); // bit count
   
   // initialize state
   initstate[0] = _mm512_set1_epi64( 0x6A09E6676A09E667 );
   initstate[1] = _mm512_set1_epi64( 0xBB67AE85BB67AE85 );
   initstate[2] = _mm512_set1_epi64( 0x3C6EF3723C6EF372 );
   initstate[3] = _mm512_set1_epi64( 0xA54FF53AA54FF53A );
   initstate[4] = _mm512_set1_epi64( 0x510E527F510E527F );
   initstate[5] = _mm512_set1_epi64( 0x9B05688C9B05688C );
   initstate[6] = _mm512_set1_epi64( 0x1F83D9AB1F83D9AB );
   initstate[7] = _mm512_set1_epi64( 0x5BE0CD195BE0CD19 );

   sha256_16way_transform_le( midstate1, vdata, initstate );

   // Do 3 rounds on the first 12 bytes of the next block
   sha256_16way_prehash_3rounds( midstate2, mexp_pre, vdata+16, midstate1 );

   do
   {
      // 1. final 16 bytes of data, with padding
      sha256_16way_final_rounds( block, vdata+16, midstate1, midstate2,
                                 mexp_pre );

      // 2. 32 byte hash from 1.
      sha256_16way_transform_le( hash32, block, initstate );
      // byte swap final hash for testing
      mm512_block_bswap_32( hash32, hash32 );

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
      *noncev = _mm512_add_epi32( *noncev, sixteen );
      n += 16;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}
*/

#endif

#if defined(SHA256D_8WAY)

int scanhash_sha256d_8way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m256i  vdata[32]    __attribute__ ((aligned (64)));
   __m256i  block[16]    __attribute__ ((aligned (32)));
   __m256i  hash32[8]    __attribute__ ((aligned (32)));
   __m256i  initstate[8] __attribute__ ((aligned (32)));
   __m256i  midstate1[8] __attribute__ ((aligned (32)));
   __m256i  midstate2[8] __attribute__ ((aligned (32)));
   __m256i  mexp_pre[8]  __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 =  (uint32_t*)&( hash32[7] );
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   __m256i *noncev = vdata + 19;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m256i last_byte = _mm256_set1_epi32( 0x80000000 );
   const __m256i eight = _mm256_set1_epi32( 8 );

   for ( int i = 0; i < 19; i++ )
      vdata[i] = _mm256_set1_epi32( pdata[i] );

   *noncev = _mm256_set_epi32( n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );

   vdata[16+4] = last_byte;
   memset_zero_256( vdata+16 + 5, 10 );
   vdata[16+15] = _mm256_set1_epi32( 80*8 ); // bit count

   block[ 8] = last_byte;
   memset_zero_256( block + 9, 6 );
   block[15] = _mm256_set1_epi32( 32*8 ); // bit count
   
   // initialize state
   initstate[0] = _mm256_set1_epi64x( 0x6A09E6676A09E667 );
   initstate[1] = _mm256_set1_epi64x( 0xBB67AE85BB67AE85 );
   initstate[2] = _mm256_set1_epi64x( 0x3C6EF3723C6EF372 );
   initstate[3] = _mm256_set1_epi64x( 0xA54FF53AA54FF53A );
   initstate[4] = _mm256_set1_epi64x( 0x510E527F510E527F );
   initstate[5] = _mm256_set1_epi64x( 0x9B05688C9B05688C );
   initstate[6] = _mm256_set1_epi64x( 0x1F83D9AB1F83D9AB );
   initstate[7] = _mm256_set1_epi64x( 0x5BE0CD195BE0CD19 );

   sha256_8way_transform_le( midstate1, vdata, initstate );
   
   // Do 3 rounds on the first 12 bytes of the next block
   sha256_8way_prehash_3rounds( midstate2, mexp_pre, vdata + 16, midstate1 );

   do
   {
      // 1. final 16 bytes of data, with padding
      sha256_8way_final_rounds( block, vdata+16, midstate1, midstate2,
                                mexp_pre );

      // 2. 32 byte hash from 1.
      sha256_8way_transform_le( hash32, block, initstate );
      // byte swap final hash for testing
      mm256_block_bswap_32( hash32, hash32 );

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
       *noncev = _mm256_add_epi32( *noncev, eight );
       n += 8;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

#if defined(SHA256D_4WAY)

int scanhash_sha256d_4way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m128i  vdata[32]     __attribute__ ((aligned (64)));
   __m128i  block[16]     __attribute__ ((aligned (32)));
   __m128i  hash32[8]     __attribute__ ((aligned (32)));
   __m128i  initstate[8]  __attribute__ ((aligned (32)));
   __m128i  midstate1[8]   __attribute__ ((aligned (32)));
   uint32_t lane_hash[8]  __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 =  (uint32_t*)&( hash32[7] );
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   __m128i *noncev = vdata + 19;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m128i last_byte = _mm_set1_epi32( 0x80000000 );
   const __m128i four = _mm_set1_epi32( 4 );

   for ( int i = 0; i < 19; i++ )
       vdata[i] = _mm_set1_epi32( pdata[i] );

   *noncev = _mm_set_epi32( n+ 3, n+ 2, n+1, n );

   vdata[16+4] = last_byte;
   memset_zero_128( vdata+16 + 5, 10 );
   vdata[16+15] = _mm_set1_epi32( 80*8 ); // bit count

   block[ 8] = last_byte;
   memset_zero_128( block + 9, 6 );
   block[15] = _mm_set1_epi32( 32*8 ); // bit count

   // initialize state
   initstate[0] = _mm_set1_epi64x( 0x6A09E6676A09E667 );
   initstate[1] = _mm_set1_epi64x( 0xBB67AE85BB67AE85 );
   initstate[2] = _mm_set1_epi64x( 0x3C6EF3723C6EF372 );
   initstate[3] = _mm_set1_epi64x( 0xA54FF53AA54FF53A );
   initstate[4] = _mm_set1_epi64x( 0x510E527F510E527F );
   initstate[5] = _mm_set1_epi64x( 0x9B05688C9B05688C );
   initstate[6] = _mm_set1_epi64x( 0x1F83D9AB1F83D9AB );
   initstate[7] = _mm_set1_epi64x( 0x5BE0CD195BE0CD19 );

   // hash first 64 bytes of data
   sha256_4way_transform_le( midstate1, vdata, initstate );

   do
   {
      // 1. final 16 bytes of data, with padding
      sha256_4way_transform_le( block, vdata+16, initstate );

      // 2. 32 byte hash from 1.
      sha256_4way_transform_le( hash32, block, initstate );
      // byte swap final hash for testing
      mm128_block_bswap_32( hash32, hash32 );

      for ( int lane = 0; lane < 4; lane++ )
      if ( unlikely( hash32_d7[ lane ] <= targ32_d7 ) )
      {
         extr_lane_4x32( lane_hash, hash32, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm_add_epi32( *noncev, four );
      n += 4;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
