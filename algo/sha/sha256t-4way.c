#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha-hash-4way.h"

#if defined(SHA256T_16WAY)

int scanhash_sha256t_16way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m512i  block[16]    __attribute__ ((aligned (64)));
   __m512i  hash32[8]    __attribute__ ((aligned (32)));
   __m512i  initstate[8] __attribute__ ((aligned (32)));
   __m512i  midstate[8]  __attribute__ ((aligned (32)));
   __m512i  midstate2[8] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   __m512i  vdata[20]    __attribute__ ((aligned (32)));
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
   const __m512i last_byte = m512_const1_32( 0x80000000 );
   const __m512i sixteen = m512_const1_32( 16 );

   for ( int i = 0; i < 19; i++ )
       vdata[i] = m512_const1_32( pdata[i] );

   *noncev = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+9, n+8,
                               n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );

   // initialize state
   initstate[0] = m512_const1_64( 0x6A09E6676A09E667 );
   initstate[1] = m512_const1_64( 0xBB67AE85BB67AE85 );
   initstate[2] = m512_const1_64( 0x3C6EF3723C6EF372 );
   initstate[3] = m512_const1_64( 0xA54FF53AA54FF53A );
   initstate[4] = m512_const1_64( 0x510E527F510E527F );
   initstate[5] = m512_const1_64( 0x9B05688C9B05688C );
   initstate[6] = m512_const1_64( 0x1F83D9AB1F83D9AB );
   initstate[7] = m512_const1_64( 0x5BE0CD195BE0CD19 );

   // hash first 64 byte block of data
   sha256_16way_transform_le( midstate, vdata, initstate );

   // Do 3 rounds on the first 12 bytes of the next block
   sha256_16way_prehash_3rounds( midstate2, vdata + 16, midstate );

   do
   {
      // 1. final 16 bytes of data, with padding
      memcpy_512( block, vdata + 16, 4 );
      block[ 4] = last_byte;
      memset_zero_512( block + 5, 10 );  
      block[15] = m512_const1_32( 80*8 ); // bit count
      sha256_16way_final_rounds( hash32, block, midstate, midstate2 );

      // 2. 32 byte hash from 1.
      memcpy_512( block, hash32, 8 );
      block[ 8] = last_byte;
      memset_zero_512( block + 9, 6 );
      block[15] = m512_const1_32( 32*8 ); // bit count
      sha256_16way_transform_le( hash32, block, initstate );

      // 3. 32 byte hash from 2.
      memcpy_512( block, hash32, 8 );
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


#endif

#if defined(SHA256T_8WAY)

int scanhash_sha256t_8way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m256i  block[16]    __attribute__ ((aligned (64)));
   __m256i  hash32[8]    __attribute__ ((aligned (32)));
   __m256i  initstate[8] __attribute__ ((aligned (32)));
   __m256i  midstate[8]  __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   __m256i  vdata[20]    __attribute__ ((aligned (32)));
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
   const __m256i last_byte = m256_const1_32( 0x80000000 );
   const __m256i eight = m256_const1_32( 8 );

   for ( int i = 0; i < 19; i++ )
       vdata[i] = m256_const1_32( pdata[i] );

   *noncev = _mm256_set_epi32( n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );

   // initialize state
   initstate[0] = m256_const1_64( 0x6A09E6676A09E667 );
   initstate[1] = m256_const1_64( 0xBB67AE85BB67AE85 );
   initstate[2] = m256_const1_64( 0x3C6EF3723C6EF372 );
   initstate[3] = m256_const1_64( 0xA54FF53AA54FF53A );
   initstate[4] = m256_const1_64( 0x510E527F510E527F );
   initstate[5] = m256_const1_64( 0x9B05688C9B05688C );
   initstate[6] = m256_const1_64( 0x1F83D9AB1F83D9AB );
   initstate[7] = m256_const1_64( 0x5BE0CD195BE0CD19 );

   // hash first 64 bytes of data
   sha256_8way_transform_le( midstate, vdata, initstate );

   do
   {
      // 1. final 16 bytes of data, with padding
      memcpy_256( block, vdata + 16, 4 );
      block[ 4] = last_byte;
      memset_zero_256( block + 5, 10 );
      block[15] = m256_const1_32( 80*8 ); // bit count
      sha256_8way_transform_le( hash32, block, midstate );

      // 2. 32 byte hash from 1.
      memcpy_256( block, hash32, 8 );
      block[ 8] = last_byte;
      memset_zero_256( block + 9, 6 );
      block[15] = m256_const1_32( 32*8 ); // bit count
      sha256_8way_transform_le( hash32, block, initstate );

      // 3. 32 byte hash from 2.
      memcpy_256( block, hash32, 8 );
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

#if defined(SHA256T_4WAY)

int scanhash_sha256t_4way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m128i  block[16]    __attribute__ ((aligned (64)));
   __m128i  hash32[8]    __attribute__ ((aligned (32)));
   __m128i  initstate[8] __attribute__ ((aligned (32)));
   __m128i  midstate[8]  __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   __m128i  vdata[20]    __attribute__ ((aligned (32)));
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
   const __m128i last_byte = m128_const1_32( 0x80000000 );
   const __m128i four = m128_const1_32( 4 );

   for ( int i = 0; i < 19; i++ )
       vdata[i] = m128_const1_32( pdata[i] );

   *noncev = _mm_set_epi32( n+ 3, n+ 2, n+1, n );

   // initialize state
   initstate[0] = m128_const1_64( 0x6A09E6676A09E667 );
   initstate[1] = m128_const1_64( 0xBB67AE85BB67AE85 );
   initstate[2] = m128_const1_64( 0x3C6EF3723C6EF372 );
   initstate[3] = m128_const1_64( 0xA54FF53AA54FF53A );
   initstate[4] = m128_const1_64( 0x510E527F510E527F );
   initstate[5] = m128_const1_64( 0x9B05688C9B05688C );
   initstate[6] = m128_const1_64( 0x1F83D9AB1F83D9AB );
   initstate[7] = m128_const1_64( 0x5BE0CD195BE0CD19 );

   // hash first 64 bytes of data
   sha256_4way_transform_le( midstate, vdata, initstate );

   do
   {
      // 1. final 16 bytes of data, with padding
      memcpy_128( block, vdata + 16, 4 );
      block[ 4] = last_byte;
      memset_zero_128( block + 5, 10 );
      block[15] = m128_const1_32( 80*8 ); // bit count
      sha256_4way_transform_le( hash32, block, midstate );

      // 2. 32 byte hash from 1.
      memcpy_128( block, hash32, 8 );
      block[ 8] = last_byte;
      memset_zero_128( block + 9, 6 );
      block[15] = m128_const1_32( 32*8 ); // bit count
      sha256_4way_transform_le( hash32, block, initstate );

      // 3. 32 byte hash from 2.
      memcpy_128( block, hash32, 8 );
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

