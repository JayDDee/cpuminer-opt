#include "algo-gate-api.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha-hash-4way.h"

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define SHA256DT_16WAY 1
#elif defined(__AVX2__)
  #define SHA256DT_8WAY 1
#else
  #define SHA256DT_4WAY 1
#endif

#if defined(SHA256DT_16WAY)

int scanhash_sha256dt_16way( struct work *work, const uint32_t max_nonce,
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
   const __m512i last_byte = m512_const1_32( 0x80000000 );
   const __m512i sixteen = m512_const1_32( 16 );

   for ( int i = 0; i < 19; i++ )
      vdata[i] = mm512_bcast_i32( pdata[i] );

   *noncev = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+9, n+8,
                               n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );

   vdata[16+4] = last_byte;
   memset_zero_512( vdata+16 + 5, 10 );
   vdata[16+15] = mm512_bcast_i32( 0x480 ); 
   
   block[ 8] = last_byte;
   memset_zero_512( block + 9, 6 );
   block[15] = mm512_bcast_i32( 0x300 ); 
   
   initstate[0] = mm512_bcast_i64( 0xdfa9bf2cdfa9bf2c );
   initstate[1] = mm512_bcast_i64( 0xb72074d4b72074d4 );
   initstate[2] = mm512_bcast_i64( 0x6bb011226bb01122 );
   initstate[3] = mm512_bcast_i64( 0xd338e869d338e869 );
   initstate[4] = mm512_bcast_i64( 0xaa3ff126aa3ff126 );
   initstate[5] = mm512_bcast_i64( 0x475bbf30475bbf30 );
   initstate[6] = mm512_bcast_i64( 0x8fd52e5b8fd52e5b );
   initstate[7] = mm512_bcast_i64( 0x9f75c9ad9f75c9ad );

   sha256_16way_transform_le( midstate1, vdata, initstate );
   
   // Do 3 rounds on the first 12 bytes of the next block
   sha256_16way_prehash_3rounds( midstate2, mexp_pre, vdata+16, midstate1 );

   do
   {
      sha256_16way_final_rounds( block, vdata+16, midstate1, midstate2,
                                 mexp_pre );
      sha256_16way_transform_le( hash32, block, initstate );
      mm512_block_bswap_32( hash32, hash32 );    

      for ( int lane = 0; lane < 16; lane++ )
      if ( hash32_d7[ lane ] <= targ32_d7 )
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

#if defined(SHA256DT_8WAY)

int scanhash_sha256dt_8way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m256i  vdata[32]    __attribute__ ((aligned (64)));
   __m256i  block[16]    __attribute__ ((aligned (32)));
   __m256i  hash32[8]    __attribute__ ((aligned (32)));
   __m256i  initstate[8] __attribute__ ((aligned (32)));
   __m256i  midstate1[8] __attribute__ ((aligned (32)));
   __m256i  midstate2[8] __attribute__ ((aligned (32)));
   __m256i  mexp_pre[16] __attribute__ ((aligned (32)));
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
   const __m256i last_byte = m256_const1_32( 0x80000000 );
   const __m256i eight = m256_const1_32( 8 );

   for ( int i = 0; i < 19; i++ )
      vdata[i] = mm256_bcast_i32( pdata[i] );

   *noncev = _mm256_set_epi32( n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );

   vdata[16+4] = last_byte;
   memset_zero_256( vdata+16 + 5, 10 );
   vdata[16+15] = mm256_bcast_i32( 0x480 );

   block[ 8] = last_byte;
   memset_zero_256( block + 9, 6 );
   block[15] = mm256_bcast_i32( 0x300 ); 
   
   // initialize state
   initstate[0] = mm256_bcast_i64( 0xdfa9bf2cdfa9bf2c );
   initstate[1] = mm256_bcast_i64( 0xb72074d4b72074d4 );
   initstate[2] = mm256_bcast_i64( 0x6bb011226bb01122 );
   initstate[3] = mm256_bcast_i64( 0xd338e869d338e869 );
   initstate[4] = mm256_bcast_i64( 0xaa3ff126aa3ff126 );
   initstate[5] = mm256_bcast_i64( 0x475bbf30475bbf30 );
   initstate[6] = mm256_bcast_i64( 0x8fd52e5b8fd52e5b );
   initstate[7] = mm256_bcast_i64( 0x9f75c9ad9f75c9ad );

   sha256_8way_transform_le( midstate1, vdata, initstate );

   // Do 3 rounds on the first 12 bytes of the next block
   sha256_8way_prehash_3rounds( midstate2, mexp_pre, vdata + 16, midstate1 );
   
   do
   {
      sha256_8way_final_rounds( block, vdata+16, midstate1, midstate2,
                                mexp_pre );
      sha256_8way_transform_le( hash32, block, initstate );
      mm256_block_bswap_32( hash32, hash32 );

      for ( int lane = 0; lane < 8; lane++ )
      if ( hash32_d7[ lane ] <= targ32_d7 )
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


#if defined(SHA256DT_4WAY)

int scanhash_sha256dt_4way( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m128i  vdata[32]    __attribute__ ((aligned (64)));
   __m128i  block[16]    __attribute__ ((aligned (32)));
   __m128i  hash32[8]    __attribute__ ((aligned (32)));
   __m128i  initstate[8] __attribute__ ((aligned (32)));
   __m128i  midstate[8]  __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
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
       vdata[i] = mm128_bcast_i32( pdata[i] );

   *noncev = _mm_set_epi32( n+ 3, n+ 2, n+1, n );

   vdata[16+4] = last_byte;
   memset_zero_128( vdata+16 + 5, 10 );
   vdata[16+15] = mm128_bcast_i32( 0x480 );

   block[ 8] = last_byte;
   memset_zero_128( block + 9, 6 );
   block[15] = mm128_bcast_i32( 0x300 );
   
   // initialize state
   initstate[0] = mm128_bcast_i64( 0xdfa9bf2cdfa9bf2c );
   initstate[1] = mm128_bcast_i64( 0xb72074d4b72074d4 );
   initstate[2] = mm128_bcast_i64( 0x6bb011226bb01122 );
   initstate[3] = mm128_bcast_i64( 0xd338e869d338e869 );
   initstate[4] = mm128_bcast_i64( 0xaa3ff126aa3ff126 );
   initstate[5] = mm128_bcast_i64( 0x475bbf30475bbf30 );
   initstate[6] = mm128_bcast_i64( 0x8fd52e5b8fd52e5b );
   initstate[7] = mm128_bcast_i64( 0x9f75c9ad9f75c9ad );

   // hash first 64 bytes of data
   sha256_4way_transform_le( midstate, vdata, initstate );

   do
   {
      sha256_4way_transform_le( block,  vdata+16, midstate  );
      sha256_4way_transform_le( hash32, block,    initstate );
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

bool register_sha256dt_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
#if defined(SHA256DT_16WAY)
    gate->scanhash   = (void*)&scanhash_sha256dt_16way;
#elif defined(SHA256DT_8WAY)
    gate->scanhash   = (void*)&scanhash_sha256dt_8way;
#else
    gate->scanhash   = (void*)&scanhash_sha256dt_4way;
#endif
    return true;
}

