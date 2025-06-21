#include "algo-gate-api.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha256-hash.h"
#include "sph_sha2.h"

#if defined(SIMD512)
  #define SHA256DT_16X32 1
#elif defined(__x86_64__) && defined(__SHA__)
  #define SHA256DT_X86_SHA256 1
#elif defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)
  #define SHA256DT_NEON_SHA256 1
#elif defined(__AVX2__)
  #define SHA256DT_8X32 1
#elif defined (__SSE2__) || defined(__ARM_NEON) 
  #define SHA256DT_4X32 1
#endif

static const uint32_t sha256dt_iv[8]  __attribute__ ((aligned (32))) =
{
   0xdfa9bf2c, 0xb72074d4, 0x6bb01122, 0xd338e869,
   0xaa3ff126, 0x475bbf30, 0x8fd52e5b, 0x9f75c9ad
};

#if defined(SHA256DT_X86_SHA256)

int scanhash_sha256dt_x86_x2sha( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t block1a[16] __attribute__ ((aligned (64)));
   uint32_t block1b[16] __attribute__ ((aligned (64)));
   uint32_t block2a[16] __attribute__ ((aligned (64)));
   uint32_t block2b[16] __attribute__ ((aligned (64)));
   uint32_t hasha[8]    __attribute__ ((aligned (32)));
   uint32_t hashb[8]    __attribute__ ((aligned (32)));
   uint32_t mstatea[8]  __attribute__ ((aligned (32)));
   uint32_t mstateb[8]  __attribute__ ((aligned (32)));
   uint32_t sstate[8]   __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   // hash first 64 byte block of data
   sha256_transform_le( mstatea, pdata, sha256dt_iv );

   // fill & pad second bock without nonce
   memcpy( block1a, pdata + 16, 12 );
   memcpy( block1b, pdata + 16, 12 );
   block1a[ 3] = block1b[ 3] = 0;
   block1a[ 4] = block1b[ 4] = 0x80000000;
   memset( block1a + 5, 0, 40 );
   memset( block1b + 5, 0, 40 );
   block1a[15] = block1b[15] = 0x480; // funky bit count

   sha256_prehash_3rounds( mstateb, block1a, sstate, mstatea);

   // Pad third block
   block2a[ 8] = block2b[ 8] = 0x80000000;
   memset( block2a + 9, 0, 24 );
   memset( block2b + 9, 0, 24 );
   block2a[15] = block2b[15] = 0x300; // bit count

   do
   {
      // Insert nonce for second block
      block1a[3] = n;
      block1b[3] = n+1;
      sha256_2x_final_rounds( block2a, block2b, block1a, block1b,
                                  mstateb, mstateb, sstate, sstate );

      sha256_2x_transform_le( hasha, hashb, block2a, block2b,
                                  sha256dt_iv, sha256dt_iv );

      if ( unlikely( bswap_32( hasha[7] ) <= ptarget[7] ) )
      {
          casti_v128( hasha, 0 ) = v128_bswap32( casti_v128( hasha, 0 ) );
          casti_v128( hasha, 1 ) = v128_bswap32( casti_v128( hasha, 1 ) );
          if ( likely( valid_hash( hasha, ptarget ) && !bench ) )
          {
             pdata[19] = n;
             submit_solution( work, hasha, mythr );
          }
      }
      if ( unlikely( bswap_32( hashb[7] ) <= ptarget[7] ) )
      {
         casti_v128( hashb, 0 ) = v128_bswap32( casti_v128( hashb, 0 ) );
         casti_v128( hashb, 1 ) = v128_bswap32( casti_v128( hashb, 1 ) );
         if ( likely( valid_hash( hashb, ptarget ) && !bench ) )
         {
            pdata[19] = n+1;
            submit_solution( work, hashb, mythr );
         }
      }
      n += 2;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(SHA256DT_NEON_SHA256)

int scanhash_sha256dt_neon_x2sha( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t block1a[16] __attribute__ ((aligned (64)));
   uint32_t block1b[16] __attribute__ ((aligned (64)));
   uint32_t block2a[16] __attribute__ ((aligned (64)));
   uint32_t block2b[16] __attribute__ ((aligned (64)));
   uint32_t hasha[8]    __attribute__ ((aligned (32)));
   uint32_t hashb[8]    __attribute__ ((aligned (32)));
   uint32_t mstate[8]   __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   // hash first 64 byte block of data
   sha256_neon_sha_transform_le( mstate, pdata, sha256dt_iv );

   // fill & pad second bock without nonce
   memcpy( block1a, pdata + 16, 12 );
   memcpy( block1b, pdata + 16, 12 );
   block1a[ 3] = block1b[ 3] = 0;
   block1a[ 4] = block1b[ 4] = 0x80000000;
   memset( block1a + 5, 0, 40 );
   memset( block1b + 5, 0, 40 );
   block1a[15] = block1b[15] = 0x480; // funky bit count

   // Pad third block
   block2a[ 8] = block2b[ 8] = 0x80000000;
   memset( block2a + 9, 0, 24 );
   memset( block2b + 9, 0, 24 );
   block2a[15] = block2b[15] = 0x300; // bit count

   do
   {
      // Insert nonce for second block
      block1a[3] = n;
      block1b[3] = n+1;
      sha256_neon_x2sha_transform_le( block2a, block2b, block1a, block1b,
                                  mstate, mstate );

      sha256_neon_x2sha_transform_le( hasha, hashb, block2a, block2b,
                                  sha256dt_iv, sha256dt_iv );

      if ( unlikely( bswap_32( hasha[7] ) <= ptarget[7] ) )
      {
          casti_v128( hasha, 0 ) = v128_bswap32( casti_v128( hasha, 0 ) );
          casti_v128( hasha, 1 ) = v128_bswap32( casti_v128( hasha, 1 ) );
          if ( likely( valid_hash( hasha, ptarget ) && !bench ) )
          {
             pdata[19] = n;
             submit_solution( work, hasha, mythr );
          }
      }
      if ( unlikely( bswap_32( hashb[7] ) <= ptarget[7] ) )
      {
         casti_v128( hashb, 0 ) = v128_bswap32( casti_v128( hashb, 0 ) );
         casti_v128( hashb, 1 ) = v128_bswap32( casti_v128( hashb, 1 ) );
         if ( likely( valid_hash( hashb, ptarget ) && !bench ) )
         {
            pdata[19] = n+1;
            submit_solution( work, hashb, mythr );
         }
      }
      n += 2;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(SHA256DT_16X32)

int scanhash_sha256dt_16x32( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m512i  block[16]    __attribute__ ((aligned (128)));
   __m512i  buf[16]      __attribute__ ((aligned (64)));
   __m512i  hash32[8]    __attribute__ ((aligned (64)));
   __m512i  mstate1[8]   __attribute__ ((aligned (64)));
   __m512i  mstate2[8]   __attribute__ ((aligned (64)));
   __m512i  istate[8]    __attribute__ ((aligned (64)));
   __m512i  mexp_pre[8]  __attribute__ ((aligned (64)));
   uint32_t phash[8]     __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 16;
   const __m512i last_byte = v512_32( 0x80000000 );
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const __m512i sixteen = v512_32( 16 );
   const bool bench = opt_benchmark;

   // prehash first block directly from pdata
   sha256_transform_le( phash, pdata, sha256dt_iv );

   // vectorize block 0 hash for second block
   mstate1[0] = v512_32( phash[0] );
   mstate1[1] = v512_32( phash[1] );
   mstate1[2] = v512_32( phash[2] );
   mstate1[3] = v512_32( phash[3] );
   mstate1[4] = v512_32( phash[4] );
   mstate1[5] = v512_32( phash[5] );
   mstate1[6] = v512_32( phash[6] );
   mstate1[7] = v512_32( phash[7] );

   // second message block data, with nonce & padding
   buf[0] = v512_32( pdata[16] );
   buf[1] = v512_32( pdata[17] );
   buf[2] = v512_32( pdata[18] );
   buf[3] = _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+ 9, n+ 8,
                              n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n +1, n );
   buf[4] = last_byte;
   memset_zero_512( buf+5, 10 );
   buf[15] = v512_32( 0x480 ); // sha256dt funky bit count

   // partially pre-expand & prehash second message block, avoiding the nonces
   sha256_16x32_prehash_3rounds( mstate2, mexp_pre, buf, mstate1 );

   // vectorize IV for second hash
   istate[0] = v512_32( sha256dt_iv[0] );
   istate[1] = v512_32( sha256dt_iv[1] );
   istate[2] = v512_32( sha256dt_iv[2] );
   istate[3] = v512_32( sha256dt_iv[3] );
   istate[4] = v512_32( sha256dt_iv[4] );
   istate[5] = v512_32( sha256dt_iv[5] );
   istate[6] = v512_32( sha256dt_iv[6] );
   istate[7] = v512_32( sha256dt_iv[7] );

   // initialize padding for second hash
   block[ 8] = last_byte;
   memset_zero_512( block+9, 6 );
   block[15] = v512_32( 0x300 ); // bit count

   do
   {
      sha256_16x32_final_rounds( block, buf, mstate1, mstate2, mexp_pre );
      if ( unlikely( sha256_16x32_transform_le_short(
                                  hash32, block, istate, ptarget ) ) )
      {
         for ( int lane = 0; lane < 16; lane++ )
         {
            extr_lane_16x32( phash, hash32, lane, 256 );
            casti_m256i( phash, 0 ) = mm256_bswap_32( casti_m256i( phash, 0 ) ); 
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
   
#elif defined(SHA256DT_8X32)

int scanhash_sha256dt_8x32( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   __m256i  vdata[32]    __attribute__ ((aligned (64)));
   __m256i  block[16]    __attribute__ ((aligned (32)));
   __m256i  hash32[8]    __attribute__ ((aligned (32)));
   __m256i  istate[8]    __attribute__ ((aligned (32)));
   __m256i  mstate1[8]   __attribute__ ((aligned (32)));
   __m256i  mstate2[8]   __attribute__ ((aligned (32)));
   __m256i  mexp_pre[8]  __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   __m256i *noncev = vdata + 19;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m256i last_byte = v256_32( 0x80000000 );
   const __m256i eight = v256_32( 8 );

   for ( int i = 0; i < 19; i++ )
      vdata[i] = v256_32( pdata[i] );

   *noncev = _mm256_set_epi32( n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+1, n );

   vdata[16+4] = last_byte;
   memset_zero_256( vdata+16 + 5, 10 );
   vdata[16+15] = v256_32( 0x480 );

   block[ 8] = last_byte;
   memset_zero_256( block + 9, 6 );
   block[15] = v256_32( 0x300 ); 
   
   // initialize state for second hash
   istate[0] = v256_32( sha256dt_iv[0] );
   istate[1] = v256_32( sha256dt_iv[1] );
   istate[2] = v256_32( sha256dt_iv[2] );
   istate[3] = v256_32( sha256dt_iv[3] );
   istate[4] = v256_32( sha256dt_iv[4] );
   istate[5] = v256_32( sha256dt_iv[5] );
   istate[6] = v256_32( sha256dt_iv[6] );
   istate[7] = v256_32( sha256dt_iv[7] );

   sha256_8x32_transform_le( mstate1, vdata, istate );

   // Do 3 rounds on the first 12 bytes of the next block
   sha256_8x32_prehash_3rounds( mstate2, mexp_pre, vdata + 16, mstate1 );
   
   do
   {
      sha256_8x32_final_rounds( block, vdata+16, mstate1, mstate2, mexp_pre );
      if ( unlikely( sha256_8x32_transform_le_short( hash32, block,
                                                     istate, ptarget ) ) )
      {
         for ( int lane = 0; lane < 8; lane++ )
         {
            extr_lane_8x32( lane_hash, hash32, lane, 256 );
            casti_m256i( lane_hash, 0 ) =
                                mm256_bswap_32( casti_m256i( lane_hash, 0 ) );
            if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
            {
               pdata[19] = n + lane;
               submit_solution( work, lane_hash, mythr );
            }
         }
      }
      *noncev = _mm256_add_epi32( *noncev, eight );
      n += 8;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(SHA256DT_4X32)

int scanhash_sha256dt_4x32( struct work *work, const uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   v128_t   vdata[32]    __attribute__ ((aligned (64)));
   v128_t   block[16]    __attribute__ ((aligned (32)));
   v128_t   hash32[8]    __attribute__ ((aligned (32)));
   v128_t   iv[8]        __attribute__ ((aligned (32)));
   v128_t   mhash1[8]    __attribute__ ((aligned (32)));
   v128_t   mhash2[8]    __attribute__ ((aligned (32)));
   v128_t   mexp_pre[8]  __attribute__ ((aligned (32)));
   uint32_t lhash[8] __attribute__ ((aligned (32)));
   uint32_t *hash32_d7 =  (uint32_t*)&( hash32[7] );
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const v128_t last_byte = v128_32( 0x80000000 );
   const v128_t four = v128_32( 4 );
   
   for ( int i = 0; i < 19; i++ )
      vdata[i] = v128_32( pdata[i] );
   vdata[16+3] = v128_set32( n+3, n+2, n+1, n );
   vdata[16+4] = last_byte;
   v128_memset_zero( vdata+16 + 5, 9 );
   vdata[16+15] = v128_32( 0x480 );

   block[ 8] = last_byte;
   v128_memset_zero( block + 9, 5 );
   block[15] = v128_32( 0x300 );
   
   iv[0] = v128_32( sha256dt_iv[0] );
   iv[1] = v128_32( sha256dt_iv[1] );
   iv[2] = v128_32( sha256dt_iv[2] );
   iv[3] = v128_32( sha256dt_iv[3] );
   iv[4] = v128_32( sha256dt_iv[4] );
   iv[5] = v128_32( sha256dt_iv[5] );
   iv[6] = v128_32( sha256dt_iv[6] );
   iv[7] = v128_32( sha256dt_iv[7] );

   sha256_4x32_transform_le( mhash1, vdata, iv );
   sha256_4x32_prehash_3rounds( mhash2, mexp_pre, vdata + 16, mhash1 );

   do
   {
      sha256_4x32_final_rounds( block, vdata+16, mhash1, mhash2, mexp_pre );
      sha256_4x32_transform_le( hash32, block, iv );

      for ( int lane = 0; lane < 4; lane++ )
      {
         if ( unlikely( bswap_32( hash32_d7[ lane ] ) <= targ32_d7 ) )
         {
            extr_lane_4x32( lhash, hash32, lane, 256 );
            casti_v128( lhash, 0 ) = v128_bswap32( casti_v128( lhash, 0 ) );
            casti_v128( lhash, 1 ) = v128_bswap32( casti_v128( lhash, 1 ) );
            if ( likely( valid_hash( lhash, ptarget ) && !bench ) )
            {
               pdata[19] = n + lane;
               submit_solution( work, lhash, mythr );
            }
         }
      }
      vdata[16+3] = v128_add32( vdata[16+3], four );
      n += 4;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else

int scanhash_sha256dt_ref( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t block1[16] __attribute__ ((aligned (32)));
   uint32_t block2[16] __attribute__ ((aligned (32)));
   uint32_t hash32[8]  __attribute__ ((aligned (32)));
   uint32_t mstate[8]  __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   memset( block1, 0, 64 );
   memset( block2, 0, 64 );

   // hash first 64 byte block of data
   sha256_transform_le( mstate, pdata, sha256dt_iv );

   // fill & pad second bock without nonce
   memcpy( block1, pdata + 16, 12 );
   block1[ 3] = n;
   block1[ 4] = 0x80000000;
   memset( block1 + 5, 0, 40 );
   block1[15] = 0x480; // funky bit count

   // Pad third block
   block2[ 8] = 0x80000000;
   memset( block2 + 9, 0, 24 );
   block2[15] = 0x300; // bit count

   do
   {
      // Insert nonce for second block
      block1[3] = n;
      sha256_transform_le( block2, block1, mstate );

      sha256_transform_le( hash32, block2, sha256dt_iv );

      if ( unlikely( bswap_32( hash32[7] ) <= ptarget[7] ) )
      {
          casti_v128( hash32, 0 ) = v128_bswap32( casti_v128( hash32, 0 ) );
          casti_v128( hash32, 1 ) = v128_bswap32( casti_v128( hash32, 1 ) );
          if ( likely( valid_hash( hash32, ptarget ) && !bench ) )
          {
             pdata[19] = n;
             submit_solution( work, hash32, mythr );
          }
      }
      n += 1;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

bool register_sha256dt_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
#if defined(SHA256DT_16X32)
    gate->scanhash = (void*)&scanhash_sha256dt_16x32;
#elif defined(SHA256DT_X86_SHA256)
    gate->optimizations = SSE2_OPT | SHA256_OPT;
    gate->scanhash = (void*)&scanhash_sha256dt_x86_x2sha;    
#elif defined(SHA256DT_NEON_SHA256)
    gate->optimizations = NEON_OPT | SHA256_OPT;
    gate->scanhash = (void*)&scanhash_sha256dt_neon_x2sha;
#elif defined(SHA256DT_8X32)
    gate->scanhash = (void*)&scanhash_sha256dt_8x32;
#elif defined(SHA256DT_4X32)
    gate->scanhash = (void*)&scanhash_sha256dt_4x32;
#else 
    gate->scanhash = (void*)&scanhash_sha256dt_ref;
#endif
    return true;
}

