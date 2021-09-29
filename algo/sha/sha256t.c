#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
//#include "algo/sha/sph_sha2.h"
#include "sha256-hash.h"

#if defined(__SHA__)

// Only used on CPUs with SHA


int scanhash_sha256t( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t block0[16]    __attribute__ ((aligned (64)));
   uint32_t block1[16]    __attribute__ ((aligned (64)));
   uint32_t hash0[8]    __attribute__ ((aligned (32)));
   uint32_t hash1[8]    __attribute__ ((aligned (32)));
   uint32_t initstate[8] __attribute__ ((aligned (32)));
   uint32_t midstate[8]  __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 1;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   __m128i shuf_bswap32 =
           _mm_set_epi64x( 0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL );

   // initialize state
   initstate[0] = 0x6A09E667;
   initstate[1] = 0xBB67AE85;
   initstate[2] = 0x3C6EF372;
   initstate[3] = 0xA54FF53A;
   initstate[4] = 0x510E527F;
   initstate[5] = 0x9B05688C;
   initstate[6] = 0x1F83D9AB;
   initstate[7] = 0x5BE0CD19;

   // hash first 64 bytes of data
   sha256_opt_transform_le( midstate, pdata, initstate );

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
      sha256_ni2way_transform_le( hash0, hash1, block0, block1, midstate, midstate );

      // 2. 32 byte hash from 1.
      memcpy( block0, hash0, 32 );
      memcpy( block1, hash1, 32 );
      block0[ 8] = block1[ 8] = 0x80000000;
      memset( block0 + 9, 0, 24 );
      memset( block1 + 9, 0, 24 );
      block0[15] = block1[15] = 32*8; // bit count
      sha256_ni2way_transform_le( hash0, hash1, block0, block1, initstate, initstate );

      // 3. 32 byte hash from 2.
      memcpy( block0, hash0, 32 );
      memcpy( block1, hash1, 32 );
      sha256_ni2way_transform_le( hash0, hash1, block0, block1, initstate, initstate );

      // byte swap final hash for testing
      casti_m128i( hash0, 0 ) =
               _mm_shuffle_epi8( casti_m128i( hash0, 0 ), shuf_bswap32 );
      casti_m128i( hash0, 1 ) =
               _mm_shuffle_epi8( casti_m128i( hash0, 1 ), shuf_bswap32 );
      casti_m128i( hash1, 0 ) =
               _mm_shuffle_epi8( casti_m128i( hash1, 0 ), shuf_bswap32 );
      casti_m128i( hash1, 1 ) =
               _mm_shuffle_epi8( casti_m128i( hash1, 1 ), shuf_bswap32 );

      if ( unlikely( valid_hash( hash0, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash0, mythr );
      }
      if ( unlikely( valid_hash( hash1, ptarget ) && !bench ) )
      {
         pdata[19] = n+1;
         submit_solution( work, hash1, mythr );
      }
      n += 2;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

