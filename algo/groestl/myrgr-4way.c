#include "myrgr-gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes_ni/hash-groestl.h"
#include "algo/sha/sha-hash-4way.h"
#if defined(__VAES__)
  #include "groestl512-hash-4way.h"
#endif

#if defined(MYRGR_8WAY)

typedef struct {
#if defined(__VAES__)
   groestl512_4way_context groestl;
#else
   hashState_groestl       groestl;
#endif
   sha256_8way_context     sha;
} myrgr_8way_ctx_holder;

myrgr_8way_ctx_holder myrgr_8way_ctx;

void init_myrgr_8way_ctx()
{
#if defined(__VAES__)
     groestl512_4way_init( &myrgr_8way_ctx.groestl, 64 );
#else
     init_groestl( &myrgr_8way_ctx.groestl, 64 );
#endif
     sha256_8way_init( &myrgr_8way_ctx.sha );
}

void myriad_8way_hash( void *output, const void *input )
{
     uint32_t vhash[16*8] __attribute__ ((aligned (128)));
     uint32_t vhashA[20*8] __attribute__ ((aligned (64)));
     uint32_t vhashB[20*8] __attribute__ ((aligned (64)));
     myrgr_8way_ctx_holder ctx;
     memcpy( &ctx, &myrgr_8way_ctx, sizeof(myrgr_8way_ctx) );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, input, 640 );
     groestl512_4way_update_close( &ctx.groestl, vhashA, vhashA, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(groestl512_4way_context) );
     groestl512_4way_update_close( &ctx.groestl, vhashB, vhashB, 640 );

     uint32_t hash0[20] __attribute__ ((aligned (64)));
     uint32_t hash1[20] __attribute__ ((aligned (64)));
     uint32_t hash2[20] __attribute__ ((aligned (64)));
     uint32_t hash3[20] __attribute__ ((aligned (64)));
     uint32_t hash4[20] __attribute__ ((aligned (64)));
     uint32_t hash5[20] __attribute__ ((aligned (64)));
     uint32_t hash6[20] __attribute__ ((aligned (64)));
     uint32_t hash7[20] __attribute__ ((aligned (64)));

//     rintrlv_4x128_8x32( vhash, vhashA, vhashB, 512 );
     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

#else

     uint32_t hash0[20] __attribute__ ((aligned (64)));
     uint32_t hash1[20] __attribute__ ((aligned (64)));
     uint32_t hash2[20] __attribute__ ((aligned (64)));
     uint32_t hash3[20] __attribute__ ((aligned (64)));
     uint32_t hash4[20] __attribute__ ((aligned (64)));
     uint32_t hash5[20] __attribute__ ((aligned (64)));  
     uint32_t hash6[20] __attribute__ ((aligned (64)));
     uint32_t hash7[20] __attribute__ ((aligned (64)));

     dintrlv_8x64( hash0, hash1, hash2, hash3,
                   hash4, hash5, hash6, hash7, input, 640 );

     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash4, (char*)hash4, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash5, (char*)hash5, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash6, (char*)hash6, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash7, (char*)hash7, 640 );
     memcpy( &ctx.groestl, &myrgr_8way_ctx.groestl, sizeof(hashState_groestl) );

#endif

     intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5,
                       hash6, hash7 );
     
     sha256_8way_update( &ctx.sha, vhash, 64 );
     sha256_8way_close( &ctx.sha, output );
}

int scanhash_myriad_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<3]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   uint32_t *noncep = vdata + 64+3;   // 4*16 + 3
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm512_bswap32_intrlv80_4x128( vdata, pdata );

   do
   {
      be32enc( noncep,    n   );
      be32enc( noncep+ 8, n+1 );
      be32enc( noncep+16, n+2 );
      be32enc( noncep+24, n+3 );
      be32enc( noncep+32, n+4 );
      be32enc( noncep+40, n+5 );
      be32enc( noncep+48, n+6 );
      be32enc( noncep+64, n+7 );

      myriad_8way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 8; lane++ )
      if ( hash7[ lane ] <= Htarg )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      n += 8;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(MYRGR_4WAY)

typedef struct {
    hashState_groestl       groestl;
    sha256_4way_context     sha;
} myrgr_4way_ctx_holder;

myrgr_4way_ctx_holder myrgr_4way_ctx;

void init_myrgr_4way_ctx()
{
     init_groestl (&myrgr_4way_ctx.groestl, 64 );
     sha256_4way_init( &myrgr_4way_ctx.sha );
}

void myriad_4way_hash( void *output, const void *input )
{
     uint32_t hash0[20] __attribute__ ((aligned (64)));
     uint32_t hash1[20] __attribute__ ((aligned (64)));
     uint32_t hash2[20] __attribute__ ((aligned (64)));
     uint32_t hash3[20] __attribute__ ((aligned (64)));
     uint32_t vhash[16*4] __attribute__ ((aligned (64)));
     myrgr_4way_ctx_holder ctx;
     memcpy( &ctx, &myrgr_4way_ctx, sizeof(myrgr_4way_ctx) );

     dintrlv_4x32( hash0, hash1, hash2, hash3, input, 640 );

     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 640 );
     memcpy( &ctx.groestl, &myrgr_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 640 );

     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );

     sha256_4way_update( &ctx.sha, vhash, 64 );
     sha256_4way_close( &ctx.sha, output );
}

int scanhash_myriad_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   do {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3,n+2,n+1,n ) );

      myriad_4way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 4; lane++ )
      if ( hash7[ lane ] <= Htarg )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      n += 4;
   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
