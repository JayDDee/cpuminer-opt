#include "x17-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/shavite/shavite-hash-2way.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/sha/sha-hash-4way.h"

#if defined(X17_8WAY)

union _x17_8way_context_overlay
{
    blake512_8way_context   blake;
    bmw512_8way_context     bmw;
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    keccak512_8way_context  keccak;
    luffa_4way_context      luffa;
//    cube_4way_context       cube;
    cube_4way_2buf_context   cube;
#if defined(__VAES__)
    groestl512_4way_context groestl;
    shavite512_4way_context shavite;
    echo_4way_context       echo;
#else
    hashState_groestl       groestl;
    sph_shavite512_context  shavite;
    hashState_echo          echo;
#endif
    simd_4way_context       simd;
    hamsi512_8way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_8way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_8way_context     sha512;
    haval256_5_8way_context haval;
} __attribute__ ((aligned (64)));
typedef union _x17_8way_context_overlay x17_8way_context_overlay;

static __thread __m512i x17_8way_midstate[16] __attribute__((aligned(64)));
static __thread blake512_8way_context blake512_8way_ctx __attribute__((aligned(64)));

int x17_8way_hash( void *state, const void *input, int thr_id )
{
     uint64_t vhash[8*8] __attribute__ ((aligned (128)));
     uint64_t vhashA[8*8] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*8] __attribute__ ((aligned (64)));
     uint64_t hash0[8] __attribute__ ((aligned (32)));
     uint64_t hash1[8] __attribute__ ((aligned (32)));
     uint64_t hash2[8] __attribute__ ((aligned (32)));
     uint64_t hash3[8] __attribute__ ((aligned (32)));
     uint64_t hash4[8] __attribute__ ((aligned (32)));
     uint64_t hash5[8] __attribute__ ((aligned (32)));
     uint64_t hash6[8] __attribute__ ((aligned (32)));
     uint64_t hash7[8] __attribute__ ((aligned (32)));
     x17_8way_context_overlay ctx;

     blake512_8way_final_le( &blake512_8way_ctx, vhash, casti_m512i( input, 9 ),
                             x17_8way_midstate );
     
     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );
     
     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );
     
#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
     groestl512_full( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
     groestl512_full( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
     groestl512_full( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
     groestl512_full( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7 );

#endif

     skein512_8way_full( &ctx.skein, vhash, vhash, 64 );

     jh512_8way_init( &ctx.jh );
     jh512_8way_update( &ctx.jh, vhash, 64 );
     jh512_8way_close( &ctx.jh, vhash );

     keccak512_8way_init( &ctx.keccak );
     keccak512_8way_update( &ctx.keccak, vhash, 64 );
     keccak512_8way_close( &ctx.keccak, vhash );

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     luffa512_4way_full( &ctx.luffa, vhashA, vhashA, 64 );
     luffa512_4way_full( &ctx.luffa, vhashB, vhashB, 64 );

     cube_4way_2buf_full( &ctx.cube, vhashA, vhashB, 512, vhashA, vhashB, 64 );
     
#if defined(__VAES__)

     shavite512_4way_full( &ctx.shavite, vhashA, vhashA, 64 );
     shavite512_4way_full( &ctx.shavite, vhashB, vhashB, 64 );

#else

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

     shavite512_full( &ctx.shavite, hash0, hash0, 64 );
     shavite512_full( &ctx.shavite, hash1, hash1, 64 );
     shavite512_full( &ctx.shavite, hash2, hash2, 64 );
     shavite512_full( &ctx.shavite, hash3, hash3, 64 );
     shavite512_full( &ctx.shavite, hash4, hash4, 64 );
     shavite512_full( &ctx.shavite, hash5, hash5, 64 );
     shavite512_full( &ctx.shavite, hash6, hash6, 64 );
     shavite512_full( &ctx.shavite, hash7, hash7, 64 );

     intrlv_4x128_512( vhashA, hash0, hash1, hash2, hash3 );
     intrlv_4x128_512( vhashB, hash4, hash5, hash6, hash7 );

#endif

     simd512_4way_full( &ctx.simd, vhashA, vhashA, 64 );
     simd512_4way_full( &ctx.simd, vhashB, vhashB, 64 );

#if defined(__VAES__)

     echo_4way_full( &ctx.echo, vhashA, 512, vhashA, 64 );
     echo_4way_full( &ctx.echo, vhashB, 512, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

     echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                     (const BitSequence *)hash0, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                     (const BitSequence *)hash1, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                     (const BitSequence *)hash2, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                     (const BitSequence *)hash3, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                     (const BitSequence *)hash4, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                     (const BitSequence *)hash5, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                     (const BitSequence *)hash6, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                     (const BitSequence *)hash7, 64 );
     
     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                      hash7 );

#endif

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                       vhash );

     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );
     fugue512_full( &ctx.fugue, hash4, hash4, 64 );
     fugue512_full( &ctx.fugue, hash5, hash5, 64 );
     fugue512_full( &ctx.fugue, hash6, hash6, 64 );
     fugue512_full( &ctx.fugue, hash7, hash7, 64 );

     intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                      hash7 );

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, 64 );
     shabal512_8way_close( &ctx.shabal, vhash );

     dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                       vhash );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, 64 );

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                      hash7 );

     sha512_8way_init( &ctx.sha512 );
     sha512_8way_update( &ctx.sha512, vhash, 64 );
     sha512_8way_close( &ctx.sha512, vhash );

     rintrlv_8x64_8x32( vhashA, vhash,  512 );

     haval256_5_8way_init( &ctx.haval );
     haval256_5_8way_update( &ctx.haval, vhashA, 64 );
     haval256_5_8way_close( &ctx.haval, state );

     return 1;
}

int scanhash_x17_8way( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   __m128i edata[5] __attribute__ ((aligned (64)));
   uint32_t *hash32_d7 = &(hash32[7*8]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32_d7 = ptarget[7];
   const __m512i eight = _mm512_set1_epi64( 8 );
   const bool bench = opt_benchmark;

   // convert LE32 to LE64
   edata[0] = mm128_swap64_32( casti_m128i( pdata, 0 ) );
   edata[1] = mm128_swap64_32( casti_m128i( pdata, 1 ) );
   edata[2] = mm128_swap64_32( casti_m128i( pdata, 2 ) );
   edata[3] = mm128_swap64_32( casti_m128i( pdata, 3 ) );
   edata[4] = mm128_swap64_32( casti_m128i( pdata, 4 ) );

   mm512_intrlv80_8x64( vdata, edata );
   *noncev = _mm512_add_epi32( *noncev, _mm512_set_epi32(
                                    0,7, 0,6, 0,5, 0,4, 0,3, 0,2, 0,1, 0,0 ) );
   blake512_8way_prehash_le( &blake512_8way_ctx, x17_8way_midstate, vdata );
   
   do
   {
      if ( likely( x17_8way_hash( hash32, vdata, thr_id ) ) )
      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( ( hash32_d7[ lane ] <= targ32_d7 ) && !bench ) )
      {
         extr_lane_8x32( lane_hash, hash32, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) ) )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm512_add_epi32( *noncev, eight );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(X17_4WAY)

union _x17_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
#if defined(__VAES__)
    groestl512_2way_context groestl;
    echo512_2way_context    echo;
#else
    hashState_groestl       groestl;
    hashState_echo          echo;
#endif
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cube_2way_context       cube;
    shavite512_2way_context shavite;
    simd_2way_context       simd;
    hamsi512_4way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
};  
typedef union _x17_4way_context_overlay x17_4way_context_overlay;

static __thread __m256i x17_4way_midstate[16] __attribute__((aligned(64)));
static __thread blake512_4way_context blake512_4way_ctx __attribute__((aligned(64)));

int x17_4way_hash( void *state, const void *input, int thr_id )
{
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
     uint64_t hash0[8] __attribute__ ((aligned (32)));
     uint64_t hash1[8] __attribute__ ((aligned (32)));
     uint64_t hash2[8] __attribute__ ((aligned (32)));
     uint64_t hash3[8] __attribute__ ((aligned (32)));
     x17_4way_context_overlay ctx;

     blake512_4way_final_le( &blake512_4way_ctx, vhash, casti_m256i( input, 9 ),
                             x17_4way_midstate );
     
//     blake512_4way_full( &ctx.blake, vhash, input, 80 );

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way_update( &ctx.bmw, vhash, 64 );
     bmw512_4way_close( &ctx.bmw, vhash );

#if defined(__VAES__)

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

     groestl512_2way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_2way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );

#else
     
     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

#endif

     skein512_4way_full( &ctx.skein, vhash, vhash, 64 );

     jh512_4way_init( &ctx.jh );
     jh512_4way_update( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way_update( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

     luffa512_2way_full( &ctx.luffa, vhashA, vhashA, 64 );
     luffa512_2way_full( &ctx.luffa, vhashB, vhashB, 64 );

     cube_2way_full( &ctx.cube, vhashA, 512, vhashA, 64 );
     cube_2way_full( &ctx.cube, vhashB, 512, vhashB, 64 );

     shavite512_2way_full( &ctx.shavite, vhashA, vhashA, 64 );
     shavite512_2way_full( &ctx.shavite, vhashB, vhashB, 64 );

     simd512_2way_full( &ctx.simd, vhashA, vhashA, 64 );
     simd512_2way_full( &ctx.simd, vhashB, vhashB, 64 );

#if defined(__VAES__)

     echo_2way_full( &ctx.echo, vhashA, 512, vhashA, 64 );
     echo_2way_full( &ctx.echo, vhashB, 512, vhashB, 64 );

     rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_2x128_512( hash0, hash1, vhashA );
     dintrlv_2x128_512( hash2, hash3, vhashB );

     echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                     (const BitSequence *)hash0, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                     (const BitSequence *)hash1, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                     (const BitSequence *)hash2, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                     (const BitSequence *)hash3, 64 );

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

#endif

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );

     intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

     shabal512_4way_init( &ctx.shabal );
     shabal512_4way_update( &ctx.shabal, vhash, 64 );
     shabal512_4way_close( &ctx.shabal, vhash );

     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );
       
     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way_update( &ctx.sha512, vhash, 64 );
     sha512_4way_close( &ctx.sha512, vhash );     

     rintrlv_4x64_4x32( vhashB, vhash,  512 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way_update( &ctx.haval, vhashB, 64 );
     haval256_5_4way_close( &ctx.haval, state );

     return 1;
}

int scanhash_x17_4way( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8*4] __attribute__ ((aligned (128)));
   uint32_t vdata[20*4] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   __m128i edata[5] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *hash32_d7 = &(hash32[7*4]);
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   __m256i  *noncev = (__m256i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32_d7 = ptarget[7];
   const __m256i four = _mm256_set1_epi64x( 4 );
   const bool bench = opt_benchmark;

   // convert LE32 to LE64
   edata[0] = mm128_swap64_32( casti_m128i( pdata, 0 ) );
   edata[1] = mm128_swap64_32( casti_m128i( pdata, 1 ) );
   edata[2] = mm128_swap64_32( casti_m128i( pdata, 2 ) );
   edata[3] = mm128_swap64_32( casti_m128i( pdata, 3 ) );
   edata[4] = mm128_swap64_32( casti_m128i( pdata, 4 ) );

   mm256_intrlv80_4x64( vdata, edata );
   *noncev = _mm256_add_epi32( *noncev, _mm256_set_epi32( 0,3,0,2, 0,1,0,0 ) );
   blake512_4way_prehash_le( &blake512_4way_ctx, x17_4way_midstate, vdata );

   do
   {
      if ( likely( x17_4way_hash( hash32, vdata, thr_id ) ) )
      for ( int lane = 0; lane < 4; lane++ )
      if ( unlikely( ( hash32_d7[ lane ] <= targ32_d7 ) && !bench ) )
      {
         extr_lane_4x32( lane_hash, hash32, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) ) )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm256_add_epi32( *noncev, four );
      n += 4;
   } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
