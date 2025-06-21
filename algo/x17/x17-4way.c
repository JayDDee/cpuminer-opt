#include "x17-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/blake512-hash.h"
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
#include "algo/sha/sha512-hash.h"

#if defined(X17_16X32)

union _x17_16way_context_overlay
{
    blake512_8x64_context    blake;
    bmw512_8x64_context      bmw;
    skein512_8x64_context    skein;
    jh512_8x64_context       jh;
    keccak512_8x64_context   keccak;
    luffa_4way_context       luffa;
    cube_4way_2buf_context   cube;
#if defined(__VAES__)
    groestl512_4way_context  groestl;
    shavite512_4way_context  shavite;
    echo_4way_context        echo;
#else
    hashState_groestl        groestl;
    sph_shavite512_context   shavite;
    hashState_echo           echo;
#endif
    simd_4way_context        simd;
    hamsi512_8x64_context    hamsi;
    hashState_fugue          fugue;
    shabal512_16x32_context  shabal;
    sph_whirlpool_context    whirlpool;
    sha512_8x64_context      sha512;
    haval256_16x32_context   haval;
} __attribute__ ((aligned (64)));
typedef union _x17_16way_context_overlay x17_16way_context_overlay;

static __thread __m512i x17_16way_midstate[16] __attribute__((aligned(64)));
static __thread blake512_8x64_context blake512_8x64_ctx __attribute__((aligned(64)));

int x17_16x64_hash( void *state, const __m512i nonceA, const __m512i nonceB,
                    int thr_id )
{
     uint64_t vhashA[8*16] __attribute__ ((aligned (128)));
     uint64_t vhashB[8*8]  __attribute__ ((aligned (64)));
     uint64_t vhashC[8*4]  __attribute__ ((aligned (64)));
     uint64_t vhashD[8*4]  __attribute__ ((aligned (64)));
     uint64_t hash00[8] __attribute__ ((aligned (32)));
     uint64_t hash01[8] __attribute__ ((aligned (32)));
     uint64_t hash02[8] __attribute__ ((aligned (32)));
     uint64_t hash03[8] __attribute__ ((aligned (32)));
     uint64_t hash04[8] __attribute__ ((aligned (32)));
     uint64_t hash05[8] __attribute__ ((aligned (32)));
     uint64_t hash06[8] __attribute__ ((aligned (32)));
     uint64_t hash07[8] __attribute__ ((aligned (32)));
     uint64_t hash08[8] __attribute__ ((aligned (32)));
     uint64_t hash09[8] __attribute__ ((aligned (32)));
     uint64_t hash10[8] __attribute__ ((aligned (32)));
     uint64_t hash11[8] __attribute__ ((aligned (32)));
     uint64_t hash12[8] __attribute__ ((aligned (32)));
     uint64_t hash13[8] __attribute__ ((aligned (32)));
     uint64_t hash14[8] __attribute__ ((aligned (32)));
     uint64_t hash15[8] __attribute__ ((aligned (32)));
     x17_16way_context_overlay ctx;

     memcpy( &ctx.blake, &blake512_8x64_ctx, sizeof (blake512_8x64_ctx) );
     blake512_8x64_final_le( &blake512_8x64_ctx, vhashA, nonceA,
                                                 x17_16way_midstate );
     blake512_8x64_final_le( &ctx.blake, vhashB, nonceB,
                                                 x17_16way_midstate );

     bmw512_8x64_full( &ctx.bmw, vhashA, vhashA, 64 );
     bmw512_8x64_full( &ctx.bmw, vhashB, vhashB, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashC, vhashD, vhashA, 512 );
     groestl512_4way_full( &ctx.groestl, vhashC, vhashC, 64 );
     groestl512_4way_full( &ctx.groestl, vhashD, vhashD, 64 );
     rintrlv_4x128_8x64( vhashA, vhashC, vhashD, 512 );

     rintrlv_8x64_4x128( vhashC, vhashD, vhashB, 512 );
     groestl512_4way_full( &ctx.groestl, vhashC, vhashC, 64 );
     groestl512_4way_full( &ctx.groestl, vhashD, vhashD, 64 );
     rintrlv_4x128_8x64( vhashA, vhashC, vhashD, 512 );
     
#else

     dintrlv_8x64_512( hash00, hash01, hash02, hash03,
                       hash04, hash05, hash06, hash07, vhashA );
     dintrlv_8x64_512( hash08, hash09, hash10, hash11,
                       hash12, hash13, hash14, hash15, vhashB );

     groestl512_full( &ctx.groestl, (char*)hash00, (char*)hash00, 512 );
     groestl512_full( &ctx.groestl, (char*)hash01, (char*)hash01, 512 );
     groestl512_full( &ctx.groestl, (char*)hash02, (char*)hash02, 512 );
     groestl512_full( &ctx.groestl, (char*)hash03, (char*)hash03, 512 );
     groestl512_full( &ctx.groestl, (char*)hash04, (char*)hash04, 512 );
     groestl512_full( &ctx.groestl, (char*)hash05, (char*)hash05, 512 );
     groestl512_full( &ctx.groestl, (char*)hash06, (char*)hash06, 512 );
     groestl512_full( &ctx.groestl, (char*)hash07, (char*)hash07, 512 );
     groestl512_full( &ctx.groestl, (char*)hash08, (char*)hash08, 512 );
     groestl512_full( &ctx.groestl, (char*)hash09, (char*)hash09, 512 );
     groestl512_full( &ctx.groestl, (char*)hash10, (char*)hash10, 512 );
     groestl512_full( &ctx.groestl, (char*)hash11, (char*)hash11, 512 );
     groestl512_full( &ctx.groestl, (char*)hash12, (char*)hash12, 512 );
     groestl512_full( &ctx.groestl, (char*)hash13, (char*)hash13, 512 );
     groestl512_full( &ctx.groestl, (char*)hash14, (char*)hash14, 512 );
     groestl512_full( &ctx.groestl, (char*)hash15, (char*)hash15, 512 );

     intrlv_8x64_512( vhashA, hash00, hash01, hash02, hash03, 
                              hash04, hash05, hash06, hash07 );
     intrlv_8x64_512( vhashB, hash08, hash09, hash10, hash11,
                              hash12, hash13, hash14, hash15 );

#endif

     skein512_8x64_full( &ctx.skein, vhashA, vhashA, 64 );
     skein512_8x64_full( &ctx.skein, vhashB, vhashB, 64 );

     jh512_8x64_init( &ctx.jh );
     jh512_8x64_update( &ctx.jh, vhashA, 64 );
     jh512_8x64_close( &ctx.jh, vhashA );
     jh512_8x64_init( &ctx.jh );
     jh512_8x64_update( &ctx.jh, vhashB, 64 );
     jh512_8x64_close( &ctx.jh, vhashB );

     keccak512_8x64_init( &ctx.keccak );
     keccak512_8x64_update( &ctx.keccak, vhashA, 64 );
     keccak512_8x64_close( &ctx.keccak, vhashA );
     keccak512_8x64_init( &ctx.keccak );
     keccak512_8x64_update( &ctx.keccak, vhashB, 64 );
     keccak512_8x64_close( &ctx.keccak, vhashB );

//
     rintrlv_8x64_4x128( vhashC, vhashD, vhashA, 512 );

     luffa512_4way_full( &ctx.luffa, vhashC, vhashC, 64 );
     luffa512_4way_full( &ctx.luffa, vhashD, vhashD, 64 );

     cube_4way_2buf_full( &ctx.cube, vhashC, vhashD, 512, vhashC, vhashD, 64 );

#if defined(__VAES__)

     shavite512_4way_full( &ctx.shavite, vhashC, vhashC, 64 );
     shavite512_4way_full( &ctx.shavite, vhashD, vhashD, 64 );

#else

     dintrlv_4x128_512( hash00, hash01, hash02, hash03, vhashC );
     dintrlv_4x128_512( hash04, hash05, hash06, hash07, vhashD );

     shavite512_full( &ctx.shavite, hash00, hash00, 64 );
     shavite512_full( &ctx.shavite, hash01, hash01, 64 );
     shavite512_full( &ctx.shavite, hash02, hash02, 64 );
     shavite512_full( &ctx.shavite, hash03, hash03, 64 );
     shavite512_full( &ctx.shavite, hash04, hash04, 64 );
     shavite512_full( &ctx.shavite, hash05, hash05, 64 );
     shavite512_full( &ctx.shavite, hash06, hash06, 64 );
     shavite512_full( &ctx.shavite, hash07, hash07, 64 );

     intrlv_4x128_512( vhashC, hash00, hash01, hash02, hash03 );
     intrlv_4x128_512( vhashD, hash04, hash05, hash06, hash07 );

#endif

     simd512_4way_full( &ctx.simd, vhashC, vhashC, 64 );
     simd512_4way_full( &ctx.simd, vhashD, vhashD, 64 );

#if defined(__VAES__)

     echo_4way_full( &ctx.echo, vhashC, 512, vhashC, 64 );
     echo_4way_full( &ctx.echo, vhashD, 512, vhashD, 64 );

     rintrlv_4x128_8x64( vhashA, vhashC, vhashD, 512 );

#else

     dintrlv_4x128_512( hash00, hash01, hash02, hash03, vhashC );
     dintrlv_4x128_512( hash04, hash05, hash06, hash07, vhashD );

     echo_full( &ctx.echo, (BitSequence *)hash00, 512,
                     (const BitSequence *)hash00, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash01, 512,
                     (const BitSequence *)hash01, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash02, 512,
                     (const BitSequence *)hash02, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash03, 512,
                     (const BitSequence *)hash03, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash04, 512,
                     (const BitSequence *)hash04, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash05, 512,
                     (const BitSequence *)hash05, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash06, 512,
                     (const BitSequence *)hash06, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash07, 512,
                     (const BitSequence *)hash07, 64 );

     intrlv_8x64_512( vhashA, hash00, hash01, hash02, hash03,
                              hash04, hash05, hash06, hash07 );

#endif

//

     rintrlv_8x64_4x128( vhashC, vhashD, vhashB, 512 );

     luffa512_4way_full( &ctx.luffa, vhashC, vhashC, 64 );
     luffa512_4way_full( &ctx.luffa, vhashD, vhashD, 64 );

     cube_4way_2buf_full( &ctx.cube, vhashC, vhashD, 512, vhashC, vhashD, 64 );

#if defined(__VAES__)

     shavite512_4way_full( &ctx.shavite, vhashC, vhashC, 64 );
     shavite512_4way_full( &ctx.shavite, vhashD, vhashD, 64 );

#else

     dintrlv_4x128_512( hash08, hash09, hash10, hash11, vhashC );
     dintrlv_4x128_512( hash12, hash13, hash14, hash15, vhashD );

     shavite512_full( &ctx.shavite, hash08, hash08, 64 );
     shavite512_full( &ctx.shavite, hash09, hash09, 64 );
     shavite512_full( &ctx.shavite, hash10, hash10, 64 );
     shavite512_full( &ctx.shavite, hash11, hash11, 64 );
     shavite512_full( &ctx.shavite, hash12, hash12, 64 );
     shavite512_full( &ctx.shavite, hash13, hash13, 64 );
     shavite512_full( &ctx.shavite, hash14, hash14, 64 );
     shavite512_full( &ctx.shavite, hash15, hash15, 64 );

     intrlv_4x128_512( vhashC, hash08, hash09, hash10, hash11 );
     intrlv_4x128_512( vhashD, hash12, hash13, hash14, hash15 );

#endif

     simd512_4way_full( &ctx.simd, vhashC, vhashC, 64 );
     simd512_4way_full( &ctx.simd, vhashD, vhashD, 64 );

#if defined(__VAES__)

     echo_4way_full( &ctx.echo, vhashC, 512, vhashC, 64 );
     echo_4way_full( &ctx.echo, vhashD, 512, vhashD, 64 );

     rintrlv_4x128_8x64( vhashB, vhashC, vhashD, 512 );

#else

     dintrlv_4x128_512( hash08, hash09, hash10, hash11, vhashC );
     dintrlv_4x128_512( hash12, hash13, hash14, hash15, vhashD );

     echo_full( &ctx.echo, (BitSequence *)hash08, 512,
                     (const BitSequence *)hash08, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash09, 512,
                     (const BitSequence *)hash09, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash10, 512,
                     (const BitSequence *)hash10, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash11, 512,
                     (const BitSequence *)hash11, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash12, 512,
                     (const BitSequence *)hash12, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash13, 512,
                     (const BitSequence *)hash13, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash14, 512,
                     (const BitSequence *)hash14, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash15, 512,
                     (const BitSequence *)hash15, 64 );

     intrlv_8x64_512( vhashB, hash08, hash09, hash10, hash11,
                              hash12, hash13, hash14, hash15 );

#endif

//
/*
     intrlv_16x32( vhashA, hash00, hash01, hash02, hash03,
                           hash04, hash05, hash06, hash07,
                           hash08, hash09, hash10, hash11,
                           hash12, hash13, hash14, hash15, 512 );
     hamsi512_16x32_full( &ctx.hamsi, vhashA, vhashA, 64 );
     dintrlv_16x32( hash00, hash01, hash02, hash03,
                    hash04, hash05, hash06, hash07,
                    hash08, hash09, hash10, hash11,
                    hash12, hash13, hash14, hash15, vhashA, 512 );
*/

     
     hamsi512_8x64_init( &ctx.hamsi );
     hamsi512_8x64_update( &ctx.hamsi, vhashA, 64 );
     hamsi512_8x64_close( &ctx.hamsi, vhashA );
     dintrlv_8x64_512( hash00, hash01, hash02, hash03,
                       hash04, hash05, hash06, hash07, vhashA );
     hamsi512_8x64_init( &ctx.hamsi );
     hamsi512_8x64_update( &ctx.hamsi, vhashB, 64 );
     hamsi512_8x64_close( &ctx.hamsi, vhashB );
     dintrlv_8x64_512( hash08, hash09, hash10, hash11,
                       hash12, hash13, hash14, hash15, vhashB );

     fugue512_full( &ctx.fugue, hash00, hash00, 64 );
     fugue512_full( &ctx.fugue, hash01, hash01, 64 );
     fugue512_full( &ctx.fugue, hash02, hash02, 64 );
     fugue512_full( &ctx.fugue, hash03, hash03, 64 );
     fugue512_full( &ctx.fugue, hash04, hash04, 64 );
     fugue512_full( &ctx.fugue, hash05, hash05, 64 );
     fugue512_full( &ctx.fugue, hash06, hash06, 64 );
     fugue512_full( &ctx.fugue, hash07, hash07, 64 );
     fugue512_full( &ctx.fugue, hash08, hash08, 64 );
     fugue512_full( &ctx.fugue, hash09, hash09, 64 );
     fugue512_full( &ctx.fugue, hash10, hash10, 64 );
     fugue512_full( &ctx.fugue, hash11, hash11, 64 );
     fugue512_full( &ctx.fugue, hash12, hash12, 64 );
     fugue512_full( &ctx.fugue, hash13, hash13, 64 );
     fugue512_full( &ctx.fugue, hash14, hash14, 64 );
     fugue512_full( &ctx.fugue, hash15, hash15, 64 );

     intrlv_16x32_512( vhashA, hash00, hash01, hash02, hash03,
                               hash04, hash05, hash06, hash07,
                               hash08, hash09, hash10, hash11,
                               hash12, hash13, hash14, hash15 );

     shabal512_16x32_init( &ctx.shabal );
     shabal512_16x32_update( &ctx.shabal, vhashA, 64 );
     shabal512_16x32_close( &ctx.shabal, vhashA );

     dintrlv_16x32_512( hash00, hash01, hash02, hash03,
                        hash04, hash05, hash06, hash07,
                        hash08, hash09, hash10, hash11,
                        hash12, hash13, hash14, hash15, vhashA );

     sph_whirlpool512_full( &ctx.whirlpool, hash00, hash00, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash01, hash01, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash02, hash02, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash03, hash03, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash04, hash04, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash05, hash05, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash06, hash06, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash07, hash07, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash08, hash08, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash09, hash09, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash10, hash10, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash11, hash11, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash12, hash12, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash13, hash13, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash14, hash14, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash15, hash15, 64 );

     intrlv_8x64_512( vhashA, hash00, hash01, hash02, hash03,
                              hash04, hash05, hash06, hash07 );
     intrlv_8x64_512( vhashB, hash08, hash09, hash10, hash11,
                              hash12, hash13, hash14, hash15 );

     sha512_8x64_init( &ctx.sha512 );
     sha512_8x64_update( &ctx.sha512, vhashA, 64 );
     sha512_8x64_close( &ctx.sha512, vhashA );
     sha512_8x64_init( &ctx.sha512 );
     sha512_8x64_update( &ctx.sha512, vhashB, 64 );
     sha512_8x64_close( &ctx.sha512, vhashB );

     dintrlv_8x64_512( hash00, hash01, hash02, hash03,
                       hash04, hash05, hash06, hash07, vhashA );
     dintrlv_8x64_512( hash08, hash09, hash10, hash11,
                       hash12, hash13, hash14, hash15, vhashB );
     intrlv_16x32_512( vhashA, hash00, hash01, hash02, hash03,
                               hash04, hash05, hash06, hash07,
                               hash08, hash09, hash10, hash11,
                               hash12, hash13, hash14, hash15 );

     haval256_16x32_init( &ctx.haval );
     haval256_16x32_update( &ctx.haval, vhashA, 64 );
     haval256_16x32_close( &ctx.haval, state );

     return 1;
}

int scanhash_x17_16x32( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8*16] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8]  __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   __m128i edata[5]      __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   uint32_t *hash32_d7 = &(hash32[7*16]);
   const uint32_t targ32_d7 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  nonceA, nonceB;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const __m512i sixteen = v512_64( 16 );
   const bool bench = opt_benchmark;

   // convert LE32 to LE64
   edata[0] = v128_swap64_32( casti_v128u32( pdata, 0 ) );
   edata[1] = v128_swap64_32( casti_v128u32( pdata, 1 ) );
   edata[2] = v128_swap64_32( casti_v128u32( pdata, 2 ) );
   edata[3] = v128_swap64_32( casti_v128u32( pdata, 3 ) );
   edata[4] = v128_swap64_32( casti_v128u32( pdata, 4 ) );

   mm512_intrlv80_8x64( vdata, edata );
   blake512_8x64_prehash_le( &blake512_8x64_ctx, x17_16way_midstate, vdata );

   nonceA = _mm512_add_epi32( casti_m512i( vdata, 9 ),
                              _mm512_set_epi64( 7, 6, 5, 4, 3, 2, 1, 0 ) );
   nonceB = _mm512_add_epi32( nonceA, v512_64( 8 ) );   
   do
   {
      if ( likely( x17_16way_hash( hash32, nonceA, nonceB, thr_id ) ) )
      for ( int lane = 0; lane < 16; lane++ )
      if ( unlikely( ( hash32_d7[ lane ] <= targ32_d7 ) ) )
      {
         extr_lane_16x32( lane_hash, hash32, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
            pdata[19] = n + lane;
            submit_solution( work, lane_hash, mythr );
         }
      }
      nonceA = _mm512_add_epi32( nonceA, sixteen );
      nonceB = _mm512_add_epi32( nonceB, sixteen );
      n += 16;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(X17_8WAY)

union _x17_8way_context_overlay
{
    blake512_8x64_context   blake;
    bmw512_8x64_context     bmw;
    skein512_8x64_context   skein;
    jh512_8x64_context      jh;
    keccak512_8x64_context  keccak;
    luffa_4way_context      luffa;
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
    hamsi512_8x64_context   hamsi;
    hashState_fugue         fugue;
    shabal512_8x32_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_8x64_context     sha512;
    haval256_8x32_context   haval;
} __attribute__ ((aligned (64)));
typedef union _x17_8way_context_overlay x17_8way_context_overlay;

static __thread __m512i x17_8way_midstate[16] __attribute__((aligned(64)));
static __thread blake512_8x64_context blake512_8x64_ctx __attribute__((aligned(64)));

int x17_8x64_hash( void *state, const void *input, int thr_id )
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

     blake512_8x64_final_le( &blake512_8x64_ctx, vhash, casti_m512i( input, 9 ),
                             x17_8way_midstate );
     
     bmw512_8x64_full( &ctx.bmw, vhash, vhash, 64 );

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

     skein512_8x64_full( &ctx.skein, vhash, vhash, 64 );

     jh512_8x64_init( &ctx.jh );
     jh512_8x64_update( &ctx.jh, vhash, 64 );
     jh512_8x64_close( &ctx.jh, vhash );

     keccak512_8x64_init( &ctx.keccak );
     keccak512_8x64_update( &ctx.keccak, vhash, 64 );
     keccak512_8x64_close( &ctx.keccak, vhash );

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

     hamsi512_8x64_init( &ctx.hamsi );
     hamsi512_8x64_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8x64_close( &ctx.hamsi, vhash );
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

     shabal512_8x32_init( &ctx.shabal );
     shabal512_8x32_update( &ctx.shabal, vhash, 64 );
     shabal512_8x32_close( &ctx.shabal, vhash );

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

     sha512_8x64_init( &ctx.sha512 );
     sha512_8x64_update( &ctx.sha512, vhash, 64 );
     sha512_8x64_close( &ctx.sha512, vhash );

     rintrlv_8x64_8x32( vhashA, vhash,  512 );

     haval256_8x32_init( &ctx.haval );
     haval256_8x32_update( &ctx.haval, vhashA, 64 );
     haval256_8x32_close( &ctx.haval, state );

     return 1;
}

int scanhash_x17_8x64( struct work *work, uint32_t max_nonce,
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
   edata[0] = v128_swap64_32( casti_v128u32( pdata, 0 ) );
   edata[1] = v128_swap64_32( casti_v128u32( pdata, 1 ) );
   edata[2] = v128_swap64_32( casti_v128u32( pdata, 2 ) );
   edata[3] = v128_swap64_32( casti_v128u32( pdata, 3 ) );
   edata[4] = v128_swap64_32( casti_v128u32( pdata, 4 ) );

   mm512_intrlv80_8x64( vdata, edata );
   *noncev = _mm512_add_epi32( *noncev, _mm512_set_epi32(
                                    0,7, 0,6, 0,5, 0,4, 0,3, 0,2, 0,1, 0,0 ) );
   blake512_8x64_prehash_le( &blake512_8x64_ctx, x17_8way_midstate, vdata );
   
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
    blake512_4x64_context   blake;
    bmw512_4x64_context     bmw;
#if defined(__VAES__)
    groestl512_2way_context groestl;
    echo512_2way_context    echo;
#else
    hashState_groestl       groestl;
    hashState_echo          echo;
#endif
    skein512_4x64_context   skein;
    jh512_4x64_context      jh;
    keccak512_4x64_context  keccak;
    luffa_2way_context      luffa;
    cube_2way_context       cube;
    shavite512_2way_context shavite;
    simd_2way_context       simd;
    hamsi512_4x64_context   hamsi;
    hashState_fugue         fugue;
    shabal512_4x32_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4x64_context     sha512;
    haval256_4x32_context   haval;
};  
typedef union _x17_4way_context_overlay x17_4way_context_overlay;

static __thread __m256i x17_4way_midstate[16] __attribute__((aligned(64)));
static __thread blake512_4x64_context blake512_4x64_ctx __attribute__((aligned(64)));

int x17_4x64_hash( void *state, const void *input, int thr_id )
{
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
     uint64_t hash0[8] __attribute__ ((aligned (32)));
     uint64_t hash1[8] __attribute__ ((aligned (32)));
     uint64_t hash2[8] __attribute__ ((aligned (32)));
     uint64_t hash3[8] __attribute__ ((aligned (32)));
     x17_4way_context_overlay ctx;

     blake512_4x64_final_le( &blake512_4x64_ctx, vhash, casti_m256i( input, 9 ),
                             x17_4way_midstate );
     
     bmw512_4x64_init( &ctx.bmw );
     bmw512_4x64_update( &ctx.bmw, vhash, 64 );
     bmw512_4x64_close( &ctx.bmw, vhash );

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

     jh512_4x64_init( &ctx.jh );
     jh512_4x64_update( &ctx.jh, vhash, 64 );
     jh512_4x64_close( &ctx.jh, vhash );

     keccak512_4x64_init( &ctx.keccak );
     keccak512_4x64_update( &ctx.keccak, vhash, 64 );
     keccak512_4x64_close( &ctx.keccak, vhash );

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

     hamsi512_4x64_init( &ctx.hamsi );
     hamsi512_4x64_update( &ctx.hamsi, vhash, 64 );
     hamsi512_4x64_close( &ctx.hamsi, vhash );

     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );

     intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

     shabal512_4x32_init( &ctx.shabal );
     shabal512_4x32_update( &ctx.shabal, vhash, 64 );
     shabal512_4x32_close( &ctx.shabal, vhash );

     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );
       
     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

     sha512_4x64_init( &ctx.sha512 );
     sha512_4x64_update( &ctx.sha512, vhash, 64 );
     sha512_4x64_close( &ctx.sha512, vhash );     

     rintrlv_4x64_4x32( vhashB, vhash,  512 );

     haval256_4x32_init( &ctx.haval );
     haval256_4x32_update( &ctx.haval, vhashB, 64 );
     haval256_4x32_close( &ctx.haval, state );

     return 1;
}

int scanhash_x17_4x64( struct work *work, uint32_t max_nonce,
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
   edata[0] = v128_swap64_32( casti_v128u32( pdata, 0 ) );
   edata[1] = v128_swap64_32( casti_v128u32( pdata, 1 ) );
   edata[2] = v128_swap64_32( casti_v128u32( pdata, 2 ) );
   edata[3] = v128_swap64_32( casti_v128u32( pdata, 3 ) );
   edata[4] = v128_swap64_32( casti_v128u32( pdata, 4 ) );

   mm256_intrlv80_4x64( vdata, edata );
   *noncev = _mm256_add_epi32( *noncev, _mm256_set_epi32( 0,3,0,2, 0,1,0,0 ) );
   blake512_4x64_prehash_le( &blake512_4x64_ctx, x17_4way_midstate, vdata );

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

#elif defined(X17_2X64)

#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#if !( defined(__SSE4_2__) || defined(__ARM_NEON) )
  #include "algo/hamsi/sph_hamsi.h"
#endif
#include "algo/shabal/sph_shabal.h"
#include "algo/haval/sph-haval.h"
#if !( defined(__AES__) || defined(__ARM_FEATURE_AES) )
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
  #include "algo/fugue/sph_fugue.h"
#endif

union _x17_context_overlay
{
        blake512_2x64_context   blake;
        bmw512_2x64_context     bmw;
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
        hashState_groestl       groestl;
#else
        sph_groestl512_context  groestl;
#endif        
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
        hashState_echo          echo;
#else
        sph_echo512_context     echo;
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
        hashState_fugue         fugue;
#else
        sph_fugue512_context    fugue;
#endif
        jh512_2x64_context      jh;
        keccak512_2x64_context  keccak;
        skein512_2x64_context   skein;
        hashState_luffa         luffa;
        cubehashParam           cube;
        sph_shavite512_context  shavite;
        simd512_context         simd;
#if defined(__SSE4_2__) || defined(__ARM_NEON)
        hamsi_2x64_context      hamsi;
#else
        sph_hamsi512_context    hamsi;
#endif
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sha512_2x64_context     sha;
        sph_haval256_5_context  haval;
};
typedef union _x17_context_overlay x17_context_overlay;

int x17_2x64_hash( void *output, const void *input, int thr_id )
{
    uint8_t vhash[80*2] __attribute__((aligned(64)));
    uint8_t hash0[64]   __attribute__((aligned(64)));
    uint8_t hash1[64]   __attribute__((aligned(64)));
    x17_context_overlay ctx;

    intrlv_2x64( vhash, input, input+80, 640 );

    blake512_2x64_full( &ctx.blake, vhash, vhash, 80 );
    bmw512_2x64_init( &ctx.bmw );
    bmw512_2x64_update( &ctx.bmw, vhash, 64 );
    bmw512_2x64_close( &ctx.bmw, vhash );

    dintrlv_2x64( hash0, hash1, vhash, 512 );

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    groestl512_full( &ctx.groestl, hash0, hash0, 512 );
    groestl512_full( &ctx.groestl, hash1, hash1, 512 );
#else
    sph_groestl512_init( &ctx.groestl );
    sph_groestl512( &ctx.groestl, hash0, 64 );
    sph_groestl512_close( &ctx.groestl, hash0 );
    sph_groestl512_init( &ctx.groestl );
    sph_groestl512( &ctx.groestl, hash1, 64 );
    sph_groestl512_close( &ctx.groestl, hash1 );
#endif

    intrlv_2x64( vhash, hash0, hash1, 512 );

    skein512_2x64_full( &ctx.skein, vhash, vhash, 64 );
    jh512_2x64_ctx( &ctx.jh, vhash, vhash, 64 );
    keccak512_2x64_ctx( &ctx.keccak, vhash, vhash, 64 );

    dintrlv_2x64( hash0, hash1, vhash, 512 );

    luffa_full( &ctx.luffa, hash0, 512, hash0, 64 );
    luffa_full( &ctx.luffa, hash1, 512, hash1, 64 );

    cubehash_full( &ctx.cube, hash0, 512, hash0, 64 );
    cubehash_full( &ctx.cube, hash1, 512, hash1, 64 );

    sph_shavite512_init( &ctx.shavite );
    sph_shavite512( &ctx.shavite, hash0, 64 );
    sph_shavite512_close( &ctx.shavite, hash0 );
    sph_shavite512_init( &ctx.shavite );
    sph_shavite512( &ctx.shavite, hash1, 64 );
    sph_shavite512_close( &ctx.shavite, hash1 );

    simd512_ctx( &ctx.simd, hash0, hash0, 64 );
    simd512_ctx( &ctx.simd, hash1, hash1, 64 );

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    echo_full( &ctx.echo, hash0, 512, hash0, 64 );
    echo_full( &ctx.echo, hash1, 512, hash1, 64 );
#else
    sph_echo512_init( &ctx.echo );
    sph_echo512( &ctx.echo, hash0, 64 );
    sph_echo512_close( &ctx.echo, hash0 );
    sph_echo512_init( &ctx.echo );
    sph_echo512( &ctx.echo, hash1, 64 );
    sph_echo512_close( &ctx.echo, hash1 );
#endif

#if defined(__SSE4_2__) || defined(__ARM_NEON)
    intrlv_2x64( vhash, hash0, hash1, 512 );
    hamsi512_2x64_ctx( &ctx.hamsi, vhash, vhash, 64 );
    dintrlv_2x64( hash0, hash1, vhash, 512 );
#else
    sph_hamsi512_init( &ctx.hamsi );
    sph_hamsi512( &ctx.hamsi, hash0, 64 );
    sph_hamsi512_close( &ctx.hamsi, hash0 );
    sph_hamsi512_init( &ctx.hamsi );
    sph_hamsi512( &ctx.hamsi, hash1, 64 );
    sph_hamsi512_close( &ctx.hamsi, hash1 );
#endif

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    fugue512_full( &ctx.fugue, hash0, hash0, 64 );
    fugue512_full( &ctx.fugue, hash1, hash1, 64 );
#else
    sph_fugue512_full( &ctx.fugue, hash0, hash0, 64 );
    sph_fugue512_full( &ctx.fugue, hash1, hash1, 64 );
#endif

    sph_shabal512_init( &ctx.shabal );
    sph_shabal512( &ctx.shabal, hash0, 64);
    sph_shabal512_close( &ctx.shabal, hash0 );
    sph_shabal512_init( &ctx.shabal );
    sph_shabal512(&ctx.shabal, hash1, 64);
    sph_shabal512_close( &ctx.shabal, hash1 );

    sph_whirlpool_init( &ctx.whirlpool );
    sph_whirlpool( &ctx.whirlpool, hash0, 64 );
    sph_whirlpool_close( &ctx.whirlpool, hash0 );
    sph_whirlpool_init( &ctx.whirlpool );
    sph_whirlpool( &ctx.whirlpool, hash1, 64 );
    sph_whirlpool_close( &ctx.whirlpool, hash1 );

    intrlv_2x64( vhash, hash0, hash1, 512 );
    sha512_2x64_ctx( &ctx.sha, vhash, vhash, 64 );
    dintrlv_2x64( hash0, hash1, vhash, 512 );

    sph_haval256_5_init( &ctx.haval );
    sph_haval256_5( &ctx.haval, hash0, 64 );
    sph_haval256_5_close( &ctx.haval, output );
    sph_haval256_5_init( &ctx.haval );
    sph_haval256_5( &ctx.haval, hash1, 64 );
    sph_haval256_5_close( &ctx.haval, output+32 );

    return 1;
}

int scanhash_x17_2x64( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*2]   __attribute__((aligned(64)));
//   uint32_t vdata[20*2] __attribute__((aligned(64)));
   uint32_t edata[20*2]   __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
//   const v128_t two = v128_64( 2 );

// convert LE32 to LE64 for 2 way blake512
//   edata[0] = v128_swap64_32( casti_v128( pdata, 0 ) );
//   edata[1] = v128_swap64_32( casti_v128( pdata, 1 ) );
//   edata[2] = v128_swap64_32( casti_v128( pdata, 2 ) );
//   edata[3] = v128_swap64_32( casti_v128( pdata, 3 ) );
//   edata[4] = v128_swap64_32( casti_v128( pdata, 4 ) );
//   vdata[9] = v128_add32( vdata[9], v128_set32( 0,1,0,0 ) );
//   blake512_2way_prehash_le( &blake512_2way_ctx, x17_2way_midstate, vdata );
//   v128_bswap32_intrlv80_2x64( vdata, edata );

   v128_bswap32_80( edata, pdata );
   memcpy( edata+20, edata, 80 );

   do
   {
      edata[19] = n;
      edata[39] = n+1;
      if ( likely( x17_2x64_hash( hash, edata, thr_id ) ) )
      {
         if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
         {
              pdata[19] = bswap_32( n );
//            pdata[19] = n;
            submit_solution( work, hash, mythr );
         }
         if ( unlikely( valid_hash( hash+8, ptarget ) && !bench ) )
         {
            pdata[19] = bswap_32( n+1 );
            submit_solution( work, hash+8, mythr );
         }
      }
      n += 2;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

#endif
