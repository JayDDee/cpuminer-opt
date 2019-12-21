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
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/sha/sha-hash-4way.h"

#if defined(X17_8WAY)

union _x17_8way_context_overlay
{
    blake512_8way_context   blake;
    bmw512_8way_context     bmw;
    hashState_groestl       groestl;
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    keccak512_8way_context  keccak;
    luffa_4way_context      luffa;
    cube_4way_context       cube;
    sph_shavite512_context  shavite;
    simd_4way_context       simd;
    hashState_echo          echo;
    hamsi512_8way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_8way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_8way_context     sha512;
    haval256_5_8way_context haval;
} __attribute__ ((aligned (64)));
typedef union _x17_8way_context_overlay x17_8way_context_overlay;

void x17_8way_hash( void *state, const void *input )
{
     uint64_t vhash[8*8] __attribute__ ((aligned (128)));
     uint64_t vhash0[8*8] __attribute__ ((aligned (64)));
     uint64_t vhash1[8*8] __attribute__ ((aligned (64)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t hash4[8] __attribute__ ((aligned (64)));
     uint64_t hash5[8] __attribute__ ((aligned (64)));
     uint64_t hash6[8] __attribute__ ((aligned (64)));
     uint64_t hash7[8] __attribute__ ((aligned (64)));
     x17_8way_context_overlay ctx;

     // 1 Blake parallel 4 way 64 bit
     blake512_8way_init( &ctx.blake );
     blake512_8way_update( &ctx.blake, input, 80 );
     blake512_8way_close( &ctx.blake, vhash );

     // 2 Bmw
     bmw512_8way_init( &ctx.bmw );
     bmw512_8way_update( &ctx.bmw, vhash, 64 );
     bmw512_8way_close( &ctx.bmw, vhash );

     // Serialize
     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash );

     // 3 Groestl
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

     // Parallellize
     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7 );

     // 4 Skein parallel 4 way 64 bit 
     skein512_8way_init( &ctx.skein );
     skein512_8way_update( &ctx.skein, vhash, 64 );
     skein512_8way_close( &ctx.skein, vhash );

     // 5 JH
     jh512_8way_init( &ctx.jh );
     jh512_8way_update( &ctx.jh, vhash, 64 );
     jh512_8way_close( &ctx.jh, vhash );

     // 6 Keccak
     keccak512_8way_init( &ctx.keccak );
     keccak512_8way_update( &ctx.keccak, vhash, 64 );
     keccak512_8way_close( &ctx.keccak, vhash );

     rintrlv_8x64_4x128( vhash0, vhash1, vhash, 512 );

     // 7 Luffa  
     luffa_4way_init( &ctx.luffa, 512 );
     luffa_4way_update_close( &ctx.luffa, vhash0, vhash0, 64 );
     luffa_4way_init( &ctx.luffa, 512 );
     luffa_4way_update_close( &ctx.luffa, vhash1, vhash1, 64 );

     // 8 Cubehash
     cube_4way_init( &ctx.cube, 512, 16, 32 );
     cube_4way_update_close( &ctx.cube, vhash0, vhash0, 64 );
     cube_4way_init( &ctx.cube, 512, 16, 32 );
     cube_4way_update_close( &ctx.cube, vhash1, vhash1, 64 );

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash0 );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash1 );

     // 9 Shavite
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash4, 64 );
     sph_shavite512_close( &ctx.shavite, hash4 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash5, 64 );
     sph_shavite512_close( &ctx.shavite, hash5 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash6, 64 );
     sph_shavite512_close( &ctx.shavite, hash6 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash7, 64 );
     sph_shavite512_close( &ctx.shavite, hash7 );

     // 10 Simd
     intrlv_4x128_512( vhash, hash0, hash1, hash2, hash3 );
     simd_4way_init( &ctx.simd, 512 );
     simd_4way_update_close( &ctx.simd, vhash, vhash, 512 );
     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
     intrlv_4x128_512( vhash, hash4, hash5, hash6, hash7 );
     simd_4way_init( &ctx.simd, 512 );
     simd_4way_update_close( &ctx.simd, vhash, vhash, 512 );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );


     // 11 Echo serial
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                            (const BitSequence *) hash0, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                            (const BitSequence *) hash1, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                            (const BitSequence *) hash2, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                            (const BitSequence *) hash3, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash4,
                            (const BitSequence *) hash4, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash5,
                            (const BitSequence *) hash5, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash6,
                            (const BitSequence *) hash6, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash7,
                            (const BitSequence *) hash7, 512 );

     // 12 Hamsi parallel 4 way 64 bit
     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                      hash7 );

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                       vhash );

     // 13 Fugue serial
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash0, 64 );
     sph_fugue512_close( &ctx.fugue, hash0 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash1, 64 );
     sph_fugue512_close( &ctx.fugue, hash1 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash2, 64 );
     sph_fugue512_close( &ctx.fugue, hash2 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash3, 64 );
     sph_fugue512_close( &ctx.fugue, hash3 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash4, 64 );
     sph_fugue512_close( &ctx.fugue, hash4 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash5, 64 );
     sph_fugue512_close( &ctx.fugue, hash5 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash6, 64 );
     sph_fugue512_close( &ctx.fugue, hash6 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash7, 64 );
     sph_fugue512_close( &ctx.fugue, hash7 );

     // 14 Shabal, parallel 4 way 32 bit
     intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                      hash7 );

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, 64 );
     shabal512_8way_close( &ctx.shabal, vhash );

     dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                       vhash );

     // 15 Whirlpool serial
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash0, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash1, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash2, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash3, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash4, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash4 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash5, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash5 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash6, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash6 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash7, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash7 );

     // 16 SHA512 parallel 64 bit 
     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                      hash7 );

     sha512_8way_init( &ctx.sha512 );
     sha512_8way_update( &ctx.sha512, vhash, 64 );
     sha512_8way_close( &ctx.sha512, vhash );

     // 17 Haval parallel 32 bit
     rintrlv_8x64_8x32( vhash0, vhash,  512 );

     haval256_5_8way_init( &ctx.haval );
     haval256_5_8way_update( &ctx.haval, vhash0, 64 );
     haval256_5_8way_close( &ctx.haval, state );
}

int scanhash_x17_8way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*16] __attribute__ ((aligned (128)));
   uint32_t vdata[24*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<3]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
     const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t Htarg = ptarget[7];

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   do
   {
      *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n,   0 ) ), *noncev );
      x17_8way_hash( hash, vdata );

      for ( int lane = 0; lane < 8; lane++ )
      if unlikely( ( hash7[ lane ] <= Htarg ) )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( likely( fulltest( lane_hash, ptarget ) && !opt_benchmark ) )
         {
            pdata[19] = n + lane;
            submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      n += 8;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );

   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(X17_4WAY)

union _x17_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cube_2way_context       cube;
    shavite512_2way_context shavite;
    simd_2way_context       simd;
    hashState_echo          echo;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
};  
typedef union _x17_4way_context_overlay x17_4way_context_overlay;

void x17_4way_hash( void *state, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
     x17_4way_context_overlay ctx;

     // 1 Blake parallel 4 way 64 bit
     blake512_4way_init( &ctx.blake );
     blake512_4way( &ctx.blake, input, 80 );
     blake512_4way_close( &ctx.blake, vhash );

     // 2 Bmw
     bmw512_4way_init( &ctx.bmw );
     bmw512_4way( &ctx.bmw, vhash, 64 );
     bmw512_4way_close( &ctx.bmw, vhash );

     // Serialize
     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     // 3 Groestl
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

     // Parallellize
     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

     // 4 Skein parallel 4 way 64 bit 
     skein512_4way_init( &ctx.skein );
     skein512_4way( &ctx.skein, vhash, 64 );
     skein512_4way_close( &ctx.skein, vhash );

     // 5 JH
     jh512_4way_init( &ctx.jh );
     jh512_4way( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     // 6 Keccak
     keccak512_4way_init( &ctx.keccak );
     keccak512_4way( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

     // 7 Luffa  parallel 2 way 128 bit
     rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhashA, vhashA, 64 );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhashB, vhashB, 64 );

     // 8 Cubehash
     cube_2way_init( &ctx.cube, 512, 16, 32 );
     cube_2way_update_close( &ctx.cube, vhashA, vhashA, 64 );
     cube_2way_init( &ctx.cube, 512, 16, 32 );
     cube_2way_update_close( &ctx.cube, vhashB, vhashB, 64 );

     // 9 Shavite
     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashA, vhashA, 64 );
     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashB, vhashB, 64 );

     // 10 Simd
     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashA, vhashA, 512 );
     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashB, vhashB, 512 );

     dintrlv_2x128_512( hash0, hash1, vhashA );
     dintrlv_2x128_512( hash2, hash3, vhashB );


     // 11 Echo serial
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     init_echo( &ctx.echo, 512 );     
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     init_echo( &ctx.echo, 512 );     
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     init_echo( &ctx.echo, 512 );     
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );

     // 12 Hamsi parallel 4 way 64 bit
     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way( &ctx.hamsi, vhash, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     // 13 Fugue serial
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash0, 64 );
     sph_fugue512_close( &ctx.fugue, hash0 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash1, 64 );
     sph_fugue512_close( &ctx.fugue, hash1 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash2, 64 );
     sph_fugue512_close( &ctx.fugue, hash2 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash3, 64 );
     sph_fugue512_close( &ctx.fugue, hash3 );

     // 14 Shabal, parallel 4 way 32 bit
     intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

     shabal512_4way_init( &ctx.shabal );
     shabal512_4way( &ctx.shabal, vhash, 64 );
     shabal512_4way_close( &ctx.shabal, vhash );

     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );
       
     // 15 Whirlpool serial
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash0, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash1, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash2, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash3, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );

     // 16 SHA512 parallel 64 bit 
     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way( &ctx.sha512, vhash, 64 );
     sha512_4way_close( &ctx.sha512, vhash );     

     // 17 Haval parallel 32 bit
     rintrlv_4x64_4x32( vhashB, vhash,  512 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way( &ctx.haval, vhashB, 64 );
     haval256_5_4way_close( &ctx.haval, state );
}

int scanhash_x17_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t Htarg = ptarget[7];

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   do
   {
      *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
              _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );
      x17_4way_hash( hash, vdata );

      for ( int lane = 0; lane < 4; lane++ )
      if unlikely( ( hash7[ lane ] <= Htarg ) )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( likely( fulltest( lane_hash, ptarget ) && !opt_benchmark ) )
         {
            pdata[19] = n + lane;
            submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      n += 4;
   } while ( likely( ( n < max_nonce - 4 ) && !work_restart[thr_id].restart ) );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
