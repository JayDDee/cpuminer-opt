#include "xevan-gate.h"

#if defined(XEVAN_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"

union _xevan_4way_context_overlay
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
typedef union _xevan_4way_context_overlay xevan_4way_context_overlay;

void xevan_4way_hash( void *output, const void *input )
{
     uint64_t hash0[16] __attribute__ ((aligned (64)));
     uint64_t hash1[16] __attribute__ ((aligned (64)));
     uint64_t hash2[16] __attribute__ ((aligned (64)));
     uint64_t hash3[16] __attribute__ ((aligned (64)));
     uint64_t vhash[16<<2] __attribute__ ((aligned (64)));
     uint64_t vhashA[16<<2] __attribute__ ((aligned (64)));
     uint64_t vhashB[16<<2] __attribute__ ((aligned (64)));
     const int dataLen = 128;
     xevan_4way_context_overlay ctx __attribute__ ((aligned (64)));

     // parallel 4 way

     blake512_4way_init( &ctx.blake );
     blake512_4way( &ctx.blake, input, 80 );
     blake512_4way_close(&ctx.blake, vhash);
     memset( &vhash[8<<2], 0, 64<<2 );

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way( &ctx.bmw, vhash, dataLen );
     bmw512_4way_close( &ctx.bmw, vhash );

     // Serial
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0,
                               dataLen<<3 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1,
                               dataLen<<3 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2,
                               dataLen<<3 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3,
                               dataLen<<3 );

     // Parallel 4way
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     skein512_4way_init( &ctx.skein );
     skein512_4way( &ctx.skein, vhash, dataLen );
     skein512_4way_close( &ctx.skein, vhash );

     jh512_4way_init( &ctx.jh );
     jh512_4way( &ctx.jh, vhash, dataLen );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way( &ctx.keccak, vhash, dataLen );
     keccak512_4way_close( &ctx.keccak, vhash );

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, dataLen<<3 );

     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhashA, vhashA, dataLen );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhashB, vhashB, dataLen );

     cube_2way_init( &ctx.cube, 512, 16, 32 );
     cube_2way_update_close( &ctx.cube, vhashA, vhashA, dataLen );
     cube_2way_init( &ctx.cube, 512, 16, 32 );
     cube_2way_update_close( &ctx.cube, vhashB, vhashB, dataLen );

     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashA, vhashA, dataLen );
     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashB, vhashB, dataLen );

     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashA, vhashA, dataLen<<3 );
     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashB, vhashB, dataLen<<3 );

     dintrlv_2x128( hash0, hash1, vhashA, dataLen<<3 );
     dintrlv_2x128( hash2, hash3, vhashB, dataLen<<3 );

     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, dataLen<<3 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, dataLen<<3 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, dataLen<<3 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, dataLen<<3 );
     // Parallel
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way( &ctx.hamsi, vhash, dataLen );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash0, dataLen );
     sph_fugue512_close( &ctx.fugue, hash0 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash1, dataLen );
     sph_fugue512_close( &ctx.fugue, hash1 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash2, dataLen );
     sph_fugue512_close( &ctx.fugue, hash2 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash3, dataLen );
     sph_fugue512_close( &ctx.fugue, hash3 );

     // Parallel 4way 32 bit
     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     shabal512_4way_init( &ctx.shabal );
     shabal512_4way( &ctx.shabal, vhash, dataLen );
     shabal512_4way_close( &ctx.shabal, vhash );

     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     // Serial
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash0, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash1, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash2, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash3, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way( &ctx.sha512, vhash, dataLen );
     sha512_4way_close( &ctx.sha512, vhash );

     rintrlv_4x64_4x32( vhashA, vhash, dataLen<<3 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way( &ctx.haval, vhashA, dataLen );
     haval256_5_4way_close( &ctx.haval, vhashA );

     rintrlv_4x32_4x64( vhash, vhashA, dataLen<<3 );

     memset( &vhash[ 4<<2 ], 0, (dataLen-32) << 2 );

     blake512_4way_init( &ctx.blake );
     blake512_4way( &ctx.blake, vhash, dataLen );
     blake512_4way_close(&ctx.blake, vhash);

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way( &ctx.bmw, vhash, dataLen );
     bmw512_4way_close( &ctx.bmw, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0,
                               dataLen<<3 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1,
                               dataLen<<3 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2,
                               dataLen<<3 );
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3,
                               dataLen<<3 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     skein512_4way_init( &ctx.skein );
     skein512_4way( &ctx.skein, vhash, dataLen );
     skein512_4way_close( &ctx.skein, vhash );

     jh512_4way_init( &ctx.jh );
     jh512_4way( &ctx.jh, vhash, dataLen );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way( &ctx.keccak, vhash, dataLen );
     keccak512_4way_close( &ctx.keccak, vhash );

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, dataLen<<3 );

     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhashA, vhashA, dataLen );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhashB, vhashB, dataLen );

     cube_2way_init( &ctx.cube, 512, 16, 32 );
     cube_2way_update_close( &ctx.cube, vhashA, vhashA, dataLen );
     cube_2way_init( &ctx.cube, 512, 16, 32 );
     cube_2way_update_close( &ctx.cube, vhashB, vhashB, dataLen );

     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashA, vhashA, dataLen );
     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashB, vhashB, dataLen );

     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashA, vhashA, dataLen<<3 );
     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashB, vhashB, dataLen<<3 );

     dintrlv_2x128( hash0, hash1, vhashA, dataLen<<3 );
     dintrlv_2x128( hash2, hash3, vhashB, dataLen<<3 );

     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, dataLen<<3 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, dataLen<<3 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, dataLen<<3 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, dataLen<<3 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way( &ctx.hamsi, vhash, dataLen );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash0, dataLen );
     sph_fugue512_close( &ctx.fugue, hash0 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash1, dataLen );
     sph_fugue512_close( &ctx.fugue, hash1 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash2, dataLen );
     sph_fugue512_close( &ctx.fugue, hash2 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash3, dataLen );
     sph_fugue512_close( &ctx.fugue, hash3 );

     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     shabal512_4way_init( &ctx.shabal );
     shabal512_4way( &ctx.shabal, vhash, dataLen );
     shabal512_4way_close( &ctx.shabal, vhash );

     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash0, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash1, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash2, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash3, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way( &ctx.sha512, vhash, dataLen );
     sha512_4way_close( &ctx.sha512, vhash );

     rintrlv_4x64_4x32( vhashA, vhash, dataLen<<3 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way( &ctx.haval, vhashA, dataLen );
     haval256_5_4way_close( &ctx.haval, output );
}

int scanhash_xevan_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   int thr_id = mythr->id;  // thr_id arg is deprecated
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned

   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;

   if ( opt_benchmark )
      ptarget[7] = 0x0cff;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   do {
      *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
               _mm256_set_epi32( n+3, 0,n+2, 0,n+1, 0, n, 0 ) ), *noncev );

      xevan_4way_hash( hash, vdata );
      for ( int lane = 0; lane < 4; lane++ )
      if ( hash7[ lane ] <= Htarg )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
	      if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
         {
             pdata[19] = n + lane;
             submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      n += 4;
   } while ( ( n < max_nonce-4 ) && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
