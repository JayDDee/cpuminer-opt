#include "x22i-gate.h"

#if defined(X22I_4WAY)

#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/lyra2/lyra2.h"
#include "algo/gost/sph_gost.h"
#include "algo/swifftx/swifftx.h"

union _x22i_4way_ctx_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    hashState_echo          echo;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cube_2way_context       cube;
    shavite512_2way_context shavite;
    simd_2way_context       simd;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
    sha256_4way_context     sha256;
};
typedef union _x22i_4way_ctx_overlay x22i_ctx_overlay;

void x22i_4way_hash( void *output, const void *input )
{
   uint64_t hash0[8*4] __attribute__ ((aligned (64)));
   uint64_t hash1[8*4] __attribute__ ((aligned (64)));
   uint64_t hash2[8*4] __attribute__ ((aligned (64)));
   uint64_t hash3[8*4] __attribute__ ((aligned (64)));
   uint64_t vhash[8*4] __attribute__ ((aligned (64)));
   uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
   uint64_t vhashB[8*4] __attribute__ ((aligned (64)));

//   unsigned char hash[64 * 4] __attribute__((aligned(64))) = {0};
   unsigned char hashA0[64]    __attribute__((aligned(64))) = {0};
   unsigned char hashA1[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA2[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA3[64]    __attribute__((aligned(32))) = {0};
   x22i_ctx_overlay ctx;

   blake512_4way_init( &ctx.blake );
   blake512_4way( &ctx.blake, input, 80 );
   blake512_4way_close( &ctx.blake, vhash );

   bmw512_4way_init( &ctx.bmw );
   bmw512_4way( &ctx.bmw, vhash, 64 );
   bmw512_4way_close( &ctx.bmw, vhash );

   dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
   
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                  (const char*)hash0, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                  (const char*)hash1, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                  (const char*)hash2, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                  (const char*)hash3, 512 );

   intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

   skein512_4way_init( &ctx.skein );
   skein512_4way( &ctx.skein, vhash, 64 );
   skein512_4way_close( &ctx.skein, vhash );

   jh512_4way_init( &ctx.jh );
   jh512_4way( &ctx.jh, vhash, 64 );
   jh512_4way_close( &ctx.jh, vhash );

   keccak512_4way_init( &ctx.keccak );
   keccak512_4way( &ctx.keccak, vhash, 64 );
   keccak512_4way_close( &ctx.keccak, vhash );

   rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

   luffa_2way_init( &ctx.luffa, 512 );
   luffa_2way_update_close( &ctx.luffa, vhashA, vhashA, 64 );
   luffa_2way_init( &ctx.luffa, 512 );
   luffa_2way_update_close( &ctx.luffa, vhashB, vhashB, 64 );

   cube_2way_init( &ctx.cube, 512, 16, 32 );
   cube_2way_update_close( &ctx.cube, vhashA, vhashA, 64 );
   cube_2way_init( &ctx.cube, 512, 16, 32 );
   cube_2way_update_close( &ctx.cube, vhashB, vhashB, 64 );

   shavite512_2way_init( &ctx.shavite );
   shavite512_2way_update_close( &ctx.shavite, vhashA, vhashA, 64 );
   shavite512_2way_init( &ctx.shavite );
   shavite512_2way_update_close( &ctx.shavite, vhashB, vhashB, 64 );

   simd_2way_init( &ctx.simd, 512 );
   simd_2way_update_close( &ctx.simd, vhashA, vhashA, 512 );
   simd_2way_init( &ctx.simd, 512 );
   simd_2way_update_close( &ctx.simd, vhashB, vhashB, 512 );

   dintrlv_2x128_512( hash0, hash1, vhashA );
   dintrlv_2x128_512( hash2, hash3, vhashB );
   
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash0,
                            (const BitSequence*)hash0, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash1,
                            (const BitSequence*)hash1, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash2,
                            (const BitSequence*)hash2, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash3,
                            (const BitSequence*)hash3, 512 );


   intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

   hamsi512_4way_init( &ctx.hamsi );
   hamsi512_4way( &ctx.hamsi, vhash, 64 );
   hamsi512_4way_close( &ctx.hamsi, vhash );

   dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

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

   intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

   shabal512_4way_init( &ctx.shabal );
   shabal512_4way( &ctx.shabal, vhash, 64 );
   shabal512_4way_close( &ctx.shabal, vhash );

   dintrlv_4x32_512( &hash0[8], &hash1[8], &hash2[8], &hash3[8], vhash );

   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash0[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash0[16] );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash1[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash1[16] );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash2[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash2[16] );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash3[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash3[16] );

   intrlv_4x64_512( vhash, &hash0[16], &hash1[16], &hash2[16], &hash3[16] );

   sha512_4way_init( &ctx.sha512 );
   sha512_4way( &ctx.sha512, vhash, 64 );
   sha512_4way_close( &ctx.sha512, vhash );

   dintrlv_4x64_512( &hash0[24], &hash1[24], &hash2[24], &hash3[24], vhash );

//	InitializeSWIFFTX();
	ComputeSingleSWIFFTX((unsigned char*)hash0, (unsigned char*)hashA0);
   ComputeSingleSWIFFTX((unsigned char*)hash1, (unsigned char*)hashA1);
   ComputeSingleSWIFFTX((unsigned char*)hash2, (unsigned char*)hashA2);
   ComputeSingleSWIFFTX((unsigned char*)hash3, (unsigned char*)hashA3);

   intrlv_4x32_512( vhashA, hashA0, hashA1, hashA2, hashA3 );

   memset( vhash, 0, 64*4 );

   haval256_5_4way_init( &ctx.haval );
   haval256_5_4way( &ctx.haval, vhashA, 64 );
   haval256_5_4way_close( &ctx.haval, vhash );

   dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );
     
	memset( hashA0, 0, 64 );
   memset( hashA1, 0, 64 );
   memset( hashA2, 0, 64 );
   memset( hashA3, 0, 64 );

   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash0, 64);
   sph_tiger_close(&ctx.tiger, (void*) hashA0);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash1, 64);
   sph_tiger_close(&ctx.tiger, (void*) hashA1);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash2, 64);
   sph_tiger_close(&ctx.tiger, (void*) hashA2);
   sph_tiger_init(&ctx.tiger);
	sph_tiger (&ctx.tiger, (const void*) hash3, 64);
	sph_tiger_close(&ctx.tiger, (void*) hashA3);

	memset( hash0, 0, 64 );
   memset( hash1, 0, 64 );
   memset( hash2, 0, 64 );
   memset( hash3, 0, 64 );

   LYRA2RE( (void*) hash0, 32, (const void*) hashA0, 32, (const void*) hashA0,
            32, 1, 4, 4 );
   LYRA2RE( (void*) hash1, 32, (const void*) hashA1, 32, (const void*) hashA1,
            32, 1, 4, 4 );
   LYRA2RE( (void*) hash2, 32, (const void*) hashA2, 32, (const void*) hashA2,
            32, 1, 4, 4 );
   LYRA2RE( (void*) hash3, 32, (const void*) hashA3, 32, (const void*) hashA3,
            32, 1, 4, 4 );

   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash0, 64);
   sph_gost512_close(&ctx.gost, (void*) hash0);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash1, 64);
   sph_gost512_close(&ctx.gost, (void*) hash1);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash2, 64);
   sph_gost512_close(&ctx.gost, (void*) hash2);
	sph_gost512_init(&ctx.gost);
	sph_gost512 (&ctx.gost, (const void*) hash3, 64);
	sph_gost512_close(&ctx.gost, (void*) hash3);

   intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

   sha256_4way_init( &ctx.sha256 );
   sha256_4way( &ctx.sha256, vhash, 64 );
   sha256_4way_close( &ctx.sha256, output );
   
//	memcpy(output, hash, 32);
}


int scanhash_x22i_4way( struct work* work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t Htarg = ptarget[7];

   if (opt_benchmark)
      ((uint32_t*)ptarget)[7] = 0x08ff;
   
   InitializeSWIFFTX();

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   do
   {
      *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
              _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );
      x22i_4way_hash( hash, vdata );

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

#endif  // X22I_4WAY
