#include "x22i-gate.h"
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
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/lyra2/lyra2.h"
#include "algo/gost/sph_gost.h"
#include "algo/swifftx/swifftx.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif
#if defined(__SHA__)
  #include "algo/sha/sha256-hash.h"
#endif

#if defined(X22I_8WAY)

union _x22i_8way_ctx_overlay
{
    blake512_8way_context   blake;
    bmw512_8way_context     bmw;
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    keccak512_8way_context  keccak;
    luffa_4way_context      luffa;
    cube_4way_context       cube;
    simd_4way_context       simd;
    hamsi512_8way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_8way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_8way_context     sha512;
    haval256_5_8way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
#if !defined(X22I_8WAY_SHA)
    sha256_8way_context     sha256;
#endif
#if defined(__VAES__)
    groestl512_4way_context groestl;
    shavite512_4way_context shavite;
    echo_4way_context       echo;
#else
    hashState_groestl       groestl;
    sph_shavite512_context  shavite;
    hashState_echo          echo;
#endif
};
typedef union _x22i_8way_ctx_overlay x22i_8way_ctx_overlay;

int x22i_8way_hash( void *output, const void *input, int thrid )
{
   uint64_t vhash[8*8] __attribute__ ((aligned (128)));
   uint64_t vhashA[8*8] __attribute__ ((aligned (64)));
   uint64_t vhashB[8*8] __attribute__ ((aligned (64)));
   uint64_t hash0[8*4] __attribute__ ((aligned (64)));
   uint64_t hash1[8*4] __attribute__ ((aligned (64)));
   uint64_t hash2[8*4] __attribute__ ((aligned (64)));
   uint64_t hash3[8*4] __attribute__ ((aligned (64)));
   uint64_t hash4[8*4] __attribute__ ((aligned (64)));
   uint64_t hash5[8*4] __attribute__ ((aligned (64)));
   uint64_t hash6[8*4] __attribute__ ((aligned (64)));
   uint64_t hash7[8*4] __attribute__ ((aligned (64)));

//   unsigned char hash[64 * 4] __attribute__((aligned(64))) = {0};
   unsigned char hashA0[64]    __attribute__((aligned(64))) = {0};
   unsigned char hashA1[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA2[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA3[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA4[64]    __attribute__((aligned(64))) = {0};
   unsigned char hashA5[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA6[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA7[64]    __attribute__((aligned(32))) = {0};
   x22i_8way_ctx_overlay ctx;

   blake512_8way_full( &ctx.blake, vhash, input, 80 );

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

   if ( work_restart[thrid].restart ) return 0;
   
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   luffa512_4way_full( &ctx.luffa, vhashA, vhashA, 64 );
   luffa512_4way_full( &ctx.luffa, vhashB, vhashB, 64 );

   cube_4way_full( &ctx.cube, vhashA, 512, vhashA, 64 );
   cube_4way_full( &ctx.cube, vhashB, 512, vhashB, 64 );

#if defined(__VAES__)

   shavite512_4way_full( &ctx.shavite, vhashA, vhashA, 64 );
   shavite512_4way_full( &ctx.shavite, vhashB, vhashB, 64 );

#else

   dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
   dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

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

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6, hash7 );

#endif

   if ( work_restart[thrid].restart ) return 0;
   
   hamsi512_8way_init( &ctx.hamsi );
   hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
   hamsi512_8way_close( &ctx.hamsi, vhash );

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );
   
   fugue512_full( &ctx.fugue, hash0, hash0, 64 );
   fugue512_full( &ctx.fugue, hash1, hash1, 64 );
   fugue512_full( &ctx.fugue, hash2, hash2, 64 );
   fugue512_full( &ctx.fugue, hash3, hash3, 64 );
   fugue512_full( &ctx.fugue, hash4, hash4, 64 );
   fugue512_full( &ctx.fugue, hash5, hash5, 64 );
   fugue512_full( &ctx.fugue, hash6, hash6, 64 );
   fugue512_full( &ctx.fugue, hash7, hash7, 64 );

   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6, hash7 );

   shabal512_8way_init( &ctx.shabal );
   shabal512_8way_update( &ctx.shabal, vhash, 64 );
   shabal512_8way_close( &ctx.shabal, vhash );

   dintrlv_8x32_512( &hash0[8], &hash1[8], &hash2[8], &hash3[8],
                     &hash4[8], &hash5[8], &hash6[8], &hash7[8], vhash );

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
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash4[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash4[16] );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash5[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash5[16] );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash6[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash6[16] );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, &hash7[8], 64 );
   sph_whirlpool_close( &ctx.whirlpool, &hash7[16] );

   intrlv_8x64_512( vhash, &hash0[16], &hash1[16], &hash2[16], &hash3[16],
                           &hash4[16], &hash5[16], &hash6[16], &hash7[16] );

   sha512_8way_init( &ctx.sha512 );
   sha512_8way_update( &ctx.sha512, vhash, 64 );
   sha512_8way_close( &ctx.sha512, vhash );

   dintrlv_8x64_512( &hash0[24], &hash1[24], &hash2[24], &hash3[24],
                     &hash4[24], &hash5[24], &hash6[24], &hash7[24], vhash );
               
   ComputeSingleSWIFFTX((unsigned char*)hash0, (unsigned char*)hashA0);
   ComputeSingleSWIFFTX((unsigned char*)hash1, (unsigned char*)hashA1);
   ComputeSingleSWIFFTX((unsigned char*)hash2, (unsigned char*)hashA2);
   ComputeSingleSWIFFTX((unsigned char*)hash3, (unsigned char*)hashA3);
   ComputeSingleSWIFFTX((unsigned char*)hash4, (unsigned char*)hashA4);
   ComputeSingleSWIFFTX((unsigned char*)hash5, (unsigned char*)hashA5);
   ComputeSingleSWIFFTX((unsigned char*)hash6, (unsigned char*)hashA6);
   ComputeSingleSWIFFTX((unsigned char*)hash7, (unsigned char*)hashA7);

   intrlv_8x32_512( vhashA, hashA0, hashA1, hashA2, hashA3,
                            hashA4, hashA5, hashA6, hashA7 );

   memset( vhash, 0, 64*8 );

   haval256_5_8way_init( &ctx.haval );
   haval256_5_8way_update( &ctx.haval, vhashA, 64 );
   haval256_5_8way_close( &ctx.haval, vhash );

   dintrlv_8x32_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

   memset( hashA0, 0, 64 );
   memset( hashA1, 0, 64 );
   memset( hashA2, 0, 64 );
   memset( hashA3, 0, 64 );
   memset( hashA4, 0, 64 );
   memset( hashA5, 0, 64 );
   memset( hashA6, 0, 64 );
   memset( hashA7, 0, 64 );

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
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash4, 64);
   sph_tiger_close(&ctx.tiger, (void*) hashA4);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash5, 64);
   sph_tiger_close(&ctx.tiger, (void*) hashA5);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash6, 64);
   sph_tiger_close(&ctx.tiger, (void*) hashA6);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash7, 64);
   sph_tiger_close(&ctx.tiger, (void*) hashA7);

   if ( work_restart[thrid].restart ) return 0;
   
   memset( hash0, 0, 64 );
   memset( hash1, 0, 64 );
   memset( hash2, 0, 64 );
   memset( hash3, 0, 64 );
   memset( hash4, 0, 64 );
   memset( hash5, 0, 64 );
   memset( hash6, 0, 64 );
   memset( hash7, 0, 64 );

   intrlv_2x256( vhash, hashA0, hashA1, 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hashA2, hashA3, 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hashA4, hashA5, 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hashA6, hashA7, 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );

   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash0, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash0 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash1, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash1 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash2, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash2 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash3, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash3 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash4, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash4 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash5, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash5 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash6, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash6 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash7, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash7 );

#if defined(X22I_8WAY_SHA)

   sha256_full( hash0, hash0, 64 );
   sha256_full( hash1, hash1, 64 );
   sha256_full( hash2, hash2, 64 );
   sha256_full( hash3, hash3, 64 );
   sha256_full( hash4, hash4, 64 );
   sha256_full( hash5, hash5, 64 );
   sha256_full( hash6, hash6, 64 );
   sha256_full( hash7, hash7, 64 );
   
#else

   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6, hash7 );

   sha256_8way_init( &ctx.sha256 );
   sha256_8way_update( &ctx.sha256, vhash, 64 );
   sha256_8way_close( &ctx.sha256, output );

#endif

   return 1;
}

#if defined(X22I_8WAY_SHA)

int scanhash_x22i_8way_sha( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x08ff;

   InitializeSWIFFTX();

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   *noncev = mm512_intrlv_blend_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      if ( x22i_8way_hash( hash, vdata, thr_id ) )
      for ( int i = 0; i < 8; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else

int scanhash_x22i_8way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &(hash[7*8]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32 = ptarget[7];
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x08ff;

   InitializeSWIFFTX();
   
   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   *noncev = mm512_intrlv_blend_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      if ( x22i_8way_hash( hash, vdata, thr_id ) )
      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( ( hashd7[ lane ] <= targ32 ) && !bench ) )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) ) )
         {
            pdata[19] = bswap_32( n + lane );
            submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

#elif defined(X22I_4WAY)

union _x22i_4way_ctx_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
#if defined(__VAES__)
    groestl512_2way_context groestl;
    echo_2way_context       echo;
#else
    hashState_groestl       groestl;
    hashState_echo          echo;
#endif
    shavite512_2way_context shavite;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cube_2way_context       cube;
    simd_2way_context       simd;
    hamsi512_4way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
#if !defined(X22I_4WAY_SHA)
    sha256_4way_context     sha256;
#endif
};
typedef union _x22i_4way_ctx_overlay x22i_ctx_overlay;

int x22i_4way_hash( void *output, const void *input, int thrid )
{
   uint64_t hash0[8*4] __attribute__ ((aligned (64)));
   uint64_t hash1[8*4] __attribute__ ((aligned (64)));
   uint64_t hash2[8*4] __attribute__ ((aligned (64)));
   uint64_t hash3[8*4] __attribute__ ((aligned (64)));
   uint64_t vhash[8*4] __attribute__ ((aligned (64)));
   uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
   uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
   unsigned char hashA0[64]    __attribute__((aligned(64))) = {0};
   unsigned char hashA1[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA2[64]    __attribute__((aligned(32))) = {0};
   unsigned char hashA3[64]    __attribute__((aligned(32))) = {0};
   x22i_ctx_overlay ctx;

   blake512_4way_full( &ctx.blake, vhash, input, 80 );

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

   if ( work_restart[thrid].restart ) return false;
   
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

   if ( work_restart[thrid].restart ) return false;
   
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
   sha512_4way_update( &ctx.sha512, vhash, 64 );
   sha512_4way_close( &ctx.sha512, vhash );
   dintrlv_4x64_512( &hash0[24], &hash1[24], &hash2[24], &hash3[24], vhash );

   if ( work_restart[thrid].restart ) return false;
   
   ComputeSingleSWIFFTX((unsigned char*)hash0, (unsigned char*)hashA0);
   ComputeSingleSWIFFTX((unsigned char*)hash1, (unsigned char*)hashA1);
   ComputeSingleSWIFFTX((unsigned char*)hash2, (unsigned char*)hashA2);
   ComputeSingleSWIFFTX((unsigned char*)hash3, (unsigned char*)hashA3);

   intrlv_4x32_512( vhashA, hashA0, hashA1, hashA2, hashA3 );

   memset( vhash, 0, 64*4 );

   haval256_5_4way_init( &ctx.haval );
   haval256_5_4way_update( &ctx.haval, vhashA, 64 );
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

   if ( work_restart[thrid].restart ) return false;

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

#if defined(X22I_4WAY_SHA)

   sha256_full( hash0, hash0, 64 );
   sha256_full( hash1, hash1, 64 );
   sha256_full( hash2, hash2, 64 );
   sha256_full( hash3, hash3, 64 );

#else

   intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

   sha256_4way_init( &ctx.sha256 );
   sha256_4way_update( &ctx.sha256, vhash, 64 );
   sha256_4way_close( &ctx.sha256, output );

#endif

   return 1;
}

#if defined(X22I_4WAY_SHA)

int scanhash_x22i_4way_sha( struct work* work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   __m256i  *noncev = (__m256i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x08ff;

   InitializeSWIFFTX();

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x22i_4way_hash( hash, vdata, thr_id ) )
      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else

int scanhash_x22i_4way( struct work* work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &(hash[ 7*4 ]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   __m256i  *noncev = (__m256i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32 = ptarget[7];
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x08ff;

   InitializeSWIFFTX();
   
   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x22i_4way_hash( hash, vdata, thr_id ) )
      for ( int lane = 0; lane < 4; lane++ )
      if ( unlikely( hashd7[ lane ] <= targ32 && !bench ) )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( valid_hash( lane_hash, ptarget ) )
         {
            pdata[19] = bswap_32( n + lane );
            submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n <= last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

#endif  // X22I_4WAY
