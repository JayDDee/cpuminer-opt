#include "x22i-gate.h"
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/blake/blake2s-hash-4way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/nist.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/lyra2/lyra2.h"
#include "algo/gost/sph_gost.h"
#include "algo/swifftx/swifftx.h"
#include "algo/panama/panama-hash-4way.h"
#include "algo/lanehash/lane.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif
#if defined(__SHA__)
  #include "algo/sha/sha256-hash.h"
#endif

void x25x_shuffle( void *hash )
{
   // Simple shuffle algorithm, instead of just reversing
   #define X25X_SHUFFLE_BLOCKS (24 * 64 / 2)
   #define X25X_SHUFFLE_ROUNDS 12

   static const uint16_t x25x_round_const[X25X_SHUFFLE_ROUNDS] =
   {
      0x142c, 0x5830, 0x678c, 0xe08c, 0x3c67, 0xd50d, 0xb1d8, 0xecb2,
      0xd7ee, 0x6783, 0xfa6c, 0x4b9c
   };

   uint16_t* block_pointer = (uint16_t*)hash;
   for ( int r = 0; r < X25X_SHUFFLE_ROUNDS; r++ )
   {
      for ( int i = 0; i < X25X_SHUFFLE_BLOCKS; i++ )
      {
         uint16_t block_value = block_pointer[ X25X_SHUFFLE_BLOCKS - i - 1 ];
         block_pointer[i] ^= block_pointer[ block_value % X25X_SHUFFLE_BLOCKS ]
                                + ( x25x_round_const[r] << (i % 16) );
      }
   }

   #undef X25X_SHUFFLE_BLOCKS
   #undef X25X_SHUFFLE_ROUNDS
}

#if defined(X25X_8WAY)

union _x25x_8way_ctx_overlay
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
#if defined(X25X_8WAY_SHA)
    sha256_context          sha256;
#else
    sha256_8way_context     sha256;
#endif
    panama_8way_context     panama;
    blake2s_8way_state      blake2s;
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
typedef union _x25x_8way_ctx_overlay x25x_8way_ctx_overlay;

int x25x_8way_hash( void *output, const void *input, int thrid )
{
   uint64_t vhash[8*8] __attribute__ ((aligned (128)));
   unsigned char hash0[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash1[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash2[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash3[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash4[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash5[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash6[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash7[25][64] __attribute__((aligned(64))) = {0};
   unsigned char vhashX[24][64*8] __attribute__ ((aligned (64)));
   uint64_t vhashA[8*8] __attribute__ ((aligned (64)));
   uint64_t vhashB[8*8] __attribute__ ((aligned (64)));
   x25x_8way_ctx_overlay ctx __attribute__ ((aligned (64)));

   blake512_8way_init( &ctx.blake );
   blake512_8way_update( &ctx.blake, input, 80 );
   blake512_8way_close( &ctx.blake, vhash );
   dintrlv_8x64_512( hash0[0], hash1[0], hash2[0], hash3[0],
                     hash4[0], hash5[0], hash6[0], hash7[0], vhash );

   bmw512_8way_init( &ctx.bmw );
   bmw512_8way_update( &ctx.bmw, vhash, 64 );
   bmw512_8way_close( &ctx.bmw, vhash );
   dintrlv_8x64_512( hash0[1], hash1[1], hash2[1], hash3[1],
                     hash4[1], hash5[1], hash6[1], hash7[1], vhash );

#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   groestl512_4way_init( &ctx.groestl, 64 );
   groestl512_4way_update_close( &ctx.groestl, vhashA, vhashA, 512 );
   groestl512_4way_init( &ctx.groestl, 64 );
   groestl512_4way_update_close( &ctx.groestl, vhashB, vhashB, 512 );
   dintrlv_4x128_512( hash0[2], hash1[2], hash2[2], hash3[2], vhashA );
   dintrlv_4x128_512( hash4[2], hash5[2], hash6[2], hash7[2], vhashB );

   intrlv_8x64_512( vhash, hash0[2], hash1[2], hash2[2], hash3[2],
                           hash4[2], hash5[2], hash6[2], hash7[2] );

#else

   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash0[2],
                                  (const char*)hash0[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash1[2],
                                  (const char*)hash1[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash2[2],
                                  (const char*)hash2[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash3[2],
                                  (const char*)hash3[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash4[2],
                                  (const char*)hash4[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash5[2],
                                  (const char*)hash5[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash6[2],
                                  (const char*)hash6[1], 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash7[2],
                                  (const char*)hash7[1], 512 );

   intrlv_8x64_512( vhash, hash0[2], hash1[2], hash2[2], hash3[2],
                           hash4[2], hash5[2], hash6[2], hash7[2] );
   
#endif

   skein512_8way_init( &ctx.skein );
   skein512_8way_update( &ctx.skein, vhash, 64 );
   skein512_8way_close( &ctx.skein, vhash );
   dintrlv_8x64_512( hash0[3], hash1[3], hash2[3], hash3[3],
                     hash4[3], hash5[3], hash6[3], hash7[3], vhash );

   jh512_8way_init( &ctx.jh );
   jh512_8way_update( &ctx.jh, vhash, 64 );
   jh512_8way_close( &ctx.jh, vhash );
   dintrlv_8x64_512( hash0[4], hash1[4], hash2[4], hash3[4],
                     hash4[4], hash5[4], hash6[4], hash7[4], vhash );
   
   keccak512_8way_init( &ctx.keccak );
   keccak512_8way_update( &ctx.keccak, vhash, 64 );
   keccak512_8way_close( &ctx.keccak, vhash );
   dintrlv_8x64_512( hash0[5], hash1[5], hash2[5], hash3[5],
                     hash4[5], hash5[5], hash6[5], hash7[5], vhash );

   if ( work_restart[thrid].restart ) return 0;
   
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   luffa_4way_init( &ctx.luffa, 512 );
   luffa_4way_update_close( &ctx.luffa, vhashA, vhashA, 64 );
   luffa_4way_init( &ctx.luffa, 512 );
   luffa_4way_update_close( &ctx.luffa, vhashB, vhashB, 64 );
   dintrlv_4x128_512( hash0[6], hash1[6], hash2[6], hash3[6], vhashA );
   dintrlv_4x128_512( hash4[6], hash5[6], hash6[6], hash7[6], vhashB );

   cube_4way_init( &ctx.cube, 512, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashA, vhashA, 64 );
   cube_4way_init( &ctx.cube, 512, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashB, vhashB, 64 );
   dintrlv_4x128_512( hash0[7], hash1[7], hash2[7], hash3[7], vhashA );
   dintrlv_4x128_512( hash4[7], hash5[7], hash6[7], hash7[7], vhashB );

#if defined(__VAES__)

   shavite512_4way_init( &ctx.shavite );
   shavite512_4way_update_close( &ctx.shavite, vhashA, vhashA, 64 );
   shavite512_4way_init( &ctx.shavite );
   shavite512_4way_update_close( &ctx.shavite, vhashB, vhashB, 64 );
   dintrlv_4x128_512( hash0[8], hash1[8], hash2[8], hash3[8], vhashA );
   dintrlv_4x128_512( hash4[8], hash5[8], hash6[8], hash7[8], vhashB );

#else

   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash0[7], 64);
   sph_shavite512_close(&ctx.shavite, hash0[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash1[7], 64);
   sph_shavite512_close(&ctx.shavite, hash1[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash2[7], 64);
   sph_shavite512_close(&ctx.shavite, hash2[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash3[7], 64);
   sph_shavite512_close(&ctx.shavite, hash3[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash4[7], 64);
   sph_shavite512_close(&ctx.shavite, hash4[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash5[7], 64);
   sph_shavite512_close(&ctx.shavite, hash5[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash6[7], 64);
   sph_shavite512_close(&ctx.shavite, hash6[8]);
   sph_shavite512_init(&ctx.shavite);
   sph_shavite512(&ctx.shavite, (const void*) hash7[7], 64);
   sph_shavite512_close(&ctx.shavite, hash7[8]);
   intrlv_4x128_512( vhashA, hash0[8], hash1[8], hash2[8], hash3[8] );
   intrlv_4x128_512( vhashB, hash4[8], hash5[8], hash6[8], hash7[8] );

#endif

   simd_4way_init( &ctx.simd, 512 );
   simd_4way_update_close( &ctx.simd, vhashA, vhashA, 512 );
   simd_4way_init( &ctx.simd, 512 );
   simd_4way_update_close( &ctx.simd, vhashB, vhashB, 512 );
   dintrlv_4x128_512( hash0[9], hash1[9], hash2[9], hash3[9], vhashA );
   dintrlv_4x128_512( hash4[9], hash5[9], hash6[9], hash7[9], vhashB );

#if defined(__VAES__)

   echo_4way_init( &ctx.echo, 512 );
   echo_4way_update_close( &ctx.echo, vhashA, vhashA, 512 );
   echo_4way_init( &ctx.echo, 512 );
   echo_4way_update_close( &ctx.echo, vhashB, vhashB, 512 );
   dintrlv_4x128_512( hash0[10], hash1[10], hash2[10], hash3[10], vhashA );
   dintrlv_4x128_512( hash4[10], hash5[10], hash6[10], hash7[10], vhashB );

   intrlv_8x64_512( vhash, hash0[10], hash1[10], hash2[10], hash3[10],
                           hash4[10], hash5[10], hash6[10], hash7[10] );

   
#else

   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash0[10],
                            (const BitSequence*)hash0[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash1[10],
                            (const BitSequence*)hash1[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash2[10],
                            (const BitSequence*)hash2[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash3[10],
                            (const BitSequence*)hash3[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash4[10],
                            (const BitSequence*)hash4[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash5[10],
                            (const BitSequence*)hash5[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash6[10],
                            (const BitSequence*)hash6[9], 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo ( &ctx.echo, (BitSequence*)hash7[10],
                            (const BitSequence*)hash7[9], 512 );
   intrlv_8x64_512( vhash, hash0[10], hash1[10], hash2[10], hash3[10],
                           hash4[10], hash5[10], hash6[10], hash7[10] );

#endif

   if ( work_restart[thrid].restart ) return 0;
   
   hamsi512_8way_init( &ctx.hamsi );
   hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
   hamsi512_8way_close( &ctx.hamsi, vhash );
   dintrlv_8x64_512( hash0[11], hash1[11], hash2[11], hash3[11],
                     hash4[11], hash5[11], hash6[11], hash7[11], vhash );
   
   fugue512_full( &ctx.fugue, hash0[12], hash0[11], 64 );
   fugue512_full( &ctx.fugue, hash1[12], hash1[11], 64 );
   fugue512_full( &ctx.fugue, hash2[12], hash2[11], 64 );
   fugue512_full( &ctx.fugue, hash3[12], hash3[11], 64 );
   fugue512_full( &ctx.fugue, hash4[12], hash4[11], 64 );
   fugue512_full( &ctx.fugue, hash5[12], hash5[11], 64 );
   fugue512_full( &ctx.fugue, hash6[12], hash6[11], 64 );
   fugue512_full( &ctx.fugue, hash7[12], hash7[11], 64 );

   intrlv_8x32_512( vhash, hash0[12], hash1[12], hash2[12], hash3[12],
                           hash4[12], hash5[12], hash6[12], hash7[12] );

   shabal512_8way_init( &ctx.shabal );
   shabal512_8way_update( &ctx.shabal, vhash, 64 );
   shabal512_8way_close( &ctx.shabal, vhash );
   dintrlv_8x32_512( hash0[13], hash1[13], hash2[13], hash3[13],
                     hash4[13], hash5[13], hash6[13], hash7[13], vhash );

   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash0[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash0[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash1[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash1[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash2[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash2[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash3[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash3[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash4[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash4[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash5[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash5[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash6[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash6[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash7[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash7[14]);
   intrlv_8x64_512( vhash, hash0[14], hash1[14], hash2[14], hash3[14],
                           hash4[14], hash5[14], hash6[14], hash7[14] );

   sha512_8way_init( &ctx.sha512 );
   sha512_8way_update( &ctx.sha512, vhash, 64 );
   sha512_8way_close( &ctx.sha512, vhash );
   dintrlv_8x64_512( hash0[15], hash1[15], hash2[15], hash3[15],
                     hash4[15], hash5[15], hash6[15], hash7[15], vhash );

   ComputeSingleSWIFFTX((unsigned char*)hash0[12], (unsigned char*)hash0[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash1[12], (unsigned char*)hash1[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash2[12], (unsigned char*)hash2[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash3[12], (unsigned char*)hash3[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash4[12], (unsigned char*)hash4[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash5[12], (unsigned char*)hash5[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash6[12], (unsigned char*)hash6[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash7[12], (unsigned char*)hash7[16]);
   intrlv_8x32_512( vhashA, hash0[16], hash1[16], hash2[16], hash3[16],
                            hash4[16], hash5[16], hash6[16], hash7[16] );
   memset( vhash, 0, 64*8 );

   haval256_5_8way_init( &ctx.haval );
   haval256_5_8way_update( &ctx.haval, vhashA, 64 );
   haval256_5_8way_close( &ctx.haval, vhash );
   dintrlv_8x32_512( hash0[17], hash1[17], hash2[17], hash3[17],
                     hash4[17], hash5[17], hash6[17], hash7[17], vhash );

   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash0[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash0[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash1[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash1[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash2[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash2[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash3[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash3[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash4[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash4[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash5[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash5[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash6[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash6[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash7[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash7[18]);

   if ( work_restart[thrid].restart ) return 0;
   
   intrlv_2x256( vhash, hash0[18], hash1[18], 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0[19], hash1[19], vhash, 256 );
   intrlv_2x256( vhash, hash2[18], hash3[18], 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2[19], hash3[19], vhash, 256 );
   intrlv_2x256( vhash, hash4[18], hash5[18], 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4[19], hash5[19], vhash, 256 );
   intrlv_2x256( vhash, hash6[18], hash7[18], 256 );
   LYRA2X_2WAY( vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash6[19], hash7[19], vhash, 256 );

   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash0[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash0[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash1[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash1[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash2[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash2[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash3[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash3[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash4[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash4[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash5[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash5[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash6[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash6[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash7[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash7[20]);

#if defined(X25X_8WAY_SHA)

   sha256_full( hash0[21], hash0[20], 64 );
   sha256_full( hash1[21], hash1[20], 64 );
   sha256_full( hash2[21], hash2[20], 64 );
   sha256_full( hash3[21], hash3[20], 64 );
   sha256_full( hash4[21], hash4[20], 64 );
   sha256_full( hash5[21], hash5[20], 64 );
   sha256_full( hash6[21], hash6[20], 64 );
   sha256_full( hash7[21], hash7[20], 64 );
   
   intrlv_8x32_512( vhash, hash0[21], hash1[21], hash2[21], hash3[21],
                           hash4[21], hash5[21], hash6[21], hash7[21] );
   
#else

   intrlv_8x32_512( vhashA, hash0[20], hash1[20], hash2[20], hash3[20],
                            hash4[20], hash5[20], hash6[20], hash7[20] );

   sha256_8way_init( &ctx.sha256 );
   sha256_8way_update( &ctx.sha256, vhashA, 64 );
   sha256_8way_close( &ctx.sha256, vhash );
   dintrlv_8x32_512( hash0[21], hash1[21], hash2[21], hash3[21],
                     hash4[21], hash5[21], hash6[21], hash7[21], vhash );

#endif

   panama_8way_init( &ctx.panama );
   panama_8way_update( &ctx.panama, vhash, 64 );
   panama_8way_close( &ctx.panama, vhash );
   dintrlv_8x32_512( hash0[22], hash1[22], hash2[22], hash3[22],
                     hash4[22], hash5[22], hash6[22], hash7[22], vhash );

   laneHash(512, (const BitSequence*)hash0[22], 512, (BitSequence*)hash0[23]);
   laneHash(512, (const BitSequence*)hash1[22], 512, (BitSequence*)hash1[23]);
   laneHash(512, (const BitSequence*)hash2[22], 512, (BitSequence*)hash2[23]);
   laneHash(512, (const BitSequence*)hash3[22], 512, (BitSequence*)hash3[23]);
   laneHash(512, (const BitSequence*)hash4[22], 512, (BitSequence*)hash4[23]);
   laneHash(512, (const BitSequence*)hash5[22], 512, (BitSequence*)hash5[23]);
   laneHash(512, (const BitSequence*)hash6[22], 512, (BitSequence*)hash6[23]);
   laneHash(512, (const BitSequence*)hash7[22], 512, (BitSequence*)hash7[23]);

   if ( work_restart[thrid].restart ) return 0;
   
   x25x_shuffle( hash0 );
   x25x_shuffle( hash1 );
   x25x_shuffle( hash2 );
   x25x_shuffle( hash3 );
   x25x_shuffle( hash4 );
   x25x_shuffle( hash5 );
   x25x_shuffle( hash6 );
   x25x_shuffle( hash7 );

   intrlv_8x32_512( vhashX[ 0], hash0[ 0], hash1[ 0], hash2[ 0], hash3[ 0],
                                hash4[ 0], hash5[ 0], hash6[ 0], hash7[ 0] );
   intrlv_8x32_512( vhashX[ 1], hash0[ 1], hash1[ 1], hash2[ 1], hash3[ 1],
                                hash4[ 1], hash5[ 1], hash6[ 1], hash7[ 1] );
   intrlv_8x32_512( vhashX[ 2], hash0[ 2], hash1[ 2], hash2[ 2], hash3[ 2],
                                hash4[ 2], hash5[ 2], hash6[ 2], hash7[ 2] );
   intrlv_8x32_512( vhashX[ 3], hash0[ 3], hash1[ 3], hash2[ 3], hash3[ 3],
                                hash4[ 3], hash5[ 3], hash6[ 3], hash7[ 3] );
   intrlv_8x32_512( vhashX[ 4], hash0[ 4], hash1[ 4], hash2[ 4], hash3[ 4],
                                hash4[ 4], hash5[ 4], hash6[ 4], hash7[ 4] );
   intrlv_8x32_512( vhashX[ 5], hash0[ 5], hash1[ 5], hash2[ 5], hash3[ 5],
                                hash4[ 5], hash5[ 5], hash6[ 5], hash7[ 5] );
   intrlv_8x32_512( vhashX[ 6], hash0[ 6], hash1[ 6], hash2[ 6], hash3[ 6],
                                hash4[ 6], hash5[ 6], hash6[ 6], hash7[ 6] );
   intrlv_8x32_512( vhashX[ 7], hash0[ 7], hash1[ 7], hash2[ 7], hash3[ 7],
                                hash4[ 7], hash5[ 7], hash6[ 7], hash7[ 7] );
   intrlv_8x32_512( vhashX[ 8], hash0[ 8], hash1[ 8], hash2[ 8], hash3[ 8],
                                hash4[ 8], hash5[ 8], hash6[ 8], hash7[ 8] );
   intrlv_8x32_512( vhashX[ 9], hash0[ 9], hash1[ 9], hash2[ 9], hash3[ 9],
                                hash4[ 9], hash5[ 9], hash6[ 9], hash7[ 9] );
   intrlv_8x32_512( vhashX[10], hash0[10], hash1[10], hash2[10], hash3[10],
                                hash4[10], hash5[10], hash6[10], hash7[10] );
   intrlv_8x32_512( vhashX[11], hash0[11], hash1[11], hash2[11], hash3[11],
                                hash4[11], hash5[11], hash6[11], hash7[11] );
   intrlv_8x32_512( vhashX[12], hash0[12], hash1[12], hash2[12], hash3[12],
                                hash4[12], hash5[12], hash6[12], hash7[12] );
   intrlv_8x32_512( vhashX[13], hash0[13], hash1[13], hash2[13], hash3[13],
                                hash4[13], hash5[13], hash6[13], hash7[13] );
   intrlv_8x32_512( vhashX[14], hash0[14], hash1[14], hash2[14], hash3[14],
                                hash4[14], hash5[14], hash6[14], hash7[14] );
   intrlv_8x32_512( vhashX[15], hash0[15], hash1[15], hash2[15], hash3[15],
                                hash4[15], hash5[15], hash6[15], hash7[15] );
   intrlv_8x32_512( vhashX[16], hash0[16], hash1[16], hash2[16], hash3[16],
                                hash4[16], hash5[16], hash6[16], hash7[16] );
   intrlv_8x32_512( vhashX[17], hash0[17], hash1[17], hash2[17], hash3[17],
                                hash4[17], hash5[17], hash6[17], hash7[17] );
   intrlv_8x32_512( vhashX[18], hash0[18], hash1[18], hash2[18], hash3[18],
                                hash4[18], hash5[18], hash6[18], hash7[18] );
   intrlv_8x32_512( vhashX[19], hash0[19], hash1[19], hash2[19], hash3[19],
                                hash4[19], hash5[19], hash6[19], hash7[19] );
   intrlv_8x32_512( vhashX[20], hash0[20], hash1[20], hash2[20], hash3[20],
                                hash4[20], hash5[20], hash6[20], hash7[20] );
   intrlv_8x32_512( vhashX[21], hash0[21], hash1[21], hash2[21], hash3[21],
                                hash4[21], hash5[21], hash6[21], hash7[21] );
   intrlv_8x32_512( vhashX[22], hash0[22], hash1[22], hash2[22], hash3[22],
                                hash4[22], hash5[22], hash6[22], hash7[22] );
   intrlv_8x32_512( vhashX[23], hash0[23], hash1[23], hash2[23], hash3[23],
                                hash4[23], hash5[23], hash6[23], hash7[23] );

   blake2s_8way_init( &ctx.blake2s, 32 );
   blake2s_8way_full_blocks( &ctx.blake2s, output, vhashX, 64*24 );

   return 1;
}

int scanhash_x25x_8way( struct work *work, uint32_t max_nonce,
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
      if ( x25x_8way_hash( hash, vdata, thr_id ) );

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

#elif defined(X25X_4WAY)

union _x25x_4way_ctx_overlay
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
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
#if defined(X25X_4WAY_SHA)
    sha256_context          sha256;
#else
    sha256_4way_context     sha256;
#endif
    panama_4way_context     panama;
    blake2s_4way_state      blake2s;
};
typedef union _x25x_4way_ctx_overlay x25x_4way_ctx_overlay;

int x25x_4way_hash( void *output, const void *input, int thrid )
{
   uint64_t vhash[8*4] __attribute__ ((aligned (128)));
   unsigned char hash0[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash1[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash2[25][64] __attribute__((aligned(64))) = {0};
   unsigned char hash3[25][64] __attribute__((aligned(64))) = {0};
   unsigned char vhashX[24][64*4] __attribute__ ((aligned (64)));
   uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
   uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
   x25x_4way_ctx_overlay ctx __attribute__ ((aligned (64)));

   blake512_4way_full( &ctx.blake, vhash, input, 80 );
   dintrlv_4x64_512( hash0[0], hash1[0], hash2[0], hash3[0], vhash );

   bmw512_4way_init( &ctx.bmw );
   bmw512_4way_update( &ctx.bmw, vhash, 64 );
   bmw512_4way_close( &ctx.bmw, vhash );
   dintrlv_4x64_512( hash0[1], hash1[1], hash2[1], hash3[1], vhash );

#if defined(__VAES__)

   rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

   groestl512_2way_full( &ctx.groestl, vhashA, vhashA, 64 );
   groestl512_2way_full( &ctx.groestl, vhashB, vhashB, 64 );

   dintrlv_2x128_512( hash0[2], hash1[2], vhashA );
   dintrlv_2x128_512( hash2[2], hash3[2], vhashB );

#else

   groestl512_full( &ctx.groestl, (char*)hash0[2], (const char*)hash0[1], 512 );
   groestl512_full( &ctx.groestl, (char*)hash1[2], (const char*)hash1[1], 512 );
   groestl512_full( &ctx.groestl, (char*)hash2[2], (const char*)hash2[1], 512 );
   groestl512_full( &ctx.groestl, (char*)hash3[2], (const char*)hash3[1], 512 );

#endif

   intrlv_4x64_512( vhash, hash0[2], hash1[2], hash2[2], hash3[2] );
   skein512_4way_full( &ctx.skein, vhash, vhash, 64 );
   dintrlv_4x64_512( hash0[3], hash1[3], hash2[3], hash3[3], vhash );

   jh512_4way_init( &ctx.jh );
   jh512_4way_update( &ctx.jh, vhash, 64 );
   jh512_4way_close( &ctx.jh, vhash );
   dintrlv_4x64_512( hash0[4], hash1[4], hash2[4], hash3[4], vhash );

   if ( work_restart[thrid].restart ) return 0;
   
   keccak512_4way_init( &ctx.keccak );
   keccak512_4way_update( &ctx.keccak, vhash, 64 );
   keccak512_4way_close( &ctx.keccak, vhash );
   dintrlv_4x64_512( hash0[5], hash1[5], hash2[5], hash3[5], vhash );

   rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

   luffa512_2way_full( &ctx.luffa, vhashA, vhashA, 64 );
   luffa512_2way_full( &ctx.luffa, vhashB, vhashB, 64 );
   dintrlv_2x128_512( hash0[6], hash1[6], vhashA );
   dintrlv_2x128_512( hash2[6], hash3[6], vhashB );
   
   cube_2way_full( &ctx.cube, vhashA, 512, vhashA, 64 );
   cube_2way_full( &ctx.cube, vhashB, 512, vhashB, 64 );
   dintrlv_2x128_512( hash0[7], hash1[7], vhashA );
   dintrlv_2x128_512( hash2[7], hash3[7], vhashB );

   shavite512_2way_full( &ctx.shavite, vhashA, vhashA, 64 );
   shavite512_2way_full( &ctx.shavite, vhashB, vhashB, 64 );
   dintrlv_2x128_512( hash0[8], hash1[8], vhashA );
   dintrlv_2x128_512( hash2[8], hash3[8], vhashB );

   simd512_2way_full( &ctx.simd, vhashA, vhashA, 64 );
   simd512_2way_full( &ctx.simd, vhashB, vhashB, 64 );
   dintrlv_2x128_512( hash0[9], hash1[9], vhashA );
   dintrlv_2x128_512( hash2[9], hash3[9], vhashB );

#if defined(__VAES__)

   echo_2way_full( &ctx.echo, vhashA, 512, vhashA, 64 );
   echo_2way_full( &ctx.echo, vhashB, 512, vhashB, 64 );
   dintrlv_2x128_512( hash0[10], hash1[10], vhashA );
   dintrlv_2x128_512( hash2[10], hash3[10], vhashB );

   rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );

#else

   echo_full( &ctx.echo, (BitSequence *)hash0[10], 512,
                   (const BitSequence *)hash0[ 9], 64 );
   echo_full( &ctx.echo, (BitSequence *)hash1[10], 512,
                   (const BitSequence *)hash1[ 9], 64 );
   echo_full( &ctx.echo, (BitSequence *)hash2[10], 512,
                   (const BitSequence *)hash2[ 9], 64 );
   echo_full( &ctx.echo, (BitSequence *)hash3[10], 512,
                   (const BitSequence *)hash3[ 9], 64 );

   intrlv_4x64_512( vhash, hash0[10], hash1[10], hash2[10], hash3[10] );

#endif

   if ( work_restart[thrid].restart ) return 0;
   
   hamsi512_4way_init( &ctx.hamsi );
   hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
   hamsi512_4way_close( &ctx.hamsi, vhash );
   dintrlv_4x64_512( hash0[11], hash1[11], hash2[11], hash3[11], vhash );

   fugue512_full( &ctx.fugue, hash0[12], hash0[11], 64 );
   fugue512_full( &ctx.fugue, hash1[12], hash1[11], 64 );
   fugue512_full( &ctx.fugue, hash2[12], hash2[11], 64 );
   fugue512_full( &ctx.fugue, hash3[12], hash3[11], 64 );

   intrlv_4x32_512( vhash, hash0[12], hash1[12], hash2[12], hash3[12] );

   shabal512_4way_init( &ctx.shabal );
   shabal512_4way_update( &ctx.shabal, vhash, 64 );
   shabal512_4way_close( &ctx.shabal, vhash );
   dintrlv_4x32_512( hash0[13], hash1[13], hash2[13], hash3[13], vhash );

   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash0[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash0[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash1[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash1[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash2[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash2[14]);
   sph_whirlpool_init(&ctx.whirlpool);
   sph_whirlpool (&ctx.whirlpool, (const void*) hash3[13], 64);
   sph_whirlpool_close(&ctx.whirlpool, hash3[14]);

   intrlv_4x64_512( vhash, hash0[14], hash1[14], hash2[14], hash3[14] );

   sha512_4way_init( &ctx.sha512 );
   sha512_4way_update( &ctx.sha512, vhash, 64 );
   sha512_4way_close( &ctx.sha512, vhash );
   dintrlv_4x64_512( hash0[15], hash1[15], hash2[15], hash3[15], vhash );

   ComputeSingleSWIFFTX((unsigned char*)hash0[12], (unsigned char*)hash0[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash1[12], (unsigned char*)hash1[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash2[12], (unsigned char*)hash2[16]);
   ComputeSingleSWIFFTX((unsigned char*)hash3[12], (unsigned char*)hash3[16]);

   intrlv_4x32_512( vhashX[0], hash0[16], hash1[16], hash2[16], hash3[16] );

   memset( vhash, 0, 64*4 );

   haval256_5_4way_init( &ctx.haval );
   haval256_5_4way_update( &ctx.haval, vhashX[0], 64 );
   haval256_5_4way_close( &ctx.haval, vhash );
   dintrlv_4x32_512( hash0[17], hash1[17], hash2[17], hash3[17], vhash );

   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash0[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash0[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash1[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash1[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash2[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash2[18]);
   sph_tiger_init(&ctx.tiger);
   sph_tiger (&ctx.tiger, (const void*) hash3[17], 64);
   sph_tiger_close(&ctx.tiger, (void*) hash3[18]);

   LYRA2RE( (void*)hash0[19], 32, (const void*)hash0[18], 32,
            (const void*)hash0[18], 32, 1, 4, 4 );
   LYRA2RE( (void*)hash1[19], 32, (const void*)hash1[18], 32,
            (const void*)hash1[18], 32, 1, 4, 4 );
   LYRA2RE( (void*)hash2[19], 32, (const void*)hash2[18], 32,
            (const void*)hash2[18], 32, 1, 4, 4 );
   LYRA2RE( (void*)hash3[19], 32, (const void*)hash3[18], 32,
            (const void*)hash3[18], 32, 1, 4, 4 );

   if ( work_restart[thrid].restart ) return 0;
   
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash0[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash0[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash1[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash1[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash2[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash2[20]);
   sph_gost512_init(&ctx.gost);
   sph_gost512 (&ctx.gost, (const void*) hash3[19], 64);
   sph_gost512_close(&ctx.gost, (void*) hash3[20]);

#if defined(X25X_4WAY_SHA)

   sha256_full( hash0[21], hash0[20], 64 );
   sha256_full( hash1[21], hash1[20], 64 );
   sha256_full( hash2[21], hash2[20], 64 );
   sha256_full( hash3[21], hash3[20], 64 );

   intrlv_4x32_512( vhash, hash0[21], hash1[21], hash2[21], hash3[21] );

#else   

   intrlv_4x32_512( vhashX[0], hash0[20], hash1[20], hash2[20], hash3[20] );
   memset( vhash, 0, 64*4 );

   sha256_4way_init( &ctx.sha256 );
   sha256_4way_update( &ctx.sha256, vhashX[0], 64 );
   sha256_4way_close( &ctx.sha256, vhash );
   dintrlv_4x32_512( hash0[21], hash1[21], hash2[21], hash3[21], vhash );

#endif

   panama_4way_init( &ctx.panama );
   panama_4way_update( &ctx.panama, vhash, 64 );
   panama_4way_close( &ctx.panama, vhash );
   dintrlv_4x32_512( hash0[22], hash1[22], hash2[22], hash3[22], vhash );

   laneHash(512, (const BitSequence*)hash0[22], 512, (BitSequence*)hash0[23]);
   laneHash(512, (const BitSequence*)hash1[22], 512, (BitSequence*)hash1[23]);
   laneHash(512, (const BitSequence*)hash2[22], 512, (BitSequence*)hash2[23]);
   laneHash(512, (const BitSequence*)hash3[22], 512, (BitSequence*)hash3[23]);

   if ( work_restart[thrid].restart ) return 0;
  
   x25x_shuffle( hash0 );
   x25x_shuffle( hash1 );
   x25x_shuffle( hash2 );
   x25x_shuffle( hash3 );

   intrlv_4x32_512( vhashX[ 0], hash0[ 0], hash1[ 0], hash2[ 0], hash3[ 0] );
   intrlv_4x32_512( vhashX[ 1], hash0[ 1], hash1[ 1], hash2[ 1], hash3[ 1] );
   intrlv_4x32_512( vhashX[ 2], hash0[ 2], hash1[ 2], hash2[ 2], hash3[ 2] );
   intrlv_4x32_512( vhashX[ 3], hash0[ 3], hash1[ 3], hash2[ 3], hash3[ 3] );
   intrlv_4x32_512( vhashX[ 4], hash0[ 4], hash1[ 4], hash2[ 4], hash3[ 4] );
   intrlv_4x32_512( vhashX[ 5], hash0[ 5], hash1[ 5], hash2[ 5], hash3[ 5] );
   intrlv_4x32_512( vhashX[ 6], hash0[ 6], hash1[ 6], hash2[ 6], hash3[ 6] );
   intrlv_4x32_512( vhashX[ 7], hash0[ 7], hash1[ 7], hash2[ 7], hash3[ 7] );
   intrlv_4x32_512( vhashX[ 8], hash0[ 8], hash1[ 8], hash2[ 8], hash3[ 8] );
   intrlv_4x32_512( vhashX[ 9], hash0[ 9], hash1[ 9], hash2[ 9], hash3[ 9] );
   intrlv_4x32_512( vhashX[10], hash0[10], hash1[10], hash2[10], hash3[10] );
   intrlv_4x32_512( vhashX[11], hash0[11], hash1[11], hash2[11], hash3[11] );
   intrlv_4x32_512( vhashX[12], hash0[12], hash1[12], hash2[12], hash3[12] );
   intrlv_4x32_512( vhashX[13], hash0[13], hash1[13], hash2[13], hash3[13] );
   intrlv_4x32_512( vhashX[14], hash0[14], hash1[14], hash2[14], hash3[14] );
   intrlv_4x32_512( vhashX[15], hash0[15], hash1[15], hash2[15], hash3[15] );
   intrlv_4x32_512( vhashX[16], hash0[16], hash1[16], hash2[16], hash3[16] );
   intrlv_4x32_512( vhashX[17], hash0[17], hash1[17], hash2[17], hash3[17] );
   intrlv_4x32_512( vhashX[18], hash0[18], hash1[18], hash2[18], hash3[18] );
   intrlv_4x32_512( vhashX[19], hash0[19], hash1[19], hash2[19], hash3[19] );
   intrlv_4x32_512( vhashX[20], hash0[20], hash1[20], hash2[20], hash3[20] );
   intrlv_4x32_512( vhashX[21], hash0[21], hash1[21], hash2[21], hash3[21] );
   intrlv_4x32_512( vhashX[22], hash0[22], hash1[22], hash2[22], hash3[22] );
   intrlv_4x32_512( vhashX[23], hash0[23], hash1[23], hash2[23], hash3[23] );

   blake2s_4way_init( &ctx.blake2s, 32 );
   blake2s_4way_full_blocks( &ctx.blake2s, output, vhashX, 64*24 );

   return 1;
}

int scanhash_x25x_4way( struct work* work, uint32_t max_nonce,
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
      if ( x25x_4way_hash( hash, vdata, thr_id ) )
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
