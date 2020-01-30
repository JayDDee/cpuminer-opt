/**
 * x21s algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 * Optimized by JayDDee@github Jan 2018
 */
#include "x16r-gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/gost/sph_gost.h"
#include "algo/lyra2/lyra2.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif
#if defined(__SHA__)
 #include <openssl/sha.h>
#endif

#if defined(X21S_8WAY) || defined(X21S_4WAY)

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread char hashOrder[X16R_HASH_FUNC_COUNT + 1] = { 0 };

#endif

#if defined (X21S_8WAY)

static __thread uint64_t* x21s_8way_matrix;

union _x21s_8way_context_overlay
{
    blake512_8way_context   blake;
    bmw512_8way_context     bmw;
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    keccak512_8way_context  keccak;
    luffa_4way_context      luffa;
    cubehashParam           cube;
//    cube_4way_context       cube;
    simd_4way_context       simd;
    hamsi512_8way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_8way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_8way_context     sha512;
    haval256_5_8way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
    sha256_8way_context     sha256;
#if defined(__VAES__)
    groestl512_4way_context groestl;
    shavite512_4way_context shavite;
    echo_4way_context       echo;
#else
    hashState_groestl       groestl;
    sph_shavite512_context  shavite;
    hashState_echo          echo;
#endif
} __attribute__ ((aligned (64)));

typedef union _x21s_8way_context_overlay x21s_8way_context_overlay;

static __thread x21s_8way_context_overlay x21s_ctx;

void x21s_8way_hash( void* output, const void* input )
{
   uint32_t vhash[20*8] __attribute__ ((aligned (128)));
   uint32_t hash0[20] __attribute__ ((aligned (64)));
   uint32_t hash1[20] __attribute__ ((aligned (64)));
   uint32_t hash2[20] __attribute__ ((aligned (64)));
   uint32_t hash3[20] __attribute__ ((aligned (64)));
   uint32_t hash4[20] __attribute__ ((aligned (64)));
   uint32_t hash5[20] __attribute__ ((aligned (64)));
   uint32_t hash6[20] __attribute__ ((aligned (64)));
   uint32_t hash7[20] __attribute__ ((aligned (64)));
   x21s_8way_context_overlay ctx;
   memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   void *in2 = (void*) hash2;
   void *in3 = (void*) hash3;
   void *in4 = (void*) hash4;
   void *in5 = (void*) hash5;
   void *in6 = (void*) hash6;
   void *in7 = (void*) hash7;
   int size = 80;

   dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 input, 640 );

   for ( int i = 0; i < 16; i++ )
   {
      const char elem = hashOrder[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            if ( i == 0 )
               blake512_8way_full( &ctx.blake, vhash, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               blake512_8way_full( &ctx.blake, vhash, vhash, size );
            }
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5,
                                 hash6, hash7, vhash );
         break;
         case BMW:
            bmw512_8way_init( &ctx.bmw );
            if ( i == 0 )
               bmw512_8way_update( &ctx.bmw, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
            bmw512_8way_update( &ctx.bmw, vhash, size );
            }
            bmw512_8way_close( &ctx.bmw, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case GROESTL:
#if defined(__VAES__)
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            groestl512_4way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            groestl512_4way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
            groestl512_full( &ctx.groestl, (char*)hash0, (char*)in0, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash1, (char*)in1, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash2, (char*)in2, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash3, (char*)in3, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash4, (char*)in4, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash5, (char*)in5, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash6, (char*)in6, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash7, (char*)in7, size<<3 );
#endif
         break;
         case JH:
            if ( i == 0 )
               jh512_8way_update( &ctx.jh, input + (64<<3), 16 );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               jh512_8way_init( &ctx.jh );
               jh512_8way_update( &ctx.jh, vhash, size );
            }
            jh512_8way_close( &ctx.jh, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case KECCAK:
            keccak512_8way_init( &ctx.keccak );
            if ( i == 0 )
               keccak512_8way_update( &ctx.keccak, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               keccak512_8way_update( &ctx.keccak, vhash, size );
            }
            keccak512_8way_close( &ctx.keccak, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case SKEIN:
            if ( i == 0 )
               skein512_8way_update( &ctx.skein, input + (64<<3), 16 );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               skein512_8way_init( &ctx.skein );
               skein512_8way_update( &ctx.skein, vhash, size );
            }
            skein512_8way_close( &ctx.skein, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case LUFFA:
            if ( i == 0 )
            {
                intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
                luffa_4way_update_close( &ctx.luffa, vhash,
                                                     vhash + (16<<2), 16 );
                dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
                memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
                intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
                luffa_4way_update_close( &ctx.luffa, vhash,
                                                     vhash + (16<<2), 16 );
                dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
            }
            else
            {
               intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
               luffa512_4way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
               intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
               luffa512_4way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
            }
         break;
         case CUBEHASH:
            if ( i == 0 )
            {
               cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                                            (const byte*)in0 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash1,
                                            (const byte*)in1 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash2,
                                            (const byte*)in2 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash3,
                                            (const byte*)in3 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash4,
                                            (const byte*)in4 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash5,
                                            (const byte*)in5 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash6,
                                            (const byte*)in6 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash7,
                                            (const byte*)in7 + 64, 16 );
            }
            else
            {
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash0,
                                             (const byte*)in0, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash1,
                                             (const byte*)in1, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash2,
                                             (const byte*)in2, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash3,
                                             (const byte*)in3, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash4,
                                             (const byte*)in4, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash5,
                                             (const byte*)in5, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash6,
                                             (const byte*)in6, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash7,
                                             (const byte*)in7, size );
            }
         break;
         case SHAVITE:
#if defined(__VAES__)
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            shavite512_4way_init( &ctx.shavite );
            shavite512_4way_update_close( &ctx.shavite, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            shavite512_4way_init( &ctx.shavite );
            shavite512_4way_update_close( &ctx.shavite, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in0, size );
            sph_shavite512_close( &ctx.shavite, hash0 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in1, size );
            sph_shavite512_close( &ctx.shavite, hash1 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in2, size );
            sph_shavite512_close( &ctx.shavite, hash2 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in3, size );
            sph_shavite512_close( &ctx.shavite, hash3 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in4, size );
            sph_shavite512_close( &ctx.shavite, hash4 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in5, size );
            sph_shavite512_close( &ctx.shavite, hash5 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in6, size );
            sph_shavite512_close( &ctx.shavite, hash6 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in7, size );
            sph_shavite512_close( &ctx.shavite, hash7 );
#endif
         break;
         case SIMD:
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            simd512_4way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            simd512_4way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
         break;
         case ECHO:
#if defined(__VAES__)
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            echo_4way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            echo_4way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
            echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                              (const BitSequence *)in0, size );
            echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                              (const BitSequence *)in1, size );
            echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                              (const BitSequence *)in2, size );
            echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                              (const BitSequence *)in3, size );
            echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                              (const BitSequence *)in4, size );
            echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                              (const BitSequence *)in5, size );
            echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                              (const BitSequence *)in6, size );
            echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                              (const BitSequence *)in7, size );
#endif
         break;
         case HAMSI:
            if ( i == 0 )
               hamsi512_8way_update( &ctx.hamsi, input + (64<<3), 16 );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               hamsi512_8way_init( &ctx.hamsi );
               hamsi512_8way_update( &ctx.hamsi, vhash, size );
            }
            hamsi512_8way_close( &ctx.hamsi, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case FUGUE:
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in0, size );
             sph_fugue512_close( &ctx.fugue, hash0 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in1, size );
             sph_fugue512_close( &ctx.fugue, hash1 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in2, size );
             sph_fugue512_close( &ctx.fugue, hash2 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in3, size );
             sph_fugue512_close( &ctx.fugue, hash3 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in4, size );
             sph_fugue512_close( &ctx.fugue, hash4 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in5, size );
             sph_fugue512_close( &ctx.fugue, hash5 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in6, size );
             sph_fugue512_close( &ctx.fugue, hash6 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in7, size );
             sph_fugue512_close( &ctx.fugue, hash7 );
         break;
         case SHABAL:
             intrlv_8x32( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                             size<<3 );
             if ( i == 0 )
                shabal512_8way_update( &ctx.shabal, vhash + (16<<3), 16 );
             else
             {
                shabal512_8way_init( &ctx.shabal );
                shabal512_8way_update( &ctx.shabal, vhash, size );
             }
             shabal512_8way_close( &ctx.shabal, vhash );
             dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case WHIRLPOOL:
            if ( i == 0 )
            {
               sph_whirlpool( &ctx.whirlpool, in0 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash0 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in1 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in2 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in3 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in4 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash4 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in5 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash5 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in6 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash6 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in7 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash7 );
            }
            else
            {
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in0, size );
               sph_whirlpool_close( &ctx.whirlpool, hash0 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in1, size );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in2, size );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in3, size );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in4, size );
               sph_whirlpool_close( &ctx.whirlpool, hash4 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in5, size );
               sph_whirlpool_close( &ctx.whirlpool, hash5 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in6, size );
               sph_whirlpool_close( &ctx.whirlpool, hash6 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in7, size );
               sph_whirlpool_close( &ctx.whirlpool, hash7 );
            }
         break;
         case SHA_512:
             sha512_8way_init( &ctx.sha512 );
             if ( i == 0 )
                sha512_8way_update( &ctx.sha512, input, size );
             else
             {
                intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                             size<<3 );
                sha512_8way_update( &ctx.sha512, vhash, size );
             }
             sha512_8way_close( &ctx.sha512, vhash );
             dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                               hash7, vhash );
          break;
      }
      size = 64;
   }

   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                    hash7 );

   haval256_5_8way_init( &ctx.haval );
   haval256_5_8way_update( &ctx.haval, vhash, 64 );
   haval256_5_8way_close( &ctx.haval, vhash );

   dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                     hash7, vhash );

   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash0, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash0 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash1, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash1 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash2, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash2 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash3, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash3 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash4, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash4 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash5, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash5 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash6, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash6 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash7, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash7 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
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

   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                    hash7 );
   sha256_8way_init( &ctx.sha256 );
   sha256_8way_update( &ctx.sha256, vhash, 64 );
   sha256_8way_close( &ctx.sha256, output );
}

int scanhash_x21s_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t vdata2[20*8] __attribute__ ((aligned (64)));
   uint32_t edata[20] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &hash[7<<3];
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t bedata1[2] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce - 16;
   const int thr_id = mythr->id;
    __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench )   ptarget[7] = 0x0cff;

   bedata1[0] = bswap_32( pdata[1] );
   bedata1[1] = bswap_32( pdata[2] );
   uint32_t ntime = bswap_32( pdata[17] );
   if ( s_ntime != ntime )
   {
      x16_r_s_getAlgoString( (const uint8_t*)bedata1, hashOrder );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
              applog( LOG_INFO, "hash order %s (%08x)", hashOrder, ntime );
   }

   // Do midstate prehash on hash functions with block size <= 64 bytes.
   const char elem = hashOrder[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';
   switch ( algo )
   {
      case JH:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         jh512_8way_init( &x21s_ctx.jh );
         jh512_8way_update( &x21s_ctx.jh, vdata, 64 );
      break;
      case SKEIN:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         skein512_8way_init( &x21s_ctx.skein );
         skein512_8way_update( &x21s_ctx.skein, vdata, 64 );
      break;
      case LUFFA:
         mm128_bswap32_80( edata, pdata );
         intrlv_4x128( vdata2, edata, edata, edata, edata, 640 );
         luffa_4way_init( &x21s_ctx.luffa, 512 );
         luffa_4way_update( &x21s_ctx.luffa, vdata2, 64 );
         rintrlv_4x128_8x64( vdata, vdata2, vdata2, 640 );
      break;
      case CUBEHASH:
         mm128_bswap32_80( edata, pdata );
         cubehashInit( &x21s_ctx.cube, 512, 16, 32 );
         cubehashUpdate( &x21s_ctx.cube, (const byte*)edata, 64 );
         intrlv_8x64( vdata, edata, edata, edata, edata,
                             edata, edata, edata, edata, 640 );
      break;
      case HAMSI:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         hamsi512_8way_init( &x21s_ctx.hamsi );
         hamsi512_8way_update( &x21s_ctx.hamsi, vdata, 64 );
      break;
      case SHABAL:
         mm256_bswap32_intrlv80_8x32( vdata2, pdata );
         shabal512_8way_init( &x21s_ctx.shabal );
         shabal512_8way_update( &x21s_ctx.shabal, vdata2, 64 );
         rintrlv_8x32_8x64( vdata, vdata2, 640 );
      break;
      case WHIRLPOOL:
         mm128_bswap32_80( edata, pdata );
         sph_whirlpool_init( &x21s_ctx.whirlpool );
         sph_whirlpool( &x21s_ctx.whirlpool, edata, 64 );
         intrlv_8x64( vdata, edata, edata, edata, edata,
                             edata, edata, edata, edata, 640 );
      break;
      default:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
   }

   *noncev = mm512_intrlv_blend_32( _mm512_set_epi32(
                             n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                             n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );

 
   do
   {
      x21s_8way_hash( hash, vdata );

      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( hash7[lane] <= Htarg ) )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
             pdata[19] = bswap_32( n + lane );
             submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
      n += 8;
   } while ( (  n < last_nonce ) && !(*restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool x21s_8way_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   const int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   x21s_8way_matrix = _mm_malloc( 2 * size, 64 );
   return x21s_8way_matrix;
}

#elif defined (X21S_4WAY)

static __thread uint64_t* x21s_4way_matrix;

union _x21s_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_echo          echo;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    hashState_luffa         luffa1;
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    simd_2way_context       simd;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
#if defined(__SHA__)
    SHA256_CTX              sha256;
#else
    sha256_4way_context     sha256;
#endif
} __attribute__ ((aligned (64)));
typedef union _x21s_4way_context_overlay x21s_4way_context_overlay;

static __thread x21s_4way_context_overlay x21s_ctx;

void x21s_4way_hash( void* output, const void* input )
{
   uint32_t hash0[20] __attribute__ ((aligned (64)));
   uint32_t hash1[20] __attribute__ ((aligned (64)));
   uint32_t hash2[20] __attribute__ ((aligned (64)));
   uint32_t hash3[20] __attribute__ ((aligned (64)));
   uint32_t vhash[20*4] __attribute__ ((aligned (64)));
   x21s_4way_context_overlay ctx;
   memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   void *in2 = (void*) hash2;
   void *in3 = (void*) hash3;
   int size = 80;

   dintrlv_4x64( hash0, hash1, hash2, hash3, input, 640 );

   // Input data is both 64 bit interleaved (input)
   // and deinterleaved in inp0-3.
   // If First function uses 64 bit data it is not required to interleave inp
   // first. It may use the inerleaved data dmost convenient, ie 4way 64 bit.
   // All other functions assume data is deinterleaved in hash0-3
   // All functions must exit with data deinterleaved in hash0-3.
   // Alias in0-3 points to either inp0-3 or hash0-3 according to
   // its hashOrder position. Size is also set accordingly.
   for ( int i = 0; i < 16; i++ )
   {
      const char elem = hashOrder[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            if ( i == 0 )
               blake512_4way_full( &ctx.blake, vhash, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               blake512_4way_full( &ctx.blake, vhash, vhash, size );
            }
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case BMW:
            bmw512_4way_init( &ctx.bmw );
            if ( i == 0 )
               bmw512_4way_update( &ctx.bmw, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               bmw512_4way_update( &ctx.bmw, vhash, size );
            }
            bmw512_4way_close( &ctx.bmw, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case GROESTL:
            groestl512_full( &ctx.groestl, (char*)hash0, (char*)in0, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash1, (char*)in1, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash2, (char*)in2, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash3, (char*)in3, size<<3 );
         break;
         case JH:
            if ( i == 0 )
               jh512_4way_update( &ctx.jh, input + (64<<2), 16 );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               jh512_4way_init( &ctx.jh );
               jh512_4way_update( &ctx.jh, vhash, size );
            }
            jh512_4way_close( &ctx.jh, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case KECCAK:
            keccak512_4way_init( &ctx.keccak );
            if ( i == 0 )
               keccak512_4way_update( &ctx.keccak, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               keccak512_4way_update( &ctx.keccak, vhash, size );
            }
            keccak512_4way_close( &ctx.keccak, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case SKEIN:
            if ( i == 0 )
               skein512_4way_update( &ctx.skein, input + (64<<2), 16 );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               skein512_4way_init( &ctx.skein );
               skein512_4way_update( &ctx.skein, vhash, size );
            }
            skein512_4way_close( &ctx.skein, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case LUFFA:
            if ( i == 0 )
            {
               update_and_final_luffa( &ctx.luffa1, (BitSequence*)hash0,
                                    (const BitSequence*)in0 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               update_and_final_luffa( &ctx.luffa1, (BitSequence*)hash1,
                                    (const BitSequence*)in1 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );  
               update_and_final_luffa( &ctx.luffa1, (BitSequence*)hash2,
                                    (const BitSequence*)in2 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );  
               update_and_final_luffa( &ctx.luffa1, (BitSequence*)hash3,
                                    (const BitSequence*)in3 + 64, 16 );
            }
            else
            {
               intrlv_2x128( vhash, in0, in1, size<<3 );
               luffa512_2way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_2x128_512( hash0, hash1, vhash );
               intrlv_2x128( vhash, in2, in3, size<<3 );
               luffa512_2way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_2x128_512( hash2, hash3, vhash );
            }
         break;
         case CUBEHASH:
            if ( i == 0 )
            {
               cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                                          (const byte*)in0 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash1,
                                          (const byte*)in1 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash2,
                                          (const byte*)in2 + 64, 16 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash3,
                                          (const byte*)in3 + 64, 16 );

            }
            else
            {   
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                                          (const byte*)in0, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash1,
                                     (const byte*)in1, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash2,
                                     (const byte*)in2, size );
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash3,
                                     (const byte*)in3, size );
            }
         break;
         case SHAVITE:
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in0, size );
            sph_shavite512_close( &ctx.shavite, hash0 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in1, size );
            sph_shavite512_close( &ctx.shavite, hash1 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in2, size );
            sph_shavite512_close( &ctx.shavite, hash2 );
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in3, size );
            sph_shavite512_close( &ctx.shavite, hash3 );
         break;
         case SIMD:
            intrlv_2x128( vhash, in0, in1, size<<3 );
            simd_2way_init( &ctx.simd, 512 );
            simd_2way_update_close( &ctx.simd, vhash, vhash, size<<3 );
            dintrlv_2x128( hash0, hash1, vhash, 512 );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            simd_2way_init( &ctx.simd, 512 );
            simd_2way_update_close( &ctx.simd, vhash, vhash, size<<3 );
            dintrlv_2x128( hash2, hash3, vhash, 512 );
         break;
         case ECHO:
            echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                              (const BitSequence *)in0, size );
            echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                              (const BitSequence *)in1, size );
            echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                              (const BitSequence *)in2, size );
            echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                              (const BitSequence *)in3, size );
         break;
         case HAMSI:
            if ( i == 0 )
               hamsi512_4way_update( &ctx.hamsi, input + (64<<2), 16 );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               hamsi512_4way_init( &ctx.hamsi );
               hamsi512_4way_update( &ctx.hamsi, vhash, size );
            }
            hamsi512_4way_close( &ctx.hamsi, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case FUGUE:
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in0, size );
             sph_fugue512_close( &ctx.fugue, hash0 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in1, size );
             sph_fugue512_close( &ctx.fugue, hash1 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in2, size );
             sph_fugue512_close( &ctx.fugue, hash2 );
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in3, size );
             sph_fugue512_close( &ctx.fugue, hash3 );
         break;
         case SHABAL:
            intrlv_4x32( vhash, in0, in1, in2, in3, size<<3 );
            if ( i == 0 )
               shabal512_4way_update( &ctx.shabal, vhash + (16<<2), 16 );
            else
            {
               shabal512_4way_init( &ctx.shabal );
               shabal512_4way_update( &ctx.shabal, vhash, size );
            }
            shabal512_4way_close( &ctx.shabal, vhash );
            dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case WHIRLPOOL:
            if ( i == 0 )
            {
               sph_whirlpool( &ctx.whirlpool, in0 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash0 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in1 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in2 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               memcpy( &ctx, &x21s_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in3 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
            }
            else
            {
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in0, size );
               sph_whirlpool_close( &ctx.whirlpool, hash0 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in1, size );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in2, size );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               sph_whirlpool_init( &ctx.whirlpool );
               sph_whirlpool( &ctx.whirlpool, in3, size );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
            }
         break;
         case SHA_512:
            sha512_4way_init( &ctx.sha512 );
            if ( i == 0 )
               sha512_4way_update( &ctx.sha512, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               sha512_4way_update( &ctx.sha512, vhash, size );
            }
            sha512_4way_close( &ctx.sha512, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
      }
      size = 64;
   }

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3,  512 );

   haval256_5_4way_init( &ctx.haval );
   haval256_5_4way_update( &ctx.haval, vhash, 64 );
   haval256_5_4way_close( &ctx.haval, vhash );

   dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 512 );

   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash0, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash0 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash1, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash1 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash2, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash2 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash3, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash3 );

   LYRA2REV2( x21s_4way_matrix, (void*) hash0, 32, (const void*) hash0, 32,
            (const void*) hash0, 32, 1, 4, 4 );
   LYRA2REV2( x21s_4way_matrix, (void*) hash1, 32, (const void*) hash1, 32,
            (const void*) hash1, 32, 1, 4, 4 );
   LYRA2REV2( x21s_4way_matrix, (void*) hash2, 32, (const void*) hash2, 32,
            (const void*) hash2, 32, 1, 4, 4 );
   LYRA2REV2( x21s_4way_matrix, (void*) hash3, 32, (const void*) hash3, 32,
            (const void*) hash3, 32, 1, 4, 4 );

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

#if defined(__SHA__)

   SHA256_Init( &ctx.sha256 );
   SHA256_Update( &ctx.sha256, hash0, 64 );
   SHA256_Final( (unsigned char*)hash0, &ctx.sha256 );
   SHA256_Init( &ctx.sha256 );
   SHA256_Update( &ctx.sha256, hash1, 64 );
   SHA256_Final( (unsigned char*)hash1, &ctx.sha256 );
   SHA256_Init( &ctx.sha256 );
   SHA256_Update( &ctx.sha256, hash2, 64 );
   SHA256_Final( (unsigned char*)hash2, &ctx.sha256 );
   SHA256_Init( &ctx.sha256 );
   SHA256_Update( &ctx.sha256, hash3, 64 );
   SHA256_Final( (unsigned char*)hash3, &ctx.sha256 );

   memcpy( output,    hash0, 32 );
   memcpy( output+32, hash1, 32 );
   memcpy( output+64, hash2, 32 );
   memcpy( output+96, hash3, 32 );

#else

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );
   sha256_4way_init( &ctx.sha256 );
   sha256_4way_update( &ctx.sha256, vhash, 64 );
   sha256_4way_close( &ctx.sha256, vhash );
   dintrlv_4x32( output, output+32, output+64,output+96, vhash, 256 );

#endif
}

int scanhash_x21s_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t vdata32[20*4] __attribute__ ((aligned (64)));
   uint32_t edata[20] __attribute__ ((aligned (64)));
   uint32_t bedata1[2] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id; 
   const bool bench = opt_benchmark;
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   if ( bench )  ptarget[7] = 0x0cff;
 
   bedata1[0] = bswap_32( pdata[1] );
   bedata1[1] = bswap_32( pdata[2] );
   uint32_t ntime = bswap_32( pdata[17] );
   if ( s_ntime != ntime )
   {
      x16_r_s_getAlgoString( (const uint8_t*)bedata1, hashOrder );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
              applog( LOG_DEBUG, "hash order %s (%08x)", hashOrder, ntime );
   }
   
   const char elem = hashOrder[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

   switch ( algo )
   {
      case JH:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         jh512_4way_init( &x21s_ctx.jh );
         jh512_4way_update( &x21s_ctx.jh, vdata, 64 );
      break;
      case SKEIN:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         skein512_4way_init( &x21s_ctx.skein );
         skein512_4way_update( &x21s_ctx.skein, vdata, 64 );
      break;
      case LUFFA:
         mm128_bswap32_80( edata, pdata );
         init_luffa( &x21s_ctx.luffa1, 512 );
         update_luffa( &x21s_ctx.luffa1, (const BitSequence*)edata, 64 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      case CUBEHASH:
         mm128_bswap32_80( edata, pdata );
         cubehashInit( &x21s_ctx.cube, 512, 16, 32 );
         cubehashUpdate( &x21s_ctx.cube, (const byte*)edata, 64 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      case HAMSI:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         hamsi512_4way_init( &x21s_ctx.hamsi );
         hamsi512_4way_update( &x21s_ctx.hamsi, vdata, 64 );
      break;
      case SHABAL:
         mm128_bswap32_intrlv80_4x32( vdata32, pdata );
         shabal512_4way_init( &x21s_ctx.shabal );
         shabal512_4way_update( &x21s_ctx.shabal, vdata32, 64 );
         rintrlv_4x32_4x64( vdata, vdata32, 640 );
      break;
      case WHIRLPOOL:
         mm128_bswap32_80( edata, pdata );
         sph_whirlpool_init( &x21s_ctx.whirlpool );
         sph_whirlpool( &x21s_ctx.whirlpool, edata, 64 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      default:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
   }

   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );

   do
   {
      x21s_4way_hash( hash, vdata );
      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_lane_solution( work, hash+(i<<3), mythr, i );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
      n += 4;
   } while ( (  n < last_nonce ) && !(*restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool x21s_4way_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   const int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   x21s_4way_matrix = _mm_malloc( size, 64 );
   return x21s_4way_matrix;
}

#endif
