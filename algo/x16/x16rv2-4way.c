/**
 * x16r algo implementation
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
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/tiger/sph_tiger.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread char hashOrder[X16R_HASH_FUNC_COUNT + 1] = { 0 };

#if defined (X16RV2_8WAY)

union _x16rv2_8way_context_overlay
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
    sph_fugue512_context    fugue;
    shabal512_8way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_8way_context     sha512;
    sph_tiger_context       tiger;
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

typedef union _x16rv2_8way_context_overlay x16rv2_8way_context_overlay;

void x16rv2_8way_hash( void* output, const void* input )
{
   uint32_t vhash[24*8] __attribute__ ((aligned (128)));
   uint32_t hash0[24] __attribute__ ((aligned (64)));
   uint32_t hash1[24] __attribute__ ((aligned (64)));
   uint32_t hash2[24] __attribute__ ((aligned (64)));
   uint32_t hash3[24] __attribute__ ((aligned (64)));
   uint32_t hash4[24] __attribute__ ((aligned (64)));
   uint32_t hash5[24] __attribute__ ((aligned (64)));
   uint32_t hash6[24] __attribute__ ((aligned (64)));
   uint32_t hash7[24] __attribute__ ((aligned (64)));
   x16rv2_8way_context_overlay ctx;
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
            blake512_8way_init( &ctx.blake );
            if ( i == 0 )
               blake512_8way_update( &ctx.blake, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               blake512_8way_update( &ctx.blake, vhash, size );
            }
            blake512_8way_close( &ctx.blake, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
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
            groestl512_4way_init( &ctx.groestl, 64 );
            groestl512_4way_update_close( &ctx.groestl, vhash, vhash, size<<3 );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            groestl512_4way_init( &ctx.groestl, 64 );
            groestl512_4way_update_close( &ctx.groestl, vhash, vhash, size<<3 );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                                 (const char*)in0, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                                 (const char*)in1, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                                 (const char*)in2, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                                 (const char*)in3, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash4,
                                                 (const char*)in4, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash5,
                                                 (const char*)in5, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash6,
                                                 (const char*)in6, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash7,
                                                 (const char*)in7, size<<3 );
#endif
               break;
         case SKEIN:
            skein512_8way_init( &ctx.skein );
            if ( i == 0 )
               skein512_8way_update( &ctx.skein, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               skein512_8way_update( &ctx.skein, vhash, size );
            }
            skein512_8way_close( &ctx.skein, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case JH:
            jh512_8way_init( &ctx.jh );
            if ( i == 0 )
               jh512_8way_update( &ctx.jh, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               jh512_8way_update( &ctx.jh, vhash, size );
            }
            jh512_8way_close( &ctx.jh, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case KECCAK:
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in0, size );
             sph_tiger_close( &ctx.tiger, hash0 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in1, size );
             sph_tiger_close( &ctx.tiger, hash1 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in2, size );
             sph_tiger_close( &ctx.tiger, hash2 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in3, size );
             sph_tiger_close( &ctx.tiger, hash3 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in4, size );
             sph_tiger_close( &ctx.tiger, hash4 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in5, size );
             sph_tiger_close( &ctx.tiger, hash5 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in6, size );
             sph_tiger_close( &ctx.tiger, hash6 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in7, size );
             sph_tiger_close( &ctx.tiger, hash7 );

             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] =
                hash4[i] = hash5[i] = hash6[i] = hash7[i] = 0;

             intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5,
                          hash6, hash7 );
             keccak512_8way_init( &ctx.keccak );
             keccak512_8way_update( &ctx.keccak, vhash, 64 );
             keccak512_8way_close( &ctx.keccak, vhash );
             dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case LUFFA:
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in0, size );
             sph_tiger_close( &ctx.tiger, hash0 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in1, size );
             sph_tiger_close( &ctx.tiger, hash1 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in2, size );
             sph_tiger_close( &ctx.tiger, hash2 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in3, size );
             sph_tiger_close( &ctx.tiger, hash3 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in4, size );
             sph_tiger_close( &ctx.tiger, hash4 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in5, size );
             sph_tiger_close( &ctx.tiger, hash5 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in6, size );
             sph_tiger_close( &ctx.tiger, hash6 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in7, size );
             sph_tiger_close( &ctx.tiger, hash7 );

             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] = 
                hash4[i] = hash5[i] = hash6[i] = hash7[i] = 0;

            intrlv_4x128_512( vhash, hash0, hash1, hash2, hash3);
            luffa_4way_init( &ctx.luffa, 512 );
            luffa_4way_update_close( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128_512( vhash, hash4, hash5, hash6, hash7);
            luffa_4way_init( &ctx.luffa, 512 );
            luffa_4way_update_close( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
         break;
         case CUBEHASH:
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            cube_4way_init( &ctx.cube, 512, 16, 32 );
            cube_4way_update_close( &ctx.cube, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            cube_4way_init( &ctx.cube, 512, 16, 32 );
            cube_4way_update_close( &ctx.cube, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
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
            simd_4way_init( &ctx.simd, 512 );
            simd_4way_update_close( &ctx.simd, vhash, vhash, size<<3 );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            simd_4way_init( &ctx.simd, 512 );
            simd_4way_update_close( &ctx.simd, vhash, vhash, size<<3 );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
         break;
         case ECHO:
#if defined(__VAES__)
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            echo_4way_init( &ctx.echo, 512 );
            echo_4way_update_close( &ctx.echo, vhash, vhash, size<<3 );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            echo_4way_init( &ctx.echo, 512 );
            echo_4way_update_close( &ctx.echo, vhash, vhash, size<<3 );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash0,
                                (const BitSequence*)in0, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash1,
                                (const BitSequence*)in1, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash2,
                                (const BitSequence*)in2, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash3,
                                (const BitSequence*)in3, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash4,
                                (const BitSequence*)in4, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash5,
                                (const BitSequence*)in5, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash6,
                                (const BitSequence*)in6, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash7,
                                (const BitSequence*)in7, size<<3 );
#endif
             break;
         case HAMSI:
             intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );

             hamsi512_8way_init( &ctx.hamsi );
             hamsi512_8way_update( &ctx.hamsi, vhash, size );
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
             shabal512_8way_init( &ctx.shabal );
             shabal512_8way_update( &ctx.shabal, vhash, size );
             shabal512_8way_close( &ctx.shabal, vhash );
             dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case WHIRLPOOL:
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
         break;
         case SHA_512:
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in0, size );
             sph_tiger_close( &ctx.tiger, hash0 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in1, size );
             sph_tiger_close( &ctx.tiger, hash1 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in2, size );
             sph_tiger_close( &ctx.tiger, hash2 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in3, size );
             sph_tiger_close( &ctx.tiger, hash3 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in4, size );
             sph_tiger_close( &ctx.tiger, hash4 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in5, size );
             sph_tiger_close( &ctx.tiger, hash5 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in6, size );
             sph_tiger_close( &ctx.tiger, hash6 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in7, size );
             sph_tiger_close( &ctx.tiger, hash7 );

             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] =
                hash4[i] = hash5[i] = hash6[i] = hash7[i] = 0;

             intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5,
                          hash6, hash7 );
             sha512_8way_init( &ctx.sha512 );
             sha512_8way_update( &ctx.sha512, vhash, 64 );
             sha512_8way_close( &ctx.sha512, vhash );
             dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
      }
      size = 64;
   }

   memcpy( output,     hash0, 32 );
   memcpy( output+32,  hash1, 32 );
   memcpy( output+64,  hash2, 32 );
   memcpy( output+96,  hash3, 32 );
   memcpy( output+128, hash4, 32 );
   memcpy( output+160, hash5, 32 );
   memcpy( output+192, hash6, 32 );
   memcpy( output+224, hash7, 32 );
}

int scanhash_x16rv2_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[8*16] __attribute__ ((aligned (128)));
   uint32_t vdata[24*8] __attribute__ ((aligned (64)));
   uint32_t bedata1[2] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
    __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   int thr_id = mythr->id;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   if ( opt_benchmark )
      ptarget[7] = 0x0cff;

   mm512_bswap32_intrlv80_8x64( vdata, pdata );

   bedata1[0] = bswap_32( pdata[1] );
   bedata1[1] = bswap_32( pdata[2] );
   const uint32_t ntime = bswap_32( pdata[17] );
   if ( s_ntime != ntime )
   {
      x16_r_s_getAlgoString( (const uint8_t*)bedata1, hashOrder );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
              applog( LOG_DEBUG, "hash order %s (%08x)", hashOrder, ntime );
   }

   do
   {
      *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
           _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                             n+3, 0, n+2, 0, n+1, 0, n,   0 ) ), *noncev );

      x16rv2_8way_hash( hash, vdata );
      pdata[19] = n;

      for ( int i = 0; i < 8; i++ )
      if ( unlikely( (hash+(i<<3))[7] <= Htarg ) )
      if( likely( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark ) )
      {
         pdata[19] = n+i;
         submit_lane_solution( work, hash+(i<<3), mythr, i );
      }
      n += 8;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );

   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (X16RV2_4WAY)

union _x16rv2_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_echo          echo;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    simd_2way_context       simd;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    sph_tiger_context       tiger;
};
typedef union _x16rv2_4way_context_overlay x16rv2_4way_context_overlay;

// Pad the 24 bytes tiger hash to 64 bytes
inline void padtiger512( uint32_t* hash )
{
  for ( int i = 6; i < 16; i++ ) hash[i] = 0;
}

void x16rv2_4way_hash( void* output, const void* input )
{
   uint32_t hash0[24] __attribute__ ((aligned (64)));
   uint32_t hash1[24] __attribute__ ((aligned (64)));
   uint32_t hash2[24] __attribute__ ((aligned (64)));
   uint32_t hash3[24] __attribute__ ((aligned (64)));
   uint32_t vhash[24*4] __attribute__ ((aligned (64)));
   x16rv2_4way_context_overlay ctx;
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   void *in2 = (void*) hash2;
   void *in3 = (void*) hash3;
   int size = 80;

   dintrlv_4x64( hash0, hash1, hash2, hash3, input, 640 );

   for ( int i = 0; i < 16; i++ )
   {
      const char elem = hashOrder[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            blake512_4way_init( &ctx.blake );
            if ( i == 0 )
               blake512_4way_update( &ctx.blake, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               blake512_4way_update( &ctx.blake, vhash, size );
            }
            blake512_4way_close( &ctx.blake, vhash );
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
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                                 (const char*)in0, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                                 (const char*)in1, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                                 (const char*)in2, size<<3 );
               init_groestl( &ctx.groestl, 64 );
               update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                                 (const char*)in3, size<<3 );
         break;
         case SKEIN:
            skein512_4way_init( &ctx.skein );
            if ( i == 0 )
               skein512_4way_update( &ctx.skein, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               skein512_4way_update( &ctx.skein, vhash, size );
            }
            skein512_4way_close( &ctx.skein, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case JH:
            jh512_4way_init( &ctx.jh );
            if ( i == 0 )
               jh512_4way_update( &ctx.jh, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               jh512_4way_update( &ctx.jh, vhash, size );
            }
            jh512_4way_close( &ctx.jh, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case KECCAK:
             sph_tiger_init( &ctx.tiger );
			    sph_tiger( &ctx.tiger, in0, size );
			    sph_tiger_close( &ctx.tiger, hash0 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in1, size );
             sph_tiger_close( &ctx.tiger, hash1 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in2, size );
             sph_tiger_close( &ctx.tiger, hash2 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in3, size );
             sph_tiger_close( &ctx.tiger, hash3 );

             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] = 0;

             intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
             keccak512_4way_init( &ctx.keccak );
             keccak512_4way_update( &ctx.keccak, vhash, 64 );
             keccak512_4way_close( &ctx.keccak, vhash );
             dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case LUFFA:
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in0, size );
             sph_tiger_close( &ctx.tiger, hash0 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in1, size );
             sph_tiger_close( &ctx.tiger, hash1 );

             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = 0;

             intrlv_2x128( vhash, hash0, hash1, 512 );
             luffa_2way_init( &ctx.luffa, 512 );
             luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
             dintrlv_2x128( hash0, hash1, vhash, 512 );

             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in2, size );
             sph_tiger_close( &ctx.tiger, hash2 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in3, size );
             sph_tiger_close( &ctx.tiger, hash3 );

             for ( int i = (24/4); i < (64/4); i++ )
                hash2[i] = hash3[i] = 0;
             
             intrlv_2x128( vhash, hash2, hash3, 512 );
             luffa_2way_init( &ctx.luffa, 512 );
             luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
             dintrlv_2x128( hash2, hash3, vhash, 512 );
         break;
         case CUBEHASH:
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
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash0,
                                (const BitSequence*)in0, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash1,
                                (const BitSequence*)in1, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash2,
                                (const BitSequence*)in2, size<<3 );
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash3,
                                (const BitSequence*)in3, size<<3 );
         break;
         case HAMSI:
             intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
             hamsi512_4way_init( &ctx.hamsi );
             hamsi512_4way_update( &ctx.hamsi, vhash, size );
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
             shabal512_4way_init( &ctx.shabal );
             shabal512_4way_update( &ctx.shabal, vhash, size );
             shabal512_4way_close( &ctx.shabal, vhash );
             dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case WHIRLPOOL:
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
         break;
         case SHA_512:
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in0, size );
             sph_tiger_close( &ctx.tiger, hash0 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in1, size );
             sph_tiger_close( &ctx.tiger, hash1 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in2, size );
             sph_tiger_close( &ctx.tiger, hash2 );
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in3, size );
             sph_tiger_close( &ctx.tiger, hash3 );

             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] = 0;
 
             intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
             sha512_4way_init( &ctx.sha512 );
             sha512_4way_update( &ctx.sha512, vhash, 64 );
             sha512_4way_close( &ctx.sha512, vhash );
             dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
      }
      size = 64;
   }
   memcpy( output,    hash0, 32 );
   memcpy( output+32, hash1, 32 );
   memcpy( output+64, hash2, 32 );
   memcpy( output+96, hash3, 32 );
}

int scanhash_x16rv2_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t bedata1[2] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   int thr_id = mythr->id; 
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   if ( opt_benchmark )
      ptarget[7] = 0x0fff;
   
   mm256_bswap32_intrlv80_4x64( vdata, pdata );

   bedata1[0] = bswap_32( pdata[1] );
   bedata1[1] = bswap_32( pdata[2] );
   const uint32_t ntime = bswap_32(pdata[17]);
   if ( s_ntime != ntime )
   {
      x16_r_s_getAlgoString( (const uint8_t*)bedata1, hashOrder );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
              applog( LOG_DEBUG, "hash order %s (%08x)", hashOrder, ntime );
   }

   do
   {
      *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
               _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

      x16rv2_4way_hash( hash, vdata );
      pdata[19] = n;

      for ( int i = 0; i < 4; i++ )
      if ( unlikely( (hash+(i<<3))[7] <= Htarg ) )
      if( likely( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark ) )
      {
         pdata[19] = n+i;
         submit_lane_solution( work, hash+(i<<3), mythr, i );
      }
      n += 4;
   } while ( likely( (  n < max_nonce ) && !(*restart) ) );

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
