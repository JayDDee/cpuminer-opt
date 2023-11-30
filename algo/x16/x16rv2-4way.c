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
#include "algo/tiger/sph_tiger.h"

#if defined (X16RV2_8WAY)

union _x16rv2_8way_context_overlay
{
    blake512_8way_context   blake;
    bmw512_8way_context     bmw;
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    keccak512_8way_context  keccak;
    luffa_4way_context      luffa;
    cubehashParam           cube;
    simd_4way_context       simd;
    hamsi512_8way_context   hamsi;
    hashState_fugue         fugue;
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
    shavite512_context      shavite;
    hashState_echo          echo;
#endif
} __attribute__ ((aligned (64)));

typedef union _x16rv2_8way_context_overlay x16rv2_8way_context_overlay;
static __thread x16rv2_8way_context_overlay x16rv2_ctx;

int x16rv2_8way_hash( void* output, const void* input, int thrid )
{
   uint32_t vhash[24*8] __attribute__ ((aligned (128)));
   uint32_t hash0[24] __attribute__ ((aligned (32)));
   uint32_t hash1[24] __attribute__ ((aligned (32)));
   uint32_t hash2[24] __attribute__ ((aligned (32)));
   uint32_t hash3[24] __attribute__ ((aligned (32)));
   uint32_t hash4[24] __attribute__ ((aligned (32)));
   uint32_t hash5[24] __attribute__ ((aligned (32)));
   uint32_t hash6[24] __attribute__ ((aligned (32)));
   uint32_t hash7[24] __attribute__ ((aligned (32)));
   x16rv2_8way_context_overlay ctx;
   memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
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
      const char elem = x16r_hash_order[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            blake512_8way_init( &ctx.blake );
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
             if ( i == 0 )
             {
                sph_tiger( &ctx.tiger, in0 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash0 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in1 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash1 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in2 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash2 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in3 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash3 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in4 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash4 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in5 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash5 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in6 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash6 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in7 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash7 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
             }
             else
             {
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
             }

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
                sph_tiger( &ctx.tiger, in0 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash0 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in1 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash1 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in2 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash2 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in3 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash3 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in4 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash4 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in5 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash5 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in6 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash6 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in7 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash7 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
             }
             else
             {
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
             }

             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] = 
                hash4[i] = hash5[i] = hash6[i] = hash7[i] = 0;

            intrlv_4x128_512( vhash, hash0, hash1, hash2, hash3);
            luffa512_4way_full( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128_512( vhash, hash4, hash5, hash6, hash7);
            luffa512_4way_full( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
         break;
         case CUBEHASH:
            if ( i == 0 )
            {
               cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                                            (const byte*)in0 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash1,
                                            (const byte*)in1 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash2,
                                            (const byte*)in2 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash3,
                                            (const byte*)in3 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash4,
                                            (const byte*)in4 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash5,
                                            (const byte*)in5 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash6,
                                            (const byte*)in6 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
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
            shavite512_4way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            shavite512_4way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
            shavite512_full( &ctx.shavite, hash0, in0, size );
            shavite512_full( &ctx.shavite, hash1, in1, size );
            shavite512_full( &ctx.shavite, hash2, in2, size );
            shavite512_full( &ctx.shavite, hash3, in3, size );
            shavite512_full( &ctx.shavite, hash4, in4, size );
            shavite512_full( &ctx.shavite, hash5, in5, size );
            shavite512_full( &ctx.shavite, hash6, in6, size );
            shavite512_full( &ctx.shavite, hash7, in7, size );
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
               hamsi512_8way_update( &ctx.hamsi, input + (72<<3), 8 );
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
            if ( i == 0 )
            {
               fugue512_update( &ctx.fugue, in0 + 76, 4 );
               fugue512_final( &ctx.fugue, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in1 + 76, 4 );
               fugue512_final( &ctx.fugue, hash1 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in2 + 76, 4 );
               fugue512_final( &ctx.fugue, hash2 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in3 + 76, 4 );
               fugue512_final( &ctx.fugue, hash3 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) ); 
               fugue512_update( &ctx.fugue, in4 + 76, 4 ); 
               fugue512_final( &ctx.fugue, hash4 ); 
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) ); 
               fugue512_update( &ctx.fugue, in5 + 76, 4 );
               fugue512_final( &ctx.fugue, hash5 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in6 + 76, 4 );
               fugue512_final( &ctx.fugue, hash6 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in7 + 76, 4 );
               fugue512_final( &ctx.fugue, hash7 );
            }
            else
            {
               fugue512_full( &ctx.fugue, hash0, hash0, size );
               fugue512_full( &ctx.fugue, hash1, hash1, size );
               fugue512_full( &ctx.fugue, hash2, hash2, size );
               fugue512_full( &ctx.fugue, hash3, hash3, size );
               fugue512_full( &ctx.fugue, hash4, hash4, size );
               fugue512_full( &ctx.fugue, hash5, hash5, size );
               fugue512_full( &ctx.fugue, hash6, hash6, size );
               fugue512_full( &ctx.fugue, hash7, hash7, size );
            }
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
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in1 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in2 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in3 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in4 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash4 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in5 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash5 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in6 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash6 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in7 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash7 );
            }
            else
            {
              sph_whirlpool512_full( &ctx.whirlpool, hash0, in0, size );
              sph_whirlpool512_full( &ctx.whirlpool, hash1, in1, size );
              sph_whirlpool512_full( &ctx.whirlpool, hash2, in2, size );
              sph_whirlpool512_full( &ctx.whirlpool, hash3, in3, size );
              sph_whirlpool512_full( &ctx.whirlpool, hash4, in4, size );
              sph_whirlpool512_full( &ctx.whirlpool, hash5, in5, size );
              sph_whirlpool512_full( &ctx.whirlpool, hash6, in6, size );
              sph_whirlpool512_full( &ctx.whirlpool, hash7, in7, size );
            }
         break;
         case SHA_512:
             if ( i == 0 )
             {
                sph_tiger( &ctx.tiger, in0 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash0 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in1 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash1 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in2 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash2 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in3 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash3 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in4 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash4 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in5 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash5 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in6 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash6 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in7 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash7 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
             }
             else
             {
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
             }

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

      if ( work_restart[thrid].restart ) return 0;

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
   return 1;
}

int scanhash_x16rv2_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t vdata2[20*8] __attribute__ ((aligned (64)));
   uint32_t edata[20] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
    __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   const int thr_id = mythr->id;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x0cff;

   static __thread uint32_t saved_height = UINT32_MAX;
   if ( work->height != saved_height )
   {
      vdata[1] = bswap_32( pdata[1] );
      vdata[2] = bswap_32( pdata[2] );
      saved_height = work->height;
      x16_r_s_getAlgoString( (const uint8_t*)(&vdata[1]), x16r_hash_order );
      if ( !opt_quiet && !thr_id )
           applog( LOG_INFO, "hash order %s", x16r_hash_order );
   }

   // Do midstate prehash on hash functions with block size <= 64 bytes.
   const char elem = x16r_hash_order[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';
   switch ( algo )
   {
      case JH:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         jh512_8way_init( &x16rv2_ctx.jh );
         jh512_8way_update( &x16rv2_ctx.jh, vdata, 64 );
      break;
      case KECCAK:
      case LUFFA:
      case SHA_512:
         v128_bswap32_80( edata, pdata );
         sph_tiger_init( &x16rv2_ctx.tiger );
         sph_tiger( &x16rv2_ctx.tiger, edata, 64 );
         intrlv_8x64( vdata, edata, edata, edata, edata,
                             edata, edata, edata, edata, 640 );
      break;
      case SKEIN:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         skein512_8way_init( &x16rv2_ctx.skein );
         skein512_8way_update( &x16rv2_ctx.skein, vdata, 64 );
      break;
      case CUBEHASH:
         v128_bswap32_80( edata, pdata );
         cubehashInit( &x16rv2_ctx.cube, 512, 16, 32 );
         cubehashUpdate( &x16rv2_ctx.cube, (const byte*)edata, 64 );
         intrlv_8x64( vdata, edata, edata, edata, edata,
                             edata, edata, edata, edata, 640 );
      break;
      case HAMSI:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         hamsi512_8way_init( &x16rv2_ctx.hamsi );
         hamsi512_8way_update( &x16rv2_ctx.hamsi, vdata, 72 );
      break;
      case FUGUE:
         v128_bswap32_80( edata, pdata );
         fugue512_init( &x16rv2_ctx.fugue );
         fugue512_update( &x16rv2_ctx.fugue, edata, 76 );
         intrlv_8x64( vdata, edata, edata, edata, edata,
                             edata, edata, edata, edata, 640 );
      break;
      case SHABAL:
         mm256_bswap32_intrlv80_8x32( vdata2, pdata );
         shabal512_8way_init( &x16rv2_ctx.shabal );
         shabal512_8way_update( &x16rv2_ctx.shabal, vdata2, 64 );
         rintrlv_8x32_8x64( vdata, vdata2, 640 );
      break;
      case WHIRLPOOL:
         v128_bswap32_80( edata, pdata );
         sph_whirlpool_init( &x16rv2_ctx.whirlpool );
         sph_whirlpool( &x16rv2_ctx.whirlpool, edata, 64 );
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
      if ( x16rv2_8way_hash( hash, vdata, thr_id ) )
      for ( int i = 0; i < 8; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  _mm512_set1_epi64( 0x0000000800000000 ) );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (X16RV2_4WAY)

union _x16rv2_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
#if defined(__VAES__)
    groestl512_2way_context groestl;
    shavite512_2way_context shavite;
    echo_2way_context       echo;
#else
    hashState_groestl       groestl;
    shavite512_context      shavite;
    hashState_echo          echo;
#endif
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cubehashParam           cube;
    simd_2way_context       simd;
    hamsi512_4way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    sph_tiger_context       tiger;
};
typedef union _x16rv2_4way_context_overlay x16rv2_4way_context_overlay;

static __thread x16rv2_4way_context_overlay x16rv2_ctx;

// Pad the 24 bytes tiger hash to 64 bytes
inline void padtiger512( uint32_t* hash )
{
  for ( int i = 6; i < 16; i++ ) hash[i] = 0;
}

int x16rv2_4way_hash( void* output, const void* input, int thrid )
{
   uint32_t vhash[20*4] __attribute__ ((aligned (64)));
   uint32_t hash0[20] __attribute__ ((aligned (32)));
   uint32_t hash1[20] __attribute__ ((aligned (32)));
   uint32_t hash2[20] __attribute__ ((aligned (32)));
   uint32_t hash3[20] __attribute__ ((aligned (32)));
   x16rv2_4way_context_overlay ctx;
   memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   void *in2 = (void*) hash2;
   void *in3 = (void*) hash3;
   int size = 80;

   dintrlv_4x64( hash0, hash1, hash2, hash3, input, 640 );

   for ( int i = 0; i < 16; i++ )
   {
      const char elem = x16r_hash_order[i];
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
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
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
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case GROESTL:
#if defined(__VAES__)
            intrlv_2x128( vhash, in0, in1, size<<3 );
            groestl512_2way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            groestl512_2way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
#else
            groestl512_full( &ctx.groestl, (char*)hash0, (char*)in0, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash1, (char*)in1, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash2, (char*)in2, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash3, (char*)in3, size<<3 );
#endif
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
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case KECCAK:
            if ( i == 0 )
            {
               sph_tiger( &ctx.tiger, in0 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in1 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash1 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in2 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash2 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in3 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash3 );
            }
            else
            {
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
            }
            for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] = 0;

            intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
            keccak512_4way_init( &ctx.keccak );
            keccak512_4way_update( &ctx.keccak, vhash, 64 );
            keccak512_4way_close( &ctx.keccak, vhash );
            dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
         case SKEIN:
            if ( i == 0 )
               skein512_4way_final16( &ctx.skein, vhash, input + (64*4) );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               skein512_4way_init( &ctx.skein );
               skein512_4way_update( &ctx.skein, vhash, size );
               skein512_4way_close( &ctx.skein, vhash );
            }
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case LUFFA:
            if ( i == 0 )
            {
               sph_tiger( &ctx.tiger, in0 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in1 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash1 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in2 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash2 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in3 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash3 );
            }
            else
            {
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
            }
            for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] =  hash2[i] = hash3[i] = 0;

            intrlv_2x128( vhash, hash0, hash1, 512 );
            luffa_2way_init( &ctx.luffa, 512 );
            luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_2x128( hash0, hash1, vhash, 512 );
            intrlv_2x128( vhash, hash2, hash3, 512 );
            luffa_2way_init( &ctx.luffa, 512 );
            luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
            dintrlv_2x128( hash2, hash3, vhash, 512 );
         break;
         case CUBEHASH:
            if ( i == 0 )
            {
               cubehashUpdateDigest( &ctx.cube, (byte*)hash0,
                                            (const byte*)in0 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash1,
                                             (const byte*)in1 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash2,
                                             (const byte*)in2 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, (byte*) hash3,
                                             (const byte*)in3 + 64, 16 );
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
            }
         break;
         case SHAVITE:
#if defined(__VAES__)
            intrlv_2x128( vhash, in0, in1, size<<3 );
            shavite512_2way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            shavite512_2way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
#else
            shavite512_full( &ctx.shavite, hash0, in0, size );
            shavite512_full( &ctx.shavite, hash1, in1, size );
            shavite512_full( &ctx.shavite, hash2, in2, size );
            shavite512_full( &ctx.shavite, hash3, in3, size );
#endif
         break;
         case SIMD:
            intrlv_2x128( vhash, in0, in1, size<<3 );
            simd512_2way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            simd512_2way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
         break;
         case ECHO:
#if defined(__VAES__)
            intrlv_2x128( vhash, in0, in1, size<<3 );
            echo_2way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            echo_2way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
#else
            echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                              (const BitSequence *)in0, size );
            echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                              (const BitSequence *)in1, size );
            echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                              (const BitSequence *)in2, size );
            echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                              (const BitSequence *)in3, size );
#endif
         break;
         case HAMSI:
            if ( i == 0 )
               hamsi512_4way_update( &ctx.hamsi, input + (72<<2), 8 );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               hamsi512_4way_init( &ctx.hamsi );
               hamsi512_4way_update( &ctx.hamsi, vhash, size );
            }
            hamsi512_4way_close( &ctx.hamsi, vhash );
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case FUGUE:
            if ( i == 0 )
            {
               fugue512_update( &ctx.fugue, in0 + 76, 4 );
               fugue512_final( &ctx.fugue, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in1 + 76, 4 );
               fugue512_final( &ctx.fugue, hash1 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in2 + 76, 4 );
               fugue512_final( &ctx.fugue, hash2 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in3 + 76, 4 );
               fugue512_final( &ctx.fugue, hash3 );
            }
            else
            {
               fugue512_full( &ctx.fugue, hash0, hash0, size );
               fugue512_full( &ctx.fugue, hash1, hash1, size );
               fugue512_full( &ctx.fugue, hash2, hash2, size );
               fugue512_full( &ctx.fugue, hash3, hash3, size );
            }
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
             dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );
          break;
          case WHIRLPOOL:
            if ( i == 0 )
            {
               sph_whirlpool( &ctx.whirlpool, in0 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in1 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in2 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in3 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
            }
            else
            {
               sph_whirlpool512_full( &ctx.whirlpool, hash0, in0, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash1, in1, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash2, in2, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash3, in3, size );
            }
         break;
         case SHA_512:
             if ( i == 0 )
             {
                sph_tiger( &ctx.tiger, in0 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash0 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in1 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash1 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in2 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash2 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in3 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash3 );
             }
             else
             {
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
             }
             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = hash2[i] = hash3[i] = 0;
 
             intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
             sha512_4way_init( &ctx.sha512 );
             sha512_4way_update( &ctx.sha512, vhash, 64 );
             sha512_4way_close( &ctx.sha512, vhash );
             dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
         break;
      }
 
      if ( work_restart[thrid].restart ) return 0;

      size = 64;
   }
   memcpy( output,    hash0, 32 );
   memcpy( output+32, hash1, 32 );
   memcpy( output+64, hash2, 32 );
   memcpy( output+96, hash3, 32 );
   return 1;
}

int scanhash_x16rv2_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t vdata32[20*4] __attribute__ ((aligned (64)));
   uint32_t edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id; 
    __m256i  *noncev = (__m256i*)vdata + 9; 
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0fff;
   
   static __thread uint32_t saved_height = UINT32_MAX;
   if ( work->height != saved_height )
   {
      vdata[1] = bswap_32( pdata[1] );
      vdata[2] = bswap_32( pdata[2] );
      saved_height = work->height;
      x16_r_s_getAlgoString( (const uint8_t*)(&vdata[1]), x16r_hash_order );
      if ( !opt_quiet && !thr_id )
           applog( LOG_INFO, "hash order %s", x16r_hash_order );
   }

   // Do midstate prehash on hash functions with block size <= 64 bytes.
   const char elem = x16r_hash_order[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';
   switch ( algo )
   {
      case JH:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         jh512_4way_init( &x16rv2_ctx.jh );
         jh512_4way_update( &x16rv2_ctx.jh, vdata, 64 );
      break;
      case KECCAK:
      case LUFFA:
      case SHA_512:
         v128_bswap32_80( edata, pdata );
         sph_tiger_init( &x16rv2_ctx.tiger );
         sph_tiger( &x16rv2_ctx.tiger, edata, 64 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      case SKEIN:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         skein512_4way_prehash64( &x16rv2_ctx.skein, vdata );
      break;
      case CUBEHASH:
         v128_bswap32_80( edata, pdata );
         cubehashInit( &x16rv2_ctx.cube, 512, 16, 32 );
         cubehashUpdate( &x16rv2_ctx.cube, (const byte*)edata, 64 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      case HAMSI:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         hamsi512_4way_init( &x16rv2_ctx.hamsi );
         hamsi512_4way_update( &x16rv2_ctx.hamsi, vdata, 72 );
      break;
      case FUGUE:
         v128_bswap32_80( edata, pdata );
         fugue512_init( &x16rv2_ctx.fugue );
         fugue512_update( &x16rv2_ctx.fugue, edata, 76 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      case SHABAL:
         v128_bswap32_intrlv80_4x32( vdata32, pdata );
         shabal512_4way_init( &x16rv2_ctx.shabal );
         shabal512_4way_update( &x16rv2_ctx.shabal, vdata32, 64 );
         rintrlv_4x32_4x64( vdata, vdata32, 640 );
      break;
      case WHIRLPOOL:
         v128_bswap32_80( edata, pdata );
         sph_whirlpool_init( &x16rv2_ctx.whirlpool );
         sph_whirlpool( &x16rv2_ctx.whirlpool, edata, 64 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      default:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
   }

   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );

   do
   {
      if ( x16rv2_4way_hash( hash, vdata, thr_id ) )
      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  _mm256_set1_epi64x( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (X16RV2_2WAY)

union _x16rv2_2x64_context_overlay
{
    blake512_2x64_context   blake;
    bmw512_2x64_context     bmw;
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    hashState_groestl       groestl;
#else
    sph_groestl512_context  groestl;
#endif
    skein512_2x64_context   skein;
    jh512_2x64_context      jh;
    keccak512_2x64_context  keccak;
    hashState_luffa         luffa;
    cubehashParam           cube;
    shavite512_context      shavite;
    simd512_context         simd;
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    hashState_echo          echo;
#else
    sph_echo512_context     echo;
#endif
#if defined(__SSE4_2__) || defined(__ARM_NEON)
    hamsi_2x64_context      hamsi;
#else
    sph_hamsi512_context    hamsi;
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
    hashState_fugue         fugue;
#else
    sph_fugue512_context    fugue;
#endif
    sph_shabal512_context   shabal;
    sph_whirlpool_context   whirlpool;
    sha512_2x64_context     sha512;
    sph_tiger_context       tiger;
} __attribute__ ((aligned (64)));

typedef union _x16rv2_2x64_context_overlay x16rv2_2x64_context_overlay;

static __thread x16rv2_2x64_context_overlay x16rv2_ctx;

// Pad the 24 bytes tiger hash to 64 bytes
static inline void padtiger512( uint32_t* hash )
{
  for ( int i = 6; i < 16; i++ ) hash[i] = 0;
}

int x16rv2_2x64_hash( void* output, const void* input, int thrid )
{
   uint32_t vhash[20*2] __attribute__ ((aligned (64)));
   uint32_t hash0[20] __attribute__ ((aligned (32)));
   uint32_t hash1[20] __attribute__ ((aligned (32)));
   x16rv2_2x64_context_overlay ctx;
   memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   int size = 80;

   dintrlv_2x64( hash0, hash1, input, 640 );

   for ( int i = 0; i < 16; i++ )
   {
      const char elem = x16r_hash_order[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            if ( i == 0 )
               blake512_2x64_full( &ctx.blake, vhash, input, size );
            else
            {
               intrlv_2x64( vhash, in0, in1, size<<3 );
               blake512_2x64_full( &ctx.blake, vhash, vhash, size );
            }
            dintrlv_2x64( hash0, hash1, vhash, 512 );
         break;
         case BMW:
            bmw512_2x64_init( &ctx.bmw );
            if ( i == 0 )
               bmw512_2x64_update( &ctx.bmw, input, size );
            else
            {
               intrlv_2x64( vhash, in0, in1, size<<3 );
               bmw512_2x64_update( &ctx.bmw, vhash, size );
            }
            bmw512_2x64_close( &ctx.bmw, vhash );
            dintrlv_2x64( hash0, hash1, vhash, 512 );
         break;
         case GROESTL:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            groestl512_full( &ctx.groestl, hash0, in0, size<<3 );
            groestl512_full( &ctx.groestl, hash1, in1, size<<3 );
#else
            sph_groestl512_init( &ctx.groestl );
            sph_groestl512( &ctx.groestl, in0, size );
            sph_groestl512_close( &ctx.groestl, hash0 );
            sph_groestl512_init( &ctx.groestl );
            sph_groestl512( &ctx.groestl, in1, size );
            sph_groestl512_close( &ctx.groestl, hash1 );
#endif
         break;
         case JH:
            if ( i == 0 )
               jh512_2x64_update( &ctx.jh, input + (64<<1), 16 );
            else
            {
               intrlv_2x64( vhash, in0, in1, size<<3 );
               jh512_2x64_init( &ctx.jh );
               jh512_2x64_update( &ctx.jh, vhash, size );
            }
            jh512_2x64_close( &ctx.jh, vhash );
            dintrlv_2x64( hash0, hash1, vhash, 512 );
         break;
         case KECCAK:
            if ( i == 0 )
            {
               sph_tiger( &ctx.tiger, in0 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in1 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash1 );
            }
            else
            {
               sph_tiger_init( &ctx.tiger );
               sph_tiger( &ctx.tiger, in0, size );
               sph_tiger_close( &ctx.tiger, hash0 );
               sph_tiger_init( &ctx.tiger );
               sph_tiger( &ctx.tiger, in1, size );
               sph_tiger_close( &ctx.tiger, hash1 );
            }
            for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = 0;

            intrlv_2x64( vhash, hash0, hash1, 512 );
            keccak512_2x64_init( &ctx.keccak );
            keccak512_2x64_update( &ctx.keccak, vhash, 64 );
            keccak512_2x64_close( &ctx.keccak, vhash );
            dintrlv_2x64( hash0, hash1, vhash, 512 );
         break;
         case SKEIN:
            if ( i == 0 )
               skein512_2x64_final16( &ctx.skein, vhash, input + (64*2) );
            else
            {
               intrlv_2x64( vhash, in0, in1, size<<3 );
               skein512_2x64_full( &ctx.skein, vhash, vhash,  size );
            }
            dintrlv_2x64( hash0, hash1, vhash, 512 );
         break;
         case LUFFA:
            if ( i == 0 )
            {
               sph_tiger( &ctx.tiger, in0 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_tiger( &ctx.tiger, in1 + 64, 16 );
               sph_tiger_close( &ctx.tiger, hash1 );
            }
            else
            {
               sph_tiger_init( &ctx.tiger );
               sph_tiger( &ctx.tiger, in0, size );
               sph_tiger_close( &ctx.tiger, hash0 );
               sph_tiger_init( &ctx.tiger );
               sph_tiger( &ctx.tiger, in1, size );
               sph_tiger_close( &ctx.tiger, hash1 );
            }
            for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = 0;
            luffa_full( &ctx.luffa, hash0, 512, hash0, 64 );
            luffa_full( &ctx.luffa, hash1, 512, hash1, 64 );
         break;
         case CUBEHASH:
            if ( i == 0 )
            {
               cubehashUpdateDigest( &ctx.cube, hash0, in0 + 64, 16 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               cubehashUpdateDigest( &ctx.cube, hash1, in1 + 64, 16 );
            }
            else
            {
               cubehash_full( &ctx.cube, hash0, 512, hash0, size );
               cubehash_full( &ctx.cube, hash1, 512, hash1, size );
            }
         break;
         case SHAVITE:
            shavite512_full( &ctx.shavite, hash0, in0, size );
            shavite512_full( &ctx.shavite, hash1, in1, size );
         break;
         case SIMD:
            simd512_ctx( &ctx.simd, hash0, in0, size );
            simd512_ctx( &ctx.simd, hash1, in1, size );
         break;
         case ECHO:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            echo_full( &ctx.echo, hash0, 512, in0, size );
            echo_full( &ctx.echo, hash1, 512, in1, size );
#else
            sph_echo512_init( &ctx.echo );
            sph_echo512( &ctx.echo, in0, size );
            sph_echo512_close( &ctx.echo, hash0 );
            sph_echo512_init( &ctx.echo );
            sph_echo512( &ctx.echo, in1, size );
            sph_echo512_close( &ctx.echo, hash1 );
#endif
         break;
         case HAMSI:
#if defined(__SSE4_2__) || defined(__ARM_NEON)
            if ( i == 0 )
               hamsi512_2x64_update( &ctx.hamsi, input + (72*2), 8 );
            else
            {
               intrlv_2x64( vhash, hash0, hash1, size<<3 );
               hamsi512_2x64_init( &ctx.hamsi );
               hamsi512_2x64_update( &ctx.hamsi, vhash, size );
            }
            hamsi512_2x64_close( &ctx.hamsi, vhash );
            dintrlv_2x64( hash0, hash1, vhash, 512 );
#else
            if ( i == 0 )
            {
               sph_hamsi512( &ctx.hamsi, in0 + 72, 8 );
               sph_hamsi512_close( &ctx.hamsi, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_hamsi512( &ctx.hamsi, in1 + 72, 8 );
               sph_hamsi512_close( &ctx.hamsi, hash1 );
            }
            else
            {
               sph_hamsi512_init( &ctx.hamsi );
               sph_hamsi512( &ctx.hamsi, hash0, size );
               sph_hamsi512_close( &ctx.hamsi, hash0 );
               sph_hamsi512_init( &ctx.hamsi );
               sph_hamsi512( &ctx.hamsi, hash1, size );
               sph_hamsi512_close( &ctx.hamsi, hash1 );
             }
#endif
         break;
         case FUGUE:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            if ( i == 0 )
            {
               fugue512_update( &ctx.fugue, in0 + 76, 4 );
               fugue512_final( &ctx.fugue, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(hashState_fugue) );
               fugue512_update( &ctx.fugue, in1 + 76, 4 );
               fugue512_final( &ctx.fugue, hash1 );
            }
            else
            {
               fugue512_full( &ctx.fugue, hash0, hash0, size );
               fugue512_full( &ctx.fugue, hash1, hash1, size );
            }
#else
            if ( i == 0 )
            {
               sph_fugue512( &ctx.fugue, in0 + 76, 4 );
               sph_fugue512_close( &ctx.fugue, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(sph_fugue512_context) );
               sph_fugue512( &ctx.fugue, in1 + 76, 4 );
               sph_fugue512_close( &ctx.fugue, hash1 );
            }
             else
             {
                sph_fugue512_full( &ctx.fugue, hash0, hash0, size );
                sph_fugue512_full( &ctx.fugue, hash1, hash1, size );
             }
#endif
             break;
         case SHABAL:
            if ( i == 0 )
            {
               sph_shabal512( &ctx.shabal, in0 + 64, 16 );
               sph_shabal512_close( &ctx.shabal, hash0 );
               memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
               sph_shabal512( &ctx.shabal, in1 + 64, 16 );
               sph_shabal512_close( &ctx.shabal, hash1 );
            }
            else
            {
               sph_shabal512_init( &ctx.shabal );
               sph_shabal512( &ctx.shabal, hash0, size );
               sph_shabal512_close( &ctx.shabal, hash0 );
               sph_shabal512_init( &ctx.shabal );
               sph_shabal512( &ctx.shabal, hash1, size );
               sph_shabal512_close( &ctx.shabal, hash1 );
             }
          break;
          case WHIRLPOOL:
            sph_whirlpool512_full( &ctx.whirlpool, hash0, in0, size );
            sph_whirlpool512_full( &ctx.whirlpool, hash1, in1, size );
         break;
         case SHA_512:
             if ( i == 0 )
             {
                sph_tiger( &ctx.tiger, in0 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash0 );
                memcpy( &ctx, &x16rv2_ctx, sizeof(ctx) );
                sph_tiger( &ctx.tiger, in1 + 64, 16 );
                sph_tiger_close( &ctx.tiger, hash1 );
             }
             else
             {
                sph_tiger_init( &ctx.tiger );
                sph_tiger( &ctx.tiger, in0, size );
                sph_tiger_close( &ctx.tiger, hash0 );
                sph_tiger_init( &ctx.tiger );
                sph_tiger( &ctx.tiger, in1, size );
                sph_tiger_close( &ctx.tiger, hash1 );
             }
             for ( int i = (24/4); i < (64/4); i++ )
                hash0[i] = hash1[i] = 0;

             intrlv_2x64( vhash, hash0, hash1, 512 );
             sha512_2x64_init( &ctx.sha512 );
             sha512_2x64_update( &ctx.sha512, vhash, 64 );
             sha512_2x64_close( &ctx.sha512, vhash );
             dintrlv_2x64( hash0, hash1, vhash, 512 );
         break;
      }

      if ( work_restart[thrid].restart ) return 0;

      size = 64;
   }
   memcpy( output,    hash0, 32 );
   memcpy( output+32, hash1, 32 );
   return 1;
}

int scanhash_x16rv2_2x64( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[2*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*2] __attribute__ ((aligned (64)));
   uint32_t edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   v128_t *noncev = (v128_t*)vdata + 9;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0fff;

   static __thread uint32_t saved_height = UINT32_MAX;
   if ( work->height != saved_height )
   {
      vdata[1] = bswap_32( pdata[1] );
      vdata[2] = bswap_32( pdata[2] );
      saved_height = work->height;
      x16_r_s_getAlgoString( (const uint8_t*)(&vdata[1]), x16r_hash_order );
      if ( !opt_quiet && !thr_id )
           applog( LOG_INFO, "hash order %s", x16r_hash_order );
   }

   // Do midstate prehash on hash functions with block size <= 64 bytes.
   const char elem = x16r_hash_order[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';
   switch ( algo )
   {
      case JH:
         v128_bswap32_intrlv80_2x64( vdata, pdata );
         jh512_2x64_init( &x16rv2_ctx.jh );
         jh512_2x64_update( &x16rv2_ctx.jh, vdata, 64 );
      break;
      case KECCAK:
      case LUFFA:
      case SHA_512:
         v128_bswap32_80( edata, pdata );
         sph_tiger_init( &x16rv2_ctx.tiger );
         sph_tiger( &x16rv2_ctx.tiger, edata, 64 );
         intrlv_2x64( vdata, edata, edata, 640 );
      break;
      case SKEIN:
         v128_bswap32_intrlv80_2x64( vdata, pdata );
         skein512_2x64_prehash64( &x16rv2_ctx.skein, vdata );
      break;
      case CUBEHASH:
         v128_bswap32_80( edata, pdata );
         cubehashInit( &x16rv2_ctx.cube, 512, 16, 32 );
         cubehashUpdate( &x16rv2_ctx.cube, edata, 64 );
         intrlv_2x64( vdata, edata, edata, 640 );
      break;
      case HAMSI:
#if defined(__SSE4_2__) || defined(__ARM_NEON)
         v128_bswap32_intrlv80_2x64( vdata, pdata );
         hamsi512_2x64_init( &x16rv2_ctx.hamsi );
         hamsi512_2x64_update( &x16rv2_ctx.hamsi, vdata, 72 );
#else
         v128_bswap32_80( edata, pdata );
         sph_hamsi512_init( &x16rv2_ctx.hamsi );
         sph_hamsi512( &x16rv2_ctx.hamsi, edata, 72 );
         intrlv_2x64( vdata, edata, edata, 640 );
#endif
      break;
      case FUGUE:
         v128_bswap32_80( edata, pdata );
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
         fugue512_init( &x16rv2_ctx.fugue );
         fugue512_update( &x16rv2_ctx.fugue, edata, 76 );
#else
         sph_fugue512_init( &x16rv2_ctx.fugue );
         sph_fugue512( &x16rv2_ctx.fugue, edata, 76 );
#endif
         intrlv_2x64( vdata, edata, edata, 640 );
      break;
      case SHABAL:
         v128_bswap32_80( edata, pdata );
         sph_shabal512_init( &x16rv2_ctx.shabal );
         sph_shabal512( &x16rv2_ctx.shabal, edata, 64);
         intrlv_2x64( vdata, edata, edata, 640 );
      break;
      default:
         v128_bswap32_intrlv80_2x64( vdata, pdata );
   }

   *noncev = v128_intrlv_blend_32( v128_set32( n+1, 0, n, 0 ), *noncev );

   do
   {
      if ( x16rv2_2x64_hash( hash, vdata, thr_id ) )
      for ( int i = 0; i < 2; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = v128_add32( *noncev, v128_64( 0x0000000200000000 ) );
      n += 2;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}




#endif
