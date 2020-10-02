#include "x13-gate.h"
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
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/fugue-aesni.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif

#if defined(X13_8WAY)

typedef struct {
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
#if defined(__VAES__)
    groestl512_4way_context groestl;
    shavite512_4way_context shavite;
    echo_4way_context       echo;
#else
    hashState_groestl       groestl;
    sph_shavite512_context  shavite;
    hashState_echo          echo;
#endif
} x13_8way_ctx_holder;

x13_8way_ctx_holder x13_8way_ctx;

void init_x13_8way_ctx()
{
     blake512_8way_init( &x13_8way_ctx.blake );
     bmw512_8way_init( &x13_8way_ctx.bmw );
     skein512_8way_init( &x13_8way_ctx.skein );
     jh512_8way_init( &x13_8way_ctx.jh );
     keccak512_8way_init( &x13_8way_ctx.keccak );
     luffa_4way_init( &x13_8way_ctx.luffa, 512 );
     cube_4way_init( &x13_8way_ctx.cube, 512, 16, 32 );
     simd_4way_init( &x13_8way_ctx.simd, 512 );
     hamsi512_8way_init( &x13_8way_ctx.hamsi );
     fugue512_Init( &x13_8way_ctx.fugue, 512 );
#if defined(__VAES__)
     groestl512_4way_init( &x13_8way_ctx.groestl, 64 );
     shavite512_4way_init( &x13_8way_ctx.shavite );
     echo_4way_init( &x13_8way_ctx.echo, 512 );
#else
     init_groestl( &x13_8way_ctx.groestl, 64 );
     sph_shavite512_init( &x13_8way_ctx.shavite );
     init_echo( &x13_8way_ctx.echo, 512 );
#endif
}

void x13_8way_hash( void *state, const void *input )
{
     uint64_t vhash[8*8] __attribute__ ((aligned (128)));
     uint64_t vhashA[4*8] __attribute__ ((aligned (64)));
     uint64_t vhashB[4*8] __attribute__ ((aligned (64)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t hash4[8] __attribute__ ((aligned (64)));
     uint64_t hash5[8] __attribute__ ((aligned (64)));
     uint64_t hash6[8] __attribute__ ((aligned (64)));
     uint64_t hash7[8] __attribute__ ((aligned (64)));

     x13_8way_ctx_holder ctx;
     memcpy( &ctx, &x13_8way_ctx, sizeof(x13_8way_ctx) );
     blake512_8way_update( &ctx.blake, input, 80 );
     blake512_8way_close( &ctx.blake, vhash );

     bmw512_8way_update( &ctx.bmw, vhash, 64 );
     bmw512_8way_close( &ctx.bmw, vhash );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_update_close( &ctx.groestl, vhashA, vhashA, 512 );
     groestl512_4way_init( &ctx.groestl, 64 );
     groestl512_4way_update_close( &ctx.groestl, vhashB, vhashB, 512 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash );

     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     memcpy( &ctx.groestl, &x13_8way_ctx.groestl,
             sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     memcpy( &ctx.groestl, &x13_8way_ctx.groestl,
             sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     memcpy( &ctx.groestl, &x13_8way_ctx.groestl,
             sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
     memcpy( &ctx.groestl, &x13_8way_ctx.groestl,
             sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
     memcpy( &ctx.groestl, &x13_8way_ctx.groestl,
             sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
     memcpy( &ctx.groestl, &x13_8way_ctx.groestl,
             sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
     memcpy( &ctx.groestl, &x13_8way_ctx.groestl,
             sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7 );

#endif

     skein512_8way_update( &ctx.skein, vhash, 64 );
     skein512_8way_close( &ctx.skein, vhash );

     jh512_8way_update( &ctx.jh, vhash, 64 );
     jh512_8way_close( &ctx.jh, vhash );

     keccak512_8way_update( &ctx.keccak, vhash, 64 );
     keccak512_8way_close( &ctx.keccak, vhash );

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     luffa_4way_update_close( &ctx.luffa, vhashA, vhashA, 64 );
     luffa_4way_init( &ctx.luffa, 512 );
     luffa_4way_update_close( &ctx.luffa, vhashB, vhashB, 64 );

     cube_4way_update_close( &ctx.cube, vhashA, vhashA, 64 );
     cube_4way_init( &ctx.cube, 512, 16, 32 );
     cube_4way_update_close( &ctx.cube, vhashB, vhashB, 64 );

#if defined(__VAES__)

     shavite512_4way_update_close( &ctx.shavite, vhashA, vhashA, 64 );
     shavite512_4way_init( &ctx.shavite );
     shavite512_4way_update_close( &ctx.shavite, vhashB, vhashB, 64 );

#else

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &x13_8way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     memcpy( &ctx.shavite, &x13_8way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     memcpy( &ctx.shavite, &x13_8way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );
     memcpy( &ctx.shavite, &x13_8way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash4, 64 );
     sph_shavite512_close( &ctx.shavite, hash4 );
     memcpy( &ctx.shavite, &x13_8way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash5, 64 );
     sph_shavite512_close( &ctx.shavite, hash5 );
     memcpy( &ctx.shavite, &x13_8way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash6, 64 );
     sph_shavite512_close( &ctx.shavite, hash6 );
     memcpy( &ctx.shavite, &x13_8way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash7, 64 );
     sph_shavite512_close( &ctx.shavite, hash7 );

     intrlv_4x128_512( vhashA, hash0, hash1, hash2, hash3 );
     intrlv_4x128_512( vhashB, hash4, hash5, hash6, hash7 );

#endif

     simd_4way_update_close( &ctx.simd, vhashA, vhashA, 512 );
     simd_4way_init( &ctx.simd, 512 );
     simd_4way_update_close( &ctx.simd, vhashB, vhashB, 512 );

#if defined(__VAES__)

     echo_4way_update_close( &ctx.echo, vhashA, vhashA, 512 );
     echo_4way_init( &ctx.echo, 512 );
     echo_4way_update_close( &ctx.echo, vhashB, vhashB, 512 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     memcpy( &ctx.echo, &x13_8way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     memcpy( &ctx.echo, &x13_8way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     memcpy( &ctx.echo, &x13_8way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );
     memcpy( &ctx.echo, &x13_8way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash4,
                       (const BitSequence *) hash4, 512 );
     memcpy( &ctx.echo, &x13_8way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash5,
                       (const BitSequence *) hash5, 512 );
     memcpy( &ctx.echo, &x13_8way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash6,
                       (const BitSequence *) hash6, 512 );
     memcpy( &ctx.echo, &x13_8way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash7,
                       (const BitSequence *) hash7, 512 );

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                      hash7 );

#endif

     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );
     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                       vhash );

     // 13 Fugue serial
     fugue512_Update( &ctx.fugue, hash0, 512 );
     fugue512_Final( &ctx.fugue, hash0 ); 
     memcpy( &ctx.fugue, &x13_8way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash1, 512 );
     fugue512_Final( &ctx.fugue, hash1 );   
     memcpy( &ctx.fugue, &x13_8way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash2, 512 );
     fugue512_Final( &ctx.fugue, hash2 );   
     memcpy( &ctx.fugue, &x13_8way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash3, 512 );
     fugue512_Final( &ctx.fugue, hash3 );   
     memcpy( &ctx.fugue, &x13_8way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash4, 512 );
     fugue512_Final( &ctx.fugue, hash4 );   
     memcpy( &ctx.fugue, &x13_8way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash5, 512 );
     fugue512_Final( &ctx.fugue, hash5 );   
     memcpy( &ctx.fugue, &x13_8way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash6, 512 );
     fugue512_Final( &ctx.fugue, hash6 );   
     memcpy( &ctx.fugue, &x13_8way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash7, 512 );
     fugue512_Final( &ctx.fugue, hash7 );   
     
     memcpy( state,     hash0, 32 );
     memcpy( state+ 32, hash1, 32 );
     memcpy( state+ 64, hash2, 32 );
     memcpy( state+ 96, hash3, 32 );
     memcpy( state+128, hash4, 32 );
     memcpy( state+160, hash5, 32 );
     memcpy( state+192, hash6, 32 );
     memcpy( state+224, hash7, 32 );
}


int scanhash_x13_8way( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[8*8] __attribute__ ((aligned (128)));
     uint32_t vdata[24*8] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     int thr_id = mythr->id;
     __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
     const uint32_t Htarg = ptarget[7];
     const uint32_t last_nonce = max_nonce -8;
     mm512_bswap32_intrlv80_8x64( vdata, pdata );

     do
     {
        *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
         _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                           n+3, 0, n+2, 0, n+1, 0, n,   0 ) ), *noncev );

         x13_8way_hash( hash, vdata );
         pdata[19] = n;

         for ( int i = 0; i < 8; i++ )
         if ( ( hash+(i<<3) )[7] <= Htarg
              && fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
         {
             pdata[19] = n+i;
             submit_solution( work, hash+(i<<3), mythr );
         }
         n += 8;
     } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce;
     return 0;
}


#elif defined(X13_4WAY)


typedef struct {
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    simd_2way_context       simd;
    hashState_echo          echo;
    hamsi512_4way_context   hamsi;
    hashState_fugue         fugue;
} x13_4way_ctx_holder;

x13_4way_ctx_holder x13_4way_ctx __attribute__ ((aligned (64)));

void init_x13_4way_ctx()
{
     blake512_4way_init( &x13_4way_ctx.blake );
     bmw512_4way_init( &x13_4way_ctx.bmw );
     init_groestl( &x13_4way_ctx.groestl, 64 );
     skein512_4way_init( &x13_4way_ctx.skein );
     jh512_4way_init( &x13_4way_ctx.jh );
     keccak512_4way_init( &x13_4way_ctx.keccak );
     luffa_2way_init( &x13_4way_ctx.luffa, 512 );
     cubehashInit( &x13_4way_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x13_4way_ctx.shavite );
     simd_2way_init( &x13_4way_ctx.simd, 512 );
     init_echo( &x13_4way_ctx.echo, 512 );
     hamsi512_4way_init( &x13_4way_ctx.hamsi );
     fugue512_Init( &x13_4way_ctx.fugue, 512 );
};

void x13_4way_hash( void *state, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     x13_4way_ctx_holder ctx;
     memcpy( &ctx, &x13_4way_ctx, sizeof(x13_4way_ctx) );

     // 1 Blake
     blake512_4way_update( &ctx.blake, input, 80 );
     blake512_4way_close( &ctx.blake, vhash );

     // 2 Bmw
     bmw512_4way_update( &ctx.bmw, vhash, 64 );
     bmw512_4way_close( &ctx.bmw, vhash );

     // Serial
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // 3 Groestl
     update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     memcpy( &ctx.groestl, &x13_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     memcpy( &ctx.groestl, &x13_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     memcpy( &ctx.groestl, &x13_4way_ctx.groestl, sizeof(hashState_groestl) );
     update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

     // Parallel 4way 64 bit
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

     // 4 Skein
     skein512_4way_update( &ctx.skein, vhash, 64 );
     skein512_4way_close( &ctx.skein, vhash );

     // 5 JH
     jh512_4way_update( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     // 6 Keccak
     keccak512_4way_update( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

     // Serial
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // 7 Luffa
     intrlv_2x128( vhash, hash0, hash1, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     dintrlv_2x128( hash0, hash1, vhash, 512 );
     intrlv_2x128( vhash, hash2, hash3, 512 );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     dintrlv_2x128( hash2, hash3, vhash, 512 );

     // 8 Cubehash
     cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*) hash0, 64 );
     memcpy( &ctx.cube, &x13_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1, 64 );
     memcpy( &ctx.cube, &x13_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*) hash2, 64 );
     memcpy( &ctx.cube, &x13_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*) hash3, 64 );

     // 9 Shavite
     sph_shavite512( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     memcpy( &ctx.shavite, &x13_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     memcpy( &ctx.shavite, &x13_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     memcpy( &ctx.shavite, &x13_4way_ctx.shavite,
             sizeof(sph_shavite512_context) );
     sph_shavite512( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );

     // 10 Simd
     intrlv_2x128( vhash, hash0, hash1, 512 );
     simd_2way_update_close( &ctx.simd, vhash, vhash, 512 );
     dintrlv_2x128( hash0, hash1, vhash, 512 );
     intrlv_2x128( vhash, hash2, hash3, 512 );
     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhash, vhash, 512 );
     dintrlv_2x128( hash2, hash3, vhash, 512 );

     // 11 Echo
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                       (const BitSequence *) hash0, 512 );
     memcpy( &ctx.echo, &x13_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     memcpy( &ctx.echo, &x13_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     memcpy( &ctx.echo, &x13_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );

     // 12 Hamsi parallel 4way 32 bit
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
     hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // 13 Fugue serial
     fugue512_Update( &ctx.fugue, hash0, 512 );
     fugue512_Final( &ctx.fugue, hash0 );      
     memcpy( &ctx.fugue, &x13_4way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash1, 512 );
     fugue512_Final( &ctx.fugue, hash1 );       
     memcpy( &ctx.fugue, &x13_4way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash2, 512 );
     fugue512_Final( &ctx.fugue, hash2 );      
     memcpy( &ctx.fugue, &x13_4way_ctx.fugue, sizeof(hashState_fugue) );
     fugue512_Update( &ctx.fugue, hash3, 512 );
     fugue512_Final( &ctx.fugue, hash3 );   

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );
}

int scanhash_x13_4way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[4*8] __attribute__ ((aligned (64)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
     int thr_id = mythr->id;  // thr_id arg is deprecated
     const uint32_t Htarg = ptarget[7];
     uint64_t htmax[] = {          0,        0xF,       0xFF,
                               0xFFF,     0xFFFF, 0x10000000  };
     uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                          0xFFFFF000, 0xFFFF0000,          0  };

     mm256_bswap32_intrlv80_4x64( vdata, pdata );

     for ( int m=0; m < 6; m++ )
       if ( Htarg <= htmax[m] )
       {
         uint32_t mask = masks[m];
         do
         {
           *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                 _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

            x13_4way_hash( hash, vdata );
            pdata[19] = n;

            for ( int i = 0; i < 4; i++ )
            if ( ( ( (hash+(i<<3))[7] & mask ) == 0 ) )
            if ( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
            {
               pdata[19] = n+i;
               submit_solution( work, hash+(i<<3), mythr );
            }
            n += 4;
         } while ( ( n < max_nonce )  && !work_restart[thr_id].restart );
         break;
       }

     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
