#include "sonoa-gate.h"
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
#include "algo/fugue/fugue-aesni.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/sha/sha-hash-4way.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif

#if defined(SONOA_8WAY)

union _sonoa_8way_context_overlay
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

typedef union _sonoa_8way_context_overlay sonoa_8way_context_overlay;

int sonoa_8way_hash( void *state, const void *input, int thr_id )
{
     uint64_t vhash[8*8] __attribute__ ((aligned (128)));
     uint64_t vhashA[8*8] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*8] __attribute__ ((aligned (64)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t hash4[8] __attribute__ ((aligned (64)));
     uint64_t hash5[8] __attribute__ ((aligned (64)));
     uint64_t hash6[8] __attribute__ ((aligned (64)));
     uint64_t hash7[8] __attribute__ ((aligned (64)));
     sonoa_8way_context_overlay ctx;

// 1
     
     blake512_8way_full( &ctx.blake, vhash, input, 80 );

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7, vhash );

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

     if ( work_restart[thr_id].restart ) return 0;
// 2

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7, vhash );

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

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

     if ( work_restart[thr_id].restart ) return 0;
// 3

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7, vhash );

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

     skein512_8way_init( &ctx.skein );
     skein512_8way_update( &ctx.skein, vhash, 64 );
     skein512_8way_close( &ctx.skein, vhash );

     jh512_8way_init( &ctx.jh );
     jh512_8way_update( &ctx.jh, vhash, 64 );
     jh512_8way_close( &ctx.jh, vhash );

     keccak512_8way_init( &ctx.keccak );
     keccak512_8way_update( &ctx.keccak, vhash, 64 );
     keccak512_8way_close( &ctx.keccak, vhash );

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

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

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

     if ( work_restart[thr_id].restart ) return 0;
// 4

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7 );

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7, vhash );

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

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

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

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, 64 );
     shabal512_8way_close( &ctx.shabal, vhash );

     rintrlv_8x32_8x64( vhashA, vhash, 512 );

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhashA, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

#if defined(__VAES__)
     
     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     echo_4way_full( &ctx.echo, vhashA, 512, vhashA, 64 );    
     echo_4way_full( &ctx.echo, vhashB, 512, vhashB, 64 );
     
#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                       vhash );

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

#endif

#if defined(__VAES__)

     shavite512_4way_full( &ctx.shavite, vhashA, vhashA, 64 );
     shavite512_4way_full( &ctx.shavite, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     shavite512_full( &ctx.shavite, hash0, hash0, 64 );
     shavite512_full( &ctx.shavite, hash1, hash1, 64 );
     shavite512_full( &ctx.shavite, hash2, hash2, 64 );
     shavite512_full( &ctx.shavite, hash3, hash3, 64 );
     shavite512_full( &ctx.shavite, hash4, hash4, 64 );
     shavite512_full( &ctx.shavite, hash5, hash5, 64 );
     shavite512_full( &ctx.shavite, hash6, hash6, 64 );
     shavite512_full( &ctx.shavite, hash7, hash7, 64 );

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7 );

#endif

     if ( work_restart[thr_id].restart ) return 0;
// 5

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

     rintrlv_8x64_8x32( vhashA, vhash, 512 );

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhashA, 64 );
     shabal512_8way_close( &ctx.shabal, vhash );

#if defined(__VAES__)

     rintrlv_8x32_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
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

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

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

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, 64 );
     shabal512_8way_close( &ctx.shabal, vhash );

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

     if ( work_restart[thr_id].restart ) return 0;
// 6

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7 );

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7, vhash );

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

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

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

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, 64 );
     shabal512_8way_close( &ctx.shabal, vhash );

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

     sha512_8way_init( &ctx.sha512 );
     sha512_8way_update( &ctx.sha512, vhash, 64 );
     sha512_8way_close( &ctx.sha512, vhash );

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                       vhash );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, 64 );

     if ( work_restart[thr_id].restart ) return 0;
// 7

     intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7 );

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                       hash7, vhash );

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

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_8way_close( &ctx.hamsi, vhash );

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

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, 64 );
     shabal512_8way_close( &ctx.shabal, vhash );

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

     sha512_8way_init( &ctx.sha512 );
     sha512_8way_update( &ctx.sha512, vhash, 64 );
     sha512_8way_close( &ctx.sha512, vhash );

     rintrlv_8x64_8x32( vhashA, vhash, 512 );

     haval256_5_8way_init( &ctx.haval );
     haval256_5_8way_update( &ctx.haval, vhashA, 64 );
     haval256_5_8way_close( &ctx.haval, state );

     return 1;
}

#elif defined(SONOA_4WAY)

union _sonoa_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
#if defined(__VAES__)
    groestl512_2way_context groestl;
    echo512_2way_context    echo;
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
};

typedef union _sonoa_4way_context_overlay sonoa_4way_context_overlay;

int sonoa_4way_hash( void *state, const void *input, int thr_id )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
     sonoa_4way_context_overlay ctx;

// 1

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
     
     if ( work_restart[thr_id].restart ) return 0;
// 2

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

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     if ( work_restart[thr_id].restart ) return 0;
// 3

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

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );

     if ( work_restart[thr_id].restart ) return 0;
// 4
     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

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

     rintrlv_4x32_4x64( vhashB, vhash, 512 ); 

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhashB, 64 );
     hamsi512_4way_close( &ctx.hamsi, vhash );

#if defined(__VAES__)

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

     echo_2way_full( &ctx.echo, vhashA, 512, vhashA, 64 );
     echo_2way_full( &ctx.echo, vhashB, 512, vhashB, 64 );

#else

     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                     (const BitSequence *)hash0, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                     (const BitSequence *)hash1, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                     (const BitSequence *)hash2, 64 );
     echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                     (const BitSequence *)hash3, 64 );

     intrlv_2x128_512( vhashA, hash0, hash1 );
     intrlv_2x128_512( vhashB, hash2, hash3 );

#endif

     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashA, vhashA, 64 );
     shavite512_2way_init( &ctx.shavite );
     shavite512_2way_update_close( &ctx.shavite, vhashB, vhashB, 64 );

     if ( work_restart[thr_id].restart ) return 0;
// 5
     rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way_update( &ctx.bmw, vhash, 64 );
     bmw512_4way_close( &ctx.bmw, vhash );

     rintrlv_4x64_4x32( vhashB, vhash,  512 );

     shabal512_4way_init( &ctx.shabal );
     shabal512_4way_update( &ctx.shabal, vhashB, 64 );
     shabal512_4way_close( &ctx.shabal, vhash );

#if defined(__VAES__)

//     rintrlv_4x32_2x128( vhashA, vhashB, vhash, 512 ); 
     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );
     intrlv_2x128_512( vhashA, hash0, hash1 );
     intrlv_2x128_512( vhashB, hash2, hash3 );
     
     groestl512_2way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_2way_full( &ctx.groestl, vhashB, vhashB, 64 );
 
     rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );

#else

     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );

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

     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

     if ( work_restart[thr_id].restart ) return 0;
// 6

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );
     
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

     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way_update( &ctx.sha512, vhash, 64 );
     sha512_4way_close( &ctx.sha512, vhash );

     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

     if ( work_restart[thr_id].restart ) return 0;    
// 7

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

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

     dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

     intrlv_4x64_512( vhash, hash0, hash1, hash2, hash3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way_update( &ctx.sha512, vhash, 64 );
     sha512_4way_close( &ctx.sha512, vhash );

     rintrlv_4x64_4x32( vhashB, vhash,  512 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way_update( &ctx.haval, vhashB, 64 );
     haval256_5_4way_close( &ctx.haval, state );

     return 1;
}

#endif
