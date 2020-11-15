#include "xevan-gate.h"
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
#include "algo/shavite/sph_shavite.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sha-hash-4way.h"
#include "algo/haval/haval-hash-4way.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif

#if defined(XEVAN_8WAY)

union _xevan_8way_context_overlay
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
typedef union _xevan_8way_context_overlay xevan_8way_context_overlay;

int xevan_8way_hash( void *output, const void *input, int thr_id )
{
     uint64_t vhash[16<<3] __attribute__ ((aligned (128)));
     uint64_t vhashA[16<<3] __attribute__ ((aligned (64)));
     uint64_t vhashB[16<<3] __attribute__ ((aligned (64)));
     uint64_t hash0[16] __attribute__ ((aligned (64)));
     uint64_t hash1[16] __attribute__ ((aligned (64)));
     uint64_t hash2[16] __attribute__ ((aligned (64)));
     uint64_t hash3[16] __attribute__ ((aligned (64)));
     uint64_t hash4[16] __attribute__ ((aligned (64)));
     uint64_t hash5[16] __attribute__ ((aligned (64)));
     uint64_t hash6[16] __attribute__ ((aligned (64)));
     uint64_t hash7[16] __attribute__ ((aligned (64)));
     const int dataLen = 128;
     xevan_8way_context_overlay ctx __attribute__ ((aligned (64)));

     blake512_8way_full( &ctx.blake, vhash, input, 80 );
     memset( &vhash[8<<3], 0, 64<<3 );

     bmw512_8way_full( &ctx.bmw, vhash, vhash, dataLen );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, dataLen<<3 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, dataLen );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, dataLen );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, dataLen<<3 );

#else

     dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash4, (char*)hash4, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash5, (char*)hash5, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash6, (char*)hash6, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash7, (char*)hash7, dataLen<<3 );

     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

#endif

     skein512_8way_full( &ctx.skein, vhash, vhash, dataLen );

     jh512_8way_init( &ctx.jh );
     jh512_8way_update( &ctx.jh, vhash, dataLen );
     jh512_8way_close( &ctx.jh, vhash );

     keccak512_8way_init( &ctx.keccak );
     keccak512_8way_update( &ctx.keccak, vhash, dataLen );
     keccak512_8way_close( &ctx.keccak, vhash );

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, dataLen<<3 );

     luffa512_4way_full( &ctx.luffa, vhashA, vhashA, dataLen );
     luffa512_4way_full( &ctx.luffa, vhashB, vhashB, dataLen );

     cube_4way_full( &ctx.cube, vhashA, 512, vhashA, dataLen );
     cube_4way_full( &ctx.cube, vhashB, 512, vhashB, dataLen );

#if defined(__VAES__)

     shavite512_4way_full( &ctx.shavite, vhashA, vhashA, dataLen );
     shavite512_4way_full( &ctx.shavite, vhashB, vhashB, dataLen );

#else

     dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, dataLen<<3 );
     dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, dataLen<<3 );

     shavite512_full( &ctx.shavite, hash0, hash0, dataLen );
     shavite512_full( &ctx.shavite, hash1, hash1, dataLen );
     shavite512_full( &ctx.shavite, hash2, hash2, dataLen );
     shavite512_full( &ctx.shavite, hash3, hash3, dataLen );
     shavite512_full( &ctx.shavite, hash4, hash4, dataLen );
     shavite512_full( &ctx.shavite, hash5, hash5, dataLen );
     shavite512_full( &ctx.shavite, hash6, hash6, dataLen );
     shavite512_full( &ctx.shavite, hash7, hash7, dataLen );

     intrlv_4x128( vhashA, hash0, hash1, hash2, hash3, dataLen<<3 );
     intrlv_4x128( vhashB, hash4, hash5, hash6, hash7, dataLen<<3 );

#endif

     simd512_4way_full( &ctx.simd, vhashA, vhashA, dataLen );
     simd512_4way_full( &ctx.simd, vhashB, vhashB, dataLen );

#if defined(__VAES__)

     echo_4way_full( &ctx.echo, vhashA, 512, vhashA, dataLen );
     echo_4way_full( &ctx.echo, vhashB, 512, vhashB, dataLen );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, dataLen<<3 );

#else

     dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, dataLen<<3 );
     dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, dataLen<<3 );

     echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                     (const BitSequence *)hash0, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                     (const BitSequence *)hash1, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                     (const BitSequence *)hash2, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                     (const BitSequence *)hash3, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                     (const BitSequence *)hash4, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                     (const BitSequence *)hash5, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                     (const BitSequence *)hash6, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                     (const BitSequence *)hash7, dataLen );
     
     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

#endif

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, dataLen );
     hamsi512_8way_close( &ctx.hamsi, vhash );

     dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

     fugue512_full( &ctx.fugue, hash0, hash0, dataLen );
     fugue512_full( &ctx.fugue, hash1, hash1, dataLen );
     fugue512_full( &ctx.fugue, hash2, hash2, dataLen );
     fugue512_full( &ctx.fugue, hash3, hash3, dataLen );
     fugue512_full( &ctx.fugue, hash4, hash4, dataLen );
     fugue512_full( &ctx.fugue, hash5, hash5, dataLen );
     fugue512_full( &ctx.fugue, hash6, hash6, dataLen );
     fugue512_full( &ctx.fugue, hash7, hash7, dataLen );

     intrlv_8x32( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, dataLen );
     shabal512_8way_close( &ctx.shabal, vhash );

     dintrlv_8x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, dataLen );

     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

     sha512_8way_init( &ctx.sha512 );
     sha512_8way_update( &ctx.sha512, vhash, dataLen );
     sha512_8way_close( &ctx.sha512, vhash );

     rintrlv_8x64_8x32( vhashA, vhash, dataLen<<3 );

     haval256_5_8way_init( &ctx.haval );
     haval256_5_8way_update( &ctx.haval, vhashA, dataLen );
     haval256_5_8way_close( &ctx.haval, vhashA );

     rintrlv_8x32_8x64( vhash, vhashA, dataLen<<3 );

     memset( &vhash[ 4<<3 ], 0, (dataLen-32) << 3 );

     blake512_8way_full( &ctx.blake, vhash, vhash, dataLen );

     bmw512_8way_full( &ctx.bmw, vhash, vhash, dataLen );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, dataLen<<3 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, dataLen );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, dataLen );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, dataLen<<3 );

#else

     dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash4, (char*)hash4, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash5, (char*)hash5, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash6, (char*)hash6, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash7, (char*)hash7, dataLen<<3 );

     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

#endif

     skein512_8way_full( &ctx.skein, vhash, vhash, dataLen );

     jh512_8way_init( &ctx.jh );
     jh512_8way_update( &ctx.jh, vhash, dataLen );
     jh512_8way_close( &ctx.jh, vhash );

     keccak512_8way_init( &ctx.keccak );
     keccak512_8way_update( &ctx.keccak, vhash, dataLen );
     keccak512_8way_close( &ctx.keccak, vhash );

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, dataLen<<3 );

     luffa512_4way_full( &ctx.luffa, vhashA, vhashA, dataLen );
     luffa512_4way_full( &ctx.luffa, vhashB, vhashB, dataLen );

     cube_4way_full( &ctx.cube, vhashA, 512, vhashA, dataLen );
     cube_4way_full( &ctx.cube, vhashB, 512, vhashB, dataLen );

#if defined(__VAES__)

     shavite512_4way_full( &ctx.shavite, vhashA, vhashA, dataLen );
     shavite512_4way_full( &ctx.shavite, vhashB, vhashB, dataLen );

#else

     dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, dataLen<<3 );
     dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, dataLen<<3 );

     shavite512_full( &ctx.shavite, hash0, hash0, dataLen );
     shavite512_full( &ctx.shavite, hash1, hash1, dataLen );
     shavite512_full( &ctx.shavite, hash2, hash2, dataLen );
     shavite512_full( &ctx.shavite, hash3, hash3, dataLen );
     shavite512_full( &ctx.shavite, hash4, hash4, dataLen );
     shavite512_full( &ctx.shavite, hash5, hash5, dataLen );
     shavite512_full( &ctx.shavite, hash6, hash6, dataLen );
     shavite512_full( &ctx.shavite, hash7, hash7, dataLen );

     intrlv_4x128( vhashA, hash0, hash1, hash2, hash3, dataLen<<3 );
     intrlv_4x128( vhashB, hash4, hash5, hash6, hash7, dataLen<<3 );

#endif

     simd512_4way_full( &ctx.simd, vhashA, vhashA, dataLen );
     simd512_4way_full( &ctx.simd, vhashB, vhashB, dataLen );

#if defined(__VAES__)

     echo_4way_full( &ctx.echo, vhashA, 512, vhashA, dataLen );
     echo_4way_full( &ctx.echo, vhashB, 512, vhashB, dataLen );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, dataLen<<3 );

#else

     dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, dataLen<<3 );
     dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, dataLen<<3 );

     echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                     (const BitSequence *)hash0, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                     (const BitSequence *)hash1, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                     (const BitSequence *)hash2, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                     (const BitSequence *)hash3, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                     (const BitSequence *)hash4, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                     (const BitSequence *)hash5, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                     (const BitSequence *)hash6, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                     (const BitSequence *)hash7, dataLen );

     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

#endif

     hamsi512_8way_init( &ctx.hamsi );
     hamsi512_8way_update( &ctx.hamsi, vhash, dataLen );
     hamsi512_8way_close( &ctx.hamsi, vhash );

     dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

     fugue512_full( &ctx.fugue, hash0, hash0, dataLen );
     fugue512_full( &ctx.fugue, hash1, hash1, dataLen );
     fugue512_full( &ctx.fugue, hash2, hash2, dataLen );
     fugue512_full( &ctx.fugue, hash3, hash3, dataLen );
     fugue512_full( &ctx.fugue, hash4, hash4, dataLen );
     fugue512_full( &ctx.fugue, hash5, hash5, dataLen );
     fugue512_full( &ctx.fugue, hash6, hash6, dataLen );
     fugue512_full( &ctx.fugue, hash7, hash7, dataLen );

     intrlv_8x32( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, dataLen );
     shabal512_8way_close( &ctx.shabal, vhash );

     dintrlv_8x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, dataLen );

     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

     sha512_8way_init( &ctx.sha512 );
     sha512_8way_update( &ctx.sha512, vhash, dataLen );
     sha512_8way_close( &ctx.sha512, vhash );

     rintrlv_8x64_8x32( vhashA, vhash, dataLen<<3 );

     haval256_5_8way_init( &ctx.haval );
     haval256_5_8way_update( &ctx.haval, vhashA, dataLen );
     haval256_5_8way_close( &ctx.haval, output );

     return 1;
}

#elif defined(XEVAN_4WAY)

union _xevan_4way_context_overlay
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
};
typedef union _xevan_4way_context_overlay xevan_4way_context_overlay;

int xevan_4way_hash( void *output, const void *input, int thr_id )
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

     blake512_4way_full( &ctx.blake, vhash, input, 80 );
     memset( &vhash[8<<2], 0, 64<<2 );

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way_update( &ctx.bmw, vhash, dataLen );
     bmw512_4way_close( &ctx.bmw, vhash );

#if defined(__VAES__)

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, dataLen<<3 );

     groestl512_2way_full( &ctx.groestl, vhashA, vhashA, dataLen );
     groestl512_2way_full( &ctx.groestl, vhashB, vhashB, dataLen );

     rintrlv_2x128_4x64( vhash, vhashA, vhashB, dataLen<<3 );

#else
     
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, dataLen<<3 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

#endif

     skein512_4way_full( &ctx.skein, vhash, vhash, dataLen );

     jh512_4way_init( &ctx.jh );
     jh512_4way_update( &ctx.jh, vhash, dataLen );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way_update( &ctx.keccak, vhash, dataLen );
     keccak512_4way_close( &ctx.keccak, vhash );

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, dataLen<<3 );

     luffa512_2way_full( &ctx.luffa, vhashA, vhashA, dataLen );
     luffa512_2way_full( &ctx.luffa, vhashB, vhashB, dataLen );

     cube_2way_full( &ctx.cube, vhashA, 512, vhashA, dataLen );
     cube_2way_full( &ctx.cube, vhashB, 512, vhashB, dataLen );

     shavite512_2way_full( &ctx.shavite, vhashA, vhashA, dataLen );
     shavite512_2way_full( &ctx.shavite, vhashB, vhashB, dataLen );

     simd512_2way_full( &ctx.simd, vhashA, vhashA, dataLen );
     simd512_2way_full( &ctx.simd, vhashB, vhashB, dataLen );

#if defined(__VAES__)

     echo_2way_full( &ctx.echo, vhashA, 512, vhashA, dataLen );
     echo_2way_full( &ctx.echo, vhashB, 512, vhashB, dataLen );

     rintrlv_2x128_4x64( vhash, vhashA, vhashB, dataLen<<3 );

#else
     
     dintrlv_2x128( hash0, hash1, vhashA, dataLen<<3 );
     dintrlv_2x128( hash2, hash3, vhashB, dataLen<<3 );

     echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                     (const BitSequence *)hash0, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                     (const BitSequence *)hash1, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                     (const BitSequence *)hash2, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                     (const BitSequence *)hash3, dataLen );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

#endif

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhash, dataLen );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     fugue512_full( &ctx.fugue, hash0, hash0, dataLen );
     fugue512_full( &ctx.fugue, hash1, hash1, dataLen );
     fugue512_full( &ctx.fugue, hash2, hash2, dataLen );
     fugue512_full( &ctx.fugue, hash3, hash3, dataLen );

     // Parallel 4way 32 bit
     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     shabal512_4way_init( &ctx.shabal );
     shabal512_4way_update( &ctx.shabal, vhash, dataLen );
     shabal512_4way_close( &ctx.shabal, vhash );

     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     // Serial
     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, dataLen );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way_update( &ctx.sha512, vhash, dataLen );
     sha512_4way_close( &ctx.sha512, vhash );

     rintrlv_4x64_4x32( vhashA, vhash, dataLen<<3 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way_update( &ctx.haval, vhashA, dataLen );
     haval256_5_4way_close( &ctx.haval, vhashA );

     rintrlv_4x32_4x64( vhash, vhashA, dataLen<<3 );

     memset( &vhash[ 4<<2 ], 0, (dataLen-32) << 2 );

     blake512_4way_init( &ctx.blake );
     blake512_4way_update( &ctx.blake, vhash, dataLen );
     blake512_4way_close(&ctx.blake, vhash);

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way_update( &ctx.bmw, vhash, dataLen );
     bmw512_4way_close( &ctx.bmw, vhash );

#if defined(__VAES__)

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, dataLen<<3 );

     groestl512_2way_full( &ctx.groestl, vhashA, vhashA, dataLen );
     groestl512_2way_full( &ctx.groestl, vhashB, vhashB, dataLen );

     rintrlv_2x128_4x64( vhash, vhashA, vhashB, dataLen<<3 );

#else

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, dataLen<<3 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

#endif

     skein512_4way_full( &ctx.skein, vhash, vhash, dataLen );

     jh512_4way_init( &ctx.jh );
     jh512_4way_update( &ctx.jh, vhash, dataLen );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way_update( &ctx.keccak, vhash, dataLen );
     keccak512_4way_close( &ctx.keccak, vhash );

     rintrlv_4x64_2x128( vhashA, vhashB, vhash, dataLen<<3 );

     luffa512_2way_full( &ctx.luffa, vhashA, vhashA, dataLen );
     luffa512_2way_full( &ctx.luffa, vhashB, vhashB, dataLen );

     cube_2way_full( &ctx.cube, vhashA, 512, vhashA, dataLen );
     cube_2way_full( &ctx.cube, vhashB, 512, vhashB, dataLen );

     shavite512_2way_full( &ctx.shavite, vhashA, vhashA, dataLen );
     shavite512_2way_full( &ctx.shavite, vhashB, vhashB, dataLen );

     simd512_2way_full( &ctx.simd, vhashA, vhashA, dataLen );
     simd512_2way_full( &ctx.simd, vhashB, vhashB, dataLen );

#if defined(__VAES__)

     echo_2way_full( &ctx.echo, vhashA, 512, vhashA, dataLen );
     echo_2way_full( &ctx.echo, vhashB, 512, vhashB, dataLen );

     rintrlv_2x128_4x64( vhash, vhashA, vhashB, dataLen<<3 );

#else

     dintrlv_2x128( hash0, hash1, vhashA, dataLen<<3 );
     dintrlv_2x128( hash2, hash3, vhashB, dataLen<<3 );

     echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                     (const BitSequence *)hash0, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                     (const BitSequence *)hash1, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                     (const BitSequence *)hash2, dataLen );
     echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                     (const BitSequence *)hash3, dataLen );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

#endif

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhash, dataLen );
     hamsi512_4way_close( &ctx.hamsi, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     fugue512_full( &ctx.fugue, hash0, hash0, dataLen );
     fugue512_full( &ctx.fugue, hash1, hash1, dataLen );
     fugue512_full( &ctx.fugue, hash2, hash2, dataLen );
     fugue512_full( &ctx.fugue, hash3, hash3, dataLen );

     intrlv_4x32( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     shabal512_4way_init( &ctx.shabal );
     shabal512_4way_update( &ctx.shabal, vhash, dataLen );
     shabal512_4way_close( &ctx.shabal, vhash );

     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, dataLen );
     sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, dataLen );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     sha512_4way_init( &ctx.sha512 );
     sha512_4way_update( &ctx.sha512, vhash, dataLen );
     sha512_4way_close( &ctx.sha512, vhash );

     rintrlv_4x64_4x32( vhashA, vhash, dataLen<<3 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way_update( &ctx.haval, vhashA, dataLen );
     haval256_5_4way_close( &ctx.haval, output );

     return 1;
}

#endif
