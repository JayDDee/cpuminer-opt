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
#include "algo/fugue/sph_fugue.h"
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
   sph_fugue512_context    fugue;
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

void xevan_8way_hash( void *output, const void *input )
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

     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash0, dataLen );
     sph_shavite512_close( &ctx.shavite, hash0 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash1, dataLen );
     sph_shavite512_close( &ctx.shavite, hash1 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash2, dataLen );
     sph_shavite512_close( &ctx.shavite, hash2 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash3, dataLen );
     sph_shavite512_close( &ctx.shavite, hash3 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash4, dataLen );
     sph_shavite512_close( &ctx.shavite, hash4 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash5, dataLen );
     sph_shavite512_close( &ctx.shavite, hash5 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash6, dataLen );
     sph_shavite512_close( &ctx.shavite, hash6 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash7, dataLen );
     sph_shavite512_close( &ctx.shavite, hash7 );

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
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash4, dataLen );
     sph_fugue512_close( &ctx.fugue, hash4 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash5, dataLen );
     sph_fugue512_close( &ctx.fugue, hash5 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash6, dataLen );
     sph_fugue512_close( &ctx.fugue, hash6 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash7, dataLen );
     sph_fugue512_close( &ctx.fugue, hash7 );

     intrlv_8x32( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, dataLen );
     shabal512_8way_close( &ctx.shabal, vhash );

     dintrlv_8x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

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
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash4, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash4 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash5, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash5 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash6, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash6 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash7, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash7 );

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

     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash0, dataLen );
     sph_shavite512_close( &ctx.shavite, hash0 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash1, dataLen );
     sph_shavite512_close( &ctx.shavite, hash1 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash2, dataLen );
     sph_shavite512_close( &ctx.shavite, hash2 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash3, dataLen );
     sph_shavite512_close( &ctx.shavite, hash3 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash4, dataLen );
     sph_shavite512_close( &ctx.shavite, hash4 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash5, dataLen );
     sph_shavite512_close( &ctx.shavite, hash5 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash6, dataLen );
     sph_shavite512_close( &ctx.shavite, hash6 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512( &ctx.shavite, hash7, dataLen );
     sph_shavite512_close( &ctx.shavite, hash7 );

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
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash4, dataLen );
     sph_fugue512_close( &ctx.fugue, hash4 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash5, dataLen );
     sph_fugue512_close( &ctx.fugue, hash5 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash6, dataLen );
     sph_fugue512_close( &ctx.fugue, hash6 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash7, dataLen );
     sph_fugue512_close( &ctx.fugue, hash7 );

     intrlv_8x32( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

     shabal512_8way_init( &ctx.shabal );
     shabal512_8way_update( &ctx.shabal, vhash, dataLen );
     shabal512_8way_close( &ctx.shabal, vhash );

     dintrlv_8x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, dataLen<<3 );

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
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash4, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash4 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash5, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash5 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash6, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash6 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash7, dataLen );
     sph_whirlpool_close( &ctx.whirlpool, hash7 );

     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                  hash7, dataLen<<3 );

     sha512_8way_init( &ctx.sha512 );
     sha512_8way_update( &ctx.sha512, vhash, dataLen );
     sha512_8way_close( &ctx.sha512, vhash );

     rintrlv_8x64_8x32( vhashA, vhash, dataLen<<3 );

     haval256_5_8way_init( &ctx.haval );
     haval256_5_8way_update( &ctx.haval, vhashA, dataLen );
     haval256_5_8way_close( &ctx.haval, output );
}

int scanhash_xevan_8way( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &(hash[7*8]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32 = ptarget[7];
   const bool bench = opt_benchmark;

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   *noncev = mm512_intrlv_blend_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      xevan_8way_hash( hash, vdata );

      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( ( hashd7[ lane ] <= targ32 ) && !bench ) )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) ) )
         {
            pdata[19] = bswap_32( n + lane );
            submit_lane_solution( work, lane_hash, mythr, lane );
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

#elif defined(XEVAN_4WAY)

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

     blake512_4way_full( &ctx.blake, vhash, input, 80 );
     memset( &vhash[8<<2], 0, 64<<2 );

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way_update( &ctx.bmw, vhash, dataLen );
     bmw512_4way_close( &ctx.bmw, vhash );

     // Serial
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, dataLen<<3 );

     // Parallel 4way
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

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

     // Parallel
     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhash, dataLen );
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
     shabal512_4way_update( &ctx.shabal, vhash, dataLen );
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

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, dataLen<<3 );

     groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, dataLen<<3 );
     groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, dataLen<<3 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, dataLen<<3 );

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

     hamsi512_4way_init( &ctx.hamsi );
     hamsi512_4way_update( &ctx.hamsi, vhash, dataLen );
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
     shabal512_4way_update( &ctx.shabal, vhash, dataLen );
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
     sha512_4way_update( &ctx.sha512, vhash, dataLen );
     sha512_4way_close( &ctx.sha512, vhash );

     rintrlv_4x64_4x32( vhashA, vhash, dataLen<<3 );

     haval256_5_4way_init( &ctx.haval );
     haval256_5_4way_update( &ctx.haval, vhashA, dataLen );
     haval256_5_4way_close( &ctx.haval, output );
}

int scanhash_xevan_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[16*4] __attribute__ ((aligned (128)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &(hash[7<<2]);
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   int thr_id = mythr->id;
   __m256i  *noncev = (__m256i*)vdata + 9; 
   const uint32_t targ32 = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0cff;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do {
      xevan_4way_hash( hash, vdata );
      for ( int lane = 0; lane < 4; lane++ )
      if ( unlikely( hashd7[ lane ] <= targ32 ) && ! bench )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
	      if ( valid_hash( lane_hash, ptarget ) )
         {
             pdata[19] = bswap_32( n + lane );
             submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
