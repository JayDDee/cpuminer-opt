#include "hmq1725-gate.h"
#include <string.h>
#include <stdint.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/shavite/sph_shavite.h"
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

#if defined(HMQ1725_8WAY)

union _hmq1725_8way_context_overlay
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

typedef union _hmq1725_8way_context_overlay hmq1725_8way_context_overlay;

extern void hmq1725_8way_hash(void *state, const void *input)
{
   uint32_t vhash [16<<3] __attribute__ ((aligned (128)));
   uint32_t vhashA[16<<3] __attribute__ ((aligned (64)));
   uint32_t vhashB[16<<3] __attribute__ ((aligned (64)));
   uint32_t vhashC[16<<3] __attribute__ ((aligned (64)));
   uint32_t hash0 [16]    __attribute__ ((aligned (64)));
   uint32_t hash1 [16]    __attribute__ ((aligned (64)));
   uint32_t hash2 [16]    __attribute__ ((aligned (64)));
   uint32_t hash3 [16]    __attribute__ ((aligned (64)));
   uint32_t hash4 [16]    __attribute__ ((aligned (64)));
   uint32_t hash5 [16]    __attribute__ ((aligned (64)));
   uint32_t hash6 [16]    __attribute__ ((aligned (64)));
   uint32_t hash7 [16]    __attribute__ ((aligned (64)));
   hmq1725_8way_context_overlay ctx __attribute__ ((aligned (64)));
   __mmask8 vh_mask;
   const __m512i vmask = m512_const1_64( 24 );
   const uint32_t mask = 24;
   __m512i* vh  = (__m512i*)vhash;
   __m512i* vhA = (__m512i*)vhashA;
   __m512i* vhB = (__m512i*)vhashB;
   __m512i* vhC = (__m512i*)vhashC;

   bmw512_8way_full( &ctx.bmw, vhash, input, 80 );

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

   sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, 64 );

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6,  hash7 );

   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   // A
#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( ( vh_mask & 0x0f ) != 0x0f )
       groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
   if ( ( vh_mask & 0xf0 ) != 0xf0 )
       groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );
   
   rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

   if ( hash0[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
   if ( hash1[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
   if ( hash2[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
   if ( hash3[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
   if ( hash4[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
   if ( hash5[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
   if ( hash6[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
   if ( hash7[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

   intrlv_8x64_512( vhashC, hash0, hash1, hash2, hash3,
                            hash4, hash5, hash6, hash7 );

#endif

   // B
   if ( likely( vh_mask & 0xff ) )
       skein512_8way_full( &ctx.skein, vhashB, vhash, 64 );

   mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

   jh512_8way_init( &ctx.jh );
   jh512_8way_update( &ctx.jh, vhash, 64 );
   jh512_8way_close( &ctx.jh, vhash );

   keccak512_8way_init( &ctx.keccak );
   keccak512_8way_update( &ctx.keccak, vhash, 64 );
   keccak512_8way_close( &ctx.keccak, vhash );

   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   // A
   if ( ( vh_mask & 0xff ) != 0xff )
       blake512_8way_full( &ctx.blake, vhashA, vhash, 64 );
   // B
   if ( vh_mask & 0xff )
       bmw512_8way_full( &ctx.bmw, vhashB, vhash, 64 );

   mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   luffa512_4way_full( &ctx.luffa, vhashA, vhashA, 64 );
   luffa512_4way_full( &ctx.luffa, vhashB, vhashB, 64 );

   cube_4way_full( &ctx.cube, vhashA, 512, vhashA, 64 );
   cube_4way_full( &ctx.cube, vhashB, 512, vhashB, 64 );

   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   if ( likely( ( vh_mask & 0xff ) != 0xff ) )
   {
      keccak512_8way_init( &ctx.keccak );
      keccak512_8way_update( &ctx.keccak, vhash, 64 );
      keccak512_8way_close( &ctx.keccak, vhashA );
   }

   if ( likely( vh_mask & 0xff ) )
   {
      jh512_8way_init( &ctx.jh );
      jh512_8way_update( &ctx.jh, vhash, 64 );
      jh512_8way_close( &ctx.jh, vhashB );
   }

   mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );

#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   shavite512_4way_full( &ctx.shavite, vhashA, vhashA, 64 );
   shavite512_4way_full( &ctx.shavite, vhashB, vhashB, 64 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

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

   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );
   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );
   // 4x32 for haval
   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6, hash7 );
     
   // A
   if ( hash0[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
   if ( hash1[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
   if ( hash2[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
   if ( hash3[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );
   if ( hash4[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, 64 );
   if ( hash5[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, 64 );
   if ( hash6[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, 64 );
   if ( hash7[0] & mask )
      sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, 64 );

   intrlv_8x64_512( vhashA, hash0, hash1, hash2, hash3,
                            hash4, hash5, hash6, hash7 );

   // B
   if ( likely( vh_mask & 0xff ) )
   {
      haval256_5_8way_init( &ctx.haval );
      haval256_5_8way_update( &ctx.haval, vhash, 64 );
      haval256_5_8way_close( &ctx.haval, vhash );
      memset( &vhash[8<<3], 0, 32<<3 );
      rintrlv_8x32_8x64( vhashB, vhash, 512 );
   }

   mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );

#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   echo_4way_full( &ctx.echo, vhashA, 512, vhashA, 64 );
   echo_4way_full( &ctx.echo, vhashB, 512, vhashB, 64 );

   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

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

   blake512_8way_full( &ctx.blake, vhash, vhash, 64 );

   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   // A
#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( ( vh_mask & 0x0f ) != 0x0f ) )
      shavite512_4way_full( &ctx.shavite, vhashA, vhashA, 64 );
   if ( likely( ( vh_mask & 0xf0 ) != 0xf0 ) )
      shavite512_4way_full( &ctx.shavite, vhashB, vhashB, 64 );

   rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

   if ( hash0[0] & mask )
      shavite512_full( &ctx.shavite, hash0, hash0, 64 ); //
   if ( hash1[0] & mask )
      shavite512_full( &ctx.shavite, hash1, hash1, 64 ); //
   if ( hash2[0] & mask )
      shavite512_full( &ctx.shavite, hash2, hash2, 64 ); //
   if ( hash3[0] & mask )
      shavite512_full( &ctx.shavite, hash3, hash3, 64 ); //
   if ( hash4[0] & mask )
      shavite512_full( &ctx.shavite, hash4, hash4, 64 ); //
   if ( hash5[0] & mask )
      shavite512_full( &ctx.shavite, hash5, hash5, 64 ); //
   if ( hash6[0] & mask )
      shavite512_full( &ctx.shavite, hash6, hash6, 64 ); //
   if ( hash7[0] & mask )
      shavite512_full( &ctx.shavite, hash7, hash7, 64 ); //

   intrlv_8x64_512( vhashC, hash0, hash1, hash2, hash3,
                            hash4, hash5, hash6, hash7 );

#endif

   // B
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( vh_mask & 0x0f ) )
      luffa512_4way_full( &ctx.luffa, vhashA, vhashA, 64 );
   if ( likely( vh_mask & 0xf0 ) )
      luffa512_4way_full( &ctx.luffa, vhash, vhashB, 64 );

   rintrlv_4x128_8x64( vhashB, vhashA, vhash, 512 );

   mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

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

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6, hash7 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

     // A   
#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( ( vh_mask & 0x0f ) != 0x0f ) )
      echo_4way_full( &ctx.echo, vhashA, 512, vhashA, 64 );
   if ( likely( ( vh_mask & 0xf0 ) != 0xf0 ) )
      echo_4way_full( &ctx.echo, vhashB, 512, vhashB, 64 );

   rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else
   
   if ( hash0[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                       (const BitSequence *)hash0, 64 );
   if ( hash1[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                       (const BitSequence *)hash1, 64 );
   if ( hash2[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                       (const BitSequence *)hash2, 64 );
   if ( hash3[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                       (const BitSequence *)hash3, 64 );
   if ( hash4[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                       (const BitSequence *)hash4, 64 );
   if ( hash5[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                       (const BitSequence *)hash5, 64 );
   if ( hash6[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                       (const BitSequence *)hash6, 64 );
   if ( hash7[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                       (const BitSequence *)hash7, 64 );

   intrlv_8x64_512( vhashC, hash0, hash1, hash2, hash3,
                            hash4, hash5, hash6, hash7 );
   
#endif

   // B
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( vh_mask & 0x0f ) )
      simd512_4way_full( &ctx.simd, vhashA, vhashA, 64 );
   if ( likely( vh_mask & 0xf0 ) )
      simd512_4way_full( &ctx.simd, vhash, vhashB, 64 );

   rintrlv_4x128_8x64( vhashB, vhashA, vhash, 512 );

   mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

   rintrlv_8x64_8x32( vhashA, vhash, 512 );

   shabal512_8way_init( &ctx.shabal );
   shabal512_8way_update( &ctx.shabal, vhashA, 64 );
   shabal512_8way_close( &ctx.shabal, vhash );

   dintrlv_8x32_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

   sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, 64 );

   // A

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6, hash7 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   if ( hash0[0] & mask )
      fugue512_full( &ctx.fugue, hash0, hash0, 64 );
   if ( hash1[0] & mask )
      fugue512_full( &ctx.fugue, hash1, hash1, 64 );
   if ( hash2[0] & mask )
      fugue512_full( &ctx.fugue, hash2, hash2, 64 );
   if ( hash3[0] & mask )
      fugue512_full( &ctx.fugue, hash3, hash3, 64 );
   if ( hash4[0] & mask )
      fugue512_full( &ctx.fugue, hash4, hash4, 64 );
   if ( hash5[0] & mask )
      fugue512_full( &ctx.fugue, hash5, hash5, 64 );
   if ( hash6[0] & mask )
      fugue512_full( &ctx.fugue, hash6, hash6, 64 );
   if ( hash7[0] & mask )
      fugue512_full( &ctx.fugue, hash7, hash7, 64 );

   intrlv_8x64_512( vhashA, hash0, hash1, hash2, hash3,
                            hash4, hash5, hash6, hash7 );

   // B
   if ( likely( vh_mask & 0xff ) )
   {
      sha512_8way_init( &ctx.sha512 );
      sha512_8way_update( &ctx.sha512, vhash, 64 );
      sha512_8way_close( &ctx.sha512, vhashB );
   }

   mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );

#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
   groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

   groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
   groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
   groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
   groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
   groestl512_full( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
   groestl512_full( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
   groestl512_full( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
   groestl512_full( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3,
                           hash4, hash5, hash6, hash7 );
   
#endif

   sha512_8way_init( &ctx.sha512 );
   sha512_8way_update( &ctx.sha512, vhash, 64 );
   sha512_8way_close( &ctx.sha512, vhash );

   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );
   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, vhash );

   // A
   if ( likely( ( vh_mask & 0xff ) != 0xff ) )
   {
      intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );
      haval256_5_8way_init( &ctx.haval );
      haval256_5_8way_update( &ctx.haval, vhash, 64 );
      haval256_5_8way_close( &ctx.haval, vhash );
      memset( &vhash[8<<3], 0, 32<<3 );
      rintrlv_8x32_8x64( vhashA, vhash, 512 );
   }

   // B
   if ( !( hash0[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
   if ( !( hash1[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
   if ( !( hash2[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
   if ( !( hash3[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );
   if ( !( hash4[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash4, hash4, 64 );
   if ( !( hash5[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash5, hash5, 64 );
   if ( !( hash6[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash6, hash6, 64 );
   if ( !( hash7[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash7, hash7, 64 );

   intrlv_8x64_512( vhashB, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                    hash7 );
   mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );

   bmw512_8way_init( &ctx.bmw );
   bmw512_8way_update( &ctx.bmw, vhash, 64 );
   bmw512_8way_close( &ctx.bmw, state );
}

int scanhash_hmq1725_8way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash64[8*8] __attribute__ ((aligned (128)));
    uint32_t vdata[20*8] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint64_t *hash64_q3 = &(hash64[3*8]);
    uint32_t *pdata = work->data;
    uint64_t *ptarget = (uint64_t*)work->target;
    const uint64_t targ64_q3 = ptarget[3];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    const uint32_t last_nonce = max_nonce - 8;
    __m512i  *noncev = (__m512i*)vdata + 9;  
    const int thr_id = mythr->id;
    const bool bench = opt_benchmark;

    mm512_bswap32_intrlv80_8x64( vdata, pdata );
    *noncev = mm512_intrlv_blend_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
    do
    {
       hmq1725_8way_hash( hash64, vdata );

       for ( int lane = 0; lane < 8; lane++ )
       if ( hash64_q3[ lane ] <= targ64_q3 && !bench )
       {
          extr_lane_8x64( lane_hash, hash64, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
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

#elif defined(HMQ1725_4WAY)

union _hmq1725_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
    hashState_groestl       groestl;
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    hashState_luffa         luffa;
    luffa_2way_context      luffa2;
    cubehashParam           cube;
    cube_2way_context       cube2;
    sph_shavite512_context  shavite;
    hashState_sd            sd;
    simd_2way_context       simd;
    hashState_echo          echo;
    hamsi512_4way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
} __attribute__ ((aligned (64)));

typedef union _hmq1725_4way_context_overlay hmq1725_4way_context_overlay;

extern void hmq1725_4way_hash(void *state, const void *input)
{
   uint32_t hash0 [16]    __attribute__ ((aligned (64)));
   uint32_t hash1 [16]    __attribute__ ((aligned (64)));
   uint32_t hash2 [16]    __attribute__ ((aligned (64)));
   uint32_t hash3 [16]    __attribute__ ((aligned (64)));
   uint32_t vhash [16<<2] __attribute__ ((aligned (64)));
   uint32_t vhashA[16<<2] __attribute__ ((aligned (64)));
   uint32_t vhashB[16<<2] __attribute__ ((aligned (64)));
   hmq1725_4way_context_overlay ctx __attribute__ ((aligned (64)));
   __m256i vh_mask;     
   int h_mask;
   const __m256i vmask = m256_const1_64( 24 );
   const uint32_t mask = 24;
   __m256i* vh  = (__m256i*)vhash;
   __m256i* vhA = (__m256i*)vhashA;
   __m256i* vhB = (__m256i*)vhashB;

   bmw512_4way_init( &ctx.bmw );
   bmw512_4way_update( &ctx.bmw, input, 80 );
   bmw512_4way_close( &ctx.bmw, vhash );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

   sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

// first fork, A is groestl serial, B is skein parallel.

   intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

   vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ), m256_zero );
   h_mask = _mm256_movemask_epi8( vh_mask );

// A

   if ( hash0[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
   if ( hash1[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
   if ( hash2[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
   if ( hash3[0] & mask )
       groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

   intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

// B

    if ( h_mask & 0xffffffff )
       skein512_4way_full( &ctx.skein, vhashB, vhash, 64 );

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    jh512_4way_init( &ctx.jh );
    jh512_4way_update( &ctx.jh, vhash, 64 );
    jh512_4way_close( &ctx.jh, vhash );

    keccak512_4way_init( &ctx.keccak );
    keccak512_4way_update( &ctx.keccak, vhash, 64 );
    keccak512_4way_close( &ctx.keccak, vhash );

// second fork, A = blake parallel, B= bmw parallel.
    
    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ), m256_zero );
    h_mask = _mm256_movemask_epi8( vh_mask );

    if ( ( h_mask & 0xffffffff ) != 0xffffffff )
       blake512_4way_full( &ctx.blake, vhashA, vhash, 64 );

    if ( h_mask & 0xffffffff )
    {
       bmw512_4way_init( &ctx.bmw );
       bmw512_4way_update( &ctx.bmw, vhash, 64 );
       bmw512_4way_close( &ctx.bmw, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );
    
    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
    rintrlv_4x64_2x128( vhashA, vhashB, vhash, 512 );

    luffa512_2way_full( &ctx.luffa2, vhashA, vhashA, 64 );
    luffa512_2way_full( &ctx.luffa2, vhashB, vhashB, 64 );

    cube_2way_full( &ctx.cube2, vhashA, 512, vhashA, 64 );
    cube_2way_full( &ctx.cube2, vhashB, 512, vhashB, 64 );

    rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );

// A= keccak parallel, B= jh parallel
    
    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ), m256_zero );
    h_mask = _mm256_movemask_epi8( vh_mask );

    if ( ( h_mask & 0xffffffff ) != 0xffffffff )
    {
        keccak512_4way_init( &ctx.keccak );
        keccak512_4way_update( &ctx.keccak, vhash, 64 );
        keccak512_4way_close( &ctx.keccak, vhashA );
    }

    if ( h_mask & 0xffffffff )
    {
        jh512_4way_init( &ctx.jh );
        jh512_4way_update( &ctx.jh, vhash, 64 );
        jh512_4way_close( &ctx.jh, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    shavite512_full( &ctx.shavite, hash0, hash0, 64 );
    shavite512_full( &ctx.shavite, hash1, hash1, 64 );
    shavite512_full( &ctx.shavite, hash2, hash2, 64 );
    shavite512_full( &ctx.shavite, hash3, hash3, 64 );

    intrlv_2x128_512( vhashA, hash0, hash1 );
    intrlv_2x128_512( vhashB, hash2, hash3 );

    simd512_2way_full( &ctx.simd, vhashA, vhashA, 64 );
    simd512_2way_full( &ctx.simd, vhashB, vhashB, 64 );

    rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );     

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ), m256_zero );
    h_mask = _mm256_movemask_epi8( vh_mask );

    dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
    intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

    // A
    if ( hash0[0] & mask )
       sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
    if ( hash1[0] & mask )
       sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
    if ( hash2[0] & mask )
       sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
    if ( hash3[0] & mask )
       sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

    intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

    // B
    if ( h_mask & 0xffffffff )
    {
       haval256_5_4way_init( &ctx.haval );
       haval256_5_4way_update( &ctx.haval, vhash, 64 );
       haval256_5_4way_close( &ctx.haval, vhash );
       memset( &vhash[8<<2], 0, 32<<2 );
       rintrlv_4x32_4x64( vhashB, vhash, 512 );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
    
    echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                    (const BitSequence *)hash0, 64 );
    echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                    (const BitSequence *)hash1, 64 );
    echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                    (const BitSequence *)hash2, 64 );
    echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                    (const BitSequence *)hash3, 64 );

    intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
     
    blake512_4way_full( &ctx.blake, vhash, vhash, 64 );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

// shavite & luffa, both serial, select individually.

    if ( hash0[0] & mask )
       shavite512_full( &ctx.shavite, hash0, hash0, 64 ); //
    else
       luffa_full( &ctx.luffa, (BitSequence*)hash0, 512,
                         (const BitSequence*)hash0, 64 );

    if ( hash1[0] & mask )
       shavite512_full( &ctx.shavite, hash1, hash1, 64 ); //
    else
       luffa_full( &ctx.luffa, (BitSequence*)hash1, 512,
                         (const BitSequence*)hash1, 64 );

    if ( hash2[0] & mask )
       shavite512_full( &ctx.shavite, hash2, hash2, 64 ); //
    else
       luffa_full( &ctx.luffa, (BitSequence*)hash2, 512,
                         (const BitSequence*)hash2, 64 );

    if ( hash3[0] & mask )
       shavite512_full( &ctx.shavite, hash3, hash3, 64 ); //
    else
       luffa_full( &ctx.luffa, (BitSequence*)hash3, 512,
                         (const BitSequence*)hash3, 64 );

    intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

    hamsi512_4way_init( &ctx.hamsi );
    hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
    hamsi512_4way_close( &ctx.hamsi, vhash );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    fugue512_full( &ctx.fugue, hash0, hash0, 64 );
    fugue512_full( &ctx.fugue, hash1, hash1, 64 );
    fugue512_full( &ctx.fugue, hash2, hash2, 64 );
    fugue512_full( &ctx.fugue, hash3, hash3, 64 );

    // In this situation serial simd seems to be faster.

    intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
   
    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                   m256_zero );
    h_mask = _mm256_movemask_epi8( vh_mask );

    if ( hash0[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                       (const BitSequence *)hash0, 64 );
    else
    {
       init_sd( &ctx.sd, 512 );
       update_final_sd( &ctx.sd, (BitSequence *)hash0,
                           (const BitSequence *)hash0, 512 );
    }

   if ( hash1[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                       (const BitSequence *)hash1, 64 );
   else
   {
       init_sd( &ctx.sd, 512 );
       update_final_sd( &ctx.sd, (BitSequence *)hash1,
                           (const BitSequence *)hash1, 512 );
   }

   if ( hash2[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                       (const BitSequence *)hash2, 64 );
   else
   {
       init_sd( &ctx.sd, 512 );
       update_final_sd( &ctx.sd, (BitSequence *)hash2,
                           (const BitSequence *)hash2, 512 );
   }

   if ( hash3[0] & mask ) //4
       echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                       (const BitSequence *)hash3, 64 );
   else
   {
       init_sd( &ctx.sd, 512 );
       update_final_sd( &ctx.sd, (BitSequence *)hash3,
                           (const BitSequence *)hash3, 512 );
   }

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );

   shabal512_4way_init( &ctx.shabal );
   shabal512_4way_update( &ctx.shabal, vhash, 64 );
   shabal512_4way_close( &ctx.shabal, vhash );

   dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 512 );

   sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
   sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

// A = fugue serial, B = sha512 parallel
   
   intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

   vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ), m256_zero );
   h_mask = _mm256_movemask_epi8( vh_mask );

   if ( hash0[0] & mask ) 
      fugue512_full( &ctx.fugue, hash0, hash0, 64 );
   if ( hash1[0] & mask ) 
      fugue512_full( &ctx.fugue, hash1, hash1, 64 );
   if ( hash2[0] & mask ) 
      fugue512_full( &ctx.fugue, hash2, hash2, 64 );
   if ( hash3[0] & mask ) 
      fugue512_full( &ctx.fugue, hash3, hash3, 64 );

   intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

   if ( h_mask & 0xffffffff )
   {
      sha512_4way_init( &ctx.sha512 );
      sha512_4way_update( &ctx.sha512, vhash, 64 );
      sha512_4way_close( &ctx.sha512, vhashB );
   }

   mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

   groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
   groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
   groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
   groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

   intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

   sha512_4way_init( &ctx.sha512 ); 
   sha512_4way_update( &ctx.sha512, vhash, 64 );
   sha512_4way_close( &ctx.sha512, vhash ); 

// A = haval parallel, B = Whirlpool serial

   vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ), m256_zero );
   h_mask = _mm256_movemask_epi8( vh_mask );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
   intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

   if ( ( h_mask & 0xffffffff ) != 0xffffffff )
   {
      haval256_5_4way_init( &ctx.haval );
      haval256_5_4way_update( &ctx.haval, vhash, 64 );
      haval256_5_4way_close( &ctx.haval, vhash );
      memset( &vhash[8<<2], 0, 32<<2 );
      rintrlv_4x32_4x64( vhashA, vhash, 512 );
   }

   if ( !( hash0[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash0, hash0, 64 );
   if ( !( hash1[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash1, hash1, 64 );
   if ( !( hash2[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash2, hash2, 64 );
   if ( !( hash3[0] & mask ) )
      sph_whirlpool512_full( &ctx.whirlpool, hash3, hash3, 64 );

   intrlv_4x64( vhashB, hash0, hash1, hash2, hash3, 512 );

   mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

   bmw512_4way_init( &ctx.bmw );
   bmw512_4way_update( &ctx.bmw, vhash, 64 );
   bmw512_4way_close( &ctx.bmw, state );
}

int scanhash_hmq1725_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash64[8*4] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint64_t *hash64_q3 = &(hash64[3*4]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint64_t targ64_q3 = ((uint64_t*)ptarget)[3];
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 4;
    __m256i  *noncev = (__m256i*)vdata + 9;
    const int thr_id = mythr->id;
    const bool bench = opt_benchmark;

    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
    do
    {
       hmq1725_4way_hash( hash64, vdata );

       for ( int lane = 0; lane < 4; lane++ )
       if ( unlikely( hash64_q3[ lane ] <= targ64_q3 && !bench ) )
       {
          extr_lane_4x64( lane_hash, hash64, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
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

#endif // HMQ1725_4WAY
