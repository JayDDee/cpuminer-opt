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
#include "algo/fugue/sph_fugue.h"
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

   bmw512_8way_init( &ctx.bmw );
   bmw512_8way_update( &ctx.bmw, input, 80 );
   bmw512_8way_close( &ctx.bmw, vhash );

   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash );

   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash0, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash0 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash1, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash1 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash2, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash2 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash3, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash3 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash4, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash4 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash5, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash5 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash6, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash6 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash7, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash7 );

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   // A

#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( ( vh_mask & 0x0f ) != 0x0f ) )
   {
     groestl512_4way_init( &ctx.groestl, 64 );
     groestl512_4way_update_close( &ctx.groestl, vhashA, vhashA, 512 );
   }
   if ( likely( ( vh_mask & 0xf0 ) != 0xf0 ) )
   {
     groestl512_4way_init( &ctx.groestl, 64 );
     groestl512_4way_update_close( &ctx.groestl, vhashB, vhashB, 512 );
   }
   rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash );

   if ( hash0[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                             (char*)hash0, 512 );
   }
   if ( hash1[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                             (char*)hash1, 512 );
   }
   if ( hash2[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                             (char*)hash2, 512 );
   }
   if ( hash3[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                             (char*)hash3, 512 );
   }
   if ( hash4[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash4,
                                             (char*)hash4, 512 );
   }
   if ( hash5[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash5,
                                             (char*)hash5, 512 );
   }
   if ( hash6[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash6,
                                             (char*)hash6, 512 );
   }
   if ( hash7[0] & mask )
   {
     init_groestl( &ctx.groestl, 64 );
     update_and_final_groestl( &ctx.groestl, (char*)hash7,
                                             (char*)hash7, 512 );
   }

   intrlv_8x64_512( vhashC, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );

#endif

   // B
   if ( likely( vh_mask & 0xff ) )
   {
      skein512_8way_init( &ctx.skein );
      skein512_8way_update( &ctx.skein, vhash, 64 );
      skein512_8way_close( &ctx.skein, vhashB );
   }

   mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

   jh512_8way_init( &ctx.jh );
   jh512_8way_update( &ctx.jh, vhash, 64 );
   jh512_8way_close( &ctx.jh, vhash );

   keccak512_8way_init( &ctx.keccak );
   keccak512_8way_update( &ctx.keccak, vhash, 64 );
   keccak512_8way_close( &ctx.keccak, vhash );

   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   if ( likely( ( vh_mask & 0xff ) != 0xff ) )
   {
      blake512_8way_init( &ctx.blake );
      blake512_8way_update( &ctx.blake, vhash, 64 );
      blake512_8way_close( &ctx.blake, vhashA );
   }

   if ( likely( vh_mask & 0xff ) )
   {
      bmw512_8way_init( &ctx.bmw );
      bmw512_8way_update( &ctx.bmw, vhash, 64 );
      bmw512_8way_close( &ctx.bmw, vhashB );
   }

   mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   luffa_4way_init( &ctx.luffa, 512 );
   luffa_4way_update_close( &ctx.luffa, vhashA, vhashA, 64 );
   luffa_4way_init( &ctx.luffa, 512 );
   luffa_4way_update_close( &ctx.luffa, vhashB, vhashB, 64 );

   cube_4way_init( &ctx.cube, 512, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashA, vhashA, 64 );
   cube_4way_init( &ctx.cube, 512, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashB, vhashB, 64 );

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

   shavite512_4way_init( &ctx.shavite );
   shavite512_4way_update_close( &ctx.shavite, vhashA, vhashA, 64 );
   shavite512_4way_init( &ctx.shavite );
   shavite512_4way_update_close( &ctx.shavite, vhashB, vhashB, 64 );

   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );
     
#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash );

   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash0, 64 );
   sph_shavite512_close( &ctx.shavite, hash0 );
   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash1, 64 );
   sph_shavite512_close( &ctx.shavite, hash1 );
   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash2, 64 );
   sph_shavite512_close( &ctx.shavite, hash2 );
   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash3, 64 );
   sph_shavite512_close( &ctx.shavite, hash3 );
   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash4, 64 );
   sph_shavite512_close( &ctx.shavite, hash4 );
   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash5, 64 );
   sph_shavite512_close( &ctx.shavite, hash5 );
   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash6, 64 );
   sph_shavite512_close( &ctx.shavite, hash6 );
   sph_shavite512_init( &ctx.shavite );
   sph_shavite512 ( &ctx.shavite, hash7, 64 );
   sph_shavite512_close( &ctx.shavite, hash7 );

   intrlv_4x128_512( vhashA, hash0, hash1, hash2, hash3 );
   intrlv_4x128_512( vhashB, hash4, hash5, hash6, hash7 );

#endif

   simd_4way_init( &ctx.simd, 512 );
   simd_4way_update_close( &ctx.simd, vhashA, vhashA, 512 );
   simd_4way_init( &ctx.simd, 512 );
   simd_4way_update_close( &ctx.simd, vhashB, vhashB, 512 );

   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );
   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash );
   // 4x32 for haval
   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );
     
   // A
   if ( hash0[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash0, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash0 );
   }
   if ( hash1[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash1, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash1 );
   }
   if ( hash2[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash2, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash2 );
   }
   if ( hash3[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash3, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash3 );
   }
   if ( hash4[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash4, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash4 );
   }
   if ( hash5[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash5, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash5 );
   }
   if ( hash6[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash6, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash6 );
   }
   if ( hash7[0] & mask )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash7, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash7 );
   }

   intrlv_8x64_512( vhashA, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );

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

   echo_4way_init( &ctx.echo, 512 );
   echo_4way_update_close( &ctx.echo, vhashA, vhashA, 512 );
   echo_4way_init( &ctx.echo, 512 );
   echo_4way_update_close( &ctx.echo, vhashB, vhashB, 512 );

   rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                     vhash );

   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash0,
                           (const BitSequence *)hash0, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash1,
                           (const BitSequence *)hash1, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash2,
                           (const BitSequence *)hash2, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash3,
                           (const BitSequence *)hash3, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash4,
                           (const BitSequence *)hash4, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash5,
                           (const BitSequence *)hash5, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash6,
                           (const BitSequence *)hash6, 512 );
   init_echo( &ctx.echo, 512 );
   update_final_echo( &ctx.echo, (BitSequence *)hash7,
                           (const BitSequence *)hash7, 512 );

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                    hash7 );

#endif

   blake512_8way_init( &ctx.blake );
   blake512_8way_update( &ctx.blake, vhash, 64 );
   blake512_8way_close( &ctx.blake, vhash );

   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   // A
#if defined(__VAES__)

   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( ( vh_mask & 0x0f ) != 0x0f ) )
   {
     shavite512_4way_init( &ctx.shavite );
     shavite512_4way_update_close( &ctx.shavite, vhashA, vhashA, 64 );
   }
   if ( likely( ( vh_mask & 0xf0 ) != 0xf0 ) )
   {
     shavite512_4way_init( &ctx.shavite );
     shavite512_4way_update_close( &ctx.shavite, vhashB, vhashB, 64 );
   }

   rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash );

   if ( hash0[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash0, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash0 ); //8
   }
   if ( hash1[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash1, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash1 ); //8
   }
   if ( hash2[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash2, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash2 ); //8
   }
   if ( hash3[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash3, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash3 ); //8
   }
   if ( hash4[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash4, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash4 ); //8
   }
   if ( hash5[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash5, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash5 ); //8
   }
   if ( hash6[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash6, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash6 ); //8
   }
   if ( hash7[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash7, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash7 ); //8
   }

   intrlv_8x64_512( vhashC, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );

#endif

   // B
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( vh_mask & 0x0f ) )
   {
      luffa_4way_init( &ctx.luffa, 512 );
      luffa_4way_update_close( &ctx.luffa, vhashA, vhashA, 64 );
   }
   if ( likely( vh_mask & 0xf0 ) )
   {
      luffa_4way_init( &ctx.luffa, 512 );
      luffa_4way_update_close( &ctx.luffa, vhash, vhashB, 64 );
   }

   rintrlv_4x128_8x64( vhashB, vhashA, vhash, 512 );

   mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

   hamsi512_8way_init( &ctx.hamsi );
   hamsi512_8way_update( &ctx.hamsi, vhash, 64 );
   hamsi512_8way_close( &ctx.hamsi, vhash );

   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash );

   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash0, 64 );
   sph_fugue512_close( &ctx.fugue, hash0 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash1, 64 );
   sph_fugue512_close( &ctx.fugue, hash1 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash2, 64 );
   sph_fugue512_close( &ctx.fugue, hash2 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash3, 64 );
   sph_fugue512_close( &ctx.fugue, hash3 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash4, 64 );
   sph_fugue512_close( &ctx.fugue, hash4 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash5, 64 );
   sph_fugue512_close( &ctx.fugue, hash5 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash6, 64 );
   sph_fugue512_close( &ctx.fugue, hash6 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash7, 64 );
   sph_fugue512_close( &ctx.fugue, hash7 );

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

     // A   
#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( ( vh_mask & 0x0f ) != 0x0f ) )
   {
     echo_4way_init( &ctx.echo, 512 );
     echo_4way_update_close( &ctx.echo, vhashA, vhashA, 512 );
   }
   if ( likely( ( vh_mask & 0xf0 ) != 0xf0 ) )
   {
     echo_4way_init( &ctx.echo, 512 );
     echo_4way_update_close( &ctx.echo, vhashB, vhashB, 512 );
   }

   rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else
   
   if ( hash0[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash0,
                               (const BitSequence *)hash0, 512 );
   }
   if ( hash1[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash1,
                               (const BitSequence *)hash1, 512 );
   }
   if ( hash2[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash2,
                               (const BitSequence *)hash2, 512 );
   }
   if ( hash3[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash3,
                               (const BitSequence *)hash3, 512 );
   }
   if ( hash4[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash4,
                               (const BitSequence *)hash4, 512 );
   }
   if ( hash5[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash5,
                               (const BitSequence *)hash5, 512 );
   }
   if ( hash6[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash6,
                               (const BitSequence *)hash6, 512 );
   }
   if ( hash7[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash7,
                               (const BitSequence *)hash7, 512 );
   }

   intrlv_8x64_512( vhashC, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );
   
#endif

   // B
   rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

   if ( likely( vh_mask & 0x0f ) )
   {
      simd_4way_init( &ctx.simd, 512 );
      simd_4way_update_close( &ctx.simd, vhashA, vhashA, 512 );
   }
   if ( likely( vh_mask & 0xf0 ) )
   {
      simd_4way_init( &ctx.simd, 512 );
      simd_4way_update_close( &ctx.simd, vhash, vhashB, 512 );
   }

   rintrlv_4x128_8x64( vhashB, vhashA, vhash, 512 );

   mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

   rintrlv_8x64_8x32( vhashA, vhash, 512 );

   shabal512_8way_init( &ctx.shabal );
   shabal512_8way_update( &ctx.shabal, vhashA, 64 );
   shabal512_8way_close( &ctx.shabal, vhash );

   dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash );

   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash0, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash0 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash1, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash1 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash2, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash2 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash3, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash3 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash4, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash4 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash5, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash5 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash6, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash6 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash7, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash7 );

   // A

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );
   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );

   if ( hash0[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash0, 64 );
      sph_fugue512_close( &ctx.fugue, hash0 );
   }
   if ( hash1[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash1, 64 );
      sph_fugue512_close( &ctx.fugue, hash1 );
   }
   if ( hash2[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash2, 64 );
      sph_fugue512_close( &ctx.fugue, hash2 );
   }
   if ( hash3[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash3, 64 );
      sph_fugue512_close( &ctx.fugue, hash3 );
   }
   if ( hash4[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash4, 64 );
      sph_fugue512_close( &ctx.fugue, hash4 );
   }
   if ( hash5[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash5, 64 );
      sph_fugue512_close( &ctx.fugue, hash5 );
   }
   if ( hash6[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash6, 64 );
      sph_fugue512_close( &ctx.fugue, hash6 );
   }
   if ( hash7[0] & mask )
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash7, 64 );
      sph_fugue512_close( &ctx.fugue, hash7 );
   }

   intrlv_8x64_512( vhashA, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                    hash7 );

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

     groestl512_4way_init( &ctx.groestl, 64 );
     groestl512_4way_update_close( &ctx.groestl, vhashA, vhashA, 512 );
     groestl512_4way_init( &ctx.groestl, 64 );
     groestl512_4way_update_close( &ctx.groestl, vhashB, vhashB, 512 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash );

   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

   intrlv_8x64_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7 );
   
#endif

   sha512_8way_init( &ctx.sha512 );
   sha512_8way_update( &ctx.sha512, vhash, 64 );
   sha512_8way_close( &ctx.sha512, vhash );

   vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], vmask ),
                                       m512_zero );
   dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                     vhash );

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
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash0, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash0 );
   }
   if ( !( hash1[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash1, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash1 );
   }
   if ( !( hash2[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash2, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash2 );
   }
   if ( !( hash3[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash3, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash3 );
   }
   if ( !( hash4[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash4, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash4 );
   }
   if ( !( hash5[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash5, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash5 );
   }
   if ( !( hash6[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash6, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash6 );
   }
   if ( !( hash7[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash7, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash7 );
   }

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
    uint32_t hash[16*8] __attribute__ ((aligned (128)));
    uint32_t vdata[20*8] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint32_t *hash7 = &(hash[49]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    const uint32_t last_nonce = max_nonce - 4;
    __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
    int thr_id = mythr->id;

    mm512_bswap32_intrlv80_8x64( vdata, pdata );
    do
    {
       *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n,   0 ) ), *noncev );

       hmq1725_8way_hash( hash, vdata );

       for ( int lane = 0; lane < 8; lane++ )
       if ( hash7[ lane<<1 ] <= Htarg )
       {
          extr_lane_8x64( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
          {
             pdata[19] = n + lane;
             submit_lane_solution( work, lane_hash, mythr, lane );
          }
       }
       n += 8;
    } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );

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
    cubehashParam           cube;
    sph_shavite512_context  shavite;
    hashState_sd            sd;
    simd_2way_context       simd;
    hashState_echo          echo;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
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
     const __m256i vmask = m256_const1_64( 24 );
     const uint32_t mask = 24;
     __m256i* vh  = (__m256i*)vhash;
     __m256i* vhA = (__m256i*)vhashA;
     __m256i* vhB = (__m256i*)vhashB;

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way_update( &ctx.bmw, input, 80 );
     bmw512_4way_close( &ctx.bmw, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash0, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash0 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash1, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash1 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash2, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash2 );
     sph_whirlpool_init( &ctx.whirlpool );
     sph_whirlpool( &ctx.whirlpool, hash3, 64 );
     sph_whirlpool_close( &ctx.whirlpool, hash3 );

// first fork, A is groestl serial, B is skein parallel.

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

     vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                   m256_zero );

// A

     if ( hash0[0] & mask )
     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                               (char*)hash0, 512 );
     }
     if ( hash1[0] & mask )
     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                               (char*)hash1, 512 );
     }
     if ( hash2[0] & mask )
     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                               (char*)hash2, 512 );
     }
     if ( hash3[0] & mask )
     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                               (char*)hash3, 512 );
     }

     intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

// B

     if ( mm256_anybits0( vh_mask ) )
     {
       skein512_4way_init( &ctx.skein );
       skein512_4way_update( &ctx.skein, vhash, 64 );
       skein512_4way_close( &ctx.skein, vhashB );
     }

     mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

     jh512_4way_init( &ctx.jh );
     jh512_4way_update( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way_update( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

// second fork, A = blake parallel, B= bmw parallel.
    
     vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                   m256_zero );

     if ( mm256_anybits1( vh_mask ) )
     {
       blake512_4way_init( &ctx.blake );
       blake512_4way_update( &ctx.blake, vhash, 64 );
       blake512_4way_close( &ctx.blake, vhashA );
     }

     if ( mm256_anybits0( vh_mask ) )
     {
       bmw512_4way_init( &ctx.bmw );
       bmw512_4way_update( &ctx.bmw, vhash, 64 );
       bmw512_4way_close( &ctx.bmw, vhashB );
     }

     mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );
    
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     init_luffa( &ctx.luffa, 512 );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash0,
                                   (const BitSequence*)hash0, 64 );
     init_luffa( &ctx.luffa, 512 );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash1,
                                   (const BitSequence*)hash1, 64 );
     init_luffa( &ctx.luffa, 512 );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash2,
                                   (const BitSequence*)hash2, 64 );
     init_luffa( &ctx.luffa, 512 );
     update_and_final_luffa( &ctx.luffa, (BitSequence*)hash3,
                                   (const BitSequence*)hash3, 64 );

     cubehashInit( &ctx.cube, 512, 16, 32 );
     cubehashUpdateDigest( &ctx.cube, (BitSequence *)hash0,
                                (const BitSequence *)hash0, 64 );
     cubehashInit( &ctx.cube, 512, 16, 32 );
     cubehashUpdateDigest( &ctx.cube, (BitSequence *)hash1,
                                (const BitSequence *)hash1, 64 );
     cubehashInit( &ctx.cube, 512, 16, 32 );
     cubehashUpdateDigest( &ctx.cube, (BitSequence *)hash2,
                                (const BitSequence *)hash2, 64 );
     cubehashInit( &ctx.cube, 512, 16, 32 );
     cubehashUpdateDigest( &ctx.cube, (BitSequence *)hash3,
                                (const BitSequence *)hash3, 64 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

// A= keccak parallel, B= jh parallel
    
     vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                  m256_zero );

     if ( mm256_anybits1( vh_mask ) )
     {
        keccak512_4way_init( &ctx.keccak );
        keccak512_4way_update( &ctx.keccak, vhash, 64 );
        keccak512_4way_close( &ctx.keccak, vhashA );
     }

     if ( mm256_anybits0( vh_mask ) )
     {
        jh512_4way_init( &ctx.jh );
        jh512_4way_update( &ctx.jh, vhash, 64 );
        jh512_4way_close( &ctx.jh, vhashB );
     }

     mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     sph_shavite512_init( &ctx.shavite );
     sph_shavite512 ( &ctx.shavite, hash0, 64 );
     sph_shavite512_close( &ctx.shavite, hash0 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512 ( &ctx.shavite, hash1, 64 );
     sph_shavite512_close( &ctx.shavite, hash1 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512 ( &ctx.shavite, hash2, 64 );
     sph_shavite512_close( &ctx.shavite, hash2 );
     sph_shavite512_init( &ctx.shavite );
     sph_shavite512 ( &ctx.shavite, hash3, 64 );
     sph_shavite512_close( &ctx.shavite, hash3 );

     intrlv_2x128_512( vhashA, hash0, hash1 );
     intrlv_2x128_512( vhashB, hash2, hash3 );

     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashA, vhashA, 512 );
     simd_2way_init( &ctx.simd, 512 );
     simd_2way_update_close( &ctx.simd, vhashB, vhashB, 512 );

     rintrlv_2x128_4x64( vhash, vhashA, vhashB, 512 );     

     vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                   m256_zero );

     dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );

     // 4x32 for haval
     intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

     // A
    
     if ( hash0[0] & mask )
     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash0, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash0 );
     }
     if ( hash1[0] & mask )
     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash1, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash1 );
     }
     if ( hash2[0] & mask )
     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash2, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash2 );
     }
     if ( hash3[0] & mask )
     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash3, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash3 );
     }

     intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

// B
     if ( mm256_anybits0( vh_mask ) )
     {
        haval256_5_4way_init( &ctx.haval );
        haval256_5_4way_update( &ctx.haval, vhash, 64 );
        haval256_5_4way_close( &ctx.haval, vhash );
        memset( &vhash[8<<2], 0, 32<<2 );
        rintrlv_4x32_4x64( vhashB, vhash, 512 );
     }

     mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
    
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash0,
                             (const BitSequence *)hash0, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                             (const BitSequence *)hash1, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                             (const BitSequence *)hash2, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                             (const BitSequence *)hash3, 512 );

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
     
     blake512_4way_init( &ctx.blake );
     blake512_4way_update( &ctx.blake, vhash, 64 );
     blake512_4way_close( &ctx.blake, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

// shavite & luffa, both serial, select individually.

   if ( hash0[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash0, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash0 ); //8
   }
   else
   {
      init_luffa( &ctx.luffa, 512 );
      update_and_final_luffa( &ctx.luffa, (BitSequence *)hash0,
                                    (const BitSequence *)hash0, 64 );
   }

   if ( hash1[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash1, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash1 ); //8
   }
   else
   {
      init_luffa( &ctx.luffa, 512 );
      update_and_final_luffa( &ctx.luffa, (BitSequence *)hash1,
                                    (const BitSequence *)hash1, 64 );
   }

   if ( hash2[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash2, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash2 ); //8
   }
   else
   {
      init_luffa( &ctx.luffa, 512 );
      update_and_final_luffa( &ctx.luffa, (BitSequence *)hash2,
                                    (const BitSequence *)hash2, 64 );
   }

   if ( hash3[0] & mask )
   {
      sph_shavite512_init( &ctx.shavite );
      sph_shavite512( &ctx.shavite, hash3, 64 ); //
      sph_shavite512_close( &ctx.shavite, hash3 ); //8
   }
   else
   {
      init_luffa( &ctx.luffa, 512 );
      update_and_final_luffa( &ctx.luffa, (BitSequence *)hash3,
                                    (const BitSequence *)hash3, 64 );
   }

   intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

   hamsi512_4way_init( &ctx.hamsi );
   hamsi512_4way_update( &ctx.hamsi, vhash, 64 );
   hamsi512_4way_close( &ctx.hamsi, vhash );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash0, 64 );
   sph_fugue512_close( &ctx.fugue, hash0 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash1, 64 );
   sph_fugue512_close( &ctx.fugue, hash1 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash2, 64 );
   sph_fugue512_close( &ctx.fugue, hash2 );
   sph_fugue512_init( &ctx.fugue );
   sph_fugue512( &ctx.fugue, hash3, 64 );
   sph_fugue512_close( &ctx.fugue, hash3 );

    // In this situation serial simd seems to be faster.

    intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );
   
    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                   m256_zero );

   if ( hash0[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash0,
                               (const BitSequence *)hash0, 512 );
   }

   else
   {
       init_sd( &ctx.sd, 512 );
       update_final_sd( &ctx.sd, (BitSequence *)hash0,
                             (const BitSequence *)hash0, 512 );
   }

   if ( hash1[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash1,
                               (const BitSequence *)hash1, 512 );
   }

   else
   {
       init_sd( &ctx.sd, 512 );
       update_final_sd( &ctx.sd, (BitSequence *)hash1,
                             (const BitSequence *)hash1, 512 );
   }

   if ( hash2[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash2,
                               (const BitSequence *)hash2, 512 );
   }

   else
   {
       init_sd( &ctx.sd, 512 );
       update_final_sd( &ctx.sd, (BitSequence *)hash2,
                             (const BitSequence *)hash2, 512 );
   }

   if ( hash3[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash3,
                               (const BitSequence *)hash3, 512 );
   }

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

   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash0, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash0 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash1, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash1 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash2, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash2 );
   sph_whirlpool_init( &ctx.whirlpool );
   sph_whirlpool( &ctx.whirlpool, hash3, 64 );
   sph_whirlpool_close( &ctx.whirlpool, hash3 );

// A = fugue serial, B = sha512 prarallel
   
   intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

   vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                 m256_zero );

   if ( hash0[0] & mask ) 
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash0, 64 );
      sph_fugue512_close( &ctx.fugue, hash0 );
   }
   if ( hash1[0] & mask ) 
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash1, 64 );
      sph_fugue512_close( &ctx.fugue, hash1 );
   }
   if ( hash2[0] & mask ) 
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash2, 64 );
      sph_fugue512_close( &ctx.fugue, hash2 );
   }
   if ( hash3[0] & mask ) 
   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash3, 64 );
      sph_fugue512_close( &ctx.fugue, hash3 );
   }

   intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

   if ( mm256_anybits0( vh_mask ) )
   {
      sha512_4way_init( &ctx.sha512 );
      sha512_4way_update( &ctx.sha512, vhash, 64 );
      sha512_4way_close( &ctx.sha512, vhashB );
   }

   mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
   init_groestl( &ctx.groestl, 64 );
   update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

   intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

   sha512_4way_init( &ctx.sha512 ); 
   sha512_4way_update( &ctx.sha512, vhash, 64 );
   sha512_4way_close( &ctx.sha512, vhash ); 

// A = haval parallel, B = Whirlpool serial

   vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                 m256_zero );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

   // 4x32 for haval
   intrlv_4x32_512( vhash, hash0, hash1, hash2, hash3 );

   if ( mm256_anybits1( vh_mask ) )
   {
      haval256_5_4way_init( &ctx.haval );
      haval256_5_4way_update( &ctx.haval, vhash, 64 );
      haval256_5_4way_close( &ctx.haval, vhash );
      memset( &vhash[8<<2], 0, 32<<2 );
      rintrlv_4x32_4x64( vhashA, vhash, 512 );
   }

   if ( !( hash0[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash0, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash0 );
   }
   if ( !( hash1[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash1, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash1 );
   }
   if ( !( hash2[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash2, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash2 );
   }
   if ( !( hash3[0] & mask ) )
   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash3, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash3 );
   }

   intrlv_4x64( vhashB, hash0, hash1, hash2, hash3, 512 );

   mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

   bmw512_4way_init( &ctx.bmw );
   bmw512_4way_update( &ctx.bmw, vhash, 64 );
   bmw512_4way_close( &ctx.bmw, vhash );

 	memcpy(state, vhash, 32<<2 );
}

int scanhash_hmq1725_4way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t hash[16*4] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint32_t *hash7 = &(hash[25]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    const uint32_t last_nonce = max_nonce - 4;
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
    int thr_id = mythr->id; 

    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    do
    {
       *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

       hmq1725_4way_hash( hash, vdata );

       for ( int lane = 0; lane < 4; lane++ )
       if ( unlikely( hash7[ lane<<1 ] <= Htarg ) )
       {
          extr_lane_4x64( lane_hash, hash, lane, 256 );
          if ( likely( fulltest( lane_hash, ptarget ) && !opt_benchmark ) )
          {
             pdata[19] = n + lane;
             submit_lane_solution( work, lane_hash, mythr, lane );
          }
       }
       n += 4;
    } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce;
    return 0;
}

#endif // HMQ1725_4WAY
