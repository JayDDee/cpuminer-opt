#include "hmq1725-gate.h"

#if defined(HMQ1725_4WAY)

#include <string.h>
#include <stdint.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa_for_sse2.h"
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
    hashState_sd            simd;
    hashState_echo          echo;
    hamsi512_4way_context   hamsi;
    sph_fugue512_context    fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
    haval256_5_4way_context haval;
};
typedef union _hmq1725_4way_context_overlay hmq1725_4way_context_overlay;

extern void hmq1725_4way_hash(void *state, const void *input)
{
// why so big? only really need 16.
     uint32_t hash0 [32]    __attribute__ ((aligned (64)));
     uint32_t hash1 [32]    __attribute__ ((aligned (64)));
     uint32_t hash2 [32]    __attribute__ ((aligned (64)));
     uint32_t hash3 [32]    __attribute__ ((aligned (64)));
     uint32_t vhash [32<<2] __attribute__ ((aligned (64)));
     uint32_t vhashA[32<<2] __attribute__ ((aligned (64)));
     uint32_t vhashB[32<<2] __attribute__ ((aligned (64)));
     hmq1725_4way_context_overlay ctx __attribute__ ((aligned (64)));
     __m256i vh_mask;     
     const __m256i vmask = m256_const1_64( 24 );
     const uint32_t mask = 24;
     __m256i* vh  = (__m256i*)vhash;
     __m256i* vhA = (__m256i*)vhashA;
     __m256i* vhB = (__m256i*)vhashB;

     bmw512_4way_init( &ctx.bmw );
     bmw512_4way( &ctx.bmw, input, 80 );
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

//     if ( hash0[0] & mask )
//     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                               (char*)hash0, 512 );
//     }
//     if ( hash1[0] & mask )
//     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                               (char*)hash1, 512 );
//     }
//     if ( hash2[0] & mask )
//     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                               (char*)hash2, 512 );
//     }
//     if ( hash3[0] & mask )
//     {
       init_groestl( &ctx.groestl, 64 );
       update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                               (char*)hash3, 512 );
//     }

     intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

// B

//     if ( mm256_any_clr_256( vh_mask ) )
//     {
       skein512_4way_init( &ctx.skein );
       skein512_4way( &ctx.skein, vhash, 64 );
       skein512_4way_close( &ctx.skein, vhashB );
//     }

     mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

     jh512_4way_init( &ctx.jh );
     jh512_4way( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

// second fork, A = blake parallel, B= bmw parallel.
    
     vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                   m256_zero );

//     if ( mm256_any_set_256( vh_mask ) )
//     {
       blake512_4way_init( &ctx.blake );
       blake512_4way( &ctx.blake, vhash, 64 );
       blake512_4way_close( &ctx.blake, vhashA );
//     }

//     if ( mm256_any_clr_256( vh_mask ) )
//     {
       bmw512_4way_init( &ctx.bmw );
       bmw512_4way( &ctx.bmw, vhash, 64 );
       bmw512_4way_close( &ctx.bmw, vhashB );
//     }

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

//     if ( mm256_any_set_256( vh_mask ) )
//     {
        keccak512_4way_init( &ctx.keccak );
        keccak512_4way( &ctx.keccak, vhash, 64 );
        keccak512_4way_close( &ctx.keccak, vhashA );
//     }

//     if ( mm256_any_clr_256( vh_mask ) )
//     {
        jh512_4way_init( &ctx.jh );
        jh512_4way( &ctx.jh, vhash, 64 );
        jh512_4way_close( &ctx.jh, vhashB );
//     }

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

     init_sd( &ctx.simd, 512 );
     update_final_sd( &ctx.simd, (BitSequence *)hash0,
                           (const BitSequence *)hash0, 512 );
     init_sd( &ctx.simd, 512 );
     update_final_sd( &ctx.simd, (BitSequence *)hash1,
                           (const BitSequence *)hash1, 512 );
     init_sd( &ctx.simd, 512 );
     update_final_sd( &ctx.simd, (BitSequence *)hash2,
                           (const BitSequence *)hash2, 512 );
     init_sd( &ctx.simd, 512 );
     update_final_sd( &ctx.simd, (BitSequence *)hash3,
                           (const BitSequence *)hash3, 512 );

// A is whirlpool serial, B is haval parallel.
    

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

     vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                   m256_zero );
     // A
    
//     if ( hash0[0] & mask )
//     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash0, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash0 );
//     }
//     if ( hash1[0] & mask )
//     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash1, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash1 );
//     }
//     if ( hash2[0] & mask )
//     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash2, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash2 );
//     }
//     if ( hash3[0] & mask )
//     {
        sph_whirlpool_init( &ctx.whirlpool );
        sph_whirlpool( &ctx.whirlpool, hash3, 64 );
        sph_whirlpool_close( &ctx.whirlpool, hash3 );
//     }

     intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

// B

//     if ( mm256_any_clr_256( vh_mask ) )
//     {
        haval256_5_4way_init( &ctx.haval );
        haval256_5_4way( &ctx.haval, vhash, 64 );
        haval256_5_4way_close( &ctx.haval, vhashB );
        memset( &vhashB[8<<2], 0, 32<<2);
//     }

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
     blake512_4way( &ctx.blake, vhash, 64 );
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
   hamsi512_4way( &ctx.hamsi, vhash, 64 );
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


//  A echo, B sd both serial
   
   if ( hash0[0] & mask ) //4
   {
       init_echo( &ctx.echo, 512 );
       update_final_echo( &ctx.echo, (BitSequence *)hash0,
                               (const BitSequence *)hash0, 512 );
   }
   else
   {
       init_sd( &ctx.simd, 512 );
       update_final_sd( &ctx.simd, (BitSequence *)hash0,
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
       init_sd( &ctx.simd, 512 );
       update_final_sd( &ctx.simd, (BitSequence *)hash1,
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
       init_sd( &ctx.simd, 512 );
       update_final_sd( &ctx.simd, (BitSequence *)hash2,
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
       init_sd( &ctx.simd, 512 );
       update_final_sd( &ctx.simd, (BitSequence *)hash3,
                             (const BitSequence *)hash3, 512 );
   }

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );

   shabal512_4way_init( &ctx.shabal );
   shabal512_4way( &ctx.shabal, vhash, 64 );
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

//   if ( hash0[0] & mask ) 
//   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash0, 64 );
      sph_fugue512_close( &ctx.fugue, hash0 );
//   }
//   if ( hash1[0] & mask ) 
//   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash1, 64 );
      sph_fugue512_close( &ctx.fugue, hash1 );
//   }
//   if ( hash2[0] & mask ) 
//   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash2, 64 );
      sph_fugue512_close( &ctx.fugue, hash2 );
//   }
//   if ( hash3[0] & mask ) 
//   {
      sph_fugue512_init( &ctx.fugue );
      sph_fugue512( &ctx.fugue, hash3, 64 );
      sph_fugue512_close( &ctx.fugue, hash3 );
//   }

   intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

//   if ( mm256_any_clr_256( vh_mask ) )
//   {
      sha512_4way_init( &ctx.sha512 );
      sha512_4way( &ctx.sha512, vhash, 64 );
      sha512_4way_close( &ctx.sha512, vhashB );
//   }

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
   sha512_4way( &ctx.sha512, vhash, 64 );
   sha512_4way_close( &ctx.sha512, vhash ); 

// A = haval parallel, B = Whirlpool serial

   vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], vmask ),
                                 m256_zero );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
     
//   if ( mm256_any_set_256( vh_mask ) ) //4
//   {
      haval256_5_4way_init( &ctx.haval );
      haval256_5_4way( &ctx.haval, vhash, 64 );
      haval256_5_4way_close( &ctx.haval, vhashA );
      memset( &vhashA[8<<2], 0, 32<<2 );
//   }

//   if ( !( hash0[0] & mask ) )
//   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash0, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash0 );
//   }
//   if ( !( hash2[0] & mask ) )
//   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash1, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash1 );
//   }
//   if ( !( hash2[0] & mask ) )
//   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash2, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash2 );
//   }
//   if ( !( hash3[0] & mask ) )
//   {
      sph_whirlpool_init( &ctx.whirlpool );
      sph_whirlpool( &ctx.whirlpool, hash3, 64 );
      sph_whirlpool_close( &ctx.whirlpool, hash3 );
//   }

   intrlv_4x64( vhashB, hash0, hash1, hash2, hash3, 512 );

   mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

   bmw512_4way_init( &ctx.bmw );
   bmw512_4way( &ctx.bmw, vhash, 64 );
   bmw512_4way_close( &ctx.bmw, vhash );

 	memcpy(state, vhash, 32<<2 );
}

int scanhash_hmq1725_4way( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
//   uint32_t *hash7 = &(hash[25]);
//   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19] - 1;
   const uint32_t first_nonce = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated
   const uint32_t Htarg = ptarget[7];
   uint64_t htmax[] = {          0,        0xF,       0xFF,
                             0xFFF,     0xFFFF, 0x10000000  };
   uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                        0xFFFFF000, 0xFFFF0000,          0  };

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   for ( int m = 0; m < 6; m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[ m ];
      do
      {
         *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                 _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );
         hmq1725_4way_hash( hash, vdata );
         for ( int i = 0; i < 4; i++ )
         if ( ( (hash+(i<<3))[7] & mask ) == 0 )
         {
            if ( fulltest( (hash+(i<<3)), ptarget ) && !opt_benchmark )
            {
               pdata[19] = n + i;
               submit_lane_solution( work, (hash+(i<<3)), mythr, i );
            }
         }
	      n += 4;
      } while ( ( n < max_nonce-4 ) && !work_restart[thr_id].restart );	
	   break;
	}
	*hashes_done = n - first_nonce + 1;
	return 0;
}

#endif // HMQ1725_4WAY
