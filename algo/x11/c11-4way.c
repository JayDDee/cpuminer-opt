#include "cpuminer-config.h"
#include "c11-gate.h"
#include <string.h>
#include <stdint.h>
#include "algo/blake/blake512-hash.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
  #include "algo/shavite/shavite-hash-4way.h"
  #include "algo/echo/echo-hash-4way.h"
#endif

#if defined (C11_8WAY)

union _c11_8way_context_overlay
{
    blake512_8way_context   blake;
    bmw512_8way_context     bmw;
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    keccak512_8way_context  keccak;
    luffa_4way_context      luffa;
    cube_4way_2buf_context   cube;
#if defined(__VAES__)
    groestl512_4way_context groestl;
    shavite512_4way_context shavite;
    echo_4way_context       echo;
#else
    hashState_groestl       groestl;
    sph_shavite512_context  shavite;
    hashState_echo          echo;
#endif
    simd_4way_context       simd;
} __attribute__ ((aligned (64)));
typedef union _c11_8way_context_overlay c11_8way_context_overlay;

static __thread __m512i c11_8way_midstate[16] __attribute__((aligned(64)));
static __thread blake512_8way_context blake512_8way_ctx __attribute__((aligned(64)));

int c11_8way_hash( void *state, const void *input, int thr_id )
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
     c11_8way_context_overlay ctx;

     blake512_8way_final_le( &blake512_8way_ctx, vhash, casti_m512i( input, 9 ),
                             c11_8way_midstate );

     bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );
     
#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else
     
     dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
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

     // 4 JH
     jh512_8way_init( &ctx.jh );
     jh512_8way_update( &ctx.jh, vhash, 64 );
     jh512_8way_close( &ctx.jh, vhash );

     // 5 Keccak
     keccak512_8way_init( &ctx.keccak );
     keccak512_8way_update( &ctx.keccak, vhash, 64 );
     keccak512_8way_close( &ctx.keccak, vhash );

     // 6 Skein
     skein512_8way_full( &ctx.skein, vhash, vhash, 64 );

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     luffa512_4way_full( &ctx.luffa, vhashA, vhashA, 64 );
     luffa512_4way_full( &ctx.luffa, vhashB, vhashB, 64 );

     cube_4way_2buf_full( &ctx.cube, vhashA, vhashB, 512, vhashA, vhashB, 64 );
     
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

     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhashA );
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhashB );

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

#endif

     memcpy( state,     hash0, 32 );
     memcpy( state+ 32, hash1, 32 );
     memcpy( state+ 64, hash2, 32 );
     memcpy( state+ 96, hash3, 32 );
     memcpy( state+128, hash4, 32 );
     memcpy( state+160, hash5, 32 );
     memcpy( state+192, hash6, 32 );
     memcpy( state+224, hash7, 32 );

     return 1;
}

int scanhash_c11_8way( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   __m128i edata[5] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32_d7 = ptarget[7];
   const __m512i eight = _mm512_set1_epi64( 8 );
   const bool bench = opt_benchmark;

   edata[0] = v128_swap64_32( casti_v128u32( pdata, 0 ) );
   edata[1] = v128_swap64_32( casti_v128u32( pdata, 1 ) );
   edata[2] = v128_swap64_32( casti_v128u32( pdata, 2 ) );
   edata[3] = v128_swap64_32( casti_v128u32( pdata, 3 ) );
   edata[4] = v128_swap64_32( casti_v128u32( pdata, 4 ) );

   mm512_intrlv80_8x64( vdata, edata );
   *noncev = _mm512_add_epi32( *noncev, _mm512_set_epi32(
                            0, 7, 0, 6, 0, 5, 0, 4, 0, 3, 0, 2, 0, 1, 0, 0 ) );
   blake512_8way_prehash_le( &blake512_8way_ctx, c11_8way_midstate, vdata );

   do
   {
      if ( likely( c11_8way_hash( hash, vdata, thr_id ) ) )
      for ( int lane = 0; lane < 8; lane++ )
      if ( ( ( hash + ( lane << 3 ) )[7] <= targ32_d7 )
           && valid_hash( hash +( lane << 3 ), ptarget ) && !bench )
      {
         pdata[19] = n + lane;
         submit_solution( work, hash + ( lane << 3 ), mythr );
      }
      *noncev = _mm512_add_epi32( *noncev, eight );
      n += 8;
   } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}
     
#elif defined (C11_4WAY)

union _c11_4way_context_overlay
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
};
typedef union _c11_4way_context_overlay c11_4way_context_overlay;

static __thread __m256i c11_4way_midstate[16] __attribute__((aligned(64)));
static __thread blake512_4way_context blake512_4way_ctx __attribute__((aligned(64)));

int c11_4way_hash( void *state, const void *input, int thr_id )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     uint64_t vhashA[8*2] __attribute__ ((aligned (64)));
     uint64_t vhashB[8*2] __attribute__ ((aligned (64)));
     c11_4way_context_overlay ctx;

     blake512_4way_final_le( &blake512_4way_ctx, vhash, casti_m256i( input, 9 ),
                             c11_4way_midstate );

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
     
     jh512_4way_init( &ctx.jh );
     jh512_4way_update( &ctx.jh, vhash, 64 );
     jh512_4way_close( &ctx.jh, vhash );

     keccak512_4way_init( &ctx.keccak );
     keccak512_4way_update( &ctx.keccak, vhash, 64 );
     keccak512_4way_close( &ctx.keccak, vhash );

     skein512_4way_full( &ctx.skein, vhash, vhash, 64 );

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

     dintrlv_2x128_512( hash0, hash1, vhashA );
     dintrlv_2x128_512( hash2, hash3, vhashB );

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

#endif

     memcpy( state,    hash0, 32 );
     memcpy( state+32, hash1, 32 );
     memcpy( state+64, hash2, 32 );
     memcpy( state+96, hash3, 32 );

     return 1;
}

int scanhash_c11_4way( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (128)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   __m128i edata[5] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m256i  *noncev = (__m256i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32_d7 = ptarget[7];
   const __m256i four = _mm256_set1_epi64x( 4 );
   const bool bench = opt_benchmark;

   edata[0] = v128_swap64_32( casti_v128u32( pdata, 0 ) );
   edata[1] = v128_swap64_32( casti_v128u32( pdata, 1 ) );
   edata[2] = v128_swap64_32( casti_v128u32( pdata, 2 ) );
   edata[3] = v128_swap64_32( casti_v128u32( pdata, 3 ) );
   edata[4] = v128_swap64_32( casti_v128u32( pdata, 4 ) );

   mm256_intrlv80_4x64( vdata, edata );

   *noncev = _mm256_add_epi32( *noncev, _mm256_set_epi32(
                                           0, 3, 0, 2, 0, 1, 0, 0 ) );
   blake512_4way_prehash_le( &blake512_4way_ctx, c11_4way_midstate, vdata );

   do
   {
      if ( likely( c11_4way_hash( hash, vdata, thr_id ) ) )
      for ( int lane = 0; lane < 4; lane++ )
      if ( ( ( hash + ( lane << 3 ) )[7] <= targ32_d7 )
           && valid_hash( hash +( lane << 3 ), ptarget ) && !bench )
      {
         pdata[19] = n + lane;
         submit_solution( work, hash + ( lane << 3 ), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev, four );
      n += 4;
   } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
