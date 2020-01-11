#include "lyra2-gate.h"
#include <memory.h>
#include <mm_malloc.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/groestl/aes_ni/hash-groestl256.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl256-hash-4way.h"
#endif

#if defined (ALLIUM_16WAY)  

typedef struct {
   blake256_16way_context     blake;
   keccak256_8way_context    keccak;
   cube_4way_context          cube;
   skein256_8way_context     skein;
#if defined(__VAES__)
   groestl256_4way_context groestl;
#else
   hashState_groestl256      groestl;
#endif
} allium_16way_ctx_holder;

static __thread allium_16way_ctx_holder allium_16way_ctx;

bool init_allium_16way_ctx()
{
   keccak256_8way_init( &allium_16way_ctx.keccak );
   cube_4way_init( &allium_16way_ctx.cube, 256, 16, 32 );
   skein256_8way_init( &allium_16way_ctx.skein );
#if defined(__VAES__)
   groestl256_4way_init( &allium_16way_ctx.groestl, 32 );
#else
   init_groestl256( &allium_16way_ctx.groestl, 32 );
#endif
   return true;
}

void allium_16way_hash( void *state, const void *input )
{
   uint32_t vhash[16*8] __attribute__ ((aligned (128)));
   uint32_t vhashA[16*8] __attribute__ ((aligned (64)));
   uint32_t vhashB[16*8] __attribute__ ((aligned (64)));
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (64)));
   uint32_t hash2[8] __attribute__ ((aligned (64)));
   uint32_t hash3[8] __attribute__ ((aligned (64)));
   uint32_t hash4[8] __attribute__ ((aligned (64)));
   uint32_t hash5[8] __attribute__ ((aligned (64)));
   uint32_t hash6[8] __attribute__ ((aligned (64)));
   uint32_t hash7[8] __attribute__ ((aligned (64)));
   uint32_t hash8[8] __attribute__ ((aligned (64)));
   uint32_t hash9[8] __attribute__ ((aligned (64)));
   uint32_t hash10[8] __attribute__ ((aligned (64)));
   uint32_t hash11[8] __attribute__ ((aligned (64)));
   uint32_t hash12[8] __attribute__ ((aligned (64)));
   uint32_t hash13[8] __attribute__ ((aligned (64)));
   uint32_t hash14[8] __attribute__ ((aligned (64)));
   uint32_t hash15[8] __attribute__ ((aligned (64)));
   allium_16way_ctx_holder ctx __attribute__ ((aligned (64)));

   memcpy( &ctx, &allium_16way_ctx, sizeof(allium_16way_ctx) );
   blake256_16way_update( &ctx.blake, input + (64<<4), 16 );
   blake256_16way_close( &ctx.blake, vhash );

   dintrlv_16x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  hash8, hash9, hash10, hash11, hash12, hash13, hash14, hash15,
                  vhash, 256 );
   intrlv_8x64( vhashA, hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                256 );
   intrlv_8x64( vhashB, hash8, hash9, hash10, hash11, hash12, hash13, hash14,
                hash15, 256 );
   
//   rintrlv_8x32_8x64( vhashA, vhash, 256 );
   keccak256_8way_update( &ctx.keccak, vhashA, 32 );
   keccak256_8way_close( &ctx.keccak, vhashA);
   keccak256_8way_init( &ctx.keccak );
   keccak256_8way_update( &ctx.keccak, vhashB, 32 );
   keccak256_8way_close( &ctx.keccak, vhashB);

   dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 vhashA, 256 );
   dintrlv_8x64( hash8, hash9, hash10, hash11, hash12, hash13, hash14, hash15,
                 vhashB, 256 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );
   intrlv_2x256( vhash, hash8, hash9, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash8, hash9, vhash, 256 );
   intrlv_2x256( vhash, hash10, hash11, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash10, hash11, vhash, 256 );
   intrlv_2x256( vhash, hash12, hash13, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash12, hash13, vhash, 256 );
   intrlv_2x256( vhash, hash14, hash15, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash14, hash15, vhash, 256 );
  
   intrlv_4x128( vhashA, hash0, hash1, hash2, hash3, 256 );
   intrlv_4x128( vhashB, hash4, hash5, hash6, hash7, 256 );

   cube_4way_update_close( &ctx.cube, vhashA, vhashA, 32 );
   cube_4way_init( &ctx.cube, 256, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashB, vhashB, 32 );

   dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, 256 );
   dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, 256 );

   intrlv_4x128( vhashA, hash8, hash9, hash10, hash11, 256 );
   intrlv_4x128( vhashB, hash12, hash13, hash14, hash15, 256 );

   cube_4way_init( &ctx.cube, 256, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashA, vhashA, 32 );
   cube_4way_init( &ctx.cube, 256, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashB, vhashB, 32 );

   dintrlv_4x128( hash8, hash9, hash10, hash11, vhashA, 256 );
   dintrlv_4x128( hash12, hash13, hash14, hash15, vhashB, 256 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );
   intrlv_2x256( vhash, hash8, hash9, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash8, hash9, vhash, 256 );
   intrlv_2x256( vhash, hash10, hash11, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash10, hash11, vhash, 256 );
   intrlv_2x256( vhash, hash12, hash13, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash12, hash13, vhash, 256 );
   intrlv_2x256( vhash, hash14, hash15, 256 );
   LYRA2RE_2WAY( vhash, 32, vhash, 32, 1, 8, 8 );
   dintrlv_2x256( hash14, hash15, vhash, 256 );

   intrlv_8x64( vhashA, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                hash7, 256 );
   intrlv_8x64( vhashB, hash8, hash9, hash10, hash11, hash12, hash13, hash14,
                hash15, 256 );

   skein256_8way_update( &ctx.skein, vhashA, 32 );
   skein256_8way_close( &ctx.skein, vhashA );
   skein256_8way_init( &ctx.skein );
   skein256_8way_update( &ctx.skein, vhashB, 32 );
   skein256_8way_close( &ctx.skein, vhashB );


   dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 vhashA, 256 );
   dintrlv_8x64( hash8, hash9, hash10, hash11, hash12, hash13, hash14, hash15,
                 vhashB, 256 );

#if defined(__VAES__)

   intrlv_4x128( vhash, hash0, hash1, hash2, hash3, 256 );

   groestl256_4way_update_close( &ctx.groestl, vhash, vhash, 256 );

   dintrlv_4x128( state, state+32, state+64, state+96, vhash, 256 );
   intrlv_4x128( vhash, hash4, hash5, hash6, hash7, 256 );

   groestl256_4way_init( &ctx.groestl, 32 );
   groestl256_4way_update_close( &ctx.groestl, vhash, vhash, 256 );
   
   dintrlv_4x128( state+128, state+160, state+192, state+224, vhash, 256 );
   intrlv_4x128( vhash, hash8, hash9, hash10, hash11, 256 );

   groestl256_4way_init( &ctx.groestl, 32 );
   groestl256_4way_update_close( &ctx.groestl, vhash, vhash, 256 );

   dintrlv_4x128( state+256, state+288, state+320, state+352, vhash, 256 );
   intrlv_4x128( vhash, hash12, hash13, hash14, hash15, 256 );

   groestl256_4way_init( &ctx.groestl, 32 );
   groestl256_4way_update_close( &ctx.groestl, vhash, vhash, 256 );
 
   dintrlv_4x128( state+384, state+416, state+448, state+480, vhash, 256 );
   
#else

   update_and_final_groestl256( &ctx.groestl, state, hash0, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+32, hash1, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+64, hash2, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+96, hash3, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+128, hash4, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+160, hash5, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+192, hash6, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+224, hash7, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+256, hash8, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+288, hash9, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+320, hash10, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+352, hash11, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+384, hash12, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+416, hash13, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+448, hash14, 256 );
   memcpy( &ctx.groestl, &allium_16way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+480, hash15, 256 );

#endif
}

int scanhash_allium_16way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*16] __attribute__ ((aligned (128)));
   uint32_t vdata[20*16] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce - 8;
   const uint32_t Htarg = ptarget[7];
   __m512i  *noncev = (__m512i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm512_bswap32_intrlv80_16x32( vdata, pdata );
   blake256_16way_init( &allium_16way_ctx.blake );
   blake256_16way_update( &allium_16way_ctx.blake, vdata, 64 );

   do {
     *noncev = mm512_bswap_32( _mm512_set_epi32( n+15, n+14, n+13, n+12,
                                                 n+11, n+10, n+ 9, n+ 8,
                                                 n+ 7, n+ 6, n+ 5, n+ 4,
                                                 n+ 3, n+ 2, n +1, n ) );

     allium_16way_hash( hash, vdata );
     pdata[19] = n;

     for ( int lane = 0; lane < 16; lane++ ) if ( (hash+(lane<<3))[7] <= Htarg )
     {
        if ( fulltest( hash+(lane<<3), ptarget ) && !opt_benchmark )
        {
           pdata[19] = n + lane;
           submit_lane_solution( work, hash+(lane<<3), mythr, lane );
         }
     }
     n += 16;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (ALLIUM_8WAY)  

typedef struct {
   blake256_8way_context     blake;
   keccak256_4way_context    keccak;
   cubehashParam             cube;
   skein256_4way_context     skein;
   hashState_groestl256      groestl;

} allium_8way_ctx_holder;

static __thread allium_8way_ctx_holder allium_8way_ctx;

bool init_allium_8way_ctx()
{
   keccak256_4way_init( &allium_8way_ctx.keccak );
   cubehashInit( &allium_8way_ctx.cube, 256, 16, 32 );
   skein256_4way_init( &allium_8way_ctx.skein );
   init_groestl256( &allium_8way_ctx.groestl, 32 );
   return true;
}

void allium_8way_hash( void *state, const void *input )
{
   uint32_t vhashA[8*8] __attribute__ ((aligned (64)));
   uint32_t vhashB[8*8] __attribute__ ((aligned (64)));
   uint32_t hash0[8] __attribute__ ((aligned (32)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   uint32_t hash4[8] __attribute__ ((aligned (64)));
   uint32_t hash5[8] __attribute__ ((aligned (32)));
   uint32_t hash6[8] __attribute__ ((aligned (32)));
   uint32_t hash7[8] __attribute__ ((aligned (32)));
   allium_8way_ctx_holder ctx __attribute__ ((aligned (64))); 

   memcpy( &ctx, &allium_8way_ctx, sizeof(allium_8way_ctx) );
   blake256_8way_update( &ctx.blake, input + (64<<3), 16 );
   blake256_8way_close( &ctx.blake, vhashA );

   dintrlv_8x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                     vhashA, 256 );
   intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 256 );
   intrlv_4x64( vhashB, hash4, hash5, hash6, hash7, 256 );

   keccak256_4way_update( &ctx.keccak, vhashA, 32 );
   keccak256_4way_close( &ctx.keccak, vhashA );
   keccak256_4way_init( &ctx.keccak );
   keccak256_4way_update( &ctx.keccak, vhashB, 32 );
   keccak256_4way_close( &ctx.keccak, vhashB );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhashA, 256 );
   dintrlv_4x64( hash4, hash5, hash6, hash7, vhashB, 256 );

   LYRA2RE( hash0, 32, hash0, 32, hash0, 32, 1, 8, 8 );
   LYRA2RE( hash1, 32, hash1, 32, hash1, 32, 1, 8, 8 );
   LYRA2RE( hash2, 32, hash2, 32, hash2, 32, 1, 8, 8 );
   LYRA2RE( hash3, 32, hash3, 32, hash3, 32, 1, 8, 8 );
   LYRA2RE( hash4, 32, hash4, 32, hash4, 32, 1, 8, 8 );
   LYRA2RE( hash5, 32, hash5, 32, hash5, 32, 1, 8, 8 );
   LYRA2RE( hash6, 32, hash6, 32, hash6, 32, 1, 8, 8 );
   LYRA2RE( hash7, 32, hash7, 32, hash7, 32, 1, 8, 8 );

   cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*)hash0, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*)hash1, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*)hash2, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*)hash3, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash4, (const byte*)hash4, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash5, (const byte*)hash5, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash6, (const byte*)hash6, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash7, (const byte*)hash7, 32 );

   LYRA2RE( hash0, 32, hash0, 32, hash0, 32, 1, 8, 8 );
   LYRA2RE( hash1, 32, hash1, 32, hash1, 32, 1, 8, 8 );
   LYRA2RE( hash2, 32, hash2, 32, hash2, 32, 1, 8, 8 );
   LYRA2RE( hash3, 32, hash3, 32, hash3, 32, 1, 8, 8 );
   LYRA2RE( hash4, 32, hash4, 32, hash4, 32, 1, 8, 8 );
   LYRA2RE( hash5, 32, hash5, 32, hash5, 32, 1, 8, 8 );
   LYRA2RE( hash6, 32, hash6, 32, hash6, 32, 1, 8, 8 );
   LYRA2RE( hash7, 32, hash7, 32, hash7, 32, 1, 8, 8 );

   intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 256 );
   intrlv_4x64( vhashB, hash4, hash5, hash6, hash7, 256 );

   skein256_4way_update( &ctx.skein, vhashA, 32 );
   skein256_4way_close( &ctx.skein, vhashA );
   skein256_4way_init( &ctx.skein );
   skein256_4way_update( &ctx.skein, vhashB, 32 );
   skein256_4way_close( &ctx.skein, vhashB );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhashA, 256 );
   dintrlv_4x64( hash4, hash5, hash6, hash7, vhashB, 256 );

   update_and_final_groestl256( &ctx.groestl, state, hash0, 256 );
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+32, hash1, 256 );
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+64, hash2, 256 );
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+96, hash3, 256 );
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+128, hash4, 256 );
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+160, hash5, 256 );
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+192, hash6, 256 );
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+224, hash7, 256 );
}

int scanhash_allium_8way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (64)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   const uint32_t Htarg = ptarget[7];
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   blake256_8way_init( &allium_8way_ctx.blake );
   blake256_8way_update( &allium_8way_ctx.blake, vdata, 64 );

   do {
     *noncev = mm256_bswap_32( _mm256_set_epi32( n+7, n+6, n+5, n+4,
                                                 n+3, n+2, n+1, n ) );

     allium_8way_hash( hash, vdata );
     pdata[19] = n;

     for ( int lane = 0; lane < 8; lane++ ) if ( (hash+(lane<<3))[7] <= Htarg )
     {
        if ( fulltest( hash+(lane<<3), ptarget ) && !opt_benchmark )
        {
           pdata[19] = n + lane;
           submit_lane_solution( work, hash+(lane<<3), mythr, lane );
         }
     }
     n += 8;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce;
   return 0;
}

#endif
