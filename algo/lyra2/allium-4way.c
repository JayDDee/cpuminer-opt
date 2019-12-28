#include "lyra2-gate.h"
#include <memory.h>
#include <mm_malloc.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/groestl/aes_ni/hash-groestl256.h"

#if defined (ALLIUM_8WAY)  

typedef struct {
   blake256_8way_context     blake;
   keccak256_8way_context    keccak;
   cube_4way_context          cube;
   skein256_8way_context     skein;
   hashState_groestl256      groestl;
} allium_8way_ctx_holder;

static __thread allium_8way_ctx_holder allium_8way_ctx;

bool init_allium_8way_ctx()
{
   keccak256_8way_init( &allium_8way_ctx.keccak );
   cube_4way_init( &allium_8way_ctx.cube, 256, 16, 32 );
   skein256_8way_init( &allium_8way_ctx.skein );
   init_groestl256( &allium_8way_ctx.groestl, 32 );
   return true;
}

void allium_8way_hash( void *state, const void *input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (128)));
   uint32_t vhashA[8*8] __attribute__ ((aligned (64)));
   uint32_t vhashB[8*8] __attribute__ ((aligned (64)));
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (64)));
   uint32_t hash2[8] __attribute__ ((aligned (64)));
   uint32_t hash3[8] __attribute__ ((aligned (64)));
   uint32_t hash4[8] __attribute__ ((aligned (64)));
   uint32_t hash5[8] __attribute__ ((aligned (64)));
   uint32_t hash6[8] __attribute__ ((aligned (64)));
   uint32_t hash7[8] __attribute__ ((aligned (64)));
   allium_8way_ctx_holder ctx __attribute__ ((aligned (64)));

   memcpy( &ctx, &allium_8way_ctx, sizeof(allium_8way_ctx) );
   blake256_8way_update( &ctx.blake, input + (64<<3), 16 );
   blake256_8way_close( &ctx.blake, vhash );

   rintrlv_8x32_8x64( vhashA, vhash, 256 );
   keccak256_8way_update( &ctx.keccak, vhashA, 32 );
   keccak256_8way_close( &ctx.keccak, vhash );

   dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 vhash, 256 );

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
  
   intrlv_4x128( vhashA, hash0, hash1, hash2, hash3, 256 );
   intrlv_4x128( vhashB, hash4, hash5, hash6, hash7, 256 );

   cube_4way_update_close( &ctx.cube, vhashA, vhashA, 32 );
   cube_4way_init( &ctx.cube, 256, 16, 32 );
   cube_4way_update_close( &ctx.cube, vhashB, vhashB, 32 );

   dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, 256 );
   dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, 256 );

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

   intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                hash7, 256 );

   skein256_8way_update( &ctx.skein, vhash, 32 );
   skein256_8way_close( &ctx.skein, vhash );

   dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 vhash, 256 );

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
   memcpy( &ctx.groestl, &allium_8way_ctx.groestl,
           sizeof(hashState_groestl256) );
}

int scanhash_allium_8way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce - 8;
   const uint32_t Htarg = ptarget[7];
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

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


#elif defined (ALLIUM_4WAY)  


typedef struct {
   blake256_4way_context     blake;
   keccak256_4way_context    keccak;
   cubehashParam             cube;
   skein256_4way_context     skein;
   hashState_groestl256      groestl;

} allium_4way_ctx_holder;

static __thread allium_4way_ctx_holder allium_4way_ctx;

bool init_allium_4way_ctx()
{
   keccak256_4way_init( &allium_4way_ctx.keccak );
   cubehashInit( &allium_4way_ctx.cube, 256, 16, 32 );
   skein256_4way_init( &allium_4way_ctx.skein );
   init_groestl256( &allium_4way_ctx.groestl, 32 );
   return true;
}

void allium_4way_hash( void *state, const void *input )
{
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   uint32_t vhash32[8*4] __attribute__ ((aligned (64)));
   uint32_t vhash64[8*4] __attribute__ ((aligned (64)));
   allium_4way_ctx_holder ctx __attribute__ ((aligned (64))); 

   memcpy( &ctx, &allium_4way_ctx, sizeof(allium_4way_ctx) );
   blake256_4way_update( &ctx.blake, input + (64<<2), 16 );
   blake256_4way_close( &ctx.blake, vhash32 );

   rintrlv_4x32_4x64( vhash64, vhash32, 256 );
   keccak256_4way_update( &ctx.keccak, vhash64, 32 );
   keccak256_4way_close( &ctx.keccak, vhash64 );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   LYRA2RE( hash0, 32, hash0, 32, hash0, 32, 1, 8, 8 );
   LYRA2RE( hash1, 32, hash1, 32, hash1, 32, 1, 8, 8 );
   LYRA2RE( hash2, 32, hash2, 32, hash2, 32, 1, 8, 8 );
   LYRA2RE( hash3, 32, hash3, 32, hash3, 32, 1, 8, 8 );

   cubehashUpdateDigest( &ctx.cube, (byte*)hash0, (const byte*)hash0, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*)hash1, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*)hash2, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*)hash3, 32 );

   LYRA2RE( hash0, 32, hash0, 32, hash0, 32, 1, 8, 8 );
   LYRA2RE( hash1, 32, hash1, 32, hash1, 32, 1, 8, 8 );
   LYRA2RE( hash2, 32, hash2, 32, hash2, 32, 1, 8, 8 );
   LYRA2RE( hash3, 32, hash3, 32, hash3, 32, 1, 8, 8 );

   intrlv_4x64( vhash64, hash0, hash1, hash2, hash3, 256 );

   skein256_4way_update( &ctx.skein, vhash64, 32 );
   skein256_4way_close( &ctx.skein, vhash64 );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   update_and_final_groestl256( &ctx.groestl, state, hash0, 256 );
   memcpy( &ctx.groestl, &allium_4way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+32, hash1, 256 );
   memcpy( &ctx.groestl, &allium_4way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+64, hash2, 256 );
   memcpy( &ctx.groestl, &allium_4way_ctx.groestl,
           sizeof(hashState_groestl256) );
   update_and_final_groestl256( &ctx.groestl, state+96, hash3, 256 );
}

int scanhash_allium_4way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t Htarg = ptarget[7];
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   blake256_4way_init( &allium_4way_ctx.blake );
   blake256_4way( &allium_4way_ctx.blake, vdata, 64 );

   do {
     *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );

     allium_4way_hash( hash, vdata );
     pdata[19] = n;

     for ( int lane = 0; lane < 4; lane++ ) if ( (hash+(lane<<3))[7] <= Htarg )
     {
        if ( fulltest( hash+(lane<<3), ptarget ) && !opt_benchmark )
        {
           pdata[19] = n + lane;
           submit_lane_solution( work, hash+(lane<<3), mythr, lane );
         }
     }
     n += 4;
   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
