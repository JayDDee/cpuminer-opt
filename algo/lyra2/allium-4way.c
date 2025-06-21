#include "lyra2-gate.h"
#include <memory.h>
#include "algo/blake/blake256-hash.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/groestl/aes_ni/hash-groestl256.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl256-hash-4way.h"
#endif
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#if !defined(__AES__) // && !defined(__ARM_FEATURE_AES) )
 #include "algo/groestl/sph_groestl.h"
#endif

#if defined(SIMD512)
  #define ALLIUM_16WAY 1
#elif defined(__AVX2__)
  #define ALLIUM_8WAY 1
#elif defined(__SSE2__) || defined(__ARM_NEON)
  #define ALLIUM_4WAY 1
#endif

#if defined (ALLIUM_16WAY)  

typedef union {
   keccak256_8x64_context    keccak;
   cube_4way_2buf_context    cube;
   skein256_8x64_context     skein;
#if defined(__VAES__)
   groestl256_4way_context   groestl;
#else
   hashState_groestl256      groestl;
#endif
} allium_16way_ctx_holder;

static void allium_16way_hash( void *state, const void *midstate_vars, 
                               const void *midhash, const void *block )
{
   uint32_t vhash[16*8] __attribute__ ((aligned (128)));
   uint32_t vhashA[16*8] __attribute__ ((aligned (64)));
   uint32_t vhashB[16*8] __attribute__ ((aligned (64)));
   uint32_t hash0[8] __attribute__ ((aligned (32)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   uint32_t hash4[8] __attribute__ ((aligned (32)));
   uint32_t hash5[8] __attribute__ ((aligned (32)));
   uint32_t hash6[8] __attribute__ ((aligned (32)));
   uint32_t hash7[8] __attribute__ ((aligned (32)));
   uint32_t hash8[8] __attribute__ ((aligned (32)));
   uint32_t hash9[8] __attribute__ ((aligned (32)));
   uint32_t hash10[8] __attribute__ ((aligned (32)));
   uint32_t hash11[8] __attribute__ ((aligned (32)));
   uint32_t hash12[8] __attribute__ ((aligned (32)));
   uint32_t hash13[8] __attribute__ ((aligned (32)));
   uint32_t hash14[8] __attribute__ ((aligned (32)));
   uint32_t hash15[8] __attribute__ ((aligned (32)));
   allium_16way_ctx_holder ctx __attribute__ ((aligned (64)));

   blake256_16x32_final_rounds_le( vhash, midstate_vars, midhash, block, 14 );

   dintrlv_16x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  hash8, hash9, hash10, hash11, hash12, hash13, hash14, hash15,
                  vhash, 256 );
   intrlv_8x64( vhashA, hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                256 );
   intrlv_8x64( vhashB, hash8, hash9, hash10, hash11, hash12, hash13, hash14,
                hash15, 256 );
   
   keccak256_8x64_init( &ctx.keccak );
   keccak256_8x64_update( &ctx.keccak, vhashA, 32 );
   keccak256_8x64_close( &ctx.keccak, vhashA);
   keccak256_8x64_init( &ctx.keccak );
   keccak256_8x64_update( &ctx.keccak, vhashB, 32 );
   keccak256_8x64_close( &ctx.keccak, vhashB);

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

   cube_4way_2buf_full( &ctx.cube, vhashA, vhashB, 256, vhashA, vhashB, 32 );

   dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, 256 );
   dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, 256 );

   intrlv_4x128( vhashA, hash8, hash9, hash10, hash11, 256 );
   intrlv_4x128( vhashB, hash12, hash13, hash14, hash15, 256 );

   cube_4way_2buf_full( &ctx.cube, vhashA, vhashB, 256, vhashA, vhashB, 32 );

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

   skein256_8x64_init( &ctx.skein );
   skein256_8x64_update( &ctx.skein, vhashA, 32 );
   skein256_8x64_close( &ctx.skein, vhashA );
   skein256_8x64_init( &ctx.skein );
   skein256_8x64_update( &ctx.skein, vhashB, 32 );
   skein256_8x64_close( &ctx.skein, vhashB );

   dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 vhashA, 256 );
   dintrlv_8x64( hash8, hash9, hash10, hash11, hash12, hash13, hash14, hash15,
                 vhashB, 256 );

#if defined(__VAES__)

   intrlv_4x128( vhash, hash0, hash1, hash2, hash3, 256 );
   groestl256_4way_full( &ctx.groestl, vhash, vhash, 32 );
   dintrlv_4x128( state, state+32, state+64, state+96, vhash, 256 );

   intrlv_4x128( vhash, hash4, hash5, hash6, hash7, 256 );
   groestl256_4way_full( &ctx.groestl, vhash, vhash, 32 );
   dintrlv_4x128( state+128, state+160, state+192, state+224, vhash, 256 );

   intrlv_4x128( vhash, hash8, hash9, hash10, hash11, 256 );
   groestl256_4way_full( &ctx.groestl, vhash, vhash, 32 );
   dintrlv_4x128( state+256, state+288, state+320, state+352, vhash, 256 );

   intrlv_4x128( vhash, hash12, hash13, hash14, hash15, 256 );
   groestl256_4way_full( &ctx.groestl, vhash, vhash, 32 );
   dintrlv_4x128( state+384, state+416, state+448, state+480, vhash, 256 );
   
#else

   groestl256_full( &ctx.groestl, state,     hash0,  256 );
   groestl256_full( &ctx.groestl, state+32,  hash1,  256 );
   groestl256_full( &ctx.groestl, state+64,  hash2,  256 );
   groestl256_full( &ctx.groestl, state+96,  hash3,  256 );
   groestl256_full( &ctx.groestl, state+128, hash4,  256 );
   groestl256_full( &ctx.groestl, state+160, hash5,  256 );
   groestl256_full( &ctx.groestl, state+192, hash6,  256 );
   groestl256_full( &ctx.groestl, state+224, hash7,  256 );
   groestl256_full( &ctx.groestl, state+256, hash8,  256 );
   groestl256_full( &ctx.groestl, state+288, hash9,  256 );
   groestl256_full( &ctx.groestl, state+320, hash10, 256 );
   groestl256_full( &ctx.groestl, state+352, hash11, 256 );
   groestl256_full( &ctx.groestl, state+384, hash12, 256 );
   groestl256_full( &ctx.groestl, state+416, hash13, 256 );
   groestl256_full( &ctx.groestl, state+448, hash14, 256 );
   groestl256_full( &ctx.groestl, state+480, hash15, 256 );

#endif
}

int scanhash_allium_16way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*16] __attribute__ ((aligned (128)));
   uint32_t midstate_vars[16*16] __attribute__ ((aligned (64)));
   __m512i block0_hash[8] __attribute__ ((aligned (64)));
   __m512i block_buf[16] __attribute__ ((aligned (64)));
   uint32_t phash[8] __attribute__ ((aligned (32))) = 
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce - 16;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const __m512i sixteen = _mm512_set1_epi32( 16 );

   if ( bench ) ( (uint32_t*)ptarget )[7] = 0x0000ff;

   // Prehash first block.
   blake256_transform_le( phash, pdata, 512, 0, 14 );

   // Interleave hash for second block prehash.
   block0_hash[0] = _mm512_set1_epi32( phash[0] );
   block0_hash[1] = _mm512_set1_epi32( phash[1] );
   block0_hash[2] = _mm512_set1_epi32( phash[2] );
   block0_hash[3] = _mm512_set1_epi32( phash[3] );
   block0_hash[4] = _mm512_set1_epi32( phash[4] );
   block0_hash[5] = _mm512_set1_epi32( phash[5] );
   block0_hash[6] = _mm512_set1_epi32( phash[6] );
   block0_hash[7] = _mm512_set1_epi32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[ 0] = _mm512_set1_epi32( pdata[16] );
   block_buf[ 1] = _mm512_set1_epi32( pdata[17] );
   block_buf[ 2] = _mm512_set1_epi32( pdata[18] );
   block_buf[ 3] =
             _mm512_set_epi32( n+15, n+14, n+13, n+12, n+11, n+10, n+ 9, n+ 8,
                               n+ 7, n+ 6, n+ 5, n+ 4, n+ 3, n+ 2, n+ 1, n );

   // Partialy prehash second block without touching nonces in block_buf[3].
   blake256_16x32_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
     allium_16way_hash( hash, midstate_vars, block0_hash, block_buf );

     for ( int lane = 0; lane < 16; lane++ ) 
     if ( unlikely( valid_hash( hash+(lane<<3), ptarget ) && !bench ) )
     {
        pdata[19] = n + lane;
        submit_solution( work, hash+(lane<<3), mythr );
     }
     block_buf[ 3] = _mm512_add_epi32( block_buf[ 3], sixteen ); 
     n += 16;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (ALLIUM_8WAY)  

typedef union {
   keccak256_4x64_context    keccak;
   cube_2way_context         cube;
   skein256_4x64_context     skein;
#if defined(__VAES__)
   groestl256_2way_context   groestl;
#else
   hashState_groestl256      groestl;
#endif
} allium_8way_ctx_holder;

static void allium_8way_hash( void *hash, const void *midstate_vars,
                               const void *midhash, const void *block )
{
   uint64_t vhashA[4*8] __attribute__ ((aligned (64)));
   uint64_t vhashB[4*8] __attribute__ ((aligned (32)));
   uint64_t *hash0 = (uint64_t*)hash;
   uint64_t *hash1 = (uint64_t*)hash+ 4;
   uint64_t *hash2 = (uint64_t*)hash+ 8;
   uint64_t *hash3 = (uint64_t*)hash+12;
   uint64_t *hash4 = (uint64_t*)hash+16;
   uint64_t *hash5 = (uint64_t*)hash+20;
   uint64_t *hash6 = (uint64_t*)hash+24;
   uint64_t *hash7 = (uint64_t*)hash+28;
   allium_8way_ctx_holder ctx __attribute__ ((aligned (64))); 

   blake256_8x32_final_rounds_le( vhashA, midstate_vars, midhash, block, 14 );

   dintrlv_8x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 vhashA, 256 );
   intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 256 );
   intrlv_4x64( vhashB, hash4, hash5, hash6, hash7, 256 );

   keccak256_4x64_init( &ctx.keccak );
   keccak256_4x64_update( &ctx.keccak, vhashA, 32 );
   keccak256_4x64_close( &ctx.keccak, vhashA );
   keccak256_4x64_init( &ctx.keccak );
   keccak256_4x64_update( &ctx.keccak, vhashB, 32 );
   keccak256_4x64_close( &ctx.keccak, vhashB );

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

   intrlv_2x128( vhashA, hash0, hash1, 256 );
   intrlv_2x128( vhashB, hash2, hash3, 256 );
   cube_2way_full( &ctx.cube, vhashA, 256, vhashA, 32 );
   cube_2way_full( &ctx.cube, vhashB, 256, vhashB, 32 );
   dintrlv_2x128( hash0, hash1, vhashA, 256 );
   dintrlv_2x128( hash2, hash3, vhashB, 256 );

   intrlv_2x128( vhashA, hash4, hash5, 256 );
   intrlv_2x128( vhashB, hash6, hash7, 256 );
   cube_2way_full( &ctx.cube, vhashA, 256, vhashA, 32 );
   cube_2way_full( &ctx.cube, vhashB, 256, vhashB, 32 );
   dintrlv_2x128( hash4, hash5, vhashA, 256 );
   dintrlv_2x128( hash6, hash7, vhashB, 256 );

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

   skein256_4x64_init( &ctx.skein );
   skein256_4x64_update( &ctx.skein, vhashA, 32 );
   skein256_4x64_close( &ctx.skein, vhashA );
   skein256_4x64_init( &ctx.skein );
   skein256_4x64_update( &ctx.skein, vhashB, 32 );
   skein256_4x64_close( &ctx.skein, vhashB );

#if defined(__VAES__)

   uint64_t vhashC[4*2] __attribute__ ((aligned (32)));
   uint64_t vhashD[4*2] __attribute__ ((aligned (32)));
   
   rintrlv_4x64_2x128( vhashC, vhashD, vhashA, 256 );
   groestl256_2way_full( &ctx.groestl, vhashC, vhashC, 32 );
   groestl256_2way_full( &ctx.groestl, vhashD, vhashD, 32 );
   dintrlv_2x128( hash0, hash1, vhashC, 256 );
   dintrlv_2x128( hash2, hash3, vhashD, 256 );

   rintrlv_4x64_2x128( vhashC, vhashD, vhashB, 256 );
   groestl256_2way_full( &ctx.groestl, vhashC, vhashC, 32 );
   groestl256_2way_full( &ctx.groestl, vhashD, vhashD, 32 );
   dintrlv_2x128( hash4, hash5, vhashC, 256 );
   dintrlv_2x128( hash6, hash7, vhashD, 256 );

#else

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhashA, 256 );
   dintrlv_4x64( hash4, hash5, hash6, hash7, vhashB, 256 );
   
   groestl256_full( &ctx.groestl, hash0, hash0, 256 );
   groestl256_full( &ctx.groestl, hash1, hash1, 256 );
   groestl256_full( &ctx.groestl, hash2, hash2, 256 );
   groestl256_full( &ctx.groestl, hash3, hash3, 256 );
   groestl256_full( &ctx.groestl, hash4, hash4, 256 );
   groestl256_full( &ctx.groestl, hash5, hash5, 256 );
   groestl256_full( &ctx.groestl, hash6, hash6, 256 );
   groestl256_full( &ctx.groestl, hash7, hash7, 256 );

#endif
}

int scanhash_allium_8way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint64_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t midstate_vars[16*8] __attribute__ ((aligned (64)));
   __m256i block0_hash[8] __attribute__ ((aligned (64)));
   __m256i block_buf[16] __attribute__ ((aligned (64)));
   uint32_t phash[8] __attribute__ ((aligned (32))) =
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t *pdata = work->data;
   uint64_t *ptarget = (uint64_t*)work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;  
   const bool bench = opt_benchmark;
   const __m256i eight = _mm256_set1_epi32( 8 );

   // Prehash first block
   blake256_transform_le( phash, pdata, 512, 0, 14 );

   block0_hash[0] = _mm256_set1_epi32( phash[0] );
   block0_hash[1] = _mm256_set1_epi32( phash[1] );
   block0_hash[2] = _mm256_set1_epi32( phash[2] );
   block0_hash[3] = _mm256_set1_epi32( phash[3] );
   block0_hash[4] = _mm256_set1_epi32( phash[4] );
   block0_hash[5] = _mm256_set1_epi32( phash[5] );
   block0_hash[6] = _mm256_set1_epi32( phash[6] );
   block0_hash[7] = _mm256_set1_epi32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[ 0] = _mm256_set1_epi32( pdata[16] );
   block_buf[ 1] = _mm256_set1_epi32( pdata[17] );
   block_buf[ 2] = _mm256_set1_epi32( pdata[18] );
   block_buf[ 3] = _mm256_set_epi32( n+ 7, n+ 6, n+ 5, n+ 4,
                                     n+ 3, n+ 2, n+ 1, n );

   // Partialy prehash second block without touching nonces
   blake256_8x32_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
     allium_8way_hash( hash, midstate_vars, block0_hash, block_buf );

     for ( int lane = 0; lane < 8; lane++ )
     {
        const uint64_t *lane_hash = hash + (lane<<2);
        if ( unlikely( valid_hash( lane_hash, ptarget ) && !bench ) )
        {
           pdata[19] = n + lane;
           submit_solution( work, lane_hash, mythr );
        }
     }
     n += 8;
     block_buf[ 3] = _mm256_add_epi32( block_buf[ 3], eight );
   } while ( likely( (n <= last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(__SSE2__) || defined(__ARM_NEON)

///////////////////
//
//    4 way

typedef union
{
   keccak256_2x64_context    keccak;
   cubehashParam             cube;
   skein256_2x64_context     skein;
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_groestl256      groestl;
#else
   sph_groestl256_context     groestl;
#endif
} allium_4way_ctx_holder;

static void allium_4way_hash( void *hash, const void *midstate_vars,
                               const void *midhash, const void *block )
{
   uint64_t vhashA[4*4] __attribute__ ((aligned (64)));
   uint64_t *hash0 = (uint64_t*)hash;
   uint64_t *hash1 = (uint64_t*)hash+ 4;
   uint64_t *hash2 = (uint64_t*)hash+ 8;
   uint64_t *hash3 = (uint64_t*)hash+12;
   allium_4way_ctx_holder ctx __attribute__ ((aligned (64)));

   blake256_4x32_final_rounds_le( vhashA, midstate_vars, midhash, block, 14 );
   dintrlv_4x32( hash0, hash1, hash2, hash3, vhashA, 256 );

   intrlv_2x64( vhashA, hash0, hash1, 256 );
   keccak256_2x64_init( &ctx.keccak );
   keccak256_2x64_update( &ctx.keccak, vhashA, 32 );
   keccak256_2x64_close( &ctx.keccak, vhashA );
   dintrlv_2x64( hash0, hash1, vhashA, 256 );
   intrlv_2x64( vhashA, hash2, hash3, 256 );
   keccak256_2x64_init( &ctx.keccak );
   keccak256_2x64_update( &ctx.keccak, vhashA, 32 );
   keccak256_2x64_close( &ctx.keccak, vhashA );
   dintrlv_2x64( hash2, hash3, vhashA, 256 );

   LYRA2RE( hash0, 32, hash0, 32, hash0, 32, 1, 8, 8 );
   LYRA2RE( hash1, 32, hash1, 32, hash1, 32, 1, 8, 8 );
   LYRA2RE( hash2, 32, hash2, 32, hash2, 32, 1, 8, 8 );
   LYRA2RE( hash3, 32, hash3, 32, hash3, 32, 1, 8, 8 );

   cubehash_full( &ctx.cube, hash0, 256, hash0, 32 );
   cubehash_full( &ctx.cube, hash1, 256, hash1, 32 );
   cubehash_full( &ctx.cube, hash2, 256, hash2, 32 );
   cubehash_full( &ctx.cube, hash3, 256, hash3, 32 );

   LYRA2RE( hash0, 32, hash0, 32, hash0, 32, 1, 8, 8 );
   LYRA2RE( hash1, 32, hash1, 32, hash1, 32, 1, 8, 8 );
   LYRA2RE( hash2, 32, hash2, 32, hash2, 32, 1, 8, 8 );
   LYRA2RE( hash3, 32, hash3, 32, hash3, 32, 1, 8, 8 );

   intrlv_2x64( vhashA, hash0, hash1, 256 );
   skein256_2x64_init( &ctx.skein );
   skein256_2x64_update( &ctx.skein, vhashA, 32 );
   skein256_2x64_close( &ctx.skein, vhashA );
   dintrlv_2x64( hash0, hash1, vhashA, 256 );
   intrlv_2x64( vhashA, hash2, hash3, 256 );
   skein256_2x64_init( &ctx.skein );
   skein256_2x64_update( &ctx.skein, vhashA, 32 );
   skein256_2x64_close( &ctx.skein, vhashA );
   dintrlv_2x64( hash2, hash3, vhashA, 256 );

#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   groestl256_full( &ctx.groestl, hash0, hash0, 256 );
   groestl256_full( &ctx.groestl, hash1, hash1, 256 );
   groestl256_full( &ctx.groestl, hash2, hash2, 256 );
   groestl256_full( &ctx.groestl, hash3, hash3, 256 );
#else
   sph_groestl256_init( &ctx.groestl );
   sph_groestl256( &ctx.groestl, hash0, 32 );
   sph_groestl256_close( &ctx.groestl, hash0 );
   sph_groestl256_init( &ctx.groestl );
   sph_groestl256( &ctx.groestl, hash1, 32 );
   sph_groestl256_close( &ctx.groestl, hash1 );
   sph_groestl256_init( &ctx.groestl );
   sph_groestl256( &ctx.groestl, hash2, 32 );
   sph_groestl256_close( &ctx.groestl, hash2 );
   sph_groestl256_init( &ctx.groestl );
   sph_groestl256( &ctx.groestl, hash3, 32 );
   sph_groestl256_close( &ctx.groestl, hash3 );
#endif
}

int scanhash_allium_4way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint64_t hash[4*4] __attribute__ ((aligned (64)));
   uint32_t midstate_vars[16*4] __attribute__ ((aligned (64)));
   v128_t block0_hash[8] __attribute__ ((aligned (64)));
   v128_t block_buf[16] __attribute__ ((aligned (64)));
   uint32_t phash[8] __attribute__ ((aligned (32))) =
   {
      0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
   };
   uint32_t *pdata = work->data;
   uint64_t *ptarget = (uint64_t*)work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   const v128u32_t four = v128_32(4);

   // Prehash first block
   blake256_transform_le( phash, pdata, 512, 0, 14 );

   block0_hash[0] = v128_32( phash[0] );
   block0_hash[1] = v128_32( phash[1] );
   block0_hash[2] = v128_32( phash[2] );
   block0_hash[3] = v128_32( phash[3] );
   block0_hash[4] = v128_32( phash[4] );
   block0_hash[5] = v128_32( phash[5] );
   block0_hash[6] = v128_32( phash[6] );
   block0_hash[7] = v128_32( phash[7] );

   // Build vectored second block, interleave last 16 bytes of data using
   // unique nonces.
   block_buf[ 0] = v128_32( pdata[16] );
   block_buf[ 1] = v128_32( pdata[17] );
   block_buf[ 2] = v128_32( pdata[18] );
   block_buf[ 3] = v128_set32( n+3, n+2, n+1, n );
   block_buf[ 4] = v128_32( 0x80000000 );
   block_buf[13] = v128_32( 1 );
   block_buf[15] = v128_32( 640 );

      // Partialy prehash second block without touching nonces
   blake256_4x32_round0_prehash_le( midstate_vars, block0_hash, block_buf );

   do {
     allium_4way_hash( hash, midstate_vars, block0_hash, block_buf );

     for ( int lane = 0; lane < 4; lane++ )
     {
        const uint64_t *lane_hash = hash + (lane<<2);
        if ( unlikely( valid_hash( lane_hash, ptarget ) && !bench ) )
        {
           pdata[19] = n + lane;
           submit_solution( work, lane_hash, mythr );
        }
     }
     n += 4;
     block_buf[3] = v128_add32( block_buf[3], four );
   } while ( likely( (n <= last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

////////////
//
//  1 way

typedef struct 
{
        blake256_context        blake;
        sph_keccak256_context      keccak;
        cubehashParam           cube;
        sph_skein256_context       skein;
#if defined (__AES__) || defined(__ARM_FEATURE_AES)
        hashState_groestl256     groestl;
#else
        sph_groestl256_context   groestl;
#endif
} allium_ctx_holder;

static __thread allium_ctx_holder allium_ctx;

bool init_allium_ctx()
{
        sph_keccak256_init( &allium_ctx.keccak );
        cubehashInit( &allium_ctx.cube, 256, 16, 32 );
        sph_skein256_init( &allium_ctx.skein );
#if defined (__AES__) || defined(__ARM_FEATURE_AES)
        init_groestl256( &allium_ctx.groestl, 32 );
#else
        sph_groestl256_init( &allium_ctx.groestl );
#endif
        return true;
}

void allium_hash(void *state, const void *input)
{
    uint32_t hash[8] __attribute__ ((aligned (64)));
    allium_ctx_holder ctx __attribute__ ((aligned (32)));

    memcpy( &ctx, &allium_ctx, sizeof(allium_ctx) );
    blake256_update( &ctx.blake, input + 64, 16 );
    blake256_close( &ctx.blake, hash );

    sph_keccak256( &ctx.keccak, hash, 32 );
    sph_keccak256_close( &ctx.keccak, hash );

    LYRA2RE( hash, 32, hash, 32, hash, 32, 1, 8, 8 );

    cubehashUpdateDigest( &ctx.cube, (byte*)hash, (const byte*)hash, 32 );

    LYRA2RE( hash, 32, hash, 32, hash, 32, 1, 8, 8 );

    sph_skein256( &ctx.skein, hash, 32 );
    sph_skein256_close( &ctx.skein, hash );

#if defined (__AES__) || defined(__ARM_FEATURE_AES)
   update_and_final_groestl256( &ctx.groestl, hash, hash, 256 );
#else
   sph_groestl256( &ctx.groestl, hash, 32 );
   sph_groestl256_close( &ctx.groestl, hash );
#endif

    memcpy(state, hash, 32);
}

int scanhash_allium( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) edata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t first_nonce = pdata[19];
    uint32_t nonce = first_nonce;
    const int thr_id = mythr->id;

    if ( opt_benchmark )
        ptarget[7] = 0x3ffff;

    for ( int i = 0; i < 19; i++ )
        edata[i] = bswap_32( pdata[i] );

    blake256_init( &allium_ctx.blake );
    blake256_update( &allium_ctx.blake, edata, 64 );

    do {
        edata[19] = nonce;
        allium_hash( hash, edata );
        if ( valid_hash( hash, ptarget ) && !opt_benchmark )
        {
            pdata[19] = bswap_32( nonce );
            submit_solution( work, hash, mythr );
        }
        nonce++;
    } while ( nonce < max_nonce && !work_restart[thr_id].restart );
    pdata[19] = nonce;
    *hashes_done = pdata[19] - first_nonce;
    return 0;
}

bool register_allium_algo( algo_gate_t* gate )
{
#if defined (ALLIUM_16WAY)
  gate->scanhash  = (void*)&scanhash_allium_16way;
#elif defined (ALLIUM_8WAY)
  gate->scanhash  = (void*)&scanhash_allium_8way;
#elif defined (ALLIUM_4WAY)
  gate->scanhash  = (void*)&scanhash_allium_4way;
#else
  gate->miner_thread_init = (void*)&init_allium_ctx;
  gate->scanhash  = (void*)&scanhash_allium;
  gate->hash      = (void*)&allium_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT
                      | VAES_OPT | NEON_OPT;
  opt_target_factor = 256.0;
  return true;
};

