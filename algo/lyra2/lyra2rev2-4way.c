#include "lyra2-gate.h"
#include <memory.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h" 
#include "algo/cubehash/cube-hash-2way.h"


#if 0
void lyra2rev2_8way_hash( void *state, const void *input )
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
   lyra2v2_8way_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &l2v2_8way_ctx, sizeof(l2v2_8way_ctx) );

   blake256_8way_update( &ctx.blake, input + (64<<3), 16 );
   blake256_8way_close( &ctx.blake, vhash );

   rintrlv_8x32_8x64( vhashA, vhash, 256 );

   keccak256_8way_update( &ctx.keccak, vhashA, 32 );
   keccak256_8way_close( &ctx.keccak, vhash );

   dintrlv_8x64( hash0, hash1, hash2, hash3,
                 hash4, hash5, hash6, hash7, vhash, 256 );

   cubehash_full( &ctx.cube, (byte*) hash0, 256, (const byte*) hash0, 32 );
   cubehash_full( &ctx.cube, (byte*) hash1, 256, (const byte*) hash1, 32 );
   cubehash_full( &ctx.cube, (byte*) hash2, 256, (const byte*) hash2, 32 );
   cubehash_full( &ctx.cube, (byte*) hash3, 256, (const byte*) hash3, 32 );
   cubehash_full( &ctx.cube, (byte*) hash4, 256, (const byte*) hash4, 32 );
   cubehash_full( &ctx.cube, (byte*) hash5, 256, (const byte*) hash5, 32 );
   cubehash_full( &ctx.cube, (byte*) hash6, 256, (const byte*) hash6, 32 );
   cubehash_full( &ctx.cube, (byte*) hash7, 256, (const byte*) hash7, 32 );

//   cube_4way_update_close( &ctx.cube, vhashA, vhashA, 32 );
//   cube_4way_init( &ctx.cube, 256, 16, 32 );
//   cube_4way_update_close( &ctx.cube, vhashB, vhashB, 32 );
//
//   dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, 256 );
//   dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, 256 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );

   intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                hash7, 256 );

   skein256_8way_update( &ctx.skein, vhash, 32 );
   skein256_8way_close( &ctx.skein, vhash );

   dintrlv_8x64( hash0, hash1, hash2, hash3,
                 hash4, hash5, hash6, hash7, vhash, 256 );

   cubehash_full( &ctx.cube, (byte*) hash0, 256, (const byte*) hash0, 32 );
   cubehash_full( &ctx.cube, (byte*) hash1, 256, (const byte*) hash1, 32 );
   cubehash_full( &ctx.cube, (byte*) hash2, 256, (const byte*) hash2, 32 );
   cubehash_full( &ctx.cube, (byte*) hash3, 256, (const byte*) hash3, 32 );
   cubehash_full( &ctx.cube, (byte*) hash4, 256, (const byte*) hash4, 32 );
   cubehash_full( &ctx.cube, (byte*) hash5, 256, (const byte*) hash5, 32 );
   cubehash_full( &ctx.cube, (byte*) hash6, 256, (const byte*) hash6, 32 );
   cubehash_full( &ctx.cube, (byte*) hash7, 256, (const byte*) hash7, 32 );

//   cube_4way_init( &ctx.cube, 256, 16, 32 );
//   cube_4way_update_close( &ctx.cube, vhashA, vhashA, 32 );
//   cube_4way_init( &ctx.cube, 256, 16, 32 );
//   cube_4way_update_close( &ctx.cube, vhashB, vhashB, 32 );
//   
//   dintrlv_4x128( hash0, hash1, hash2, hash3, vhashA, 256 );
//   dintrlv_4x128( hash4, hash5, hash6, hash7, vhashB, 256 );

   intrlv_8x32( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                hash7, 256 );

   bmw256_8way_update( &ctx.bmw, vhash, 32 );
   bmw256_8way_close( &ctx.bmw, state );
}
#endif




#if defined (LYRA2REV2_8WAY)

typedef struct {
   blake256_8way_context     blake;
   keccak256_8way_context    keccak;
   cubehashParam             cube;
   skein256_8way_context     skein;
   bmw256_8way_context          bmw;
} lyra2v2_8way_ctx_holder __attribute__ ((aligned (64)));

static lyra2v2_8way_ctx_holder l2v2_8way_ctx;

bool init_lyra2rev2_8way_ctx()
{
   keccak256_8way_init( &l2v2_8way_ctx.keccak );
   cubehashInit( &l2v2_8way_ctx.cube, 256, 16, 32 );
   skein256_8way_init( &l2v2_8way_ctx.skein );
   bmw256_8way_init( &l2v2_8way_ctx.bmw );
   return true;
}

void lyra2rev2_8way_hash( void *state, const void *input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (128)));
   uint32_t vhashA[8*8] __attribute__ ((aligned (64)));
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (64)));
   uint32_t hash2[8] __attribute__ ((aligned (64)));
   uint32_t hash3[8] __attribute__ ((aligned (64)));
   uint32_t hash4[8] __attribute__ ((aligned (64)));
   uint32_t hash5[8] __attribute__ ((aligned (64)));
   uint32_t hash6[8] __attribute__ ((aligned (64)));
   uint32_t hash7[8] __attribute__ ((aligned (64)));
   lyra2v2_8way_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &l2v2_8way_ctx, sizeof(l2v2_8way_ctx) );

   blake256_8way_update( &ctx.blake, input + (64<<3), 16 );
   blake256_8way_close( &ctx.blake, vhash );

   rintrlv_8x32_8x64( vhashA, vhash, 256 );

   keccak256_8way_update( &ctx.keccak, vhashA, 32 );
   keccak256_8way_close( &ctx.keccak, vhash );

   dintrlv_8x64( hash0, hash1, hash2, hash3,
                 hash4, hash5, hash6, hash7, vhash, 256 );

   cubehash_full( &ctx.cube, (byte*) hash0, 256, (const byte*) hash0, 32 );
   cubehash_full( &ctx.cube, (byte*) hash1, 256, (const byte*) hash1, 32 );
   cubehash_full( &ctx.cube, (byte*) hash2, 256, (const byte*) hash2, 32 );
   cubehash_full( &ctx.cube, (byte*) hash3, 256, (const byte*) hash3, 32 );
   cubehash_full( &ctx.cube, (byte*) hash4, 256, (const byte*) hash4, 32 );
   cubehash_full( &ctx.cube, (byte*) hash5, 256, (const byte*) hash5, 32 );
   cubehash_full( &ctx.cube, (byte*) hash6, 256, (const byte*) hash6, 32 );
   cubehash_full( &ctx.cube, (byte*) hash7, 256, (const byte*) hash7, 32 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2REV2_2WAY( l2v2_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );

   intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                hash7, 256 );

   skein256_8way_update( &ctx.skein, vhash, 32 );
   skein256_8way_close( &ctx.skein, vhash );

   dintrlv_8x64( hash0, hash1, hash2, hash3,
                 hash4, hash5, hash6, hash7, vhash, 256 );

   cubehash_full( &ctx.cube, (byte*) hash0, 256, (const byte*) hash0, 32 );
   cubehash_full( &ctx.cube, (byte*) hash1, 256, (const byte*) hash1, 32 );
   cubehash_full( &ctx.cube, (byte*) hash2, 256, (const byte*) hash2, 32 );
   cubehash_full( &ctx.cube, (byte*) hash3, 256, (const byte*) hash3, 32 );
   cubehash_full( &ctx.cube, (byte*) hash4, 256, (const byte*) hash4, 32 );
   cubehash_full( &ctx.cube, (byte*) hash5, 256, (const byte*) hash5, 32 );
   cubehash_full( &ctx.cube, (byte*) hash6, 256, (const byte*) hash6, 32 );
   cubehash_full( &ctx.cube, (byte*) hash7, 256, (const byte*) hash7, 32 );

   intrlv_8x32( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6, 
                hash7, 256 );

   bmw256_8way_update( &ctx.bmw, vhash, 32 );
   bmw256_8way_close( &ctx.bmw, state );
}

int scanhash_lyra2rev2_8way( struct work *work, const uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &hash[7*8];
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   const uint32_t targ32 = ptarget[7];
   __m256i  *noncev = (__m256i*)vdata + 19;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0000ff;

   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   *noncev = _mm256_set_epi32( n+7, n+6, n+5, n+4, n+3, n+2, n+1, n );
   blake256_8way_init( &l2v2_8way_ctx.blake );
   blake256_8way_update( &l2v2_8way_ctx.blake, vdata, 64 );

   do
   {
      lyra2rev2_8way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( hashd7[lane] <= targ32 ) )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
             pdata[19] = bswap_32( n + lane );
             submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      *noncev = _mm256_add_epi32( *noncev, m256_const1_32( 8 ) );
      n += 8;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (LYRA2REV2_4WAY)

typedef struct {
   blake256_4way_context     blake;
   keccak256_4way_context    keccak;
   cubehashParam             cube;
   skein256_4way_context     skein;
   bmw256_4way_context          bmw;
} lyra2v2_4way_ctx_holder;

static lyra2v2_4way_ctx_holder l2v2_4way_ctx;

bool init_lyra2rev2_4way_ctx()
{
   keccak256_4way_init( &l2v2_4way_ctx.keccak );
   cubehashInit( &l2v2_4way_ctx.cube, 256, 16, 32 );
   skein256_4way_init( &l2v2_4way_ctx.skein );
   bmw256_4way_init( &l2v2_4way_ctx.bmw );
   return true;
}

void lyra2rev2_4way_hash( void *state, const void *input )
{
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   uint32_t vhash[8*4] __attribute__ ((aligned (64)));
   uint64_t vhash64[4*4] __attribute__ ((aligned (64)));
   lyra2v2_4way_ctx_holder ctx __attribute__ ((aligned (64))); 
   memcpy( &ctx, &l2v2_4way_ctx, sizeof(l2v2_4way_ctx) );

   blake256_4way_update( &ctx.blake, input + (64<<2), 16 );
   blake256_4way_close( &ctx.blake, vhash );

   rintrlv_4x32_4x64( vhash64, vhash, 256 );

   keccak256_4way_update( &ctx.keccak, vhash64, 32 );
   keccak256_4way_close( &ctx.keccak, vhash64 );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );

   LYRA2REV2( l2v2_wholeMatrix, hash0, 32, hash0, 32, hash0, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash1, 32, hash1, 32, hash1, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash2, 32, hash2, 32, hash2, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash3, 32, hash3, 32, hash3, 32, 1, 4, 4 );

   intrlv_4x64( vhash64, hash0, hash1, hash2, hash3, 256 );

   skein256_4way_update( &ctx.skein, vhash64, 32 );
   skein256_4way_close( &ctx.skein, vhash64 );

   dintrlv_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 256 );

   bmw256_4way_update( &ctx.bmw, vhash, 32 );
   bmw256_4way_close( &ctx.bmw, state );
}

int scanhash_lyra2rev2_4way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &(hash[7<<2]);
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const uint32_t targ32 = ptarget[7];
   __m128i *noncev = (__m128i*)vdata + 19;  
   int thr_id = mythr->id; 

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );

   blake256_4way_init( &l2v2_4way_ctx.blake );
   blake256_4way_update( &l2v2_4way_ctx.blake, vdata, 64 );

   do
   {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );

      lyra2rev2_4way_hash( hash, vdata );

      for ( int lane = 0; lane < 4; lane++ ) if ( hashd7[lane] <= targ32 )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( valid_hash( lane_hash, ptarget ) && !opt_benchmark )
         {
            pdata[19] = n + lane;         
            submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      n += 4;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart);
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
