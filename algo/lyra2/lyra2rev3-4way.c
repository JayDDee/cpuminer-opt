#include "lyra2-gate.h"
#include <memory.h>

#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h" 


#if defined (LYRA2REV3_8WAY)

typedef struct {
   blake256_8way_context     blake;
   cubehashParam             cube;
   bmw256_8way_context       bmw;
} lyra2v3_8way_ctx_holder;

static lyra2v3_8way_ctx_holder l2v3_8way_ctx;

bool init_lyra2rev3_8way_ctx()
{
   blake256_8way_init( &l2v3_8way_ctx.blake );
   cubehashInit( &l2v3_8way_ctx.cube, 256, 16, 32 );
   bmw256_8way_init( &l2v3_8way_ctx.bmw );
   return true;
}

void lyra2rev3_8way_hash( void *state, const void *input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (64)));
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   uint32_t hash4[8] __attribute__ ((aligned (32)));
   uint32_t hash5[8] __attribute__ ((aligned (32)));
   uint32_t hash6[8] __attribute__ ((aligned (32)));
   uint32_t hash7[8] __attribute__ ((aligned (32)));
   lyra2v3_8way_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &l2v3_8way_ctx, sizeof(l2v3_8way_ctx) );

   blake256_8way( &ctx.blake, input, 80 );
   blake256_8way_close( &ctx.blake, vhash );

   dintrlv_8x32( hash0, hash1, hash2, hash3,
                       hash4, hash5, hash6, hash7, vhash, 256 );

   LYRA2REV3( l2v3_wholeMatrix, hash0, 32, hash0, 32, hash0, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash1, 32, hash1, 32, hash1, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash2, 32, hash2, 32, hash2, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash3, 32, hash3, 32, hash3, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash4, 32, hash4, 32, hash4, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash5, 32, hash5, 32, hash5, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash6, 32, hash6, 32, hash6, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash7, 32, hash7, 32, hash7, 32, 1, 4, 4 );

   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash4, (const byte*) hash4, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash5, (const byte*) hash5, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash6, (const byte*) hash6, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash7, (const byte*) hash7, 32 );

   LYRA2REV3( l2v3_wholeMatrix, hash0, 32, hash0, 32, hash0, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash1, 32, hash1, 32, hash1, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash2, 32, hash2, 32, hash2, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash3, 32, hash3, 32, hash3, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash4, 32, hash4, 32, hash4, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash5, 32, hash5, 32, hash5, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash6, 32, hash6, 32, hash6, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash7, 32, hash7, 32, hash7, 32, 1, 4, 4 );

   intrlv_8x32( vhash, hash0, hash1, hash2, hash3,
                             hash4, hash5, hash6, hash7, 256 );

   bmw256_8way( &ctx.bmw, vhash, 32 );
   bmw256_8way_close( &ctx.bmw, state );

   }

int scanhash_lyra2rev3_8way( struct work *work, const uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (64)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<3]);
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t Htarg = ptarget[7];
   __m256i  *noncev = (__m256i*)vdata + 19;   // aligned
   const int thr_id = mythr->id;  // thr_id arg is deprecated

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm256_bswap32_intrlv80_8x32( vdata, pdata );
   do
   {
      *noncev = mm256_bswap_32( _mm256_set_epi32( n+7, n+6, n+5, n+4,
                                                  n+3, n+2, n+1, n ) );

      lyra2rev3_8way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 8; lane++ ) if ( hash7[lane] <= Htarg )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
         {
              pdata[19] = n + lane;
              submit_lane_solution( work, lane_hash, mythr, lane );
         }
      }
      n += 8;
   } while ( (n < max_nonce-8) && !work_restart[thr_id].restart);
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif

#if defined (LYRA2REV3_4WAY)  


typedef struct {
   blake256_4way_context     blake;
   cubehashParam             cube;
   bmw256_4way_context       bmw;
} lyra2v3_4way_ctx_holder;

static lyra2v3_4way_ctx_holder l2v3_4way_ctx;

bool init_lyra2rev3_4way_ctx()
{
   blake256_4way_init( &l2v3_4way_ctx.blake );
   cubehashInit( &l2v3_4way_ctx.cube, 256, 16, 32 );
   bmw256_4way_init( &l2v3_4way_ctx.bmw );
   return true;
}

void lyra2rev3_4way_hash( void *state, const void *input )
{
   uint32_t vhash[8*4] __attribute__ ((aligned (64)));
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   lyra2v3_4way_ctx_holder ctx __attribute__ ((aligned (64))); 
   memcpy( &ctx, &l2v3_4way_ctx, sizeof(l2v3_4way_ctx) );

   blake256_4way( &ctx.blake, input, 80 );
   blake256_4way_close( &ctx.blake, vhash );
   dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 256 );

   LYRA2REV3( l2v3_wholeMatrix, hash0, 32, hash0, 32, hash0, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash1, 32, hash1, 32, hash1, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash2, 32, hash2, 32, hash2, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash3, 32, hash3, 32, hash3, 32, 1, 4, 4 );
   
   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   cubehashInit( &ctx.cube, 256, 16, 32 );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );

   LYRA2REV3( l2v3_wholeMatrix, hash0, 32, hash0, 32, hash0, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash1, 32, hash1, 32, hash1, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash2, 32, hash2, 32, hash2, 32, 1, 4, 4 );
   LYRA2REV3( l2v3_wholeMatrix, hash3, 32, hash3, 32, hash3, 32, 1, 4, 4 );

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 256 );
   bmw256_4way( &ctx.bmw, vhash, 32 );
   bmw256_4way_close( &ctx.bmw, state );
}

int scanhash_lyra2rev3_4way( struct work *work, const uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr ) 
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t Htarg = ptarget[7];
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   const int thr_id = mythr->id;  // thr_id arg is deprecated
   
   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   do
   {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );

      lyra2rev3_4way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 4; lane++ ) if ( hash7[lane] <= Htarg )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
         {
              pdata[19] = n + lane;    
              submit_lane_solution( work, lane_hash, mythr, lane );
	      }
      }
      n += 4;
   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
