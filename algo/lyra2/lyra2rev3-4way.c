#include "lyra2-gate.h"
#include <memory.h>

#if defined (LYRA2REV3_4WAY)	

#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h" 

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
   mm128_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash, 256 );

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

   mm128_interleave_4x32( vhash, hash0, hash1, hash2, hash3, 256 );
   bmw256_4way( &ctx.bmw, vhash, 32 );
   bmw256_4way_close( &ctx.bmw, state );

}

int scanhash_lyra2rev3_4way( int thr_id, struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr ) 
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t edata[20] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[7<<2]);
   uint32_t lane_hash[8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t Htarg = ptarget[7];
   __m128i  *noncev = (__m128i*)vdata + 19;   // aligned
   /* int */ thr_id = mythr->id;  // thr_id arg is deprecated
   
   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   // Need big endian data
   casti_m128i( edata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( edata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( edata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( edata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( edata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

   mm128_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   do
   {
      *noncev = mm128_bswap_32( _mm_set_epi32( n+3, n+2, n+1, n ) );

      lyra2rev3_4way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 4; lane++ ) if ( hash7[lane] <= Htarg )
      {
         mm128_extract_lane_4x32( lane_hash, hash, lane, 256 );

         if ( fulltest( lane_hash, ptarget ) )
         {
              pdata[19] = n + lane;    
              work_set_target_ratio( work, lane_hash );
              if ( submit_work( mythr, work ) )
                applog( LOG_NOTICE, "Share %d submitted by thread %d, lane %d.",
		             accepted_share_count + rejected_share_count + 1,
			     thr_id, lane );
              else
                applog( LOG_WARNING, "Failed to submit share." );
	 }
      }
      n += 4;
   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
