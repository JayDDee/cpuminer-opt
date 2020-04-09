#include "lyra2-gate.h"
#include <memory.h>

#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/cubehash/cubehash_sse2.h" 
#include "algo/cubehash/cube-hash-2way.h"

#if defined (LYRA2REV3_16WAY)

typedef struct {
   blake256_16way_context     blake;
   cube_4way_context          cube;
   bmw256_16way_context       bmw;
} lyra2v3_16way_ctx_holder;

static __thread lyra2v3_16way_ctx_holder l2v3_16way_ctx;

bool init_lyra2rev3_16way_ctx()
{
   blake256_16way_init( &l2v3_16way_ctx.blake );
   cube_4way_init( &l2v3_16way_ctx.cube, 256, 16, 32 );
   bmw256_16way_init( &l2v3_16way_ctx.bmw );
   return true;
}

void lyra2rev3_16way_hash( void *state, const void *input )
{
   uint32_t vhash[16*8] __attribute__ ((aligned (128)));
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
   lyra2v3_16way_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &l2v3_16way_ctx, sizeof(l2v3_16way_ctx) );

   blake256_16way_update( &ctx.blake, input + (64*16), 16 );
   blake256_16way_close( &ctx.blake, vhash );

   dintrlv_16x32( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
           hash8, hash9, hash10, hash11 ,hash12, hash13, hash14, hash15,
           vhash, 256 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );
   intrlv_2x256( vhash, hash8, hash9, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash8, hash9, vhash, 256 );
   intrlv_2x256( vhash, hash10, hash11, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash10, hash11, vhash, 256 );
   intrlv_2x256( vhash, hash12, hash13, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash12, hash13, vhash, 256 );
   intrlv_2x256( vhash, hash14, hash15, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash14, hash15, vhash, 256 );

   intrlv_4x128( vhash, hash0, hash1, hash2, hash3, 256 );
   cube_4way_full( &ctx.cube, vhash, 256, vhash, 32 );
   dintrlv_4x128( hash0, hash1, hash2, hash3, vhash, 256 );
   intrlv_4x128( vhash, hash4, hash5, hash6, hash7, 256 );
   cube_4way_full( &ctx.cube, vhash, 256, vhash, 32 );
   dintrlv_4x128( hash4, hash5, hash6, hash7, vhash, 256 );
   intrlv_4x128( vhash, hash8, hash9, hash10, hash11, 256 );
   cube_4way_full( &ctx.cube, vhash, 256, vhash, 32 );
   dintrlv_4x128( hash8, hash9, hash10, hash11, vhash, 256 );
   intrlv_4x128( vhash, hash12, hash13, hash14, hash15, 256 );
   cube_4way_full( &ctx.cube, vhash, 256, vhash, 32 );
   dintrlv_4x128( hash12, hash13, hash14, hash15, vhash, 256 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );
   intrlv_2x256( vhash, hash8, hash9, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash8, hash9, vhash, 256 );
   intrlv_2x256( vhash, hash10, hash11, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash10, hash11, vhash, 256 );
   intrlv_2x256( vhash, hash12, hash13, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash12, hash13, vhash, 256 );
   intrlv_2x256( vhash, hash14, hash15, 256 );
   LYRA2REV3_2WAY( l2v3_wholeMatrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash14, hash15, vhash, 256 );

   intrlv_16x32( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
             hash7, hash8, hash9, hash10, hash11, hash12, hash13, hash14,
             hash15, 256 );

   bmw256_16way_update( &ctx.bmw, vhash, 32 );
   bmw256_16way_close( &ctx.bmw, state );
}


int scanhash_lyra2rev3_16way( struct work *work, const uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*16] __attribute__ ((aligned (128)));
   uint32_t vdata[20*16] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &hash[7*16];
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce - 16;
   const uint32_t targ32 = ptarget[7];
   __m512i  *noncev = (__m512i*)vdata + 19;
   const int thr_id = mythr->id;

   if ( opt_benchmark )  ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm512_bswap32_intrlv80_16x32( vdata, pdata );

   blake256_16way_init( &l2v3_16way_ctx.blake );
   blake256_16way_update( &l2v3_16way_ctx.blake, vdata, 64 );

   do
   {
      *noncev = mm512_bswap_32( _mm512_set_epi32( n+15, n+14, n+13, n+12,
                                                  n+11, n+10, n+ 9, n+ 8,
                                                  n+ 7, n+ 6, n+ 5, n+ 4,
                                                  n+ 3, n+ 2, n+ 1, n ) );

      lyra2rev3_16way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 16; lane++ )
      if ( unlikely( hashd7[lane] <= targ32 ) )
      {
         extr_lane_16x32( lane_hash, hash, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !opt_benchmark ) )
         {
             pdata[19] = n + lane;
             submit_solution( work, lane_hash, mythr );
         }
      }
      n += 16;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (LYRA2REV3_8WAY)

typedef struct {
   blake256_8way_context     blake;
   cubehashParam             cube;
   bmw256_8way_context       bmw;
} lyra2v3_8way_ctx_holder;

static __thread lyra2v3_8way_ctx_holder l2v3_8way_ctx;

bool init_lyra2rev3_8way_ctx()
{
   blake256_8way_init( &l2v3_8way_ctx.blake );
   cubehashInit( &l2v3_8way_ctx.cube, 256, 16, 32 );
   bmw256_8way_init( &l2v3_8way_ctx.bmw );
   return true;
}

void lyra2rev3_8way_hash( void *state, const void *input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (128)));
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

   blake256_8way_update( &ctx.blake, input + (64*8), 16 );
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

   cubehash_full( &ctx.cube, (byte*) hash0, 256, (const byte*) hash0, 32 );
   cubehash_full( &ctx.cube, (byte*) hash1, 256, (const byte*) hash1, 32 );
   cubehash_full( &ctx.cube, (byte*) hash2, 256, (const byte*) hash2, 32 );
   cubehash_full( &ctx.cube, (byte*) hash3, 256, (const byte*) hash3, 32 );
   cubehash_full( &ctx.cube, (byte*) hash4, 256, (const byte*) hash4, 32 );
   cubehash_full( &ctx.cube, (byte*) hash5, 256, (const byte*) hash5, 32 );
   cubehash_full( &ctx.cube, (byte*) hash6, 256, (const byte*) hash6, 32 );
   cubehash_full( &ctx.cube, (byte*) hash7, 256, (const byte*) hash7, 32 );

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

   bmw256_8way_update( &ctx.bmw, vhash, 32 );
   bmw256_8way_close( &ctx.bmw, state );

   }

int scanhash_lyra2rev3_8way( struct work *work, const uint32_t max_nonce,
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
   blake256_8way_init( &l2v3_8way_ctx.blake );
   blake256_8way_update( &l2v3_8way_ctx.blake, vdata, 64 );

   do
   {
      lyra2rev3_8way_hash( hash, vdata );
      pdata[19] = n;

      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( hashd7[lane] <= targ32 ) )
      {
         extr_lane_8x32( lane_hash, hash, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm256_add_epi32( *noncev, m256_const1_32( 8 ) );
      n += 8;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

#if defined (LYRA2REV3_4WAY)  

typedef struct {
   blake256_4way_context     blake;
   cubehashParam             cube;
   bmw256_4way_context       bmw;
} lyra2v3_4way_ctx_holder;

//static lyra2v3_4way_ctx_holder l2v3_4way_ctx;
static __thread lyra2v3_4way_ctx_holder l2v3_4way_ctx;

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

   blake256_4way_update( &ctx.blake, input + (64*4), 16 );
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
   bmw256_4way_update( &ctx.bmw, vhash, 32 );
   bmw256_4way_close( &ctx.bmw, state );
}

int scanhash_lyra2rev3_4way( struct work *work, const uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr ) 
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *hashd7 = &(hash[7*4]);
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t targ32 = ptarget[7];
   __m128i  *noncev = (__m128i*)vdata + 19; 
   const int thr_id = mythr->id;
   
   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   mm128_bswap32_intrlv80_4x32( vdata, pdata );
   *noncev = _mm_set_epi32( n+3, n+2, n+1, n );

   blake256_4way_init( &l2v3_4way_ctx.blake );
   blake256_4way_update( &l2v3_4way_ctx.blake, vdata, 64 );

   do
   {
      lyra2rev3_4way_hash( hash, vdata );
      for ( int lane = 0; lane < 4; lane++ ) if ( hashd7[lane] <= targ32 )
      {
         extr_lane_4x32( lane_hash, hash, lane, 256 );
         if ( valid_hash( lane_hash, ptarget ) && !opt_benchmark ) 
         {
              pdata[19] = bswap_32( n + lane );    
              submit_solution( work, lane_hash, mythr );
	      }
      }
      *noncev = _mm_add_epi32( *noncev, m128_const1_32( 4 ) );
      n += 4;
   } while ( (n < max_nonce-4) && !work_restart[thr_id].restart);
   pdata[19] = n;
   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
