#include "skunk-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/skein/skein-hash-4way.h"
#include "algo/gost/sph_gost.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/cubehash/cube-hash-2way.h"

#if defined(SKUNK_8WAY)

typedef struct {
    skein512_8way_context skein;
    cube_4way_context     cube;
    hashState_fugue         fugue;
    sph_gost512_context   gost;
} skunk_8way_ctx_holder;

static __thread skunk_8way_ctx_holder skunk_8way_ctx;

void skunk_8way_hash( void *output, const void *input )
{
     uint64_t vhash[8*8] __attribute__ ((aligned (128)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t hash4[8] __attribute__ ((aligned (64)));
     uint64_t hash5[8] __attribute__ ((aligned (64)));
     uint64_t hash6[8] __attribute__ ((aligned (64)));
     uint64_t hash7[8] __attribute__ ((aligned (64)));

     skunk_8way_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &skunk_8way_ctx, sizeof(skunk_8way_ctx) );

     skein512_8way_final16( &ctx.skein, vhash, input );
     dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                        hash7, vhash, 512 );
  
     intrlv_4x128_512( vhash, hash0, hash1, hash2, hash3 ); 
     cube_4way_update_close( &ctx.cube, vhash, vhash, 64 ); 
     dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
     intrlv_4x128_512( vhash, hash4, hash5, hash6, hash7 ); 
     cube_4way_init( &ctx.cube, 512, 16, 32 );           
     cube_4way_update_close( &ctx.cube, vhash, vhash, 64 );  
     dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );

     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );
     fugue512_full( &ctx.fugue, hash4, hash4, 64 );
     fugue512_full( &ctx.fugue, hash5, hash5, 64 );
     fugue512_full( &ctx.fugue, hash6, hash6, 64 );
     fugue512_full( &ctx.fugue, hash7, hash7, 64 );

     sph_gost512( &ctx.gost, hash0, 64 );
     sph_gost512_close( &ctx.gost, output );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash1, 64 );
     sph_gost512_close( &ctx.gost, output+ 32 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash2, 64 );
     sph_gost512_close( &ctx.gost, output+ 64 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash3, 64 );
     sph_gost512_close( &ctx.gost, output+ 96 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash4, 64 );
     sph_gost512_close( &ctx.gost, output+128 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash5, 64 );
     sph_gost512_close( &ctx.gost, output+160 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash6, 64 );
     sph_gost512_close( &ctx.gost, output+192 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash7, 64 );
     sph_gost512_close( &ctx.gost, output+224 );
}

int scanhash_skunk_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[24*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   __m512i  *noncev = (__m512i*)vdata + 9; 
   const int thr_id = mythr->id;  
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0fff;

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   skein512_8way_prehash64( &skunk_8way_ctx.skein, vdata );
   *noncev = mm512_intrlv_blend_32( 
             _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                               n+3, 0, n+2, 0, n+1, 0, n  , 0 ), *noncev );
   do
   {
      skunk_8way_hash( hash, vdata );

      for ( int i = 0; i < 8; i++ )
      if ( unlikely( valid_hash( hash+(i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
      n +=8;
   } while ( likely( ( n < last_nonce ) && !( *restart ) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool skunk_8way_thread_init()
{
   skein512_8way_init( &skunk_8way_ctx.skein );
   cube_4way_init( &skunk_8way_ctx.cube, 512, 16, 32 );
   sph_gost512_init( &skunk_8way_ctx.gost );
   return true;
}

#elif defined(SKUNK_4WAY)

typedef struct {
    skein512_4way_context skein;
    cubehashParam         cube;
    hashState_fugue       fugue;
    sph_gost512_context   gost;
} skunk_4way_ctx_holder;

static __thread skunk_4way_ctx_holder skunk_4way_ctx;

void skunk_4way_hash( void *output, const void *input )
{
     uint64_t vhash[8*4] __attribute__ ((aligned (128)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));

     skunk_4way_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &skunk_4way_ctx, sizeof(skunk_4way_ctx) );

     skein512_4way_final16( &ctx.skein, vhash, input + (64*4) );
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*)hash0, 64 );
     memcpy( &ctx.cube, &skunk_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash1, (const byte*) hash1, 64 );
     memcpy( &ctx.cube, &skunk_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash2, (const byte*) hash2, 64 );
     memcpy( &ctx.cube, &skunk_4way_ctx.cube, sizeof(cubehashParam) );
     cubehashUpdateDigest( &ctx.cube, (byte*)hash3, (const byte*) hash3, 64 );

     fugue512_full( &ctx.fugue, hash0, hash0, 64 );
     fugue512_full( &ctx.fugue, hash1, hash1, 64 );
     fugue512_full( &ctx.fugue, hash2, hash2, 64 );
     fugue512_full( &ctx.fugue, hash3, hash3, 64 );

     sph_gost512( &ctx.gost, hash0, 64 );
     sph_gost512_close( &ctx.gost, hash0 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash1, 64 );
     sph_gost512_close( &ctx.gost, hash1 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash2, 64 );
     sph_gost512_close( &ctx.gost, hash2 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash3, 64 );
     sph_gost512_close( &ctx.gost, hash3 );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
     memcpy( output+64, hash2, 32 );
     memcpy( output+96, hash3, 32 );
}

int scanhash_skunk_4way( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   __m256i  *noncev = (__m256i*)vdata + 9; 
   const int thr_id = mythr->id; 
   volatile uint8_t *restart = &( work_restart[ thr_id ].restart );
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0fff;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   skein512_4way_prehash64( &skunk_4way_ctx.skein, vdata );
   *noncev = mm256_intrlv_blend_32(
             _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      skunk_4way_hash( hash, vdata );

      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash+(i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n + i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
      n +=4;
   } while ( likely( ( n < last_nonce ) && !( *restart ) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool skunk_4way_thread_init()
{
   skein512_4way_init( &skunk_4way_ctx.skein );
   cubehashInit( &skunk_4way_ctx.cube, 512, 16, 32 );
   sph_gost512_init( &skunk_4way_ctx.gost );
   return true;
}

#endif
