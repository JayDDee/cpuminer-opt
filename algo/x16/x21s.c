/**
 * x16r algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 * Optimized by JayDDee@github Jan 2018
 */
#include "x16r-gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "algo/sha/sha256-hash.h"
#include "algo/haval/sph-haval.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/gost/sph_gost.h"
#include "algo/lyra2/lyra2.h"

#if !defined(X16R_8WAY) && !defined(X16R_4WAY)

static __thread uint64_t* x21s_matrix;

union _x21s_context_overlay
{
        sph_haval256_5_context  haval;
        sph_tiger_context       tiger;
        sph_gost512_context     gost;
        sha256_context      sha256;
};
typedef union _x21s_context_overlay x21s_context_overlay;

int x21s_hash( void* output, const void* input, int thrid )
{
   uint32_t _ALIGN(128) hash[16];
   x21s_context_overlay ctx;

   if ( !x16r_hash_generic( hash, input, thrid ) )
      return 0;

   sph_haval256_5_init( &ctx.haval );
   sph_haval256_5( &ctx.haval, (const void*) hash, 64) ;
   sph_haval256_5_close( &ctx.haval, hash );

   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash );

   LYRA2REV2( x21s_matrix, (void*) hash, 32, (const void*) hash, 32,
               (const void*) hash, 32, 1, 4, 4);

   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash );

   sha256_full( hash, hash, 64 );

   memcpy( output, hash, 32 );

   return 1;
}

int scanhash_x21s( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash32[8];
   uint32_t _ALIGN(128) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;
   if ( bench )  ptarget[7] = 0x0cff;

   mm128_bswap32_80( edata, pdata );

   static __thread uint32_t s_ntime = UINT32_MAX;
   if ( s_ntime != pdata[17] )
   {
      uint32_t ntime = swab32(pdata[17]);
      x16_r_s_getAlgoString( (const uint8_t*)(&edata[1]), x16r_hash_order );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
          applog( LOG_INFO, "hash order %s (%08x)", x16r_hash_order, ntime );
   }

   x16r_prehash( edata, pdata );

   do
   {
      edata[19] = nonce;
      if ( x21s_hash( hash32, edata, thr_id ) )
      if ( unlikely( valid_hash( hash32, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( nonce );
         submit_solution( work, hash32, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !(*restart) );
   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce;
   return 0;
}

bool x21s_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   const int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   x21s_matrix = _mm_malloc( size, 64 );
   return x21s_matrix;
}

#endif
