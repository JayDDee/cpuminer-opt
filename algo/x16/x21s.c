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

int x21s_hash( void* output, const void* input, const int thrid )
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

bool x21s_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   const int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   x21s_matrix = _mm_malloc( size, 64 );
   return x21s_matrix;
}

#endif
