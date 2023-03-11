/**
 * x21s algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 * Optimized by JayDDee@github Jan 2018
 */
#include "x16r-gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "algo/haval/haval-hash-4way.h"
#include "algo/tiger/sph_tiger.h"
#include "algo/gost/sph_gost.h"
#include "algo/lyra2/lyra2.h"
#if defined(__SHA__)
  #include "algo/sha/sha256-hash.h"
#endif

#if defined (X21S_8WAY)

static __thread uint64_t* x21s_8way_matrix;

union _x21s_8way_context_overlay
{
    haval256_5_8way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
    sha256_8way_context     sha256;
} __attribute__ ((aligned (64)));

typedef union _x21s_8way_context_overlay x21s_8way_context_overlay;

int x21s_8way_hash( void* output, const void* input, const int thrid )
{
   uint32_t vhash[16*8] __attribute__ ((aligned (128)));
   uint8_t shash[64*8] __attribute__ ((aligned (64)));
   uint32_t *hash0 = (uint32_t*)  shash;
   uint32_t *hash1 = (uint32_t*)( shash+64  ); 
   uint32_t *hash2 = (uint32_t*)( shash+128 );
   uint32_t *hash3 = (uint32_t*)( shash+192 );
   uint32_t *hash4 = (uint32_t*)( shash+256 );
   uint32_t *hash5 = (uint32_t*)( shash+320 );
   uint32_t *hash6 = (uint32_t*)( shash+384 );
   uint32_t *hash7 = (uint32_t*)( shash+448 );
   x21s_8way_context_overlay ctx;

   if ( !x16r_8way_hash_generic( shash, input, thrid ) )
      return 0;

   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                    hash7 );

   haval256_5_8way_init( &ctx.haval );
   haval256_5_8way_update( &ctx.haval, vhash, 64 );
   haval256_5_8way_close( &ctx.haval, vhash );

   dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                     hash7, vhash );

   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash0, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash0 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash1, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash1 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash2, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash2 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash3, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash3 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash4, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash4 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash5, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash5 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash6, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash6 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash7, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash7 );

   intrlv_2x256( vhash, hash0, hash1, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash0, hash1, vhash, 256 );
   intrlv_2x256( vhash, hash2, hash3, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash2, hash3, vhash, 256 );
   intrlv_2x256( vhash, hash4, hash5, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash4, hash5, vhash, 256 );
   intrlv_2x256( vhash, hash6, hash7, 256 );
   LYRA2REV2_2WAY( x21s_8way_matrix, vhash, 32, vhash, 32, 1, 4, 4 );
   dintrlv_2x256( hash6, hash7, vhash, 256 );

   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash0, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash0 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash1, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash1 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash2, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash2 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash3, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash3 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash4, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash4 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash5, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash5 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash6, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash6 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash7, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash7 );

   intrlv_8x32_512( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                    hash7 );
   sha256_8way_init( &ctx.sha256 );
   sha256_8way_update( &ctx.sha256, vhash, 64 );
   sha256_8way_close( &ctx.sha256, output );

   return 1;
}

bool x21s_8way_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   const int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   x21s_8way_matrix = _mm_malloc( 2 * size, 64 );
   return x21s_8way_matrix;
}

#elif defined (X21S_4WAY)

static __thread uint64_t* x21s_4way_matrix;

union _x21s_4way_context_overlay
{
    haval256_5_4way_context haval;
    sph_tiger_context       tiger;
    sph_gost512_context     gost;
#if !defined(__SHA__)
    sha256_4way_context     sha256;
#endif
} __attribute__ ((aligned (64)));

typedef union _x21s_4way_context_overlay x21s_4way_context_overlay;

int x21s_4way_hash( void* output, const void* input, const int thrid )
{
   uint32_t vhash[16*4] __attribute__ ((aligned (64)));
   uint8_t  shash[64*4] __attribute__ ((aligned (64)));
   x21s_4way_context_overlay ctx;
   uint32_t *hash0 = (uint32_t*)  shash;
   uint32_t *hash1 = (uint32_t*)( shash+64  );
   uint32_t *hash2 = (uint32_t*)( shash+128 );
   uint32_t *hash3 = (uint32_t*)( shash+192 );

   if ( !x16r_4way_hash_generic( shash, input, thrid ) )
      return 0;

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3,  512 );

   haval256_5_4way_init( &ctx.haval );
   haval256_5_4way_update( &ctx.haval, vhash, 64 );
   haval256_5_4way_close( &ctx.haval, vhash );

   dintrlv_4x32( hash0, hash1, hash2, hash3, vhash, 512 );

   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash0, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash0 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash1, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash1 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash2, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash2 );
   sph_tiger_init( &ctx.tiger );
   sph_tiger ( &ctx.tiger, (const void*) hash3, 64 );
   sph_tiger_close( &ctx.tiger, (void*) hash3 );

   LYRA2REV2( x21s_4way_matrix, (void*) hash0, 32, (const void*) hash0, 32,
            (const void*) hash0, 32, 1, 4, 4 );
   LYRA2REV2( x21s_4way_matrix, (void*) hash1, 32, (const void*) hash1, 32,
            (const void*) hash1, 32, 1, 4, 4 );
   LYRA2REV2( x21s_4way_matrix, (void*) hash2, 32, (const void*) hash2, 32,
            (const void*) hash2, 32, 1, 4, 4 );
   LYRA2REV2( x21s_4way_matrix, (void*) hash3, 32, (const void*) hash3, 32,
            (const void*) hash3, 32, 1, 4, 4 );

   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash0, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash0 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash1, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash1 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash2, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash2 );
   sph_gost512_init( &ctx.gost );
   sph_gost512 ( &ctx.gost, (const void*) hash3, 64 );
   sph_gost512_close( &ctx.gost, (void*) hash3 );

#if defined(__SHA__)

   sha256_full( output,    hash0, 64 );
   sha256_full( output+32, hash1, 64 );
   sha256_full( output+64, hash2, 64 );
   sha256_full( output+96, hash3, 64 );

#else

   intrlv_4x32( vhash, hash0, hash1, hash2, hash3, 512 );
   sha256_4way_init( &ctx.sha256 );
   sha256_4way_update( &ctx.sha256, vhash, 64 );
   sha256_4way_close( &ctx.sha256, vhash );
   dintrlv_4x32( output, output+32, output+64,output+96, vhash, 256 );

#endif

   return 1;
}

bool x21s_4way_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   const int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   x21s_4way_matrix = _mm_malloc( size, 64 );
   return x21s_4way_matrix;
}

#endif
