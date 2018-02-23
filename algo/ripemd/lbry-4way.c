#include "lbry-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/sha/sha2-hash-4way.h"
#include "ripemd-hash-4way.h"

#define LBRY_INPUT_SIZE 112
#define LBRY_MIDSTATE    64
#define LBRY_TAIL (LBRY_INPUT_SIZE) - (LBRY_MIDSTATE)

#if defined(LBRY_8WAY)

static __thread sha256_8way_context sha256_8w_mid;

void lbry_8way_hash( void* output, const void* input )
{
   uint32_t _ALIGN(64) vhashA[16<<3];
   uint32_t _ALIGN(64) vhashB[16<<3];
   uint32_t _ALIGN(64) vhashC[16<<3];
   uint32_t _ALIGN(32) h0[32];
   uint32_t _ALIGN(32) h1[32];
   uint32_t _ALIGN(32) h2[32];
   uint32_t _ALIGN(32) h3[32];
   uint32_t _ALIGN(32) h4[32];
   uint32_t _ALIGN(32) h5[32];
   uint32_t _ALIGN(32) h6[32];
   uint32_t _ALIGN(32) h7[32];
   sha256_8way_context     ctx_sha256 __attribute__ ((aligned (64)));
   sha512_4way_context     ctx_sha512;
   ripemd160_8way_context  ctx_ripemd;

   memcpy( &ctx_sha256, &sha256_8w_mid, sizeof(ctx_sha256) );
   sha256_8way( &ctx_sha256, input + (LBRY_MIDSTATE<<3), LBRY_TAIL );
   sha256_8way_close( &ctx_sha256, vhashA );

   sha256_8way_init( &ctx_sha256 );
   sha256_8way( &ctx_sha256, vhashA, 32 );
   sha256_8way_close( &ctx_sha256, vhashA );

   // reinterleave to do sha512 4-way 64 bit twice.
   mm256_deinterleave_8x32( h0, h1, h2, h3, h4, h5, h6, h7, vhashA, 256 );
   mm256_interleave_4x64( vhashA, h0, h1, h2, h3, 256 );
   mm256_interleave_4x64( vhashB, h4, h5, h6, h7, 256 );

   sha512_4way_init( &ctx_sha512 );
   sha512_4way( &ctx_sha512, vhashA, 32 );
   sha512_4way_close( &ctx_sha512, vhashA );

   sha512_4way_init( &ctx_sha512 );
   sha512_4way( &ctx_sha512, vhashB, 32 );
   sha512_4way_close( &ctx_sha512, vhashB );

   // back to 8-way 32 bit
   mm256_deinterleave_4x64( h0, h1, h2, h3, vhashA, 512 );
   mm256_deinterleave_4x64( h4, h5, h6, h7, vhashB, 512 );
   mm256_interleave_8x32( vhashA, h0, h1, h2, h3, h4, h5, h6, h7, 512 );

   ripemd160_8way_init( &ctx_ripemd );
   ripemd160_8way( &ctx_ripemd, vhashA, 32 );
   ripemd160_8way_close( &ctx_ripemd, vhashB );

   ripemd160_8way_init( &ctx_ripemd );
   ripemd160_8way( &ctx_ripemd, vhashA+(8<<3), 32 );
   ripemd160_8way_close( &ctx_ripemd, vhashC );

   sha256_8way_init( &ctx_sha256 );
   sha256_8way( &ctx_sha256, vhashB, 20 );
   sha256_8way( &ctx_sha256, vhashC, 20 );
   sha256_8way_close( &ctx_sha256, vhashA );

   sha256_8way_init( &ctx_sha256 );
   sha256_8way( &ctx_sha256, vhashA, 32 );
   sha256_8way_close( &ctx_sha256, vhashA );

   mm256_deinterleave_8x32( output,     output+ 32, output+ 64, output+ 96,
                            output+128, output+160, output+192, output+224,
                            vhashA, 256 );
}

int scanhash_lbry_8way( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done)
{
   uint32_t hash[8*8] __attribute__ ((aligned (64)));
   uint32_t vdata[32*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[27];
   const uint32_t first_nonce = pdata[27];
   const uint32_t Htarg = ptarget[7];
   uint32_t edata[32] __attribute__ ((aligned (64)));
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   uint32_t *noncep = vdata + 216; // 27*8

   uint64_t htmax[] = {          0,        0xF,       0xFF,
                             0xFFF,     0xFFFF, 0x10000000 };
   uint32_t masks[] = { 0xFFFFFFFF, 0xFFFFFFF0, 0xFFFFFF00,
                        0xFFFFF000, 0xFFFF0000,          0 };

   // we need bigendian data...
   swab32_array( edata, pdata, 32 );
   mm256_interleave_8x32( vdata, edata, edata, edata, edata,
                                 edata, edata, edata, edata, 1024 );
   sha256_8way_init( &sha256_8w_mid );
   sha256_8way( &sha256_8w_mid, vdata, LBRY_MIDSTATE );

   for ( int m = 0; m < sizeof(masks); m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do
      {
         be32enc( noncep,   n   );
         be32enc( noncep+1, n+1 );
         be32enc( noncep+2, n+2 );
         be32enc( noncep+3, n+3 );
         be32enc( noncep+4, n+4 );
         be32enc( noncep+5, n+5 );
         be32enc( noncep+6, n+6 );
         be32enc( noncep+7, n+7 );

         lbry_8way_hash( hash, vdata );

         for ( int i = 0; i < 8; i++ )
         if ( !( (hash+(i<<3))[7] & mask ) && fulltest( hash+(i<<3), ptarget ) )
         {
            pdata[27] = n+i;
            nonces[ num_found++ ] = n+i;
            work_set_target_ratio( work, hash+(i<<3) );
         }
         n+=8;
      } while ( ( num_found == 0 ) && ( n < max_nonce )
                   && !work_restart[thr_id].restart );
      break;
   }

   *hashes_done = n - first_nonce;
   return num_found;
}

#elif defined(LBRY_4WAY)

static __thread sha256_4way_context sha256_mid;

void lbry_4way_hash( void* output, const void* input )
{
   sha256_4way_context     ctx_sha256 __attribute__ ((aligned (64)));
   sha512_4way_context     ctx_sha512;
   ripemd160_4way_context  ctx_ripemd;
   uint32_t _ALIGN(64) vhashA[16<<2];
   uint32_t _ALIGN(64) vhashB[16<<2];
   uint32_t _ALIGN(64) vhashC[16<<2];

   memcpy( &ctx_sha256, &sha256_mid, sizeof(ctx_sha256) );
   sha256_4way( &ctx_sha256, input + (LBRY_MIDSTATE<<2), LBRY_TAIL );
   sha256_4way_close( &ctx_sha256, vhashA );

   sha256_4way_init( &ctx_sha256 );
   sha256_4way( &ctx_sha256, vhashA, 32 );
   sha256_4way_close( &ctx_sha256, vhashA );

   // sha512 64 bit data, 64 byte output
   mm256_reinterleave_4x64( vhashB, vhashA, 256 );
   sha512_4way_init( &ctx_sha512 );
   sha512_4way( &ctx_sha512, vhashB, 32 );
   sha512_4way_close( &ctx_sha512, vhashB );
   mm256_reinterleave_4x32( vhashA, vhashB, 512 );

   ripemd160_4way_init( &ctx_ripemd );
   ripemd160_4way( &ctx_ripemd, vhashA, 32 );
   ripemd160_4way_close( &ctx_ripemd, vhashB );

   ripemd160_4way_init( &ctx_ripemd );
   ripemd160_4way( &ctx_ripemd, vhashA+(8<<2), 32 );
   ripemd160_4way_close( &ctx_ripemd, vhashC );

   sha256_4way_init( &ctx_sha256 );
   sha256_4way( &ctx_sha256, vhashB, 20 );
   sha256_4way( &ctx_sha256, vhashC, 20 );
   sha256_4way_close( &ctx_sha256, vhashA );

   sha256_4way_init( &ctx_sha256 );
   sha256_4way( &ctx_sha256, vhashA, 32 );
   sha256_4way_close( &ctx_sha256, vhashA );

   mm_deinterleave_4x32( output, output+32, output+64, output+96, vhashA, 256 );
}

int scanhash_lbry_4way( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done)
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[32*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[27];
   const uint32_t first_nonce = pdata[27];
   const uint32_t Htarg = ptarget[7];
   uint32_t edata[32] __attribute__ ((aligned (64)));
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   uint32_t *noncep = vdata + 108; // 27*4

   uint64_t htmax[] = {          0,        0xF,       0xFF,
                             0xFFF,     0xFFFF, 0x10000000 };
   uint32_t masks[] = {	0xFFFFFFFF, 0xFFFFFFF0,	0xFFFFFF00,
                        0xFFFFF000, 0xFFFF0000,          0 };

   // we need bigendian data...
   swab32_array( edata, pdata, 32 );
   mm_interleave_4x32( vdata, edata, edata, edata, edata, 1024 );
   sha256_4way_init( &sha256_mid );
   sha256_4way( &sha256_mid, vdata, LBRY_MIDSTATE );

   for ( int m = 0; m < sizeof(masks); m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do
      {
         be32enc( noncep,   n   );
         be32enc( noncep+1, n+1 );
         be32enc( noncep+2, n+2 );
         be32enc( noncep+3, n+3 );

         lbry_4way_hash( hash, vdata );

         for ( int i = 0; i < 4; i++ )
         if ( !( (hash+(i<<3))[7] & mask ) && fulltest( hash+(i<<3), ptarget ) )
         {
            pdata[27] = n+i;
            nonces[ num_found++ ] = n+i;
            work_set_target_ratio( work, hash+(i<<3) );
         }
         n+=4;
      } while ( ( num_found == 0 ) && ( n < max_nonce )
                   && !work_restart[thr_id].restart );
      break;
   }

   *hashes_done = n - first_nonce;
   return num_found;
}

#endif
