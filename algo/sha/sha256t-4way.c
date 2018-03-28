#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "sha2-hash-4way.h"
//#include <openssl/sha.h>

#if defined(SHA256T_8WAY)

static __thread sha256_8way_context sha256_ctx8 __attribute__ ((aligned (64)));

void sha256t_8way_hash( void* output, const void* input )
{
   uint32_t vhash[8*8] __attribute__ ((aligned (64)));
   sha256_8way_context ctx;
   memcpy( &ctx, &sha256_ctx8, sizeof ctx );

   sha256_8way( &ctx, input + (64<<3), 16 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, vhash );

   sha256_8way_init( &ctx );
   sha256_8way( &ctx, vhash, 32 );
   sha256_8way_close( &ctx, vhash );

   mm256_deinterleave_8x32( output,     output+ 32, output+ 64, output+ 96,
                            output+128, output+160, output+192, output+224,
                            vhash, 256 );
}

int scanhash_sha256t_8way( int thr_id, struct work *work,
                           uint32_t max_nonce, uint64_t *hashes_done )
{
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t hash[8*8] __attribute__ ((aligned (32)));
   uint32_t edata[20] __attribute__ ((aligned (32)));;
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   uint32_t *noncep = vdata + 152;   // 19*8

   const uint64_t htmax[] = {          0,
                                     0xF,
                                    0xFF,
                                   0xFFF,
                                  0xFFFF,
                              0x10000000 };
   const uint32_t masks[] = {  0xFFFFFFFF,
                               0xFFFFFFF0,
                               0xFFFFFF00,
                               0xFFFFF000,
                               0xFFFF0000,
                                        0 };

   for ( int k = 0; k < 19; k++ )
      be32enc( &edata[k], pdata[k] );

   mm256_interleave_8x32( vdata, edata, edata, edata, edata,
                                 edata, edata, edata, edata, 640 );
   sha256_8way_init( &sha256_ctx8 );
   sha256_8way( &sha256_ctx8, vdata, 64 );
        
   for ( int m = 0; m < 6; m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do {
         be32enc( noncep,    n   );
         be32enc( noncep +1, n+1 );
         be32enc( noncep +2, n+2 );
         be32enc( noncep +3, n+3 );
         be32enc( noncep +4, n+4 );
         be32enc( noncep +5, n+5 );
         be32enc( noncep +6, n+6 );
         be32enc( noncep +7, n+7 );
         pdata[19] = n;

         sha256t_8way_hash( hash, vdata );

         for ( int i = 0; i < 8; i++ )
         if ( ( !( ( hash+(i<<3) )[7] & mask ) )
              && fulltest( hash+(i<<3), ptarget ) )
         {
            pdata[19] = n+i;
            nonces[ num_found++ ] = n+i;
            work_set_target_ratio( work, hash+(i<<3) );
         }
         n += 8;

      } while ( (num_found == 0) && (n < max_nonce)
                && !work_restart[thr_id].restart );
      break;
   }
    
   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#elif defined(SHA256T_4WAY)

static __thread sha256_4way_context sha256_ctx4 __attribute__ ((aligned (64)));

void sha256t_4way_hash( void* output, const void* input )
{
   uint32_t vhash[8*4] __attribute__ ((aligned (64)));
   sha256_4way_context ctx;
   memcpy( &ctx, &sha256_ctx4, sizeof ctx );

   sha256_4way( &ctx, input + (64<<2), 16 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way( &ctx, vhash, 32 );
   sha256_4way_close( &ctx, vhash );

   sha256_4way_init( &ctx );
   sha256_4way( &ctx, vhash, 32 );
   sha256_4way_close( &ctx, vhash );

   mm_deinterleave_4x32( output,     output+ 32, output+ 64, output+ 96,
                         vhash, 256 );
}

int scanhash_sha256t_4way( int thr_id, struct work *work,
                           uint32_t max_nonce, uint64_t *hashes_done )
{
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t hash[8*4] __attribute__ ((aligned (32)));
   uint32_t edata[20] __attribute__ ((aligned (32)));;
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   uint32_t *noncep = vdata + 76;   // 19*4

   const uint64_t htmax[] = {          0,
                                     0xF,
                                    0xFF,
                                   0xFFF,
                                  0xFFFF,
                              0x10000000 };
   const uint32_t masks[] = {  0xFFFFFFFF,
                               0xFFFFFFF0,
                               0xFFFFFF00,
                               0xFFFFF000,
                               0xFFFF0000,
                                        0 };

   for ( int k = 0; k < 19; k++ )
      be32enc( &edata[k], pdata[k] );

   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );
   sha256_4way_init( &sha256_ctx4 );
   sha256_4way( &sha256_ctx4, vdata, 64 );

   for ( int m = 0; m < 6; m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do {
         be32enc( noncep,    n   );
         be32enc( noncep +1, n+1 );
         be32enc( noncep +2, n+2 );
         be32enc( noncep +3, n+3 );
         pdata[19] = n;

         sha256t_4way_hash( hash, vdata );

         for ( int i = 0; i < 4; i++ )
         if ( ( !( ( hash+(i<<3) )[7] & mask ) )
              && fulltest( hash+(i<<3), ptarget ) )
         {
            pdata[19] = n+i;
            nonces[ num_found++ ] = n+i;
            work_set_target_ratio( work, hash+(i<<3) );
         }
         n += 4;

      } while ( (num_found == 0) && (n < max_nonce)
                && !work_restart[thr_id].restart );
      break;
   }

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif

