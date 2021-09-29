#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/sha/sha256-hash.h"

static __thread sha256_context sha256q_ctx __attribute__ ((aligned (64)));

void sha256q_midstate( const void* input )
{
   sha256_ctx_init( &sha256q_ctx );
   sha256_update( &sha256q_ctx, input, 64 );
}

int sha256q_hash( void* output, const void* input )
{
   uint32_t _ALIGN(64) hash[16];
   const int midlen = 64;            // bytes
   const int tail   = 80 - midlen;   // 16

   sha256_context ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &sha256q_ctx, sizeof sha256q_ctx );

   sha256_update( &ctx, input + midlen, tail );
   sha256_final( &ctx, hash );

   sha256_full( hash,   hash, 32 );
   sha256_full( hash,   hash, 32 );
   sha256_full( output, hash, 32 );
   
   return 1;
}

int scanhash_sha256q( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20] __attribute__((aligned(64)));
   uint32_t hash[8] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 1;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   mm128_bswap32_80( edata, pdata );
   sha256q_midstate( edata );

   do
   {
      edata[19] = n;
      if ( likely( sha256q_hash( hash, edata ) ) )
      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

