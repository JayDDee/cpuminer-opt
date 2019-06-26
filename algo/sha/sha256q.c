#include "sha256t-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>

static __thread SHA256_CTX sha256q_ctx __attribute__ ((aligned (64)));

void sha256q_midstate( const void* input )
{
    SHA256_Init( &sha256q_ctx );
    SHA256_Update( &sha256q_ctx, input, 64 );
}

void sha256q_hash( void* output, const void* input )
{
   uint32_t _ALIGN(64) hash[16];
   const int midlen = 64;            // bytes
   const int tail   = 80 - midlen;   // 16

   SHA256_CTX ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &sha256q_ctx, sizeof sha256q_ctx );

   SHA256_Update( &ctx, input + midlen, tail );
   SHA256_Final( (unsigned char*)hash, &ctx );

   SHA256_Init( &ctx );
   SHA256_Update( &ctx, hash, 32 );
   SHA256_Final( (unsigned char*)hash, &ctx );

   SHA256_Init( &ctx );
   SHA256_Update( &ctx, hash, 32 );
   SHA256_Final( (unsigned char*)hash, &ctx );

   SHA256_Init( &ctx );
   SHA256_Update( &ctx, hash, 32 );
   SHA256_Final( (unsigned char*)hash, &ctx );

   memcpy( output, hash, 32 );
}

int scanhash_sha256q( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19] - 1;
   const uint32_t first_nonce = pdata[19];
   const uint32_t Htarg = ptarget[7];
#ifdef _MSC_VER
   uint32_t __declspec(align(32)) hash64[8];
#else
   uint32_t hash64[8] __attribute__((aligned(32)));
#endif
   uint32_t endiandata[32];
   int thr_id = mythr->id;  // thr_id arg is deprecated

   uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000
	};
   uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0
	};

   // we need bigendian data...
   casti_m128i( endiandata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( endiandata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( endiandata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( endiandata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( endiandata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

   sha256q_midstate( endiandata );

   for ( int m = 0; m < 6; m++ )
   {
      if ( Htarg <= htmax[m] )
      {
         uint32_t mask = masks[m];
         do {
            pdata[19] = ++n;
            be32enc(&endiandata[19], n);
            sha256q_hash( hash64, endiandata );
            if ( !( hash64[7] & mask ) )
            if ( fulltest( hash64, ptarget ) && !opt_benchmark )
               submit_solution( work, hash64, mythr );
         } while ( n < max_nonce && !work_restart[thr_id].restart );
         break;
      }
   }
   *hashes_done = n - first_nonce + 1;
   pdata[19] = n;
   return 0;
}
