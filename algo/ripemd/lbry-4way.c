#include "lbry-gate.h"

#if defined(LBRY_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/sha/sha2-hash-4way.h"
#include "ripemd-hash-4way.h"

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
   sha256_4way( &ctx_sha256, input+(64<<2), 48 );
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
   bool *found = work->nfound;
   int num_found = 0;
   uint32_t *noncep0 = vdata + 108; // 27*4
   uint32_t *noncep1 = vdata + 109;
   uint32_t *noncep2 = vdata + 110;
   uint32_t *noncep3 = vdata + 111;

   uint64_t htmax[] = {          0,        0xF,       0xFF,
                             0xFFF,     0xFFFF, 0x10000000 };
   uint32_t masks[] = {	0xFFFFFFFF, 0xFFFFFFF0,	0xFFFFFF00,
                        0xFFFFF000, 0xFFFF0000,          0 };

   // we need bigendian data...
   swab32_array( edata, pdata, 32 );
   mm_interleave_4x32( vdata, edata, edata, edata, edata, 1024 );
   sha256_4way_init( &sha256_mid );
   sha256_4way( &sha256_mid, vdata, 64 );

   for ( int m = 0; m < sizeof(masks); m++ ) if ( Htarg <= htmax[m] )
   {
      uint32_t mask = masks[m];
      do
      {
         found[0] = found[1] = found[2] = found[3] = false;
         be32enc( noncep0, n   );
         be32enc( noncep1, n+1 );
         be32enc( noncep2, n+2 );
         be32enc( noncep3, n+3 );
         lbry_4way_hash( hash, vdata );

         if ( !( hash[7] & mask ) && fulltest( hash, ptarget ) )
         {
            found[0] = true;
            num_found++;
            nonces[0] = pdata[27] = n;
            work_set_target_ratio( work, hash );
         }
         if ( !( (hash+8)[7] & mask ) && fulltest( hash+8, ptarget ) ) 
         {
            found[1] = true;
            num_found++;
            nonces[1] = n+1;
            work_set_target_ratio( work, hash+8 );
         }
         if ( !( (hash+16)[7] & mask ) && fulltest( hash+16, ptarget ) ) 
         {
            found[2] = true;
            num_found++;
            nonces[2] = n+2;
            work_set_target_ratio( work, hash+16 );
         }
         if ( !( (hash+24)[7] & mask ) && fulltest( hash+24, ptarget ) ) 
         {
            found[3] = true;
            num_found++;
            nonces[3] = n+3;
            work_set_target_ratio( work, hash+24 );
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
