#include "pentablake-gate.h"

#if defined (__AVX2__)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake-hash-4way.h"
#include "sph_blake.h"

//#define DEBUG_ALGO

extern void pentablakehash_4way( void *output, const void *input )
{
	unsigned char _ALIGN(32) hash[128];
//	// same as uint32_t hashA[16], hashB[16];
//	#define hashB hash+64

     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     blake512_4way_context ctx;


     blake512_4way_init( &ctx );
     blake512_4way( &ctx, input, 80 );
     blake512_4way_close( &ctx, vhash );

uint64_t sin0[10], sin1[10], sin2[10], sin3[10];
mm256_deinterleave_4x64( sin0, sin1, sin2, sin3, input, 640 );
sph_blake512_context ctx2_blake;
sph_blake512_init(&ctx2_blake);
sph_blake512(&ctx2_blake, sin0, 80);
sph_blake512_close(&ctx2_blake, (void*) hash);

mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
uint64_t* hash64 = (uint64_t*)hash;
for( int i = 0; i < 8; i++ )
{
   if ( hash0[i] != hash64[i] )
      printf("hash mismatch %u\n",i);
}

     blake512_4way_init( &ctx );
     blake512_4way( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     blake512_4way_init( &ctx );
     blake512_4way( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     blake512_4way_init( &ctx );
     blake512_4way( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     blake512_4way_init( &ctx );
     blake512_4way( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
     memcpy( output+64, hash2, 32 );
     memcpy( output+96, hash3, 32 );

/*
     uint64_t sin0[10] __attribute__ ((aligned (64)));
     uint64_t sin1[10] __attribute__ ((aligned (64)));
     uint64_t sin2[10] __attribute__ ((aligned (64)));
     uint64_t sin3[10] __attribute__ ((aligned (64)));

	sph_blake512_context     ctx_blake;

	sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, input, 80);
	sph_blake512_close(&ctx_blake, hash);

        sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, hash, 64);
	sph_blake512_close(&ctx_blake, hash);

        sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, hash, 64);
	sph_blake512_close(&ctx_blake, hash);

        sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, hash, 64);
	sph_blake512_close(&ctx_blake, hash);

        sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, hash, 64);
	sph_blake512_close(&ctx_blake, hash);

	memcpy(output, hash, 32);
*/
}

int scanhash_pentablake_4way( int thr_id, struct work *work,
                              uint32_t max_nonce, uint64_t *hashes_done )
{
    uint32_t hash[4*8] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t endiandata[32] __attribute__ ((aligned (64)));
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];
    uint32_t *nonces = work->nonces;
    bool *found = work->nfound;
    int num_found = 0;
    uint32_t *noncep0 = vdata + 73;   // 9*8 + 1
    uint32_t *noncep1 = vdata + 75;
    uint32_t *noncep2 = vdata + 77;
    uint32_t *noncep3 = vdata + 79;

//    uint32_t _ALIGN(32) hash64[8];
//    uint32_t _ALIGN(32) endiandata[32];

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
    swab32_array( endiandata, pdata, 20 );

    uint64_t *edata = (uint64_t*)endiandata;
    mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

    for ( int m=0; m < 6; m++ )
    {
        if ( Htarg <= htmax[m] )
        {
           uint32_t mask = masks[m];
           do {
              found[0] = found[1] = found[2] = found[3] = false;
              be32enc( noncep0, n   );
              be32enc( noncep1, n+1 );
              be32enc( noncep2, n+2 );
              be32enc( noncep3, n+3 );

              pentablakehash_4way( hash, vdata );

              // return immediately on nonce found, only one submit
              if ( ( !(hash[7] & mask) ) && fulltest( hash, ptarget ) )
              {
                  found[0] = true;
                  num_found++;
                  nonces[0] = n;
                  pdata[19] = n;
                  *hashes_done = n - first_nonce + 1;
                  return 1;
              }
              if ( (! ((hash+8)[7] & mask) ) && fulltest( hash+8, ptarget ) )
              {
                  found[1] = true;
                  num_found++;
                  nonces[1] = n;
                  *hashes_done = n - first_nonce + 1;
                  return 1;
              }
              if ( ( !((hash+16)[7] & mask) ) && fulltest( hash+16, ptarget ) )
              {
                  found[2] = true;
                  num_found++;
                  nonces[2] = n;
                  *hashes_done = n - first_nonce + 1;
                  return 1;
              }
              if ( ( !((hash+24)[7] & mask) ) && fulltest( hash+24, ptarget ) )
              {
                  found[3] = true;
                  num_found++;
                  nonces[3] = n;
                  *hashes_done = n - first_nonce + 1;
                  return 1;
              }
              n += 4;

           } while (n < max_nonce && !work_restart[thr_id].restart);
           break;
        }
    }

    *hashes_done = n - first_nonce + 1;
    pdata[19] = n;
    return 0;
} 

#endif
