#include "pentablake-gate.h"

#if defined (__AVX2__)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "blake-hash-4way.h"
#include "sph_blake.h"

extern void pentablakehash_4way( void *output, const void *input )
{

     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     blake512_4way_context ctx;


     blake512_4way_init( &ctx );
     blake512_4way_update( &ctx, input, 80 );
     blake512_4way_close( &ctx, vhash );

     blake512_4way_init( &ctx );
     blake512_4way_update( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     blake512_4way_init( &ctx );
     blake512_4way_update( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     blake512_4way_init( &ctx );
     blake512_4way_update( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     blake512_4way_init( &ctx );
     blake512_4way_update( &ctx, vhash, 64 );
     blake512_4way_close( &ctx, vhash );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
     memcpy( output+64, hash2, 32 );
     memcpy( output+96, hash3, 32 );
}

int scanhash_pentablake_4way( struct work *work,
      uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t hash[4*8] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t endiandata[32] __attribute__ ((aligned (64)));
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];
    uint32_t *noncep = vdata + 73;   // 9*8 + 1
    int thr_id = mythr->id;  // thr_id arg is deprecated

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
    intrlv_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

    for ( int m=0; m < 6; m++ )
    {
        if ( Htarg <= htmax[m] )
        {
           uint32_t mask = masks[m];
           do {
              be32enc( noncep,   n   );
              be32enc( noncep+2, n+1 );
              be32enc( noncep+4, n+2 );
              be32enc( noncep+6, n+3 );

              pentablakehash_4way( hash, vdata );

              for ( int i = 0; i < 4; i++ )
              if ( !( (hash+(i<<3))[7] & mask )
                  && fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
              {
                 pdata[19] = n + i;
                 submit_solution( work, hash+(i<<3), mythr );
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
