#include "groestl-gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#if defined(GROESTL_4WAY_VAES)

#include "groestl512-hash-4way.h"

void groestl_4way_hash( void *output, const void *input )
{
     uint32_t hash[16*4] __attribute__ ((aligned (128)));
     groestl512_4way_context ctx;

     groestl512_4way_init( &ctx, 64 );
     groestl512_4way_update_close( &ctx, hash, input, 640 );

     groestl512_4way_init( &ctx, 64 );
     groestl512_4way_update_close( &ctx, hash, hash, 512 );

     dintrlv_4x128( output, output+32, output+64, output+96, hash, 256 );
 }

int scanhash_groestl_4way( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[8*4] __attribute__ ((aligned (128)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     const uint32_t last_nonce = max_nonce - 4;
     uint32_t *noncep = vdata + 64+3;   // 4*16 + 3
     int thr_id = mythr->id;
     const uint32_t Htarg = ptarget[7];

     mm512_bswap32_intrlv80_4x128( vdata, pdata );

     do
     {
        be32enc( noncep,    n   );
        be32enc( noncep+ 4, n+1 );
        be32enc( noncep+ 8, n+2 );
        be32enc( noncep+12, n+3 );

        groestl_4way_hash( hash, vdata );
        pdata[19] = n;

        for ( int lane = 0; lane < 4; lane++ )
        if ( ( hash+(lane<<3) )[7] <= Htarg )
        if ( fulltest( hash+(lane<<3), ptarget) && !opt_benchmark )
        {
           pdata[19] = n + lane;
           submit_solution( work, hash+(lane<<3), mythr );
        }
        n += 4;
     } while ( ( n < last_nonce ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce;
     return 0;
}

#endif
