#include "skein2-gate.h"
#include <string.h>
#include <stdint.h>
#include "skein-hash-4way.h"

#if defined(SKEIN2_4WAY)

void skein2hash_4way( void *output, const void *input )
{
   skein512_4way_context ctx;
   uint64_t hash[8*4] __attribute__ ((aligned (64)));
   uint64_t *out64 = (uint64_t*)output;

   skein512_4way_init( &ctx );
   skein512_4way( &ctx, input, 80 );
   skein512_4way_close( &ctx, hash );

   skein512_4way_init( &ctx );
   skein512_4way( &ctx, hash, 64 );
   skein512_4way_close( &ctx, hash );

   mm256_deinterleave_4x64( out64, out64+4, out64+8, out64+12, hash, 256 );
}

int scanhash_skein2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done )
{
    uint32_t hash[8*4] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t endiandata[20] __attribute__ ((aligned (64)));
    uint64_t *edata = (uint64_t*)endiandata;
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    // hash is returned deinterleaved
    uint32_t *nonces = work->nonces;
    bool *found = work->nfound;
    int num_found = 0;

    swab32_array( endiandata, pdata, 20 );

    mm256_interleave_4x64( vdata, edata, edata, edata, edata, 640 );

    uint32_t *noncep0 = vdata + 73;   // 9*8 + 1
    uint32_t *noncep1 = vdata + 75;
    uint32_t *noncep2 = vdata + 77;
    uint32_t *noncep3 = vdata + 79;

    do 
    {
       found[0] = found[1] = found[2] = found[3] = false;
       be32enc( noncep0, n   );
       be32enc( noncep1, n+1 );
       be32enc( noncep2, n+2 );
       be32enc( noncep3, n+3 );

       skein2hash( hash, vdata );

       if ( hash[7] < Htarg && fulltest( hash, ptarget ) )
       {
           found[0] = true;
           num_found++;
           nonces[0] = n;
       }
       if ( (hash+8)[7] < Htarg && fulltest( hash+8, ptarget ) )
       {
           found[1] = true;
           num_found++;
           nonces[1] = n+1;
       }
       if ( (hash+16)[7] < Htarg && fulltest( hash+16, ptarget ) )
       {
           found[2] = true;
           num_found++;
           nonces[2] = n+2;
       }
       if ( (hash+24)[7] < Htarg && fulltest( hash+24, ptarget ) )
       {
           found[3] = true;
           num_found++;
           nonces[3] = n+3;
       }
       n += 4;
    } while ( (num_found == 0) && (n < max_nonce)
             &&  !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return num_found;
}

#endif
