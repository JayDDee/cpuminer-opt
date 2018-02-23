#include "skein-gate.h"
#include <string.h>
#include <stdint.h>
#include "skein-hash-4way.h"
#include "algo/sha/sha2-hash-4way.h"

#if defined (SKEIN_4WAY)

void skeinhash_4way( void *state, const void *input )
{
     uint64_t vhash64[8*4] __attribute__ ((aligned (64)));
     uint32_t vhash32[16*4] __attribute__ ((aligned (64)));
     skein512_4way_context ctx_skein;
     sha256_4way_context ctx_sha256;

     skein512_4way_init( &ctx_skein );
     skein512_4way( &ctx_skein, input, 80 );
     skein512_4way_close( &ctx_skein, vhash64 );

     mm256_reinterleave_4x32( vhash32, vhash64, 512 );

     sha256_4way_init( &ctx_sha256 );
     sha256_4way( &ctx_sha256, vhash32, 64 );
     sha256_4way_close( &ctx_sha256, vhash32 );

     mm_deinterleave_4x32( state, state+32, state+64, state+96, vhash32, 256 );
}

int scanhash_skein_4way( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done )
{
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t hash[8*4] __attribute__ ((aligned (64)));
    uint32_t edata[20] __attribute__ ((aligned (64)));
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    // hash is returned deinterleaved
    uint32_t *nonces = work->nonces;
    int num_found = 0;

// data is 80 bytes, 20 u32 or 4 u64.
	
    swab32_array( edata, pdata, 20 );
 
    mm256_interleave_4x64( vdata, edata, edata, edata, edata, 640 );

    uint32_t *noncep = vdata + 73;   // 9*8 + 1

   do
   {
       be32enc( noncep,   n   );
       be32enc( noncep+2, n+1 );
       be32enc( noncep+4, n+2 );
       be32enc( noncep+6, n+3 );

       skeinhash_4way( hash, vdata );

       for ( int i = 0; i < 4; i++ )
       if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
       {
           pdata[19] = n+i;
           nonces[ num_found++ ] = n+i;
           work_set_target_ratio( work, hash+(i<<3) );
       }
       n += 4;
    } while ( (num_found == 0) && (n < max_nonce)
               && !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return num_found;
}

#endif
