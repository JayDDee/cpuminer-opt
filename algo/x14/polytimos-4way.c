#include "polytimos-gate.h"

#if defined(POLYTIMOS_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/skein/skein-hash-4way.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/fugue//sph_fugue.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/gost/sph_gost.h"
#include "algo/echo/aes_ni/hash_api.h"

typedef struct {
   skein512_4way_context   skein;
   shabal512_4way_context  shabal;
   hashState_echo          echo;
   luffa_2way_context      luffa;
   sph_fugue512_context    fugue;
   sph_gost512_context     gost;
} poly_4way_ctx_holder;

poly_4way_ctx_holder poly_4way_ctx;

void init_polytimos_4way_ctx()
{
    skein512_4way_init( &poly_4way_ctx.skein );
    shabal512_4way_init( &poly_4way_ctx.shabal );
    init_echo( &poly_4way_ctx.echo, 512  );
    luffa_2way_init( &poly_4way_ctx.luffa, 512 );
    sph_fugue512_init( &poly_4way_ctx.fugue );
    sph_gost512_init( &poly_4way_ctx.gost );
}

void polytimos_4way_hash( void *output, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     poly_4way_ctx_holder ctx __attribute__ ((aligned (64)));
     memcpy( &ctx, &poly_4way_ctx, sizeof(poly_4way_ctx) );

     skein512_4way( &ctx.skein, input, 80 );
     skein512_4way_close( &ctx.skein, vhash );

     // Need to convert from 64 bit interleaved to 32 bit interleaved.
     uint32_t vhash32[16*4];
     mm256_reinterleave_4x32( vhash32, vhash, 512 );
     shabal512_4way( &ctx.shabal, vhash32, 64 );
     shabal512_4way_close( &ctx.shabal, vhash32 );
     mm_deinterleave_4x32( hash0, hash1, hash2, hash3, vhash32, 512 );

     update_final_echo ( &ctx.echo, (BitSequence *)hash0,
                         (const BitSequence *)hash0, 512 );
     memcpy( &ctx.echo, &poly_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     memcpy( &ctx.echo, &poly_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     memcpy( &ctx.echo, &poly_4way_ctx.echo, sizeof(hashState_echo) );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );

     mm256_interleave_2x128( vhash, hash0, hash1, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     mm256_deinterleave_2x128( hash0, hash1, vhash, 512 );
     mm256_interleave_2x128( vhash, hash2, hash3, 512 );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     mm256_deinterleave_2x128( hash2, hash3, vhash, 512 );

     sph_fugue512( &ctx.fugue, hash0, 64 );
     sph_fugue512_close( &ctx.fugue, hash0 );
     memcpy( &ctx.fugue, &poly_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash1, 64 );
     sph_fugue512_close( &ctx.fugue, hash1 );
     memcpy( &ctx.fugue, &poly_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash2, 64 );
     sph_fugue512_close( &ctx.fugue, hash2 );
     memcpy( &ctx.fugue, &poly_4way_ctx.fugue, sizeof(sph_fugue512_context) );
     sph_fugue512( &ctx.fugue, hash3, 64 );
     sph_fugue512_close( &ctx.fugue, hash3 );

     sph_gost512( &ctx.gost, hash0, 64 );
     sph_gost512_close( &ctx.gost, hash0 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash1, 64 );
     sph_gost512_close( &ctx.gost, hash1 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash2, 64 );
     sph_gost512_close( &ctx.gost, hash2 );
     sph_gost512_init( &ctx.gost );
     sph_gost512( &ctx.gost, hash3, 64 );
     sph_gost512_close( &ctx.gost, hash3 );

     memcpy( output,    hash0, 32 );
     memcpy( output+32, hash1, 32 );
     memcpy( output+64, hash2, 32 );
     memcpy( output+96, hash3, 32 );
}

int scanhash_polytimos_4way( int thr_id, struct work *work, uint32_t max_nonce,                              uint64_t *hashes_done )
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t endiandata[20] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   uint32_t *nonces = work->nonces;
   int num_found = 0;
   uint32_t *noncep = vdata + 73;   // 9*8 + 1
   const uint32_t Htarg = ptarget[7];
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   if ( opt_benchmark )
      ptarget[7] = 0x0cff;

   for ( int i=0; i < 19; i++ )
      be32enc( &endiandata[i], pdata[i] );

   uint64_t *edata = (uint64_t*)endiandata;
   mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );
   do {
      be32enc( noncep,   n   );
      be32enc( noncep+2, n+1 );
      be32enc( noncep+4, n+2 );
      be32enc( noncep+6, n+3 );

      polytimos_4way_hash(hash, vdata);
      pdata[19] = n;

      for ( int i = 0; i < 4; i++ )
      if ( (hash+(i<<3))[7] <= Htarg && fulltest( hash+(i<<3), ptarget ) )
      {
         pdata[19] = n+i;
         nonces[ num_found++ ] = n+i;
         work_set_target_ratio( work, hash+(i<<3) );
      }
      n += 4;

   } while ( ( num_found == 0 ) && ( n < max_nonce ) && !(*restart));

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
