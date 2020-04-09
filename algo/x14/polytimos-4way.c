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

union _poly_4way_context_overlay
{
   skein512_4way_context   skein;
   shabal512_4way_context  shabal;
   hashState_echo          echo;
   luffa_2way_context      luffa;
   sph_fugue512_context    fugue;
   sph_gost512_context     gost;
};
typedef union _poly_4way_context_overlay poly_4way_context_overlay;

void polytimos_4way_hash( void *output, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     poly_4way_context_overlay ctx;

     skein512_4way_init( &ctx.skein );
     skein512_4way_update( &ctx.skein, input, 80 );
     skein512_4way_close( &ctx.skein, vhash );

     // Need to convert from 64 bit interleaved to 32 bit interleaved.
     uint32_t vhash32[16*4];
     rintrlv_4x64_4x32( vhash32, vhash, 512 );
     shabal512_4way_init( &ctx.shabal );
     shabal512_4way_update( &ctx.shabal, vhash32, 64 );
     shabal512_4way_close( &ctx.shabal, vhash32 );
     dintrlv_4x32( hash0, hash1, hash2, hash3, vhash32, 512 );

     init_echo( &ctx.echo, 512 );
     update_final_echo ( &ctx.echo, (BitSequence *)hash0,
                         (const BitSequence *)hash0, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash1,
                       (const BitSequence *) hash1, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash2,
                       (const BitSequence *) hash2, 512 );
     init_echo( &ctx.echo, 512 );
     update_final_echo( &ctx.echo, (BitSequence *)hash3,
                       (const BitSequence *) hash3, 512 );

     intrlv_2x128( vhash, hash0, hash1, 512 );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     dintrlv_2x128( hash0, hash1, vhash, 512 );
     intrlv_2x128( vhash, hash2, hash3, 512 );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_init( &ctx.luffa, 512 );
     luffa_2way_update_close( &ctx.luffa, vhash, vhash, 64 );
     dintrlv_2x128( hash2, hash3, vhash, 512 );

     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash0, 64 );
     sph_fugue512_close( &ctx.fugue, hash0 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash1, 64 );
     sph_fugue512_close( &ctx.fugue, hash1 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash2, 64 );
     sph_fugue512_close( &ctx.fugue, hash2 );
     sph_fugue512_init( &ctx.fugue );
     sph_fugue512( &ctx.fugue, hash3, 64 );
     sph_fugue512_close( &ctx.fugue, hash3 );

     sph_gost512_init( &ctx.gost );
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

int scanhash_polytimos_4way( struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
     __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   const uint32_t Htarg = ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   if ( opt_benchmark )
      ptarget[7] = 0x0cff;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   do {
      *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                 _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

      polytimos_4way_hash(hash, vdata);
      pdata[19] = n;

      for ( int i = 0; i < 4; i++ ) if ( (hash+(i<<3))[7] <= Htarg )
      if( fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
      {
         pdata[19] = n+i;
         submit_solution( work, hash+(i<<3), mythr );
      }
      n += 4;

   } while ( ( n < max_nonce-4 ) && !(*restart));

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
