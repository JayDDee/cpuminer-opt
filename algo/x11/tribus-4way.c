#include "tribus-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(TRIBUS_4WAY)

#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/echo/aes_ni/hash_api.h"

//hashState_echo tribus_4way_ctx __attribute__ ((aligned (64)));
static __thread jh512_4way_context ctx_mid;
/*
void init_tribus_4way_ctx()
{
     init_echo( &tribus_4way_ctx, 512 );
}
*/
void tribus_hash_4way(void *state, const void *input)
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     jh512_4way_context     ctx_jh;
     keccak512_4way_context ctx_keccak;
     hashState_echo         ctx_echo;

     memcpy( &ctx_jh, &ctx_mid, sizeof(ctx_mid) );
     jh512_4way( &ctx_jh, input + (64<<2), 16 );
     jh512_4way_close( &ctx_jh, vhash );

     keccak512_4way_init( &ctx_keccak );
     keccak512_4way( &ctx_keccak, vhash, 64 );
     keccak512_4way_close( &ctx_keccak, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     // hash echo serially
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash0,
                        (const BitSequence *) hash0, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash1,
                        (const BitSequence *) hash1, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash2,
                        (const BitSequence *) hash2, 512 );
     init_echo( &ctx_echo, 512 );
     update_final_echo( &ctx_echo, (BitSequence *) hash3,
                        (const BitSequence *) hash3, 512 );

     memcpy( state,       hash0, 32 );
     memcpy( state+32,    hash1, 32 );
     memcpy( state+64,    hash2, 32 );
     memcpy( state+96,    hash3, 32 );
}

int scanhash_tribus_4way( struct work *work, uint32_t max_nonce,
            uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[4*8] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t Htarg = ptarget[7];
   uint32_t n = pdata[19];
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   int thr_id = mythr->id;  // thr_id arg is deprecated

   uint64_t htmax[] = {          0,
                               0xF,
                              0xFF,
                             0xFFF,
                            0xFFFF,
                        0x10000000 };

   uint32_t masks[] = {	0xFFFFFFFF,
                        0xFFFFFFF0,
                        0xFFFFFF00,
                        0xFFFFF000,
                        0xFFFF0000,
                                 0 };

   mm256_bswap32_intrlv80_4x64( vdata, pdata );

   // precalc midstate
   // doing it one way then then interleaving would be faster but too
   // complicated tto interleave context.
   jh512_4way_init( &ctx_mid );
   jh512_4way( &ctx_mid, vdata, 64 );

   for ( int m = 0; m < 6; m++ )
   {
      if ( Htarg <= htmax[m] )
      {
         uint32_t mask = masks[m];
         do {
           *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                 _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

            tribus_hash_4way( hash, vdata );

            pdata[19] = n;

            for ( int i = 0; i < 4; i++ )
            if ( ( !( (hash+(i<<3))[7] & mask ) )
                 && fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
            {
               pdata[19] = n+i;
               submit_lane_solution( work, hash+(i<<3), mythr, i );
            }
            n += 4;
         } while ( ( n < max_nonce )  && !work_restart[thr_id].restart);
         break;
      }
   }

   *hashes_done = n - first_nonce + 1;
   return 0;
}

#endif
