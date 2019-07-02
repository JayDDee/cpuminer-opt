#include "nist5-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(NIST5_4WAY)

#include "algo/blake/blake-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"

// no improvement with midstate
//static __thread blake512_4way_context ctx_mid;

void nist5hash_4way( void *out, const void *input )
{
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t vhash[8*4] __attribute__ ((aligned (64)));
     blake512_4way_context  ctx_blake;
     hashState_groestl      ctx_groestl;
     jh512_4way_context     ctx_jh;
     skein512_4way_context  ctx_skein;
     keccak512_4way_context ctx_keccak;

//     memcpy( &ctx_blake, &ctx_mid, sizeof(ctx_mid) );
//     blake512_4way( &ctx_blake, input + (64<<2), 16 );

     blake512_4way_init( &ctx_blake );
     blake512_4way( &ctx_blake, input, 80 );
     blake512_4way_close( &ctx_blake, vhash );

     mm256_dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash0,
                               (const char*)hash0, 512 );
     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash1,
                               (const char*)hash1, 512 );
     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash2,
                               (const char*)hash2, 512 );
     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash3,
                               (const char*)hash3, 512 );

     mm256_intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

     jh512_4way_init( &ctx_jh );
     jh512_4way( &ctx_jh, vhash, 64 );
     jh512_4way_close( &ctx_jh, vhash );

     keccak512_4way_init( &ctx_keccak );
     keccak512_4way( &ctx_keccak, vhash, 64 );
     keccak512_4way_close( &ctx_keccak, vhash );

     skein512_4way_init( &ctx_skein );
     skein512_4way( &ctx_skein, vhash, 64 );
     skein512_4way_close( &ctx_skein, out );
}

int scanhash_nist5_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[4*16] __attribute__ ((aligned (64)));
     uint32_t *hash7 = &(hash[25]);
     uint32_t lane_hash[8] __attribute__ ((aligned (32)));
     uint32_t vdata[24*4] __attribute__ ((aligned (64)));
     uint32_t endiandata[20] __attribute__((aligned(64)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     const uint32_t Htarg = ptarget[7];
     uint32_t *noncep = vdata + 73;   // 9*8 + 1
     int thr_id = mythr->id;  // thr_id arg is deprecated

     uint64_t htmax[] = {          0,
                                 0xF,
                                0xFF,
                               0xFFF,
                              0xFFFF,
                          0x10000000 };

     uint32_t masks[] = { 0xFFFFFFFF,
                          0xFFFFFFF0,
                          0xFFFFFF00,
                          0xFFFFF000,
                          0xFFFF0000,
                                   0 };

     // we need bigendian data...
     swab32_array( endiandata, pdata, 20 );

     uint64_t *edata = (uint64_t*)endiandata;
     mm256_intrlv_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

     // precalc midstate
//     blake512_4way_init( &ctx_mid );
//     blake512_4way( &ctx_mid, vdata, 64 );

     for ( int m=0; m < 6; m++ )
     {
        if (Htarg <= htmax[m])
        {
           uint32_t mask = masks[m];

           do {
              be32enc( noncep,   n   );
              be32enc( noncep+2, n+1 );
              be32enc( noncep+4, n+2 );
              be32enc( noncep+6, n+3 );

              nist5hash_4way( hash, vdata );

              for ( int lane = 0; lane < 4; lane++ )
              if ( ( hash7[ lane ] & mask ) == 0 )
              {
                 mm256_extr_lane_4x64( lane_hash, hash, lane, 256 );
                 if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
                 {
                    pdata[19] = n + lane;
                    submit_lane_solution( work, lane_hash, mythr, lane );
                 }
              }
              n += 4;
           } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
           break;
        }
     }
     *hashes_done = n - first_nonce + 1;
     return 0;
}

#endif
