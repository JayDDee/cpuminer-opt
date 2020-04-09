#include "nist5-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"

#if defined(NIST5_8WAY)

void nist5hash_8way( void *out, const void *input )
{
     uint64_t vhash[8*16] __attribute__ ((aligned (128)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     uint64_t hash4[8] __attribute__ ((aligned (64)));
     uint64_t hash5[8] __attribute__ ((aligned (64)));
     uint64_t hash6[8] __attribute__ ((aligned (64)));
     uint64_t hash7[8] __attribute__ ((aligned (64)));

     blake512_8way_context  ctx_blake;
     hashState_groestl      ctx_groestl;
     jh512_8way_context     ctx_jh;
     skein512_8way_context  ctx_skein;
     keccak512_8way_context ctx_keccak;

     blake512_8way_init( &ctx_blake );
     blake512_8way_update( &ctx_blake, input, 80 );
     blake512_8way_close( &ctx_blake, vhash );

     dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                   vhash, 512 );

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
     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash4,
                               (const char*)hash4, 512 );
     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash5,
                               (const char*)hash5, 512 );
     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash6,
                               (const char*)hash6, 512 );
     init_groestl( &ctx_groestl, 64 );
     update_and_final_groestl( &ctx_groestl, (char*)hash7,
                               (const char*)hash7, 512 );

     intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7, 512 );

     jh512_8way_init( &ctx_jh );
     jh512_8way_update( &ctx_jh, vhash, 64 );
     jh512_8way_close( &ctx_jh, vhash );

     keccak512_8way_init( &ctx_keccak );
     keccak512_8way_update( &ctx_keccak, vhash, 64 );
     keccak512_8way_close( &ctx_keccak, vhash );

     skein512_8way_init( &ctx_skein );
     skein512_8way_update( &ctx_skein, vhash, 64 );
     skein512_8way_close( &ctx_skein, out );
}

int scanhash_nist5_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t hash[16*8] __attribute__ ((aligned (128)));
     uint32_t vdata[24*8] __attribute__ ((aligned (64)));
     uint32_t lane_hash[8] __attribute__ ((aligned (64)));
     uint32_t *hash7 = &(hash[49]);
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     const uint32_t Htarg = ptarget[7];
     __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
     int thr_id = mythr->id;  

     mm512_bswap32_intrlv80_8x64( vdata, pdata );

     do {
        *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
               _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                 n+3, 0, n+2, 0, n+1, 0, n  , 0 ) ), *noncev );

        nist5hash_8way( hash, vdata );

        for ( int lane = 0; lane < 8; lane++ )
        if ( hash7[ lane<<1 ] <= Htarg )
        {
           extr_lane_8x64( lane_hash, hash, lane, 256 );
           if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
           {
              pdata[19] = n + lane;
              submit_solution( work, lane_hash, mythr );
           }
        }
        n += 8;
     } while ( ( n < max_nonce-8 ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce;
     return 0;
}

#elif defined(NIST5_4WAY)

void nist5hash_4way( void *out, const void *input )
{
     uint64_t vhash[8*4] __attribute__ ((aligned (128)));
     uint64_t hash0[8] __attribute__ ((aligned (64)));
     uint64_t hash1[8] __attribute__ ((aligned (64)));
     uint64_t hash2[8] __attribute__ ((aligned (64)));
     uint64_t hash3[8] __attribute__ ((aligned (64)));
     blake512_4way_context  ctx_blake;
     hashState_groestl      ctx_groestl;
     jh512_4way_context     ctx_jh;
     skein512_4way_context  ctx_skein;
     keccak512_4way_context ctx_keccak;

     blake512_4way_init( &ctx_blake );
     blake512_4way_update( &ctx_blake, input, 80 );
     blake512_4way_close( &ctx_blake, vhash );

     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

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

     intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

     jh512_4way_init( &ctx_jh );
     jh512_4way_update( &ctx_jh, vhash, 64 );
     jh512_4way_close( &ctx_jh, vhash );

     keccak512_4way_init( &ctx_keccak );
     keccak512_4way_update( &ctx_keccak, vhash, 64 );
     keccak512_4way_close( &ctx_keccak, vhash );

     skein512_4way_init( &ctx_skein );
     skein512_4way_update( &ctx_skein, vhash, 64 );
     skein512_4way_close( &ctx_skein, out );
}

int scanhash_nist5_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
     uint32_t vdata[4*24] __attribute__ ((aligned (128)));
     uint32_t hash[4*16] __attribute__ ((aligned (64)));
     uint32_t *hash7 = &(hash[25]);
     uint32_t lane_hash[8] __attribute__ ((aligned (32)));
     uint32_t *pdata = work->data;
     uint32_t *ptarget = work->target;
     uint32_t n = pdata[19];
     const uint32_t first_nonce = pdata[19];
     const uint32_t Htarg = ptarget[7];
     __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
     int thr_id = mythr->id;  

     mm256_bswap32_intrlv80_4x64( vdata, pdata );

     do {
        *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
               _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

        nist5hash_4way( hash, vdata );

        for ( int lane = 0; lane < 4; lane++ )
        if ( hash7[ lane<<1 ] <= Htarg )
        {
           extr_lane_4x64( lane_hash, hash, lane, 256 );
           if ( fulltest( lane_hash, ptarget ) && !opt_benchmark )
           {
              pdata[19] = n + lane;
              submit_solution( work, lane_hash, mythr );
           }
        }
        n += 4;
     } while ( ( n < max_nonce-4 ) && !work_restart[thr_id].restart );
     *hashes_done = n - first_nonce;
     return 0;
}

#endif
