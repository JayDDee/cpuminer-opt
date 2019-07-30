#include "cpuminer-config.h"
#include "anime-gate.h"

#if defined (ANIME_4WAY)

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"

typedef struct {
    blake512_4way_context  blake;
    bmw512_4way_context    bmw;
    hashState_groestl      groestl;
    jh512_4way_context     jh;
    skein512_4way_context  skein;
    keccak512_4way_context keccak;
} anime_4way_ctx_holder;

anime_4way_ctx_holder anime_4way_ctx __attribute__ ((aligned (64)));

void init_anime_4way_ctx()
{
     blake512_4way_init( &anime_4way_ctx.blake );
     bmw512_4way_init( &anime_4way_ctx.bmw );
     init_groestl( &anime_4way_ctx.groestl, 64 );
     skein512_4way_init( &anime_4way_ctx.skein );
     jh512_4way_init( &anime_4way_ctx.jh );
     keccak512_4way_init( &anime_4way_ctx.keccak );
}

void anime_4way_hash( void *state, const void *input )
{
    uint64_t hash0[8] __attribute__ ((aligned (64)));
    uint64_t hash1[8] __attribute__ ((aligned (64)));
    uint64_t hash2[8] __attribute__ ((aligned (64)));
    uint64_t hash3[8] __attribute__ ((aligned (64)));
    uint64_t vhash[8*4] __attribute__ ((aligned (64)));
    uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
    uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
    __m256i* vh  = (__m256i*)vhash;
    __m256i* vhA = (__m256i*)vhashA;
    __m256i* vhB = (__m256i*)vhashB;
    __m256i vh_mask;
    const uint32_t mask = 8;
    const __m256i bit3_mask = m256_const1_64( 8 );
    const __m256i zero = _mm256_setzero_si256();
    anime_4way_ctx_holder ctx;
    memcpy( &ctx, &anime_4way_ctx, sizeof(anime_4way_ctx) );

    bmw512_4way( &ctx.bmw, input, 80 );
    bmw512_4way_close( &ctx.bmw, vhash );

    blake512_4way( &ctx.blake, vhash, 64 );
    blake512_4way_close( &ctx.blake, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    if ( hash0[0] & mask )
    {
       update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                               (char*)hash0, 512 );
    }
    if ( hash1[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                               (char*)hash1, 512 );
    }
    if ( hash2[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                               (char*)hash2, 512 );
    }
    if ( hash3[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                               (char*)hash3, 512 );
    }

    intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

    if ( mm256_anybits0( vh_mask ) )
    {
       skein512_4way( &ctx.skein, vhash, 64 );
       skein512_4way_close( &ctx.skein, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

    intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

    jh512_4way( &ctx.jh, vhash, 64 );
    jh512_4way_close( &ctx.jh, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );

    if ( mm256_anybits1( vh_mask ) )
    {
       blake512_4way_init( &ctx.blake );
       blake512_4way( &ctx.blake, vhash, 64 );
       blake512_4way_close( &ctx.blake, vhashA );
    }
    if ( mm256_anybits0( vh_mask ) )
    {
       bmw512_4way_init( &ctx.bmw );
       bmw512_4way( &ctx.bmw, vhash, 64 );
       bmw512_4way_close( &ctx.bmw, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    keccak512_4way( &ctx.keccak, vhash, 64 );
    keccak512_4way_close( &ctx.keccak, vhash );

    skein512_4way_init( &ctx.skein );
    skein512_4way( &ctx.skein, vhash, 64 );
    skein512_4way_close( &ctx.skein, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );

    if ( mm256_anybits1( vh_mask ) )
    {
       keccak512_4way_init( &ctx.keccak );
       keccak512_4way( &ctx.keccak, vhash, 64 );
       keccak512_4way_close( &ctx.keccak, vhashA );
    }
    if ( mm256_anybits0( vh_mask ) )
    {
       jh512_4way_init( &ctx.jh );
       jh512_4way( &ctx.jh, vhash, 64 );
       jh512_4way_close( &ctx.jh, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    dintrlv_4x64( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_anime_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t hash[4*8] __attribute__ ((aligned (64)));
    uint32_t vdata[24*4] __attribute__ ((aligned (64)));
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
    int thr_id = mythr->id;  // thr_id arg is deprecated
    const uint32_t Htarg = ptarget[7];
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

    mm256_bswap32_intrlv80_4x64( vdata, pdata );

    for (int m=0; m < 6; m++)
       if (Htarg <= htmax[m])
       {
          uint32_t mask = masks[m];

          do
          {
             *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

             anime_4way_hash( hash, vdata );
             pdata[19] = n;

             for ( int i = 0; i < 4; i++ )
             if ( ( ( (hash+(i<<3))[7] & mask ) == 0 )
                && fulltest( hash+(i<<3), ptarget ) && !opt_benchmark )
             {
                pdata[19] = n+i;
                submit_lane_solution( work, hash+(i<<3), mythr, i );
             }
             n += 4;
          } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
          break;
       }

    *hashes_done = n - first_nonce + 1;
    return 0;
}

#endif
