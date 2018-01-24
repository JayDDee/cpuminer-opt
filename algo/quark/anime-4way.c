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
    __m256i bit3_mask; bit3_mask = _mm256_set1_epi64x( 8 );
    int i;
    anime_4way_ctx_holder ctx;
    memcpy( &ctx, &anime_4way_ctx, sizeof(anime_4way_ctx) );

    bmw512_4way( &ctx.bmw, vhash, 80 );
    bmw512_4way_close( &ctx.bmw, vhash );

    blake512_4way( &ctx.blake, input, 64 );
    blake512_4way_close( &ctx.blake, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ),
                                  mm256_zero );

       mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
       update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                               (char*)hash0, 512 );
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                               (char*)hash1, 512 );
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                               (char*)hash2, 512 );
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                               (char*)hash3, 512 );
       mm256_interleave_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

       skein512_4way( &ctx.skein, vhash, 64 );
       skein512_4way_close( &ctx.skein, vhashB );

    for ( i = 0; i < 8; i++ )
       vh[i] = _mm256_blendv_epi8( vhA[i], vhB[i], vh_mask );

    mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
    mm256_interleave_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

    jh512_4way( &ctx.jh, vhash, 64 );
    jh512_4way_close( &ctx.jh, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ),
                                  mm256_zero );

       blake512_4way_init( &ctx.blake );
       blake512_4way( &ctx.blake, vhash, 64 );
       blake512_4way_close( &ctx.blake, vhashA );

       bmw512_4way_init( &ctx.bmw );
       bmw512_4way( &ctx.bmw, vhash, 64 );
       bmw512_4way_close( &ctx.bmw, vhashB );

    for ( i = 0; i < 8; i++ )
       vh[i] = _mm256_blendv_epi8( vhA[i], vhB[i], vh_mask );

    keccak512_4way( &ctx.keccak, vhash, 64 );
    keccak512_4way_close( &ctx.keccak, vhash );

    skein512_4way_init( &ctx.skein );
    skein512_4way( &ctx.skein, vhash, 64 );
    skein512_4way_close( &ctx.skein, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ),
                                  mm256_zero );

       keccak512_4way_init( &ctx.keccak );
       keccak512_4way( &ctx.keccak, vhash, 64 );
       keccak512_4way_close( &ctx.keccak, vhashA );

       jh512_4way_init( &ctx.jh );
       jh512_4way( &ctx.jh, vhash, 64 );
       jh512_4way_close( &ctx.jh, vhashB );

    for ( i = 0; i < 8; i++ )
       vh[i] = _mm256_blendv_epi8( vhA[i], vhB[i], vh_mask );

    mm256_deinterleave_4x64( state, state+32, state+64, state+96, vhash, 256 );
}

int scanhash_anime_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done)
{
    uint32_t hash[4*8] __attribute__ ((aligned (64)));
    uint32_t vdata[24*4] __attribute__ ((aligned (64)));
    uint32_t endiandata[20] __attribute__((aligned(64)));
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    uint32_t *nonces = work->nonces;
    bool *found = work->nfound;
    int num_found = 0;
    uint32_t *noncep0 = vdata + 73;   // 9*8 + 1
    uint32_t *noncep1 = vdata + 75;
    uint32_t *noncep2 = vdata + 77;
    uint32_t *noncep3 = vdata + 79;
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

    swab32_array( endiandata, pdata, 20 );

    uint64_t *edata = (uint64_t*)endiandata;
    mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

    for (int m=0; m < 6; m++)
       if (Htarg <= htmax[m])
       {
          uint32_t mask = masks[m];

          do
          {
              found[0] = found[1] = found[2] = found[3] = false;
              be32enc( noncep0, n   );
              be32enc( noncep1, n+1 );
              be32enc( noncep2, n+2 );
              be32enc( noncep3, n+3 );

              anime_4way_hash( hash, vdata );
              pdata[19] = n;

             if ( ( hash[7] & mask ) == 0 && fulltest( hash, ptarget ) ) 
             {
                found[0] = true;
                num_found++;
                nonces[0] = n;
                work_set_target_ratio( work, hash );
             }
             if ( ( (hash+8)[7] & mask ) == 0 && fulltest( hash+8, ptarget ) )
             {
                found[1] = true;
                num_found++;
                nonces[1] = n+1;
                work_set_target_ratio( work, hash );
             }
             if ( ( (hash+16)[7] & mask ) == 0 && fulltest( hash+16, ptarget ) )
             {
                found[2] = true;
                num_found++;
                nonces[2] = n+2;
                work_set_target_ratio( work, hash );
             }
             if ( ( (hash+24)[7] & mask ) == 0 && fulltest( hash+24, ptarget ) )
             {
                found[3] = true;
                num_found++;
                nonces[3] = n+3;
                work_set_target_ratio( work, hash );
             }
             n += 4;
          } while ( ( num_found == 0 ) && ( n < max_nonce )
              && !work_restart[thr_id].restart );
          break;
       }

    *hashes_done = n - first_nonce + 1;
    return num_found;
}

#endif
