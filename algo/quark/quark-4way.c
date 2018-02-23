#include "cpuminer-config.h"
#include "quark-gate.h"

#if defined (QUARK_4WAY)

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
} quark_4way_ctx_holder;

quark_4way_ctx_holder quark_4way_ctx __attribute__ ((aligned (64)));

void init_quark_4way_ctx()
{
     blake512_4way_init( &quark_4way_ctx.blake );
     bmw512_4way_init( &quark_4way_ctx.bmw );
     init_groestl( &quark_4way_ctx.groestl, 64 );
     skein512_4way_init( &quark_4way_ctx.skein );
     jh512_4way_init( &quark_4way_ctx.jh );
     keccak512_4way_init( &quark_4way_ctx.keccak );
}

void quark_4way_hash( void *state, const void *input )
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
    quark_4way_ctx_holder ctx;
    memcpy( &ctx, &quark_4way_ctx, sizeof(quark_4way_ctx) );

    blake512_4way( &ctx.blake, input, 80 );
    blake512_4way_close( &ctx.blake, vhash );

    bmw512_4way( &ctx.bmw, vhash, 64 );
    bmw512_4way_close( &ctx.bmw, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ),
                                  m256_zero );

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
                                  m256_zero );

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
                                  m256_zero );

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

int scanhash_quark_4way( int thr_id, struct work *work, uint32_t max_nonce,
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
    int num_found = 0;
    uint32_t *noncep = vdata + 73;   // 9*8 + 1

    swab32_array( endiandata, pdata, 20 );

    uint64_t *edata = (uint64_t*)endiandata;
    mm256_interleave_4x64( (uint64_t*)vdata, edata, edata, edata, edata, 640 );

    do
    {
       be32enc( noncep,   n   );
       be32enc( noncep+2, n+1 );
       be32enc( noncep+4, n+2 );
       be32enc( noncep+6, n+3 );

       quark_4way_hash( hash, vdata );
       pdata[19] = n;

       for ( int i = 0; i < 4; i++ )
       if ( ( ( (hash+(i<<3))[7] & 0xFFFFFF00 ) == 0 )
            && fulltest( hash+(i<<3), ptarget ) )
       {
          pdata[19] = n+i;
          nonces[ num_found++ ] = n+i;
          work_set_target_ratio( work, hash+(i<<3) );
       }
       n += 4;
    } while ( ( num_found == 0 ) && ( n < max_nonce )
              && !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return num_found;
}

#endif
