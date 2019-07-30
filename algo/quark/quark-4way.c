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
    quark_4way_ctx_holder ctx;
    const __m256i bit3_mask = m256_const1_64( 8 );
    const uint32_t mask = 8;
    const __m256i zero = _mm256_setzero_si256();

    memcpy( &ctx, &quark_4way_ctx, sizeof(quark_4way_ctx) );

    blake512_4way( &ctx.blake, input, 80 );
    blake512_4way_close( &ctx.blake, vhash );

    bmw512_4way( &ctx.bmw, vhash, 64 );
    bmw512_4way_close( &ctx.bmw, vhash );

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

    // Final blend, directly to state, only need 32 bytes.
    casti_m256i( state, 0 ) = _mm256_blendv_epi8( vhA[0], vhB[0], vh_mask );
    casti_m256i( state, 1 ) = _mm256_blendv_epi8( vhA[1], vhB[1], vh_mask );
    casti_m256i( state, 2 ) = _mm256_blendv_epi8( vhA[2], vhB[2], vh_mask );
    casti_m256i( state, 3 ) = _mm256_blendv_epi8( vhA[3], vhB[3], vh_mask );
}

int scanhash_quark_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t hash[4*8] __attribute__ ((aligned (64)));
    uint32_t vdata[24*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint32_t *hash7 = &(hash[25]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
    int thr_id = mythr->id;  // thr_id arg is deprecated

    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    do
    {
       *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

       quark_4way_hash( hash, vdata );
       pdata[19] = n;

       for ( int i = 0; i < 4; i++ )
       if ( ( hash7[ i<<1 ] & 0xFFFFFF00 ) == 0 )
       {
          extr_lane_4x64( lane_hash, hash, i, 256 );
          if ( fulltest( lane_hash, ptarget ) && !opt_benchmark  )
          {
            pdata[19] = n+i;
            submit_lane_solution( work, lane_hash, mythr, i );
          }
       }
       n += 4;
    } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return 0;
}

#endif
