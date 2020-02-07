#include "cpuminer-config.h"
#include "anime-gate.h"

#if !defined(ANIME_8WAY) && !defined(ANIME_4WAY)

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/skein/sph_skein.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#ifdef __AES__
 #include "algo/groestl/aes_ni/hash-groestl.h"
#else
 #include "algo/groestl/sph_groestl.h"
#endif

typedef struct {
    sph_blake512_context  blake;
    sph_bmw512_context    bmw;
#ifdef __AES__
    hashState_groestl groestl;
#else
    sph_groestl512_context groestl;
#endif
    sph_jh512_context      jh;
    sph_skein512_context   skein;
    sph_keccak512_context  keccak;
} anime_ctx_holder;

anime_ctx_holder anime_ctx __attribute__ ((aligned (64)));

void init_anime_ctx()
{
     sph_blake512_init( &anime_ctx.blake );
     sph_bmw512_init( &anime_ctx.bmw );
#ifdef __AES__
    init_groestl( &anime_ctx.groestl, 64 );
#else
     sph_groestl512_init( &anime_ctx.groestl );
#endif
     sph_skein512_init( &anime_ctx.skein );
     sph_jh512_init( &anime_ctx.jh );
     sph_keccak512_init( &anime_ctx.keccak );
}

void anime_hash( void *state, const void *input )
{
    unsigned char hash[128] __attribute__ ((aligned (32)));
    uint32_t mask = 8;
    anime_ctx_holder ctx;
    memcpy( &ctx, &anime_ctx, sizeof(anime_ctx) );

    sph_bmw512( &ctx.bmw, input, 80 );
    sph_bmw512_close( &ctx.bmw, hash );

    sph_blake512( &ctx.blake, hash, 64 );
    sph_blake512_close( &ctx.blake, hash );

    if ( ( hash[0] & mask ) != 0 ) 
    {
#ifdef __AES__
       update_and_final_groestl( &ctx.groestl, (char*)hash, (char*)hash, 512 );
       reinit_groestl( &ctx.groestl );
#else
       sph_groestl512 ( &ctx.groestl, hash, 64 );
       sph_groestl512_close( &ctx.groestl, hash );
       sph_groestl512_init( &ctx.groestl );
#endif
    }
    else
    {
       sph_skein512( &ctx.skein, hash, 64 );
       sph_skein512_close( &ctx.skein, hash );
       sph_skein512_init( &ctx.skein );
    }

#ifdef __AES__
    update_and_final_groestl( &ctx.groestl, (char*)hash, (char*)hash, 512 );
#else
    sph_groestl512 ( &ctx.groestl, hash, 64 );
    sph_groestl512_close( &ctx.groestl, hash );
#endif

    sph_jh512( &ctx.jh, hash, 64 );
    sph_jh512_close( &ctx.jh, hash );

    if ( ( hash[0] & mask ) != 0 )
    {
       sph_blake512_init( &ctx.blake );
       sph_blake512( &ctx.blake, hash, 64 );
       sph_blake512_close( &ctx.blake, hash );
    }
    else
    {
       sph_bmw512_init( &ctx.bmw );
       sph_bmw512( &ctx.bmw, hash, 64 );
       sph_bmw512_close( &ctx.bmw, hash );
    }

    sph_keccak512( &ctx.keccak, hash, 64 );
    sph_keccak512_close( &ctx.keccak, hash );

    sph_skein512( &ctx.skein, hash, 64 );
    sph_skein512_close( &ctx.skein, hash );

    if ( ( hash[0] & mask ) != 0 )
    {
       sph_keccak512_init( &ctx.keccak );
       sph_keccak512( &ctx.keccak, hash, 64 );
       sph_keccak512_close( &ctx.keccak, hash );
    }
    else
    {
       sph_jh512_init( &ctx.jh );
       sph_jh512( &ctx.jh, hash, 64 );
       sph_jh512_close( &ctx.jh, hash );
    }

   memcpy( state, hash, 32 );
}

int scanhash_anime( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr)
{
    uint32_t hash[8] __attribute__ ((aligned (64)));
    uint32_t edata[20] __attribute__((aligned(64)));
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    const int thr_id = mythr->id;
    const int bench = opt_benchmark;
    
    swab32_array( edata, pdata, 20 );

    do
    {
        edata[19] = n;
        anime_hash( hash, edata );
        if ( valid_hash( hash, ptarget ) && !bench )
        {
           be32enc( &pdata[19], n );
           submit_solution( work, hash, mythr );
        }
        n++;
    } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );
    *hashes_done = n - first_nonce;
    pdata[19] = n;
    return 0;
}
#endif
