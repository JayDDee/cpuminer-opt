#include "allium-gate.h"
#include <memory.h>
#include "algo/blake/sph_blake.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/cubehash/sse2/cubehash_sse2.h" 
#if defined(__AES__)
#include "algo/groestl/aes_ni/hash-groestl256.h"
#else
#include "algo/groestl/sph_groestl.h"
#endif
#include "lyra2.h"

typedef struct {
        sph_blake256_context     blake;
        sph_keccak256_context    keccak;
        cubehashParam            cube;
        sph_skein256_context     skein;
#if defined (__AES__)
        hashState_groestl256     groestl;
#else
        sph_groestl256_context   groestl;
#endif
} allium_ctx_holder;

static __thread allium_ctx_holder allium_ctx;

bool init_allium_ctx()
{
        sph_keccak256_init( &allium_ctx.keccak );
        cubehashInit( &allium_ctx.cube, 256, 16, 32 );
        sph_skein256_init( &allium_ctx.skein );
#if defined (__AES__)
        init_groestl256( &allium_ctx.groestl, 32 );
#else
        sph_groestl256_init( &allium_ctx.groestl );
#endif
        return true;
}

void allium_hash(void *state, const void *input)
{
    uint32_t hash[8] __attribute__ ((aligned (64)));
    allium_ctx_holder ctx __attribute__ ((aligned (32)));

    memcpy( &ctx, &allium_ctx, sizeof(allium_ctx) );
    sph_blake256( &ctx.blake, input + 64, 16 );
    sph_blake256_close( &ctx.blake, hash );

    sph_keccak256( &ctx.keccak, hash, 32 );
    sph_keccak256_close( &ctx.keccak, hash );

    LYRA2RE( hash, 32, hash, 32, hash, 32, 1, 8, 8 );

    cubehashUpdateDigest( &ctx.cube, (byte*)hash, (const byte*)hash, 32 );

    LYRA2RE( hash, 32, hash, 32, hash, 32, 1, 8, 8 );

    sph_skein256( &ctx.skein, hash, 32 );
    sph_skein256_close( &ctx.skein, hash );

#if defined (__AES__)
   update_and_final_groestl256( &ctx.groestl, hash, hash, 256 );
#else
   sph_groestl256( &ctx.groestl, hash, 32 );
   sph_groestl256_close( &ctx.groestl, hash );
#endif

    memcpy(state, hash, 32);
}

int scanhash_allium( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done )
{
    uint32_t _ALIGN(128) hash[8];
    uint32_t _ALIGN(128) endiandata[20];
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t nonce = first_nonce;

    if ( opt_benchmark )
        ptarget[7] = 0x3ffff;

    for ( int i = 0; i < 19; i++ )
        be32enc( &endiandata[i], pdata[i] );

    sph_blake256_init( &allium_ctx.blake );
    sph_blake256( &allium_ctx.blake, endiandata, 64 );

    do {
        be32enc( &endiandata[19], nonce );
        allium_hash( hash, endiandata );

        if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
        {
            work_set_target_ratio( work, hash );
            pdata[19] = nonce;
            *hashes_done = pdata[19] - first_nonce;
            return 1;
        }
        nonce++;

    } while (nonce < max_nonce && !work_restart[thr_id].restart);

    pdata[19] = nonce;
    *hashes_done = pdata[19] - first_nonce + 1;
    return 0;
}

