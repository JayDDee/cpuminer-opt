#include "cpuminer-config.h"
#include "x11-gate.h"

#include <string.h>
#include <stdint.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"

#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#endif

#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/sse2/nist.h"
#include "algo/blake/sse2/blake.c"  
#include "algo/keccak/sse2/keccak.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"

typedef struct {
    hashState_luffa         luffa;
    cubehashParam           cube;
    hashState_sd            simd;
    sph_shavite512_context  shavite;
#ifdef NO_AES_NI
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#else
    hashState_echo          echo;
    hashState_groestl       groestl;
#endif
} x11_ctx_holder;

x11_ctx_holder x11_ctx;

void init_x11_ctx()
{
     init_luffa( &x11_ctx.luffa, 512 );
     cubehashInit( &x11_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x11_ctx.shavite );
     init_sd( &x11_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &x11_ctx.groestl );
     sph_echo512_init( &x11_ctx.echo );
#else
     init_echo( &x11_ctx.echo, 512 );
     init_groestl( &x11_ctx.groestl, 64 );
#endif
}

void x11_hash( void *state, const void *input )
{
     unsigned char hash[128] __attribute__ ((aligned (32)));
     unsigned char hashbuf[128] __attribute__ ((aligned (16)));
     sph_u64 hashctA;
     sph_u64 hashctB;
     x11_ctx_holder ctx;
     memcpy( &ctx, &x11_ctx, sizeof(x11_ctx) );
     size_t hashptr;

     DECL_BLK;
     BLK_I;
     BLK_W;
     BLK_C;

     DECL_BMW;
     BMW_I;
     BMW_U;
     #define M(x)    sph_dec64le_aligned(data + 8 * (x))
     #define H(x)    (h[x])
     #define dH(x)   (dh[x])
     BMW_C;
     #undef M
     #undef H
     #undef dH

#ifdef NO_AES_NI
     sph_groestl512 (&ctx.groestl, hash, 64);
     sph_groestl512_close(&ctx.groestl, hash);
#else
     update_and_final_groestl( &ctx.groestl, (char*)hash, (char*)hash, 512 );
//     update_groestl( &ctx.groestl, (char*)hash, 512 );
//     final_groestl( &ctx.groestl, (char*)hash );
#endif

     DECL_SKN;
     SKN_I;
     SKN_U;
     SKN_C;

     DECL_JH;
     JH_H;

     DECL_KEC;
     KEC_I;
     KEC_U;
     KEC_C;

//   asm volatile ("emms");

     update_luffa( &ctx.luffa, (const BitSequence*)hash, 64 );
     final_luffa( &ctx.luffa, (BitSequence*)hash+64 );

     cubehashUpdate( &ctx.cube, (const byte*) hash+64, 64 );
     cubehashDigest( &ctx.cube, (byte*)hash );

     sph_shavite512( &ctx.shavite, hash, 64 );
     sph_shavite512_close( &ctx.shavite, hash+64 );

     update_sd( &ctx.simd, (const BitSequence *)hash+64, 512 );
     final_sd( &ctx.simd, (BitSequence *)hash );

#ifdef NO_AES_NI
     sph_echo512 (&ctx.echo, hash, 64 );
     sph_echo512_close(&ctx.echo, hash+64 );
#else
     update_echo ( &ctx.echo, (const BitSequence *) hash, 512 );
     final_echo( &ctx.echo, (BitSequence *) hash+64 );
#endif

//        asm volatile ("emms");
     memcpy( state, hash+64, 32 );
}

int scanhash_x11( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
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

        // big endian encode 0..18 uint32_t, 64 bits at a time
        swab32_array( endiandata, pdata, 20 );

        for (int m=0; m < 6; m++) 
          if (Htarg <= htmax[m])
          {
            uint32_t mask = masks[m];
            do
            {
              pdata[19] = ++n;
              be32enc( &endiandata[19], n );
              x11_hash( hash64, &endiandata );
              if ( ( hash64[7] & mask ) == 0 )
              {
                 if ( fulltest( hash64, ptarget ) )
                 {
                    *hashes_done = n - first_nonce + 1;
                    work_set_target_ratio( work, hash64 );
                    return true;
                 }
              }
            } while ( n < max_nonce && !work_restart[thr_id].restart );
          }

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}
