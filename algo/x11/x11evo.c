#include "cpuminer-config.h"
#include "x11evo-gate.h"

#if !defined(X11EVO_8WAY) && !defined(X11EVO_4WAY)

#include <string.h>
#include <stdint.h>
#include <compat/portable_endian.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#ifdef __AES__
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/echo/aes_ni/hash_api.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#endif
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"

typedef struct {
#ifdef __AES__
    hashState_echo          echo;
    hashState_groestl       groestl;
#else
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#endif
    hashState_luffa         luffa;
    cubehashParam           cube;
    hashState_sd            simd;
    sph_blake512_context    blake;
    sph_bmw512_context      bmw;
    sph_skein512_context    skein;
    sph_jh512_context       jh;
    sph_keccak512_context   keccak;
    sph_shavite512_context  shavite;
} x11evo_ctx_holder;

static x11evo_ctx_holder x11evo_ctx __attribute__ ((aligned (64)));

void init_x11evo_ctx()
{
#ifdef __AES__
     init_echo( &x11evo_ctx.echo, 512 );
     init_groestl( &x11evo_ctx.groestl, 64 );
#else
     sph_groestl512_init( &x11evo_ctx.groestl );
     sph_echo512_init( &x11evo_ctx.echo );
#endif
     init_luffa( &x11evo_ctx.luffa, 512 );
     cubehashInit( &x11evo_ctx.cube, 512, 16, 32 );
     init_sd( &x11evo_ctx.simd, 512 );
     sph_blake512_init( &x11evo_ctx.blake );
     sph_bmw512_init( &x11evo_ctx.bmw );
     sph_skein512_init( &x11evo_ctx.skein );
     sph_jh512_init( &x11evo_ctx.jh );
     sph_keccak512_init( &x11evo_ctx.keccak );
     sph_shavite512_init( &x11evo_ctx.shavite );
}

static char hashOrder[X11EVO_FUNC_COUNT + 1] = { 0 };
static __thread uint32_t s_ntime = UINT32_MAX;

void x11evo_hash( void *state, const void *input )
{
   uint32_t hash[16] __attribute__ ((aligned (64)));
   x11evo_ctx_holder ctx __attribute__ ((aligned (64)));
   memcpy( &ctx, &x11evo_ctx, sizeof(x11evo_ctx) );

   if ( s_seq == -1 )
   {
       uint32_t *data = (uint32_t*) input;
       const uint32_t ntime = data[17];
       evo_twisted_code(ntime, hashOrder);
    }

   int i;
   for ( i = 0; i < strlen(hashOrder); i++ )
   {
	char elem = hashOrder[i];
	uint8_t idx;
	if (elem >= 'A')
		idx = elem - 'A' + 10;
	else
		idx = elem - '0';

	int size = 64;

	switch (idx)
        {
           case 0:
	      sph_blake512( &ctx.blake, (char*)input, 80 );
	      sph_blake512_close( &ctx.blake, (char*)hash );
	      break;
	   case 1:
	      sph_bmw512( &ctx.bmw, (char*)hash, size );
	      sph_bmw512_close( &ctx.bmw, (char*)hash );
	      break;
	   case 2:
#ifdef __AES__
         update_and_final_groestl( &ctx.groestl, (char*)hash,
                                        (const char*)hash, 512 );
#else
	      sph_groestl512( &ctx.groestl, (char*)hash, size );
	      sph_groestl512_close( &ctx.groestl, (char*)hash );
#endif
	      break;
	    case 3:
	      sph_skein512( &ctx.skein, (char*)hash, size );
	      sph_skein512_close( &ctx.skein, (char*)hash );
	      break;
	    case 4:
	      sph_jh512( &ctx.jh, (char*)hash, size );
	      sph_jh512_close( &ctx.jh, (char*)hash );
	      break;
	    case 5:
	      sph_keccak512( &ctx.keccak, (char*)hash, size );
	      sph_keccak512_close( &ctx.keccak, (char*)hash );
	      break;
	    case 6:
              update_and_final_luffa( &ctx.luffa, (char*)hash,
                                      (const char*)hash, 64 );
	      break;
	    case 7:
              cubehashUpdateDigest( &ctx.cube, (char*)hash, 
                                    (const char*)hash, 64 );
	      break;
	    case 8:
	      sph_shavite512( &ctx.shavite, (char*)hash, size );
	      sph_shavite512_close( &ctx.shavite, (char*)hash );
	      break;
	    case 9:
              update_final_sd( &ctx.simd, (char*)hash, (const char*)hash, 512 );
	      break;
	    case 10:
#ifdef __AES__
         update_final_echo( &ctx.echo, (char*)hash,
                                 (const char*)hash, 512 );
#else
	      sph_echo512( &ctx.echo, (char*)hash, size );
	      sph_echo512_close( &ctx.echo, (char*)hash );
#endif
	      break;
	}
    }
    memcpy( state, hash, 32 );
}

//static const uint32_t diff1targ = 0x0000ffff;

int scanhash_x11evo( struct work* work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;  // thr_id arg is deprecated
        const uint32_t Htarg = ptarget[7];

        swab32_array( endiandata, pdata, 20 );

        int ntime = endiandata[17];
        if ( ntime != s_ntime  ||  s_seq == -1 )
        {
            evo_twisted_code( ntime, hashOrder );
            s_ntime = ntime;
        }

        uint32_t hmask = 0xFFFFFFFF;
        if ( Htarg  > 0 )
        {
         if ( Htarg <= 0xF )
            hmask = 0xFFFFFFF0;
         else if ( Htarg <= 0xFF )
            hmask = 0xFFFFFF00;
         else if ( Htarg <= 0xFFF )
            hmask = 0xFFFF000;
         else if ( Htarg <= 0xFFFF )
           hmask = 0xFFFF000;
        }

        do
        {
          pdata[19] = ++n;
          be32enc( &endiandata[19], n );
          x11evo_hash( hash64, endiandata );
          if ( ( hash64[7] & hmask ) == 0 )
          {
             if ( fulltest( hash64, ptarget ) )
                submit_solution( work, hash64, mythr );
          }
        } while ( n < max_nonce && !work_restart[thr_id].restart );

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
#endif
