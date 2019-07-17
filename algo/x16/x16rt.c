#include "x16r-gate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include <openssl/sha.h>
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#endif

static __thread uint32_t s_ntime = UINT32_MAX;
static __thread bool s_implemented = false;
static __thread char hashOrder[X16R_HASH_FUNC_COUNT + 1] = { 0 };

union _x16rt_context_overlay
{
#if defined(__AES__)
        hashState_echo          echo;
        hashState_groestl       groestl;
#else
        sph_groestl512_context   groestl;
        sph_echo512_context      echo;
#endif
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_skein512_context    skein;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        hashState_luffa         luffa;
        cubehashParam           cube;
        sph_shavite512_context  shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_fugue512_context    fugue;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        SHA512_CTX              sha512;
};
typedef union _x16rt_context_overlay x16rt_context_overlay;

void x16rt_hash( void* output, const void* input )
{
   uint32_t _ALIGN(128) hash[16];
   x16rt_context_overlay ctx;
   int size = 80;
   void *in = (void*) input;

/*
   void *in = (void*) input;
   uint32_t *in32 = (uint32_t*) in;
   uint32_t ntime = in32[17];
   if ( s_ntime == UINT32_MAX )
   {
      uint32_t _ALIGN(64) timeHash[8];
      x16rt_getTimeHash(ntime, &timeHash);
      x16rt_getAlgoString(&timeHash[0], hashOrder);
   }
*/
   
   for ( int i = 0; i < 16; i++ )
   {
      const char elem = hashOrder[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            sph_blake512_init( &ctx.blake );
            sph_blake512( &ctx.blake, in, size );
            sph_blake512_close( &ctx.blake, hash );
         break;
         case BMW:
            sph_bmw512_init( &ctx.bmw );
            sph_bmw512(&ctx.bmw, in, size);
            sph_bmw512_close(&ctx.bmw, hash);
         break;
         case GROESTL:
#if defined(__AES__)
            init_groestl( &ctx.groestl, 64 );
            update_and_final_groestl( &ctx.groestl, (char*)hash,
                                      (const char*)in, size<<3 );
#else
            sph_groestl512_init( &ctx.groestl );
            sph_groestl512( &ctx.groestl, in, size );
            sph_groestl512_close(&ctx.groestl, hash);
#endif
         break;
         case SKEIN:
            sph_skein512_init( &ctx.skein );
            sph_skein512( &ctx.skein, in, size );
            sph_skein512_close( &ctx.skein, hash );
         break;
         case JH:
            sph_jh512_init( &ctx.jh );
            sph_jh512(&ctx.jh, in, size );
            sph_jh512_close(&ctx.jh, hash );
         break;
         case KECCAK:
            sph_keccak512_init( &ctx.keccak );
            sph_keccak512( &ctx.keccak, in, size );
            sph_keccak512_close( &ctx.keccak, hash );
         break;
         case LUFFA:
            init_luffa( &ctx.luffa, 512 );
            update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                    (const BitSequence*)in, size );
         break;
         case CUBEHASH:
            cubehashInit( &ctx.cube, 512, 16, 32 );
            cubehashUpdateDigest( &ctx.cube, (byte*) hash,
                                  (const byte*)in, size );
         break;
         case SHAVITE:
            sph_shavite512_init( &ctx.shavite );
            sph_shavite512( &ctx.shavite, in, size );
            sph_shavite512_close( &ctx.shavite, hash );
         break;
         case SIMD:
             init_sd( &ctx.simd, 512 );
             update_final_sd( &ctx.simd, (BitSequence *)hash,
                              (const BitSequence*)in, size<<3 );
         break;
         case ECHO:
#if defined(__AES__)
             init_echo( &ctx.echo, 512 );
             update_final_echo ( &ctx.echo, (BitSequence *)hash,
                                (const BitSequence*)in, size<<3 );
#else
             sph_echo512_init( &ctx.echo );
             sph_echo512( &ctx.echo, in, size );
             sph_echo512_close( &ctx.echo, hash );
#endif
         break;
         case HAMSI:
             sph_hamsi512_init( &ctx.hamsi );
             sph_hamsi512( &ctx.hamsi, in, size );
             sph_hamsi512_close( &ctx.hamsi, hash );
         break;
         case FUGUE:
             sph_fugue512_init( &ctx.fugue );
             sph_fugue512( &ctx.fugue, in, size );
             sph_fugue512_close( &ctx.fugue, hash );
         break;
         case SHABAL:
             sph_shabal512_init( &ctx.shabal );
             sph_shabal512( &ctx.shabal, in, size );
             sph_shabal512_close( &ctx.shabal, hash );
         break;
         case WHIRLPOOL:
             sph_whirlpool_init( &ctx.whirlpool );
             sph_whirlpool( &ctx.whirlpool, in, size );
             sph_whirlpool_close( &ctx.whirlpool, hash );
         break;
         case SHA_512:
             SHA512_Init( &ctx.sha512 );
             SHA512_Update( &ctx.sha512, in, size );
             SHA512_Final( (unsigned char*) hash, &ctx.sha512 );
         break;
      }
      in = (void*) hash;
      size = 64;
   }
   memcpy(output, hash, 32);
}

int scanhash_x16rt( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash32[8];
   uint32_t _ALIGN(128) endiandata[20];
   uint32_t _ALIGN(64) timeHash[8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   int thr_id = mythr->id;  // thr_id arg is deprecated
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   casti_m128i( endiandata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( endiandata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( endiandata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( endiandata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( endiandata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

   uint32_t ntime = swab32( pdata[17] );
   if ( s_ntime != ntime )
   {
      x16rt_getTimeHash( ntime, &timeHash );
      x16rt_getAlgoString( &timeHash[0], hashOrder );
      s_ntime = ntime;
      s_implemented = true;
      if ( opt_debug && !thr_id )
          applog( LOG_INFO, "hash order: %s time: (%08x) time hash: (%08x)",
                               hashOrder, ntime, timeHash );
   }
   if ( !s_implemented )
   {
      applog( LOG_WARNING, "s not implemented");
      sleep(1);
      return 0;
   }
   
   if ( opt_benchmark )
      ptarget[7] = 0x0cff;

   do
   {
      be32enc( &endiandata[19], nonce );
      x16rt_hash( hash32, endiandata );

      if ( hash32[7] <= Htarg )
      if (fulltest( hash32, ptarget ) && !opt_benchmark )
      {
         pdata[19] = nonce;
         submit_solution( work, hash32, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !(*restart) );
   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce + 1;
   return 0;
}
