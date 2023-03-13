/**
 * x16r algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 * Optimized by JayDDee@github Jan 2018
 */
#include "x16r-gate.h"

#if !defined(X16R_8WAY) && !defined(X16R_4WAY)

#include "algo/tiger/sph_tiger.h"

union _x16rv2_context_overlay
{
#if defined(__AES__)
        hashState_echo          echo;
        hashState_groestl       groestl;
        hashState_fugue         fugue;
#else
        sph_groestl512_context   groestl;
        sph_echo512_context      echo;
        sph_fugue512_context    fugue;
#endif
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_skein512_context    skein;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        hashState_luffa         luffa;
        cubehashParam           cube;
        shavite512_context      shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;
        sph_tiger_context       tiger;
};
typedef union _x16rv2_context_overlay x16rv2_context_overlay;

// Pad the 24 bytes tiger hash to 64 bytes
inline void padtiger512(uint32_t* hash) {
   for (int i = (24/4); i < (64/4); i++) hash[i] = 0;
}

int x16rv2_hash( void* output, const void* input, int thrid )
{
   uint32_t _ALIGN(128) hash[16];
   x16rv2_context_overlay ctx;
   void *in = (void*) input;
   int size = 80;

   for ( int i = 0; i < 16; i++ )
   {
      const char elem = x16r_hash_order[i];
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
            sph_tiger_init( &ctx.tiger );
            sph_tiger( &ctx.tiger, in, size );
            sph_tiger_close( &ctx.tiger, hash );
            padtiger512( hash );
            sph_keccak512_init( &ctx.keccak );
            sph_keccak512( &ctx.keccak, hash, 64 );
            sph_keccak512_close( &ctx.keccak, hash );
         break;
         case LUFFA:
            sph_tiger_init( &ctx.tiger );
            sph_tiger( &ctx.tiger, in, size );
            sph_tiger_close( &ctx.tiger, hash );
            padtiger512( hash );
            init_luffa( &ctx.luffa, 512 );
            update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                    (const BitSequence*)hash, 64 );
         break;
         case CUBEHASH:
            cubehashInit( &ctx.cube, 512, 16, 32 );
            cubehashUpdateDigest( &ctx.cube, (byte*) hash,
                                  (const byte*)in, size );
         break;
         case SHAVITE:
            shavite512_full( &ctx.shavite, hash, in, size );
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
#if defined(__AES__)
             fugue512_full( &ctx.fugue, hash, in, size );
#else
             sph_fugue512_full( &ctx.fugue, hash, in, size );
#endif
	     break;
         case SHABAL:
             sph_shabal512_init( &ctx.shabal );
             sph_shabal512( &ctx.shabal, in, size );
             sph_shabal512_close( &ctx.shabal, hash );
         break;
         case WHIRLPOOL:
             sph_whirlpool512_full( &ctx.whirlpool, hash, in, size );
         break;
         case SHA_512:
             sph_tiger_init( &ctx.tiger );
             sph_tiger( &ctx.tiger, in, size );
             sph_tiger_close( &ctx.tiger, hash );
             padtiger512( hash );
             sph_sha512_init( &ctx.sha512 );
             sph_sha512( &ctx.sha512, hash, 64 );
             sph_sha512_close( &ctx.sha512, hash );
         break;
      }

      if ( work_restart[thrid].restart ) return 0;

      in = (void*) hash;
      size = 64;
   }
   memcpy(output, hash, 32);
   return 1;
}

int scanhash_x16rv2( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash32[8];
   uint32_t _ALIGN(128) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;  
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   casti_m128i( edata, 0 ) = mm128_bswap_32( casti_m128i( pdata, 0 ) );
   casti_m128i( edata, 1 ) = mm128_bswap_32( casti_m128i( pdata, 1 ) );
   casti_m128i( edata, 2 ) = mm128_bswap_32( casti_m128i( pdata, 2 ) );
   casti_m128i( edata, 3 ) = mm128_bswap_32( casti_m128i( pdata, 3 ) );
   casti_m128i( edata, 4 ) = mm128_bswap_32( casti_m128i( pdata, 4 ) );

   static __thread uint32_t s_ntime = UINT32_MAX;
   if ( s_ntime != pdata[17] )
   {
      uint32_t ntime = swab32(pdata[17]);
      x16_r_s_getAlgoString( (const uint8_t*) (&edata[1]), x16r_hash_order );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
              applog( LOG_DEBUG, "hash order %s (%08x)",
                                 x16r_hash_order, ntime );
   }

   if ( bench )   ptarget[7] = 0x0cff;

   do
   {
      edata[19] = nonce;
      if ( x16rv2_hash( hash32, edata, thr_id ) )
      if ( unlikely( valid_hash( hash32, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( nonce );
         submit_solution( work, hash32, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !(*restart) );
   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce;
   return 0;
}

#endif
