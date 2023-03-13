/**
 * x16r algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 * Optimized by JayDDee@github Jan 2018
 */
#include "x16r-gate.h"

static void hex_getAlgoString(const uint32_t* prevblock, char *output)
{
   char *sptr = output;
   uint8_t* data = (uint8_t*)prevblock;

   for (uint8_t j = 0; j < X16R_HASH_FUNC_COUNT; j++) {
      uint8_t b = (15 - j) >> 1; // 16 ascii hex chars, reversed
      uint8_t algoDigit = (j & 1) ? data[b] & 0xF : data[b] >> 4;
      if (algoDigit >= 10)
         sprintf(sptr, "%c", 'A' + (algoDigit - 10));
      else
         sprintf(sptr, "%u", (uint32_t) algoDigit);
      sptr++;
   }
   *sptr = '\0';
}

static __thread x16r_context_overlay hex_ctx;

int hex_hash( void* output, const void* input, int thrid )
{
   uint32_t _ALIGN(128) hash[16];
   x16r_context_overlay ctx;
   memcpy( &ctx, &hex_ctx, sizeof(ctx) );
   void *in = (void*) input;
   int size = 80;

   char elem = x16r_hash_order[0];
   uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

   for ( int i = 0; i < 16; i++ )
   {
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
            groestl512_full( &ctx.groestl, (char*)hash, (char*)in, size<<3 );
#else
            sph_groestl512_init( &ctx.groestl );
            sph_groestl512( &ctx.groestl, in, size );
            sph_groestl512_close(&ctx.groestl, hash);
#endif
         break;
         case JH:
            if ( i == 0 )
               sph_jh512(&ctx.jh, in+64, 16 );
            else
            {   
               sph_jh512_init( &ctx.jh );
               sph_jh512(&ctx.jh, in, size );
            }
            sph_jh512_close(&ctx.jh, hash );
         break;
         case KECCAK:
            sph_keccak512_init( &ctx.keccak );
            sph_keccak512( &ctx.keccak, in, size );
            sph_keccak512_close( &ctx.keccak, hash );
         break;
         case SKEIN:
            if ( i == 0 )
               sph_skein512(&ctx.skein, in+64, 16 );
            else
            {
               sph_skein512_init( &ctx.skein );
               sph_skein512( &ctx.skein, in, size );
            }
            sph_skein512_close( &ctx.skein, hash );
         break;
         case LUFFA:
            if ( i == 0 )
            update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                          (const BitSequence*)in+64, 16 );
            else
            {
               init_luffa( &ctx.luffa, 512 );
               update_and_final_luffa( &ctx.luffa, (BitSequence*)hash,
                                             (const BitSequence*)in, size );
            }
            break;
         case CUBEHASH:
            if ( i == 0 )
               cubehashUpdateDigest( &ctx.cube, (byte*)hash,
                                          (const byte*)in+64, 16 );
            else
            {
               cubehashInit( &ctx.cube, 512, 16, 32 );
               cubehashUpdateDigest( &ctx.cube, (byte*)hash,
                                          (const byte*)in, size );
            }
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
            echo_full( &ctx.echo, (BitSequence *)hash, 512,
                              (const BitSequence *)in, size );
#else
             sph_echo512_init( &ctx.echo );
             sph_echo512( &ctx.echo, in, size );
             sph_echo512_close( &ctx.echo, hash );
#endif
         break;
         case HAMSI:
            if ( i == 0 ) 
               sph_hamsi512( &ctx.hamsi, in+64, 16 );
            else
            {
               sph_hamsi512_init( &ctx.hamsi );
               sph_hamsi512( &ctx.hamsi, in, size );
            }
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
            if ( i == 0 ) 
               sph_shabal512( &ctx.shabal, in+64, 16 );
            else
            {
               sph_shabal512_init( &ctx.shabal );
               sph_shabal512( &ctx.shabal, in, size );
            }
            sph_shabal512_close( &ctx.shabal, hash );
         break;
         case WHIRLPOOL:
            if ( i == 0 ) 
            {
                sph_whirlpool( &ctx.whirlpool, in+64, 16 );
                sph_whirlpool_close( &ctx.whirlpool, hash );
            }
            else
                sph_whirlpool512_full( &ctx.whirlpool, hash, in,  size );
         break;
         case SHA_512:
             sph_sha512_init( &ctx.sha512 );
             sph_sha512( &ctx.sha512, in, size );
             sph_sha512_close( &ctx.sha512, hash );
         break;
      }

      if ( work_restart[thrid].restart ) return 0;

      algo = (uint8_t)hash[0] % X16R_HASH_FUNC_COUNT;
      in = (void*) hash;
      size = 64;
   }
   memcpy(output, hash, 32);
   return 1;
}

int scanhash_hex( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash32[8];
   uint32_t _ALIGN(128) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;
   if ( bench )  ptarget[7] = 0x0cff;

   mm128_bswap32_80( edata, pdata );
   
   static __thread uint32_t s_ntime = UINT32_MAX;
   uint32_t ntime = swab32(pdata[17]);
   if ( s_ntime != ntime )
   {
      hex_getAlgoString( (const uint32_t*) (&edata[1]), x16r_hash_order );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
              applog( LOG_INFO, "hash order %s (%08x)", x16r_hash_order, ntime );
   }

   // Do midstate prehash on hash functions with block size <= 64 bytes.
   const char elem = x16r_hash_order[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';
   switch ( algo )
   {
      case JH:
         sph_jh512_init( &hex_ctx.jh );
         sph_jh512( &hex_ctx.jh, edata, 64 );
      break;
      case SKEIN:
         sph_skein512_init( &hex_ctx.skein );
         sph_skein512( &hex_ctx.skein, edata, 64 );
      break;
      case LUFFA:
         init_luffa( &hex_ctx.luffa, 512 );
         update_luffa( &hex_ctx.luffa, (const BitSequence*)edata, 64 );
      break;
      case CUBEHASH:
         cubehashInit( &hex_ctx.cube, 512, 16, 32 );
         cubehashUpdate( &hex_ctx.cube, (const byte*)edata, 64 );
      break;
      case HAMSI:
         sph_hamsi512_init( &hex_ctx.hamsi );
         sph_hamsi512( &hex_ctx.hamsi, edata, 64 );
      break;
      case SHABAL:
         sph_shabal512_init( &hex_ctx.shabal );
         sph_shabal512( &hex_ctx.shabal, edata, 64 );
      break;
      case WHIRLPOOL:
         sph_whirlpool_init( &hex_ctx.whirlpool );
         sph_whirlpool( &hex_ctx.whirlpool, edata, 64 );
      break;
   }
   
   do
   {
      edata[19] = nonce;
      if ( hex_hash( hash32, edata, thr_id ) );
      if ( unlikely( valid_hash( hash32, ptarget ) && !bench ) )
      {
         be32enc( &pdata[19], nonce );
         submit_solution( work, hash32, mythr );
      }
      nonce++;
   } while ( nonce < last_nonce && !(*restart) );
   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce;
   return 0;
}

