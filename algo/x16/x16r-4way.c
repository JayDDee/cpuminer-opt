/**
 * x16r algo implementation
 *
 * Implementation by tpruvot@github Jan 2018
 * Optimized by https://github.com/JayDDee/ Jan 2018
 */
#include "x16r-gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// The hash and prehash code is shared among x16r, x16s, x16rt, and x21s.
// The generic function performs the x16 hash as per the hash order
// and produces a 512 bit intermediate hash which needs to be converted
// to 256 bit final hash by a wrapper function. 

#if defined (X16R_8WAY)

// Perform midstate prehash of hash functions with block size <= 72 bytes.

void x16r_8way_prehash( void *vdata, void *pdata )
{
   uint32_t vdata2[20*8] __attribute__ ((aligned (64)));
   uint32_t edata[20] __attribute__ ((aligned (64)));

   const char elem = x16r_hash_order[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

   switch ( algo )
   {
      case JH:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         jh512_8way_init( &x16r_ctx.jh );
         jh512_8way_update( &x16r_ctx.jh, vdata, 64 );
      break;
      case KECCAK:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         keccak512_8way_init( &x16r_ctx.keccak );
         keccak512_8way_update( &x16r_ctx.keccak, vdata, 72 );
      break;
      case SKEIN:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         skein512_8way_init( &x16r_ctx.skein );
         skein512_8way_update( &x16r_ctx.skein, vdata, 64 );
      break;
      case LUFFA:
         mm128_bswap32_80( edata, pdata );
         intrlv_4x128( vdata2, edata, edata, edata, edata, 640 );
         luffa_4way_init( &x16r_ctx.luffa, 512 );
         luffa_4way_update( &x16r_ctx.luffa, vdata2, 64 );
         rintrlv_4x128_8x64( vdata, vdata2, vdata2, 640 );
      break;
      case CUBEHASH:
         mm128_bswap32_80( edata, pdata );
         intrlv_4x128( vdata2, edata, edata, edata, edata, 640 );
         cube_4way_init( &x16r_ctx.cube, 512, 16, 32 );
         cube_4way_update( &x16r_ctx.cube, vdata2, 64 );
         rintrlv_4x128_8x64( vdata, vdata2, vdata2, 640 );
      break;
      case HAMSI:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
         hamsi512_8way_init( &x16r_ctx.hamsi );
         hamsi512_8way_update( &x16r_ctx.hamsi, vdata, 64 );
      break;
      case SHABAL:
         mm256_bswap32_intrlv80_8x32( vdata2, pdata );
         shabal512_8way_init( &x16r_ctx.shabal );
         shabal512_8way_update( &x16r_ctx.shabal, vdata2, 64 );
         rintrlv_8x32_8x64( vdata, vdata2, 640 );
      break;
      case WHIRLPOOL:
         mm128_bswap32_80( edata, pdata );
         sph_whirlpool_init( &x16r_ctx.whirlpool );
         sph_whirlpool( &x16r_ctx.whirlpool, edata, 64 );
         intrlv_8x64( vdata, edata, edata, edata, edata,
                             edata, edata, edata, edata, 640 );
      break;
      default:
         mm512_bswap32_intrlv80_8x64( vdata, pdata );
   }
}

// Perform the full x16r hash and returns 512 bit intermediate hash.
// Called by wrapper hash function to optionally continue hashing and
// convert to final hash.

int x16r_8way_hash_generic( void* output, const void* input, int thrid )
{
   uint32_t vhash[20*8] __attribute__ ((aligned (128)));
   uint32_t hash0[20] __attribute__ ((aligned (64)));
   uint32_t hash1[20] __attribute__ ((aligned (64)));
   uint32_t hash2[20] __attribute__ ((aligned (64)));
   uint32_t hash3[20] __attribute__ ((aligned (64)));
   uint32_t hash4[20] __attribute__ ((aligned (64)));
   uint32_t hash5[20] __attribute__ ((aligned (64)));
   uint32_t hash6[20] __attribute__ ((aligned (64)));
   uint32_t hash7[20] __attribute__ ((aligned (64)));
   x16r_8way_context_overlay ctx;
   memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   void *in2 = (void*) hash2;
   void *in3 = (void*) hash3;
   void *in4 = (void*) hash4;
   void *in5 = (void*) hash5;
   void *in6 = (void*) hash6;
   void *in7 = (void*) hash7;
   int size = 80;

   dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 input, 640 );

   for ( int i = 0; i < 16; i++ )
   {
      const char elem = x16r_hash_order[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            if ( i == 0 )
               blake512_8way_full( &ctx.blake, vhash, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7, 
                            size<<3 );
               blake512_8way_full( &ctx.blake, vhash, vhash, size );
            }
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5,
                                 hash6, hash7, vhash );
         break;
         case BMW:
            bmw512_8way_init( &ctx.bmw );
            if ( i == 0 )
               bmw512_8way_update( &ctx.bmw, input, size );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
            bmw512_8way_update( &ctx.bmw, vhash, size );
            }
            bmw512_8way_close( &ctx.bmw, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case GROESTL:
#if defined(__VAES__)
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            groestl512_4way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            groestl512_4way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
            groestl512_full( &ctx.groestl, (char*)hash0, (char*)in0, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash1, (char*)in1, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash2, (char*)in2, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash3, (char*)in3, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash4, (char*)in4, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash5, (char*)in5, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash6, (char*)in6, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash7, (char*)in7, size<<3 );
#endif
         break;
         case JH:
            if ( i == 0 )
               jh512_8way_update( &ctx.jh, input + (64<<3), 16 );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7, 
                            size<<3 );
               jh512_8way_init( &ctx.jh );
               jh512_8way_update( &ctx.jh, vhash, size );
            }
            jh512_8way_close( &ctx.jh, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case KECCAK:
           if ( i == 0 )
               keccak512_8way_update( &ctx.keccak, input + (72<<3), 8 );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7, 
                            size<<3 );
               keccak512_8way_init( &ctx.keccak );
               keccak512_8way_update( &ctx.keccak, vhash, size );
            }
            keccak512_8way_close( &ctx.keccak, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case SKEIN:
            if ( i == 0 )
               skein512_8way_update( &ctx.skein, input + (64<<3), 16 );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               skein512_8way_init( &ctx.skein );
               skein512_8way_update( &ctx.skein, vhash, size );
            }
            skein512_8way_close( &ctx.skein, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case LUFFA:
            if ( i == 0 )
            {
               intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
               luffa_4way_update_close( &ctx.luffa, vhash,
                                                    vhash + (16<<2), 16 );
               dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
               luffa_4way_update_close( &ctx.luffa, vhash, 
                                                    vhash + (16<<2), 16 );
               dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
            }
            else
            {
               intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
               luffa512_4way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
               intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
               luffa512_4way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
            }
         break;
         case CUBEHASH:
            if ( i == 0 )
            {
               intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
               cube_4way_update_close( &ctx.cube, vhash,
                                                  vhash + (16<<2), 16 );
               dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
               cube_4way_update_close( &ctx.cube, vhash,
                                                  vhash + (16<<2), 16 );
               dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
            }
            else
            {
               intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
               cube_4way_full( &ctx.cube, vhash, 512, vhash, size );
               dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
               intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
               cube_4way_full( &ctx.cube, vhash, 512, vhash, size );
               dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
            }
         break;
         case SHAVITE:
#if defined(__VAES__)
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            shavite512_4way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            shavite512_4way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
            shavite512_full( &ctx.shavite, hash0, in0, size );
            shavite512_full( &ctx.shavite, hash1, in1, size );
            shavite512_full( &ctx.shavite, hash2, in2, size );
            shavite512_full( &ctx.shavite, hash3, in3, size );
            shavite512_full( &ctx.shavite, hash4, in4, size );
            shavite512_full( &ctx.shavite, hash5, in5, size );
            shavite512_full( &ctx.shavite, hash6, in6, size );
            shavite512_full( &ctx.shavite, hash7, in7, size );
#endif
         break;
         case SIMD:
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            simd512_4way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            simd512_4way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
         break;
         case ECHO:
#if defined(__VAES__)
            intrlv_4x128( vhash, in0, in1, in2, in3, size<<3 );
            echo_4way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_4x128_512( hash0, hash1, hash2, hash3, vhash );
            intrlv_4x128( vhash, in4, in5, in6, in7, size<<3 );
            echo_4way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_4x128_512( hash4, hash5, hash6, hash7, vhash );
#else
            echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                              (const BitSequence *)in0, size );
            echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                              (const BitSequence *)in1, size );
            echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                              (const BitSequence *)in2, size );
            echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                              (const BitSequence *)in3, size );
            echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                              (const BitSequence *)in4, size );
            echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                              (const BitSequence *)in5, size );
            echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                              (const BitSequence *)in6, size );
            echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                              (const BitSequence *)in7, size );
#endif
         break;
         case HAMSI:
            if ( i == 0 )
               hamsi512_8way_update( &ctx.hamsi, input + (64<<3), 16 );
            else
            {
               intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                            size<<3 );
               hamsi512_8way_init( &ctx.hamsi );
               hamsi512_8way_update( &ctx.hamsi, vhash, size );
            }
            hamsi512_8way_close( &ctx.hamsi, vhash );
            dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case FUGUE:
             fugue512_full( &ctx.fugue, hash0, in0, size );
             fugue512_full( &ctx.fugue, hash1, in1, size );
             fugue512_full( &ctx.fugue, hash2, in2, size );
             fugue512_full( &ctx.fugue, hash3, in3, size );
             fugue512_full( &ctx.fugue, hash4, in4, size );
             fugue512_full( &ctx.fugue, hash5, in5, size );
             fugue512_full( &ctx.fugue, hash6, in6, size );
             fugue512_full( &ctx.fugue, hash7, in7, size );
         break;
         case SHABAL:
             intrlv_8x32( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                             size<<3 );
             if ( i == 0 )
                shabal512_8way_update( &ctx.shabal, vhash + (16<<3), 16 );
             else
             {
                shabal512_8way_init( &ctx.shabal );
                shabal512_8way_update( &ctx.shabal, vhash, size );
             }
             shabal512_8way_close( &ctx.shabal, vhash );
             dintrlv_8x32_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                          hash7, vhash );
         break;
         case WHIRLPOOL:
            if ( i == 0 )
            {
               sph_whirlpool( &ctx.whirlpool, in0 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash0 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in1 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in2 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in3 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in4 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash4 ); 
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in5 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash5 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in6 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash6 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in7 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash7 );
            }
            else
            {
               sph_whirlpool512_full( &ctx.whirlpool, hash0, in0, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash1, in1, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash2, in2, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash3, in3, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash4, in4, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash5, in5, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash6, in6, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash7, in7, size );
            }
         break;
         case SHA_512:
             sha512_8way_init( &ctx.sha512 );
             if ( i == 0 )
                sha512_8way_update( &ctx.sha512, input, size );
             else
             {
                intrlv_8x64( vhash, in0, in1, in2, in3, in4, in5, in6, in7,
                             size<<3 );
                sha512_8way_update( &ctx.sha512, vhash, size );
             }
             sha512_8way_close( &ctx.sha512, vhash );
             dintrlv_8x64_512( hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                               hash7, vhash );
          break;
      }

      if ( work_restart[thrid].restart ) return 0;

      size = 64;
   }

   memcpy( output,     hash0, 64 );
   memcpy( output+64,  hash1, 64 );
   memcpy( output+128, hash2, 64 );
   memcpy( output+192, hash3, 64 );
   memcpy( output+256, hash4, 64 );
   memcpy( output+320, hash5, 64 );
   memcpy( output+384, hash6, 64 );
   memcpy( output+448, hash7, 64 );

   return 1;
}

// x16-r,-s,-rt wrapper called directly by scanhash to repackage 512 bit
// hash to 256 bit final hash.
int x16r_8way_hash( void* output, const void* input, int thrid )
{
   uint8_t hash[64*8] __attribute__ ((aligned (128)));
   if ( !x16r_8way_hash_generic( hash, input, thrid ) )
      return 0;

   memcpy( output,     hash,     32 );
   memcpy( output+32,  hash+64,  32 );
   memcpy( output+64,  hash+128, 32 );
   memcpy( output+96,  hash+192, 32 );
   memcpy( output+128, hash+256, 32 );
   memcpy( output+160, hash+320, 32 );
   memcpy( output+192, hash+384, 32 );
   memcpy( output+224, hash+448, 32 );

   return 1;
   }

// x16r only
int scanhash_x16r_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t bedata1[2] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
    __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   const int thr_id = mythr->id;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench )   ptarget[7] = 0x0cff;

   bedata1[0] = bswap_32( pdata[1] );
   bedata1[1] = bswap_32( pdata[2] );

   static __thread uint32_t s_ntime = UINT32_MAX;
   const uint32_t ntime = bswap_32( pdata[17] );
   if ( s_ntime != ntime )
   {
      x16_r_s_getAlgoString( (const uint8_t*)bedata1, x16r_hash_order );
      s_ntime = ntime;

      if ( opt_debug && !thr_id )
          applog( LOG_INFO, "hash order %s (%08x)", x16r_hash_order, ntime );
   }

   x16r_8way_prehash( vdata, pdata );
   *noncev = mm512_intrlv_blend_32( _mm512_set_epi32(
                             n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                             n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      if( x16r_8way_hash( hash, vdata, thr_id ) );
      for ( int i = 0; i < 8; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (X16R_4WAY)

void x16r_4way_prehash( void *vdata, void *pdata )
{
   uint32_t vdata2[20*4] __attribute__ ((aligned (64)));
   uint32_t edata[20] __attribute__ ((aligned (64)));

   const char elem = x16r_hash_order[0];
   const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

   switch ( algo )
   {
      case JH:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         jh512_4way_init( &x16r_ctx.jh );
         jh512_4way_update( &x16r_ctx.jh, vdata, 64 );
      break;
      case KECCAK:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         keccak512_4way_init( &x16r_ctx.keccak );
         keccak512_4way_update( &x16r_ctx.keccak, vdata, 72 );
      break;
      case SKEIN:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         skein512_4way_prehash64( &x16r_ctx.skein, vdata );
      break;
      case LUFFA:
         mm128_bswap32_80( edata, pdata );
         intrlv_2x128( vdata2, edata, edata, 640 );
         luffa_2way_init( &x16r_ctx.luffa, 512 );
         luffa_2way_update( &x16r_ctx.luffa, vdata2, 64 );
         rintrlv_2x128_4x64( vdata, vdata2, vdata2, 640 );
         break;
      case CUBEHASH:
         mm128_bswap32_80( edata, pdata );
         intrlv_2x128( vdata2, edata, edata, 640 );
         cube_2way_init( &x16r_ctx.cube, 512, 16, 32 );
         cube_2way_update( &x16r_ctx.cube, vdata2, 64 );
         rintrlv_2x128_4x64( vdata, vdata2, vdata2, 640 );
      break;
      case HAMSI:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
         hamsi512_4way_init( &x16r_ctx.hamsi );
         hamsi512_4way_update( &x16r_ctx.hamsi, vdata, 64 );
      break;
      case SHABAL:
         mm128_bswap32_intrlv80_4x32( vdata2, pdata );
         shabal512_4way_init( &x16r_ctx.shabal );
         shabal512_4way_update( &x16r_ctx.shabal, vdata2, 64 );
         rintrlv_4x32_4x64( vdata, vdata2, 640 );
      break;
      case WHIRLPOOL:
         mm128_bswap32_80( edata, pdata );
         sph_whirlpool_init( &x16r_ctx.whirlpool );
         sph_whirlpool( &x16r_ctx.whirlpool, edata, 64 );
         intrlv_4x64( vdata, edata, edata, edata, edata, 640 );
      break;
      default:
         mm256_bswap32_intrlv80_4x64( vdata, pdata );
   }
}

int x16r_4way_hash_generic( void* output, const void* input, int thrid )
{
   uint32_t vhash[20*4] __attribute__ ((aligned (128)));
   uint32_t hash0[20] __attribute__ ((aligned (64)));
   uint32_t hash1[20] __attribute__ ((aligned (64)));
   uint32_t hash2[20] __attribute__ ((aligned (64)));
   uint32_t hash3[20] __attribute__ ((aligned (64)));
   x16r_4way_context_overlay ctx;
   memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
   void *in0 = (void*) hash0;
   void *in1 = (void*) hash1;
   void *in2 = (void*) hash2;
   void *in3 = (void*) hash3;
   int size = 80;

   dintrlv_4x64( hash0, hash1, hash2, hash3, input, 640 );

   for ( int i = 0; i < 16; i++ )
   {
      const char elem = x16r_hash_order[i];
      const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

      switch ( algo )
      {
         case BLAKE:
            if ( i == 0 )
               blake512_4way_full( &ctx.blake, vhash, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               blake512_4way_full( &ctx.blake, vhash, vhash, size );
            }
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case BMW:
            bmw512_4way_init( &ctx.bmw );
            if ( i == 0 )
               bmw512_4way_update( &ctx.bmw, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               bmw512_4way_update( &ctx.bmw, vhash, size );
            }
            bmw512_4way_close( &ctx.bmw, vhash );
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case GROESTL:
#if defined(__VAES__)
            intrlv_2x128( vhash, in0, in1, size<<3 );
            groestl512_2way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            groestl512_2way_full( &ctx.groestl, vhash, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
#else
            groestl512_full( &ctx.groestl, (char*)hash0, (char*)in0, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash1, (char*)in1, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash2, (char*)in2, size<<3 );
            groestl512_full( &ctx.groestl, (char*)hash3, (char*)in3, size<<3 );
#endif
   	    break;
         case JH:
            if ( i == 0 )
               jh512_4way_update( &ctx.jh, input + (64<<2), 16 );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               jh512_4way_init( &ctx.jh );
               jh512_4way_update( &ctx.jh, vhash, size );
            }
            jh512_4way_close( &ctx.jh, vhash );
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case KECCAK:
           if ( i == 0 )
               keccak512_4way_update( &ctx.keccak, input + (72<<2), 8 );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               keccak512_4way_init( &ctx.keccak );
               keccak512_4way_update( &ctx.keccak, vhash, size );
            }
            keccak512_4way_close( &ctx.keccak, vhash );
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case SKEIN:
            if ( i == 0 )
               skein512_4way_final16( &ctx.skein, vhash, input + (64*4) );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               skein512_4way_full( &ctx.skein, vhash, vhash, size );
            }
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case LUFFA:
            if ( i == 0 )
            {
              intrlv_2x128( vhash, hash0, hash1, 640 );
              luffa_2way_update_close( &ctx.luffa, vhash, vhash + (16<<1), 16 );
              dintrlv_2x128_512( hash0, hash1, vhash );
              intrlv_2x128( vhash, hash2, hash3, 640 );
              memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
              luffa_2way_update_close( &ctx.luffa, vhash, vhash + (16<<1), 16 );
              dintrlv_2x128_512( hash2, hash3, vhash );
            }
            else
            {
               intrlv_2x128( vhash, in0, in1, size<<3 );
               luffa512_2way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_2x128_512( hash0, hash1, vhash );
               intrlv_2x128( vhash, in2, in3, size<<3 );
               luffa512_2way_full( &ctx.luffa, vhash, vhash, size );
               dintrlv_2x128_512( hash2, hash3, vhash );
            }
         break;
         case CUBEHASH:
            if ( i == 0 )
            {
               intrlv_2x128( vhash, in0, in1, size<<3 );
               cube_2way_update_close( &ctx.cube, vhash,
                                                  vhash + (16<<1), 16 );
               dintrlv_2x128_512( hash0, hash1, vhash );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               intrlv_2x128( vhash, in2, in3, size<<3 );
               cube_2way_update_close( &ctx.cube, vhash,
                                                  vhash + (16<<1), 16 );
               dintrlv_2x128_512( hash2, hash3, vhash );
            }
            else
            {
               intrlv_2x128( vhash, in0, in1, size<<3 );
               cube_2way_full( &ctx.cube, vhash, 512, vhash, size );
               dintrlv_2x128_512( hash0, hash1, vhash );
               intrlv_2x128( vhash, in2, in3, size<<3 );
               cube_2way_full( &ctx.cube, vhash, 512, vhash, size );
               dintrlv_2x128_512( hash2, hash3, vhash );
            }
         break;
         case SHAVITE:
#if defined(__VAES__)
            intrlv_2x128( vhash, in0, in1, size<<3 );
            shavite512_2way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            shavite512_2way_full( &ctx.shavite, vhash, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
#else
            shavite512_full( &ctx.shavite, hash0, in0, size );
            shavite512_full( &ctx.shavite, hash1, in1, size );
            shavite512_full( &ctx.shavite, hash2, in2, size );
            shavite512_full( &ctx.shavite, hash3, in3, size );
#endif
   	    break;
         case SIMD:
            intrlv_2x128( vhash, in0, in1, size<<3 );
            simd512_2way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            simd512_2way_full( &ctx.simd, vhash, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
         break;
         case ECHO:
#if defined(__VAES__)
            intrlv_2x128( vhash, in0, in1, size<<3 );
            echo_2way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_2x128_512( hash0, hash1, vhash );
            intrlv_2x128( vhash, in2, in3, size<<3 );
            echo_2way_full( &ctx.echo, vhash, 512, vhash, size );
            dintrlv_2x128_512( hash2, hash3, vhash );
#else
            echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                              (const BitSequence *)in0, size );
            echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                              (const BitSequence *)in1, size );
            echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                              (const BitSequence *)in2, size );
            echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                              (const BitSequence *)in3, size );
#endif
   	    break;
         case HAMSI:
            if ( i == 0 )
               hamsi512_4way_update( &ctx.hamsi, input + (64<<2), 16 );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               hamsi512_4way_init( &ctx.hamsi );
               hamsi512_4way_update( &ctx.hamsi, vhash, size );
            }
            hamsi512_4way_close( &ctx.hamsi, vhash );
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case FUGUE:
             fugue512_full( &ctx.fugue, hash0, in0, size );
             fugue512_full( &ctx.fugue, hash1, in1, size );
             fugue512_full( &ctx.fugue, hash2, in2, size );
             fugue512_full( &ctx.fugue, hash3, in3, size );
         break;
         case SHABAL:
             intrlv_4x32( vhash, in0, in1, in2, in3, size<<3 );
             if ( i == 0 )
                shabal512_4way_update( &ctx.shabal, vhash + (16<<2), 16 );
             else
             {
                shabal512_4way_init( &ctx.shabal );
                shabal512_4way_update( &ctx.shabal, vhash, size );
             }
             shabal512_4way_close( &ctx.shabal, vhash );
             dintrlv_4x32_512( hash0, hash1, hash2, hash3, vhash );
         break;
         case WHIRLPOOL:
            if ( i == 0 )
            {
               sph_whirlpool( &ctx.whirlpool, in0 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash0 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in1 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash1 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in2 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash2 );
               memcpy( &ctx, &x16r_ctx, sizeof(ctx) );
               sph_whirlpool( &ctx.whirlpool, in3 + 64, 16 );
               sph_whirlpool_close( &ctx.whirlpool, hash3 );
            }
            else
            {
               sph_whirlpool512_full( &ctx.whirlpool, hash0, in0, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash1, in1, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash2, in2, size );
               sph_whirlpool512_full( &ctx.whirlpool, hash3, in3, size );
            }
         break;
         case SHA_512:
            sha512_4way_init( &ctx.sha512 );
            if ( i == 0 )
               sha512_4way_update( &ctx.sha512, input, size );
            else
            {
               intrlv_4x64( vhash, in0, in1, in2, in3, size<<3 );
               sha512_4way_init( &ctx.sha512 );
               sha512_4way_update( &ctx.sha512, vhash, size );
            }
            sha512_4way_close( &ctx.sha512, vhash );
            dintrlv_4x64_512( hash0, hash1, hash2, hash3, vhash );
         break;
      }

      if ( work_restart[thrid].restart ) return 0;
      
      size = 64;
   }
   memcpy( output,     hash0, 64 );
   memcpy( output+64,  hash1, 64 );
   memcpy( output+128, hash2, 64 );
   memcpy( output+192, hash3, 64 );

   return 1;
}

int x16r_4way_hash( void* output, const void* input, int thrid )
{
   uint8_t hash[64*4] __attribute__ ((aligned (64)));
   if ( !x16r_4way_hash_generic( hash, input, thrid ) )
      return 0;

   memcpy( output,     hash,     32 );
   memcpy( output+32,  hash+64,  32 );
   memcpy( output+64,  hash+128, 32 );
   memcpy( output+96,  hash+192, 32 );

   return 1;
}

int scanhash_x16r_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t bedata1[2] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   if ( bench )  ptarget[7] = 0x0cff;

   bedata1[0] = bswap_32( pdata[1] );
   bedata1[1] = bswap_32( pdata[2] );

   static __thread uint32_t s_ntime = UINT32_MAX;
   const uint32_t ntime = bswap_32( pdata[17] );
   if ( s_ntime != ntime )
   {
      x16_r_s_getAlgoString( (const uint8_t*)bedata1, x16r_hash_order );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
         applog( LOG_INFO, "hash order %s (%08x)", x16r_hash_order, ntime );
   }

   x16r_4way_prehash( vdata, pdata );
   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x16r_4way_hash( hash, vdata, thr_id ) );
      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
