#include "miner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#include "x16r-gate.h"

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X20R_8WAY   1
#elif defined(__AVX2__) && defined(__AES__)
  #define X20R_4WAY   1
#elif defined(__SSE2__) || defined(__ARM_NEON)
  #define X20R_2WAY   1
#endif

// X20R is not what it seems. It does not permute 20 functions over 20 rounds,
// it only permutes 16 of them. The last 4 functions are victims of trying to
// fit 20 elements in the space for only 16. Arithmetic overflow recycles the
// first 4 functions.  Otherwise it's identical to X16R. 
// Welcome to the real X20R.

#define X20R_HASH_FUNC_COUNT 20
/*
enum x20r_algo
{
	BLAKE = 0,
	BMW,
	GROESTL,
	JH,
	KECCAK,
	SKEIN,
	LUFFA,
	CUBEHASH,
	SHAVITE,
	SIMD,
	ECHO,
	HAMSI,
	FUGUE,
	SHABAL,
	WHIRLPOOL,
	SHA512,
	HAVAL,       // Last 4 names are meaningless and not used
	GOST,
	RADIOGATUN,
	PANAMA,   
	X20R_HASH_FUNC_COUNT
};
*/
static __thread char x20r_hash_order[ X20R_HASH_FUNC_COUNT + 1 ] = {0};

static void x20r_getAlgoString(const uint8_t* prevblock, char *output)
{
	char *sptr = output;

	for (int j = 0; j < X20R_HASH_FUNC_COUNT; j++) {
		uint8_t b = (19 - j) >> 1; // 16 ascii hex chars, reversed
		uint8_t algoDigit = (j & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
		if (algoDigit >= 10)
			sprintf(sptr, "%c", 'A' + (algoDigit - 10));
		else
			sprintf(sptr, "%u", (uint32_t) algoDigit);
		sptr++;
	}
	*sptr = '\0';
}

#if defined(X20R_8WAY)

int x20r_8x64_hash( void* output, const void* input, int thrid )
{
   uint8_t hash[64*8] __attribute__ ((aligned (128)));
   if ( !x16r_8x64_hash_generic( hash, input, thrid, x20r_hash_order,
                                 X20R_HASH_FUNC_COUNT ) )
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

int scanhash_x20r_8x64( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
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

   static __thread uint32_t saved_height = UINT32_MAX;
   if ( work->height != saved_height )
   {
      vdata[1] = bswap_32( pdata[1] );
      vdata[2] = bswap_32( pdata[2] );
      vdata[3] = bswap_32( pdata[3] );
      saved_height = work->height;
      x20r_getAlgoString( (const uint8_t*)(&vdata[1]), x20r_hash_order );
      if ( !opt_quiet && !thr_id )
           applog( LOG_INFO, "hash order %s", x20r_hash_order );
   }

   x16r_8x64_prehash( vdata, pdata, x20r_hash_order );
   *noncev = mm512_intrlv_blend_32( _mm512_set_epi32(
                             n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                             n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      if( x20r_8x64_hash( hash, vdata, thr_id ) );
      for ( int i = 0; i < 8; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  _mm512_set1_epi64( 0x0000000800000000 ) );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}


#elif defined(X20R_4WAY)

int x20r_4x64_hash( void* output, const void* input, int thrid )
{
   uint8_t hash[64*4] __attribute__ ((aligned (64)));
   if ( !x16r_4x64_hash_generic( hash, input, thrid, x20r_hash_order,
                                 X20R_HASH_FUNC_COUNT ) )
      return 0;

   memcpy( output,     hash,     32 );
   memcpy( output+32,  hash+64,  32 );
   memcpy( output+64,  hash+128, 32 );
   memcpy( output+96,  hash+192, 32 );

   return 1;
}

int scanhash_x20r_4x64( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
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

   static __thread uint32_t saved_height = UINT32_MAX;
   if ( work->height != saved_height )
   {
      vdata[1] = bswap_32( pdata[1] );
      vdata[2] = bswap_32( pdata[2] );
      vdata[3] = bswap_32( pdata[3] );
      saved_height = work->height;
      x20r_getAlgoString( (const uint8_t*)(&vdata[1]), x20r_hash_order );
      if ( !opt_quiet && !thr_id )
           applog( LOG_INFO, "hash order %s", x20r_hash_order );
   }
   
   x16r_4x64_prehash( vdata, pdata, x20r_hash_order );
   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x20r_4x64_hash( hash, vdata, thr_id ) );
      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  _mm256_set1_epi64x( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(X20R_2WAY)

int x20r_2x64_hash( void* output, const void* input, int thrid )
{
   uint8_t hash[64*2] __attribute__ ((aligned (64)));
   if ( !x16r_2x64_hash_generic( hash, input, thrid, x20r_hash_order,
                                 X20R_HASH_FUNC_COUNT ) )
      return 0;

   memcpy( output,     hash,     32 );
   memcpy( output+32,  hash+64,  32 );

   return 1;
}

int scanhash_x20r_2x64( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*2] __attribute__ ((aligned (64)));
   uint32_t vdata[20*2] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   v128_t *noncev = (v128_t*)vdata + 9;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);

   if ( bench )  ptarget[7] = 0x0cff;

   static __thread uint32_t saved_height = UINT32_MAX;
   if ( work->height != saved_height )
   {
      vdata[1] = bswap_32( pdata[1] );
      vdata[2] = bswap_32( pdata[2] );
      vdata[3] = bswap_32( pdata[3] );
      saved_height = work->height;
      x20r_getAlgoString( (const uint8_t*)(&vdata[1]), x20r_hash_order );
      if ( !opt_quiet && !thr_id )
           applog( LOG_INFO, "hash order %s", x20r_hash_order );
   }
   
   x16r_2x64_prehash( vdata, pdata, x20r_hash_order );
   *noncev = v128_intrlv_blend_32( v128_set32( n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x20r_2x64_hash( hash, vdata, thr_id ) );
      for ( int i = 0; i < 2; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = v128_add32( *noncev, v128_64( 0x0000000200000000 ) );
      n += 2;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else

int x20r_hash( void* output, const void* input, int thrid )
{
   uint8_t hash[64] __attribute__ ((aligned (64)));
   if ( !x16r_hash_generic( hash, input, thrid, x20r_hash_order, 
                            X20R_HASH_FUNC_COUNT ) )
      return 0;

    memcpy( output, hash, 32 );
    return 1;
}

int scanhash_x20r( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(32) hash32[8];
   uint32_t _ALIGN(32) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;
   if ( bench )  ptarget[7] = 0x0cff;

   static __thread uint32_t saved_height = UINT32_MAX;
   if ( work->height != saved_height )
   {
      edata[1] = bswap_32( pdata[1] );
      edata[2] = bswap_32( pdata[2] );
      edata[3] = bswap_32( pdata[3] );
      saved_height = work->height;
      x20r_getAlgoString( (const uint8_t*)(&edata[1]), x20r_hash_order );
      if ( !opt_quiet && !thr_id )
           applog( LOG_INFO, "hash order %s", x20r_hash_order );
   }

   x16r_prehash( edata, pdata, x20r_hash_order );

   do
   {
      edata[19] = nonce;
      if ( x20r_hash( hash32, edata, thr_id ) )
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

bool register_x20r_algo( algo_gate_t* gate )
{
#if defined (X20R_8WAY)
  gate->scanhash          = (void*)&scanhash_x20r_8x64;
#elif defined (X20R_4WAY)
  gate->scanhash          = (void*)&scanhash_x20r_4x64;
#elif defined (X20R_2WAY)
  gate->scanhash          = (void*)&scanhash_x20r_2x64;
#else
  gate->scanhash          = (void*)&scanhash_x20r;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT
                      | NEON_OPT;
  opt_target_factor = 256.0;
  return true;
};

