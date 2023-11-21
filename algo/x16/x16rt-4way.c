#include "x16r-gate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined (X16RT_8WAY)

int scanhash_x16rt_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[16*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) timeHash[8*8];
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

   static __thread uint32_t s_ntime = UINT32_MAX;
   uint32_t masked_ntime = bswap_32( pdata[17] ) & 0xffffff80;
   if ( s_ntime != masked_ntime )
   {
      x16rt_getTimeHash( masked_ntime, &timeHash );
      x16rt_getAlgoString( &timeHash[0], x16r_hash_order );
      s_ntime = masked_ntime;
      if ( !opt_quiet && !thr_id )
          applog( LOG_INFO, "Hash order %s, Ntime %08x",
                            x16r_hash_order, bswap_32( pdata[17] ) );
   }

   x16r_8way_prehash( vdata, pdata, x16r_hash_order );
   *noncev = mm512_intrlv_blend_32( _mm512_set_epi32(
                             n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                             n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      if ( x16r_8way_hash( hash, vdata, thr_id ) )
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

#elif defined (X16RT_4WAY)

int scanhash_x16rt_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[4*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) timeHash[4*8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;  
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0cff;

   static __thread uint32_t s_ntime = UINT32_MAX;
   uint32_t masked_ntime = bswap_32( pdata[17] ) & 0xffffff80;
   if ( s_ntime != masked_ntime )
   {
      x16rt_getTimeHash( masked_ntime, &timeHash );
      x16rt_getAlgoString( &timeHash[0], x16r_hash_order );
      s_ntime = masked_ntime;
      if ( !opt_quiet && !thr_id )
          applog( LOG_INFO, "Hash order %s, Ntime %08x",
                            x16r_hash_order, bswap_32( pdata[17] ) );
   }

   x16r_4way_prehash( vdata, pdata, x16r_hash_order );
   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x16r_4way_hash( hash, vdata, thr_id ) )
      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  _mm256_set1_epi64x( 0x0000000400000000 ) );
      n += 4;
   } while ( (  n < last_nonce ) && !(*restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined (X16RT_2WAY)

int scanhash_x16rt_2x64( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr)
{
   uint32_t hash[2*16] __attribute__ ((aligned (64)));
   uint32_t vdata[24*2] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) timeHash[4*8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   v128_t *noncev = (v128_t*)vdata + 9;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench )  ptarget[7] = 0x0cff;

   static __thread uint32_t s_ntime = UINT32_MAX;
   uint32_t masked_ntime = bswap_32( pdata[17] ) & 0xffffff80;
   if ( s_ntime != masked_ntime )
   {
      x16rt_getTimeHash( masked_ntime, &timeHash );
      x16rt_getAlgoString( &timeHash[0], x16r_hash_order );
      s_ntime = masked_ntime;
      if ( !opt_quiet && !thr_id )
          applog( LOG_INFO, "Hash order %s, Ntime %08x",
                            x16r_hash_order, bswap_32( pdata[17] ) );
   }

   x16r_2x64_prehash( vdata, pdata, x16r_hash_order );
   *noncev = v128_intrlv_blend_32( v128_set32( n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x16r_2x64_hash( hash, vdata, thr_id ) )
      for ( int i = 0; i < 2; i++ )
      if ( unlikely( valid_hash( hash + (i<<3), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<3), mythr );
      }
      *noncev = v128_add32( *noncev, v128_64( 0x0000000200000000 ) );
      n += 2;
   } while ( (  n < last_nonce ) && !(*restart) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
