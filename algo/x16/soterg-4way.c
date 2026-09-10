/* SoterG n-way path.
 *
 * The 12-stage cascade is a subset of x16r's 16, so the whole interleaved
 * chain is reused: soterg's stage ids are translated into x16r's ids and the
 * order string is handed to x16r_{8,4}way_hash_generic with a func_count of 12.
 * Only the order derivation is soterg's own. That is also how the GPU miner
 * does it, and the ids are not the same in both enums -- SHABAL is 1 here and
 * 13 there -- so the map is load-bearing.
 */
#include "soterg-gate.h"
#include "x16r-gate.h"
#include <string.h>

#if defined(X16R_8WAY) || defined(X16R_4WAY) || defined(X16R_2WAY)

/* Shared by all widths: resolve the order once per job and translate it. */
static void soterg_nway_set_order( const uint32_t *pdata, int thr_id )
{
   /* Keyed on the MASKED time: the order only changes when the 96-second
    * bucket does, so this avoids re-deriving and re-logging every job. */
   static __thread uint32_t s_masked = UINT32_MAX;
   char own[ SOTERG_FUNC_COUNT + 1 ];
   uint32_t ntime = bswap_32( pdata[17] );
   uint32_t masked = ntime & SOTERG_TIME_MASK;

   if ( s_masked == masked ) return;
   soterg_getAlgoString( ntime, own );
   soterg_order_to_x16r_ids( own, x16r_hash_order );
   s_masked = masked;
   if ( !opt_quiet && !thr_id )
      applog( LOG_INFO, "hash order %s (%08x, masked %08x)",
              own, ntime, ntime & SOTERG_TIME_MASK );
}

#endif

#if defined(X16R_8WAY)

int scanhash_soterg_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[16*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   __m512i *noncev = (__m512i*)vdata + 9;
   const int thr_id = mythr->id;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x0cff;

   soterg_nway_set_order( pdata, thr_id );
   x16r_8way_prehash( vdata, pdata, x16r_hash_order );
   *noncev = mm512_intrlv_blend_32( _mm512_set_epi32(
                             n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                             n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      if ( x16r_8way_hash_generic( hash, vdata, thr_id, x16r_hash_order,
                                   SOTERG_FUNC_COUNT ) )
      /* 64 bytes per lane out of the generic: stride 16 uint32, digest is
       * the first 32 bytes of each. */
      for ( int i = 0; i < 8; i++ )
      if ( unlikely( valid_hash( hash + (i<<4), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<4), mythr );
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  _mm512_set1_epi64( 0x0000000800000000 ) );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(X16R_4WAY)

int scanhash_soterg_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash[16*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   __m256i *noncev = (__m256i*)vdata + 9;
   const int thr_id = mythr->id;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x0cff;

   soterg_nway_set_order( pdata, thr_id );
   x16r_4way_prehash( vdata, pdata, x16r_hash_order );
   /* 4x64: the nonce group is 256 bits wide. Using the 128-bit form here
    * writes at the wrong offset and corrupts memory. */
   *noncev = mm256_intrlv_blend_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x16r_4way_hash_generic( hash, vdata, thr_id, x16r_hash_order,
                                   SOTERG_FUNC_COUNT ) )
      /* 64 bytes per lane out of the generic: stride 16 uint32, digest is
       * the first 32 bytes of each. */
      for ( int i = 0; i < 4; i++ )
      if ( unlikely( valid_hash( hash + (i<<4), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<4), mythr );
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  _mm256_set1_epi64x( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#elif defined(X16R_2WAY)

/* 2x64 is what NEON and plain-SSE2 builds select. Without it those fall back to
 * the scalar sph cascade, which matters most on aarch64. */
int scanhash_soterg_2x64( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
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
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;

   if ( bench ) ptarget[7] = 0x0cff;

   soterg_nway_set_order( pdata, thr_id );
   x16r_2x64_prehash( vdata, pdata, x16r_hash_order );
   *noncev = v128_intrlv_blend_32( v128_set32( n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( x16r_2x64_hash_generic( hash, vdata, thr_id, x16r_hash_order,
                                   SOTERG_FUNC_COUNT ) )
      /* 64 bytes per lane out of the generic: stride 16 uint32. */
      for ( int i = 0; i < 2; i++ )
      if ( unlikely( valid_hash( hash + (i<<4), ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n+i );
         submit_solution( work, hash+(i<<4), mythr );
      }
      *noncev = v128_add32( *noncev, v128_64( 0x0000000200000000 ) );
      n += 2;
   } while ( likely( ( n < last_nonce ) && !(*restart) ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif
