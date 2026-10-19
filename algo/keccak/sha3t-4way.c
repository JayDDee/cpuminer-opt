/*
 * sha3t -- batched paths (8x64 AVX-512 / 4x64 AVX2 / 2x64 SSE2+NEON).
 *
 * Structurally sha3d-4way.c with a third keccak256 iteration; the shared n-way
 * cores take SHA3 padding from hard_coded_eb, set by register_sha3t_algo.
 *
 * Each width self-tests: anchor the scalar reference on the BC3 block KATs,
 * then compare the batched path against it lane by lane over randomised
 * headers. Hard-fails, so a non-conformant build refuses to mine.
 *
 * NOTE: Scalar and batched paths use different nonce conventions, and the
 * differential must reproduce it or it reports false failures: scalar hashes
 * be32enc(n) at header offset 76, the batched loops blend a raw vector word so
 * lane L hashes le32enc(n+L) and byte-swaps on submit. Both self-consistent
 * (batched n just lives in byte-swapped space); inherited from sha3d/keccak.
 */

#include "keccak-gate.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "keccak-hash-4way.h"

// Shared by all three widths: build one randomised 20-word header, hash it
// n-way, and compare every lane against the scalar reference.
#if defined(SHA3T_8WAY) || defined(SHA3T_4WAY) || defined(SHA3T_2WAY)

#define SHA3T_DIFF_ITERS 64

static bool sha3t_lane_check( const void *vhash, const uint32_t *pdata,
                              int lanes, int it,
                              void (*extract)( void*, const void*, int, int ) )
{
   for ( int lane = 0; lane < lanes; lane++ )
   {
      uint32_t _ALIGN(64) eds[20];
      uint32_t _ALIGN(64) ref[8];
      uint32_t _ALIGN(64) lane_hash[8];

      for ( int i = 0; i < 19; i++ ) be32enc( &eds[i], pdata[i] );
      le32enc( &eds[19], pdata[19] + lane );   // see the nonce note above
      sha3t_hash( ref, eds );

      extract( lane_hash, vhash, lane, 256 );
      if ( memcmp( ref, lane_hash, 32 ) != 0 )
      {
         applog( LOG_ERR, "sha3t %d-way differential FAILED: iter %d lane %d",
                 lanes, it, lane );
         return false;
      }
   }
   return true;
}

static void sha3t_rand_header( uint32_t *pdata, uint32_t *lcg )
{
   for ( int i = 0; i < 20; i++ )
   {
      *lcg = (*lcg) * 1664525u + 1013904223u;
      pdata[i] = *lcg;
   }
}

#endif

#if defined(SHA3T_8WAY)

// Pre-padded driver instead of three init/update/close round trips; see
// SHA3T_PREPAD_FN in keccak-hash-4way.c. The self-test below re-checks it
// against the scalar reference at every start.
void sha3t_hash_8way( void *state, const void *input )
{
   sha3t_8x64_prepad( state, input );
}

int scanhash_sha3t_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[24*8] __attribute__ ((aligned (128)));
   uint32_t hash[16*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash7 = &(hash[49]);   // 3*16+1
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
   const uint32_t Htarg = ptarget[7];
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   *noncev = mm512_intrlv_blend_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n  , 0 ), *noncev );
   do {
      sha3t_hash_8way( hash, vdata );

      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( hash7[ lane<<1 ] <= Htarg && !bench ) )
      {
          extr_lane_8x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
              pdata[19] = bswap_32( n + lane );
              submit_solution( work, lane_hash, mythr );
          }
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  _mm512_set1_epi64( 0x0000000800000000 ) );
      n += 8;

   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool sha3t_8way_self_test( void )
{
   if ( !sha3t_kat_check() )
   {
      applog( LOG_ERR, "sha3t scalar reference KAT mismatch - cannot anchor" );
      return false;
   }

   uint32_t lcg = 0x9e3779b9u;
   for ( int it = 0; it < SHA3T_DIFF_ITERS; it++ )
   {
      uint32_t pdata[20] = { 0 };  // init only silences aarch64 -Wmaybe-uninit
      uint32_t vdata[24*8] __attribute__ ((aligned (128)));
      uint32_t vhash[16*8] __attribute__ ((aligned (128)));

      sha3t_rand_header( pdata, &lcg );
      mm512_bswap32_intrlv80_8x64( vdata, pdata );
      __m512i *noncev = (__m512i*)vdata + 9;
      const uint32_t n = pdata[19];
      *noncev = mm512_intrlv_blend_32(
                 _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                   n+3, 0, n+2, 0, n+1, 0, n  , 0 ), *noncev );
      sha3t_hash_8way( vhash, vdata );

      if ( !sha3t_lane_check( vhash, pdata, 8, it, extr_lane_8x64 ) )
         return false;
   }

   applog( LOG_NOTICE,
           "sha3t 8-way self-test PASSED (consensus KAT + %dx8 differential)",
           SHA3T_DIFF_ITERS );
   return true;
}

#elif defined(SHA3T_4WAY)

// Pre-padded driver, as for the 8-way path above.
void sha3t_hash_4way( void *state, const void *input )
{
   sha3t_4x64_prepad( state, input );
}

int scanhash_sha3t_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[24*4] __attribute__ ((aligned (64)));
   uint32_t hash[16*4] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[25]);   // 3*8+1
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
   const uint32_t Htarg = ptarget[7];
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   *noncev = mm256_intrlv_blend_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do {
      sha3t_hash_4way( hash, vdata );

      for ( int lane = 0; lane < 4; lane++ )
      if ( unlikely( hash7[ lane<<1 ] <= Htarg && !bench ) )
      {
          extr_lane_4x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
              pdata[19] = bswap_32( n + lane );
              submit_solution( work, lane_hash, mythr );
          }
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  _mm256_set1_epi64x( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool sha3t_4way_self_test( void )
{
   if ( !sha3t_kat_check() )
   {
      applog( LOG_ERR, "sha3t scalar reference KAT mismatch - cannot anchor" );
      return false;
   }

   uint32_t lcg = 0x9e3779b9u;
   for ( int it = 0; it < SHA3T_DIFF_ITERS; it++ )
   {
      uint32_t pdata[20] = { 0 };  // init only silences aarch64 -Wmaybe-uninit
      uint32_t vdata[24*4] __attribute__ ((aligned (64)));
      uint32_t vhash[16*4] __attribute__ ((aligned (64)));

      sha3t_rand_header( pdata, &lcg );
      mm256_bswap32_intrlv80_4x64( vdata, pdata );
      __m256i *noncev = (__m256i*)vdata + 9;
      const uint32_t n = pdata[19];
      *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
      sha3t_hash_4way( vhash, vdata );

      if ( !sha3t_lane_check( vhash, pdata, 4, it, extr_lane_4x64 ) )
         return false;
   }

   applog( LOG_NOTICE,
           "sha3t 4-way self-test PASSED (consensus KAT + %dx4 differential)",
           SHA3T_DIFF_ITERS );
   return true;
}

#elif defined(SHA3T_2WAY)

// Pre-padded driver, as for the 8-way path above.
void sha3t_hash_2x64( void *state, const void *input )
{
   sha3t_2x64_prepad( state, input );
}

int scanhash_sha3t_2x64( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t vdata[24*2] __attribute__ ((aligned (64)));
   uint32_t hash[16*2] __attribute__ ((aligned (32)));
   uint32_t lane_hash[8] __attribute__ ((aligned (32)));
   uint32_t *hash7 = &(hash[13]);   // 3*4+1
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t n = pdata[19];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 2;
   v128_t *noncev = (v128_t*)vdata + 9;
   const uint32_t Htarg = ptarget[7];
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   v128_bswap32_intrlv80_2x64( vdata, pdata );
   *noncev = v128_intrlv_blend_32( v128_set32( n+1, 0, n, 0 ), *noncev );
   do {
      sha3t_hash_2x64( hash, vdata );

      for ( int lane = 0; lane < 2; lane++ )
      if ( unlikely( hash7[ lane<<1 ] <= Htarg && !bench ) )
      {
          extr_lane_2x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
              pdata[19] = bswap_32( n + lane );
              submit_solution( work, lane_hash, mythr );
          }
      }
      *noncev = v128_add32( *noncev, v128_64( 0x0000000200000000 ) );
      n += 2;
   } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool sha3t_2way_self_test( void )
{
   if ( !sha3t_kat_check() )
   {
      applog( LOG_ERR, "sha3t scalar reference KAT mismatch - cannot anchor" );
      return false;
   }

   uint32_t lcg = 0x9e3779b9u;
   for ( int it = 0; it < SHA3T_DIFF_ITERS; it++ )
   {
      uint32_t pdata[20] = { 0 };  // init only silences aarch64 -Wmaybe-uninit
      uint32_t vdata[24*2] __attribute__ ((aligned (64)));
      uint32_t vhash[16*2] __attribute__ ((aligned (64)));

      sha3t_rand_header( pdata, &lcg );
      v128_bswap32_intrlv80_2x64( vdata, pdata );
      v128_t *noncev = (v128_t*)vdata + 9;
      const uint32_t n = pdata[19];
      *noncev = v128_intrlv_blend_32( v128_set32( n+1, 0, n, 0 ), *noncev );
      sha3t_hash_2x64( vhash, vdata );

      if ( !sha3t_lane_check( vhash, pdata, 2, it, extr_lane_2x64 ) )
         return false;
   }

   applog( LOG_NOTICE,
           "sha3t 2-way self-test PASSED (consensus KAT + %dx2 differential)",
           SHA3T_DIFF_ITERS );
   return true;
}

#endif
