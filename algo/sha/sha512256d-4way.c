#include "algo-gate-api.h"
#include "sha256-hash.h"
#include "sha512-hash.h"
#include <string.h>
#include <stdint.h>

#if defined(SIMD512)
#define SHA512256D_8WAY 1
#elif defined(__AVX2__)
#define SHA512256D_4WAY 1
#elif defined(__SSE2__) || defined(__ARM_NEON)
#define SHA512256D_2WAY 1
#endif

#if defined(SHA512256D_8WAY)

static void sha512256d_8x64_init( sha512_8x64_context *ctx )
{
  ctx->count = 0;
  ctx->initialized = true;
  ctx->val[0] = v512_64( 0x22312194FC2BF72C );
  ctx->val[1] = v512_64( 0x9F555FA3C84C64C2 );
  ctx->val[2] = v512_64( 0x2393B86B6F53B151 );
  ctx->val[3] = v512_64( 0x963877195940EABD );
  ctx->val[4] = v512_64( 0x96283EE2A88EFFE3 );
  ctx->val[5] = v512_64( 0xBE5E1E2553863992 );
  ctx->val[6] = v512_64( 0x2B0199FC2C85B8AA );
  ctx->val[7] = v512_64( 0x0EB72DDC81C52CA2 );
}

int scanhash_sha512256d_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash[8*8] __attribute__ ((aligned (128)));
    uint32_t vdata[20*8] __attribute__ ((aligned (64)));
    sha512_8x64_context ctx; 
    uint32_t lane_hash[8] __attribute__ ((aligned (32)));
    uint64_t *hash_q3 = &(hash[3*8]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint64_t targ_q3 = ((uint64_t*)ptarget)[3];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 8;
    uint32_t n = first_nonce;
    __m512i  *noncev = (__m512i*)vdata + 9;
    const int thr_id = mythr->id;
    const bool bench = opt_benchmark;
    const __m512i eight = v512_64( 0x0000000800000000 );

    mm512_bswap32_intrlv80_8x64( vdata, pdata );
    *noncev = mm512_intrlv_blend_32(
                _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                  n+3, 0, n+2, 0, n+1, 0, n  , 0 ), *noncev );
    do
    {
       sha512256d_8x64_init( &ctx );
       sha512_8x64_update( &ctx, vdata, 80 );
       sha512_8x64_close( &ctx, hash );        

       sha512256d_8x64_init( &ctx );
       sha512_8x64_update( &ctx, hash, 32 );
       sha512_8x64_close( &ctx, hash );

       for ( int lane = 0; lane < 8; lane++ )
       if ( unlikely( hash_q3[ lane ] <= targ_q3 && !bench ) )
       {
          extr_lane_8x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) && !bench )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       *noncev = _mm512_add_epi32( *noncev, eight );
       n += 8;
    } while ( likely( (n < last_nonce) && !work_restart[thr_id].restart ) );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#elif defined(SHA512256D_4WAY)

static void sha512256d_4x64_init( sha512_4x64_context *ctx )
{
  ctx->count = 0;
  ctx->initialized = true;
  ctx->val[0] = v256_64( 0x22312194FC2BF72C );
  ctx->val[1] = v256_64( 0x9F555FA3C84C64C2 );
  ctx->val[2] = v256_64( 0x2393B86B6F53B151 );
  ctx->val[3] = v256_64( 0x963877195940EABD );
  ctx->val[4] = v256_64( 0x96283EE2A88EFFE3 );
  ctx->val[5] = v256_64( 0xBE5E1E2553863992 );
  ctx->val[6] = v256_64( 0x2B0199FC2C85B8AA );
  ctx->val[7] = v256_64( 0x0EB72DDC81C52CA2 );
}

int scanhash_sha512256d_4way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash[8*4] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    sha512_4x64_context ctx;
    uint32_t lane_hash[8] __attribute__ ((aligned (32)));
    uint64_t *hash_q3 = &(hash[3*4]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint64_t targ_q3 = ((uint64_t*)ptarget)[3];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 4;
    uint32_t n = first_nonce;
    const int thr_id = mythr->id;
    const bool bench = opt_benchmark;
    const __m256i four = v256_64( 0x0000000400000000 );

    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    casti_m256i( vdata,9 ) = mm256_intrlv_blend_32( _mm256_set_epi32(
                     n+3, 0, n+2, 0, n+1, 0, n, 0 ), casti_m256i( vdata,9 ) );
    do
    {
       sha512256d_4x64_init( &ctx );
       sha512_4x64_update( &ctx, vdata, 80 );
       sha512_4x64_close( &ctx, hash );

       sha512256d_4x64_init( &ctx );
       sha512_4x64_update( &ctx, hash, 32 );
       sha512_4x64_close( &ctx, hash );

       for ( int lane = 0; lane < 4; lane++ )
       if ( hash_q3[ lane ] <= targ_q3 )
       {
          extr_lane_4x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) && !bench )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       casti_m256i( vdata,9 ) = _mm256_add_epi32( casti_m256i( vdata,9 ), four );
       n += 4;
    } while ( (n < last_nonce) && !work_restart[thr_id].restart );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#elif defined(SHA512256D_2WAY)

static void sha512256d_2x64_init( sha512_2x64_context *ctx )
{
  ctx->count = 0;
  ctx->initialized = true;
  ctx->val[0] = v128_64( 0x22312194FC2BF72C );
  ctx->val[1] = v128_64( 0x9F555FA3C84C64C2 );
  ctx->val[2] = v128_64( 0x2393B86B6F53B151 );
  ctx->val[3] = v128_64( 0x963877195940EABD );
  ctx->val[4] = v128_64( 0x96283EE2A88EFFE3 );
  ctx->val[5] = v128_64( 0xBE5E1E2553863992 );
  ctx->val[6] = v128_64( 0x2B0199FC2C85B8AA );
  ctx->val[7] = v128_64( 0x0EB72DDC81C52CA2 );
}

int scanhash_sha512256d_2x64( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash[8*2] __attribute__ ((aligned (64)));
    uint32_t vdata[20*2] __attribute__ ((aligned (64)));
    sha512_2x64_context ctx;
    uint32_t lane_hash[8] __attribute__ ((aligned (32)));
    uint64_t *hash_q3 = &(hash[3*2]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint64_t targ_q3 = ((uint64_t*)ptarget)[3];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 4;
    uint32_t n = first_nonce;
    v128u64_t *noncev = (v128u64_t*)vdata + 9;
    const int thr_id = mythr->id;
    const bool bench = opt_benchmark;
    const v128_t two = v128_64( 0x0000000200000000 );

    v128_bswap32_intrlv80_2x64( vdata, pdata );
    *noncev = v128_intrlv_blend_32( v128_set32( n+1, 0, n, 0 ), *noncev );

    do
    {
       sha512256d_2x64_init( &ctx );
       sha512_2x64_update( &ctx, vdata, 80 );
       sha512_2x64_close( &ctx, hash );

       sha512256d_2x64_init( &ctx );
       sha512_2x64_update( &ctx, hash, 32 );
       sha512_2x64_close( &ctx, hash );

       for ( int lane = 0; lane < 2; lane++ )
       if ( hash_q3[ lane ] <= targ_q3 )
       {
          extr_lane_2x64( lane_hash, hash, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) && !bench )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       *noncev = v128_add32( *noncev, two );
       n += 2;
    } while ( (n < last_nonce) && !work_restart[thr_id].restart );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#else

#include "sph_sha2.h"

static const uint64_t H512_256[8] =
{
   0x22312194FC2BF72C, 0x9F555FA3C84C64C2,
   0x2393B86B6F53B151, 0x963877195940EABD,
   0x96283EE2A88EFFE3, 0xBE5E1E2553863992,
   0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
};

static void sha512256d_init( sph_sha512_context *ctx )
{
   memcpy( ctx->val, H512_256, sizeof H512_256 );
   ctx->count = 0;
}

int scanhash_sha512256d( struct work *work,   uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t hash64[8] __attribute__ ((aligned (64)));
   uint32_t endiandata[20] __attribute__ ((aligned (64)));
   sph_sha512_context ctx;
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   int thr_id = mythr->id;

   swab32_array( endiandata, pdata, 20 );

   do {
      be32enc( &endiandata[19], n );

      sha512256d_init( &ctx );
      sph_sha512( &ctx, endiandata, 80 );
      sph_sha512_close( &ctx, hash64 );

      sha512256d_init( &ctx );
      sph_sha512( &ctx, hash64, 32 );
      sph_sha512_close( &ctx, hash64 );
      
      if ( hash64[7] <= Htarg )
      if ( fulltest( hash64, ptarget ) && !opt_benchmark )
      {
         pdata[19] = n;
         submit_solution( work, hash64, mythr );
      }
      n++;

   } while (n < max_nonce && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   pdata[19] = n;

   return 0;
}

#endif

bool register_sha512256d_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
#if defined(SHA512256D_8WAY)
   gate->scanhash = (void*)&scanhash_sha512256d_8way;
#elif defined(SHA512256D_4WAY)
   gate->scanhash = (void*)&scanhash_sha512256d_4way;
#elif defined(SHA512256D_2WAY)
   gate->scanhash = (void*)&scanhash_sha512256d_2x64;
#else
   gate->scanhash = (void*)&scanhash_sha512256d;
#endif
   return true;
};

