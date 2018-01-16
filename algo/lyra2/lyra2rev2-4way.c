#include "lyra2rev2-gate.h"
#include <memory.h>

#ifdef __AVX2__	

#include "algo/blake/blake-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"

#include "algo/cubehash/sph_cubehash.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/cubehash/sse2/cubehash_sse2.h" 

typedef struct {
   blake256_4way_context     blake;
   keccak256_4way_context    keccak;
   cubehashParam             cube;
   skein256_4way_context     skein;
        sph_bmw256_context       bmw;

} lyra2v2_4way_ctx_holder;

static lyra2v2_4way_ctx_holder l2v2_4way_ctx;

void init_lyra2rev2_4way_ctx()
{
//   blake256_4way_init( &l2v2_4way_ctx.blake );
   keccak256_4way_init( &l2v2_4way_ctx.keccak );
   cubehashInit( &l2v2_4way_ctx.cube, 256, 16, 32 );
   skein256_4way_init( &l2v2_4way_ctx.skein );
        sph_bmw256_init( &l2v2_4way_ctx.bmw );
}

void lyra2rev2_4way_hash( void *state, const void *input )
{
   uint32_t hash0[8] __attribute__ ((aligned (64)));
   uint32_t hash1[8] __attribute__ ((aligned (32)));
   uint32_t hash2[8] __attribute__ ((aligned (32)));
   uint32_t hash3[8] __attribute__ ((aligned (32)));
   uint32_t vhash[8*4] __attribute__ ((aligned (64)));
   uint64_t vhash64[4*4] __attribute__ ((aligned (64)));
   lyra2v2_4way_ctx_holder ctx __attribute__ ((aligned (64))); 
   memcpy( &ctx, &l2v2_4way_ctx, sizeof(l2v2_4way_ctx) );

   blake256_4way( &ctx.blake, input + (64<<2), 16 );
//   blake256_4way( &ctx.blake, input, 80 );
   blake256_4way_close( &ctx.blake, vhash );

   mm256_reinterleave_4x64( vhash64, vhash, 256 );
   keccak256_4way( &ctx.keccak, vhash64, 32 );
   keccak256_4way_close( &ctx.keccak, vhash64 );
   mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   memcpy( &ctx.cube, &l2v2_4way_ctx.cube, sizeof ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   memcpy( &ctx.cube, &l2v2_4way_ctx.cube, sizeof ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   memcpy( &ctx.cube, &l2v2_4way_ctx.cube, sizeof ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );

   LYRA2REV2( l2v2_wholeMatrix, hash0, 32, hash0, 32, hash0, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash1, 32, hash1, 32, hash1, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash2, 32, hash2, 32, hash2, 32, 1, 4, 4 );
   LYRA2REV2( l2v2_wholeMatrix, hash3, 32, hash3, 32, hash3, 32, 1, 4, 4 );

   mm256_interleave_4x64( vhash64, hash0, hash1, hash2, hash3, 256 );
   skein256_4way( &ctx.skein, vhash64, 32 );
   skein256_4way_close( &ctx.skein, vhash64 );
   mm256_deinterleave_4x64( hash0, hash1, hash2, hash3, vhash64, 256 );

   memcpy( &ctx.cube, &l2v2_4way_ctx.cube, sizeof ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash0, (const byte*) hash0, 32 );
   memcpy( &ctx.cube, &l2v2_4way_ctx.cube, sizeof ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash1, (const byte*) hash1, 32 );
   memcpy( &ctx.cube, &l2v2_4way_ctx.cube, sizeof ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash2, (const byte*) hash2, 32 );
   memcpy( &ctx.cube, &l2v2_4way_ctx.cube, sizeof ctx.cube );
   cubehashUpdateDigest( &ctx.cube, (byte*) hash3, (const byte*) hash3, 32 );


	sph_bmw256( &ctx.bmw, hash0, 32 );
	sph_bmw256_close( &ctx.bmw, hash0 );
        memcpy( &ctx.bmw, &l2v2_4way_ctx.bmw, sizeof ctx.bmw );
        sph_bmw256( &ctx.bmw, hash1, 32 );
        sph_bmw256_close( &ctx.bmw, hash1 );
        memcpy( &ctx.bmw, &l2v2_4way_ctx.bmw, sizeof ctx.bmw );
        sph_bmw256( &ctx.bmw, hash2, 32 );
        sph_bmw256_close( &ctx.bmw, hash2 );
        memcpy( &ctx.bmw, &l2v2_4way_ctx.bmw, sizeof ctx.bmw );
        sph_bmw256( &ctx.bmw, hash3, 32 );
        sph_bmw256_close( &ctx.bmw, hash3 );


   memcpy( state,    hash0, 32 );
   memcpy( state+32, hash1, 32 );
   memcpy( state+64, hash2, 32 );
   memcpy( state+96, hash3, 32 );
}

int scanhash_lyra2rev2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done )
{
   uint32_t hash[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t Htarg = ptarget[7];
   uint32_t *nonces = work->nonces;
   bool *found = work->nfound;
   int num_found = 0;
   uint32_t *noncep0 = vdata + 76; // 19*4
   uint32_t *noncep1 = vdata + 77;
   uint32_t *noncep2 = vdata + 78;
   uint32_t *noncep3 = vdata + 79;

   if ( opt_benchmark )
      ( (uint32_t*)ptarget )[7] = 0x0000ff;

   swab32_array( edata, pdata, 20 );

   mm_interleave_4x32( vdata, edata, edata, edata, edata, 640 );

   blake256_4way_init( &l2v2_4way_ctx.blake );
   blake256_4way( &l2v2_4way_ctx.blake, vdata, 64 );

   do {
      found[0] = found[1] = found[2] = found[3] = false;
      be32enc( noncep0, n   );
      be32enc( noncep1, n+1 );
      be32enc( noncep2, n+2 );
      be32enc( noncep3, n+3 );

      lyra2rev2_4way_hash( hash, vdata );
      pdata[19] = n;

      if ( hash[7] <= Htarg && fulltest( hash, ptarget ) )
      {
          found[0] = true;
          num_found++;
          nonces[0] = pdata[19] = n;
          work_set_target_ratio( work, hash );
      }
      if ( (hash+8)[7] <= Htarg && fulltest( hash+8, ptarget ) )
      {
          found[1] = true;
          num_found++;
          nonces[1] = n+1;
          work_set_target_ratio( work, hash+8 );
      }
      if ( (hash+16)[7] <= Htarg && fulltest( hash+16, ptarget ) )
      {
          found[2] = true;
          num_found++;
          nonces[2] = n+2;
          work_set_target_ratio( work, hash+16 );
      }
      if ( (hash+24)[7] <= Htarg && fulltest( hash+24, ptarget ) )
      {
          found[3] = true;
          num_found++;
          nonces[3] = n+3;
          work_set_target_ratio( work, hash+24 );
      }
      n += 4;
   } while ( (num_found == 0) && (n < max_nonce-4)
                   && !work_restart[thr_id].restart);

   *hashes_done = n - first_nonce + 1;
   return num_found;
}

#endif
