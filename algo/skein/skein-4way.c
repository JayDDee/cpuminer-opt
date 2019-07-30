#include "skein-gate.h"
#include <string.h>
#include <stdint.h>
#include "skein-hash-4way.h"
#if defined(__SHA__)
  #include <openssl/sha.h>
#else
  #include "algo/sha/sha-hash-4way.h"
#endif

#if defined (SKEIN_4WAY)

void skeinhash_4way( void *state, const void *input )
{
     uint64_t vhash64[16*4] __attribute__ ((aligned (64)));
     skein512_4way_context ctx_skein;
#if defined(__SHA__)
     uint32_t hash0[16] __attribute__ ((aligned (64)));
     uint32_t hash1[16] __attribute__ ((aligned (64)));
     uint32_t hash2[16] __attribute__ ((aligned (64)));
     uint32_t hash3[16] __attribute__ ((aligned (64)));
     SHA256_CTX           ctx_sha256;
#else
     uint32_t vhash32[16*4] __attribute__ ((aligned (64)));
     sha256_4way_context ctx_sha256;
#endif

     skein512_4way_init( &ctx_skein );
     skein512_4way( &ctx_skein, input, 80 );
     skein512_4way_close( &ctx_skein, vhash64 );

#if defined(__SHA__)      
     dintrlv_4x64( hash0, hash1, hash2, hash3, vhash64, 512 );

     SHA256_Init( &ctx_sha256 );
     SHA256_Update( &ctx_sha256, (unsigned char*)hash0, 64 );
     SHA256_Final( (unsigned char*)hash0, &ctx_sha256 );

     SHA256_Init( &ctx_sha256 );
     SHA256_Update( &ctx_sha256, (unsigned char*)hash1, 64 );
     SHA256_Final( (unsigned char*)hash1, &ctx_sha256 );

     SHA256_Init( &ctx_sha256 );
     SHA256_Update( &ctx_sha256, (unsigned char*)hash2, 64 );
     SHA256_Final( (unsigned char*)hash2, &ctx_sha256 );

     SHA256_Init( &ctx_sha256 );
     SHA256_Update( &ctx_sha256, (unsigned char*)hash3, 64 );
     SHA256_Final( (unsigned char*)hash3, &ctx_sha256 );

     intrlv_4x32( state, hash0, hash1, hash2, hash3, 256 );
#else
     rintrlv_4x64_4x32( vhash32, vhash64, 512 );

     sha256_4way_init( &ctx_sha256 );
     sha256_4way( &ctx_sha256, vhash32, 64 );
     sha256_4way_close( &ctx_sha256, state );
#endif
}

int scanhash_skein_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t hash[16*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (32)));
    uint32_t *hash7 = &(hash[7<<2]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint32_t Htarg = ptarget[7];
    const uint32_t first_nonce = pdata[19];
    uint32_t n = first_nonce;
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
    int thr_id = mythr->id;  // thr_id arg is deprecated

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   do
   {
       *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

       skeinhash_4way( hash, vdata );

       for ( int lane = 0; lane < 4; lane++ )
       if (  hash7[ lane ] <= Htarg )
       {
          extr_lane_4x32( lane_hash, hash, lane, 256 );
          if ( fulltest( lane_hash, ptarget ) )
          {
             pdata[19] = n + lane;
             submit_lane_solution( work, lane_hash, mythr, lane );
          }
       }
       n += 4;
    } while ( (n < max_nonce) && !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return 0;
}

#endif
