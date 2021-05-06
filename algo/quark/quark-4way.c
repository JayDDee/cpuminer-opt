#include "cpuminer-config.h"
#include "quark-gate.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#if defined(__VAES__)
  #include "algo/groestl/groestl512-hash-4way.h"
#endif

#if defined (QUARK_8WAY)

typedef struct {
    blake512_8way_context  blake;
    bmw512_8way_context    bmw;
    jh512_8way_context     jh;
    skein512_8way_context  skein;
    keccak512_8way_context keccak;
#if defined(__VAES__)
    groestl512_4way_context groestl;
#else
    hashState_groestl       groestl;
#endif
} quark_8way_ctx_holder;

quark_8way_ctx_holder quark_8way_ctx __attribute__ ((aligned (128)));

void init_quark_8way_ctx()
{
     blake512_8way_init( &quark_8way_ctx.blake );
     bmw512_8way_init( &quark_8way_ctx.bmw );
     skein512_8way_init( &quark_8way_ctx.skein );
     jh512_8way_init( &quark_8way_ctx.jh );
     keccak512_8way_init( &quark_8way_ctx.keccak );
#if defined(__VAES__)
     groestl512_4way_init( &quark_8way_ctx.groestl, 64 );
#else
     init_groestl( &quark_8way_ctx.groestl, 64 );
#endif
}

void quark_8way_hash( void *state, const void *input )
{
    uint64_t vhash[8*8] __attribute__ ((aligned (128)));
    uint64_t vhashA[8*8] __attribute__ ((aligned (64)));
    uint64_t vhashB[8*8] __attribute__ ((aligned (64)));
    uint64_t vhashC[8*8] __attribute__ ((aligned (64)));
#if !defined(__VAES__)
    uint64_t hash0[8] __attribute__ ((aligned (64)));
    uint64_t hash1[8] __attribute__ ((aligned (64)));
    uint64_t hash2[8] __attribute__ ((aligned (64)));
    uint64_t hash3[8] __attribute__ ((aligned (64)));
    uint64_t hash4[8] __attribute__ ((aligned (64)));
    uint64_t hash5[8] __attribute__ ((aligned (64)));
    uint64_t hash6[8] __attribute__ ((aligned (64)));
    uint64_t hash7[8] __attribute__ ((aligned (64)));
#endif
    __m512i* vh  = (__m512i*)vhash;
    __m512i* vhA = (__m512i*)vhashA;
    __m512i* vhB = (__m512i*)vhashB;
    __m512i* vhC = (__m512i*)vhashC;
    __mmask8 vh_mask;
    quark_8way_ctx_holder ctx;
    const uint32_t mask = 8;
    const __m512i bit3_mask = m512_const1_64( mask );
    const __m512i zero = _mm512_setzero_si512();

    memcpy( &ctx, &quark_8way_ctx, sizeof(quark_8way_ctx) );

    blake512_8way_full( &ctx.blake, vhash, input, 80 );

    bmw512_8way_full( &ctx.bmw, vhash, vhash, 64 );
    
    vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], bit3_mask ),
                                       zero );

    
#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

    if ( ( vh_mask & 0x0f ) != 0x0f )
       groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
    if ( ( vh_mask & 0xf0 ) != 0xf0 )
       groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

    rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else

    dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash, 512 );

     if ( hash0[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
     if ( hash1[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
     if ( hash2[0] & 8)
       groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
     if ( hash3[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
     if ( hash4[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
     if ( hash5[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
     if ( hash6[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
     if ( hash7[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

    intrlv_8x64( vhashC, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7, 512 );

#endif

    if ( vh_mask & 0xff )
       skein512_8way_full( &ctx.skein, vhashB, vhash, 64 );

    mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_full( &ctx.groestl, vhashA, vhashA, 64 );
     groestl512_4way_full( &ctx.groestl, vhashB, vhashB, 64 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

    dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash, 512 );

    groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
    groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
    groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
    groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
    groestl512_full( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
    groestl512_full( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
    groestl512_full( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
    groestl512_full( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

    intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 512 );

#endif

    jh512_8way_update( &ctx.jh, vhash, 64 );
    jh512_8way_close( &ctx.jh, vhash );

    vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], bit3_mask ),
                                       zero );

    if ( ( vh_mask & 0xff ) != 0xff )
       blake512_8way_full( &ctx.blake, vhashA, vhash, 64 );
    if ( vh_mask & 0xff )
       bmw512_8way_full( &ctx.bmw, vhashB, vhash, 64 );

    mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );

    keccak512_8way_update( &ctx.keccak, vhash, 64 );
    keccak512_8way_close( &ctx.keccak, vhash );

    skein512_8way_full( &ctx.skein, vhash, vhash, 64 );

    vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], bit3_mask ),
                                       zero );

    if ( ( vh_mask & 0xff ) != 0xff )
    {
       keccak512_8way_init( &ctx.keccak );
       keccak512_8way_update( &ctx.keccak, vhash, 64 );
       keccak512_8way_close( &ctx.keccak, vhashA );
    }

    if ( vh_mask & 0xff )
    {
       jh512_8way_init( &ctx.jh );
       jh512_8way_update( &ctx.jh, vhash, 64 );
       jh512_8way_close( &ctx.jh, vhashB );
    }

   // Final blend, directly to state, only need 32 bytes.
   casti_m512i( state,0 ) = _mm512_mask_blend_epi64( vh_mask, vhA[0], vhB[0] );
   casti_m512i( state,1 ) = _mm512_mask_blend_epi64( vh_mask, vhA[1], vhB[1] );
   casti_m512i( state,2 ) = _mm512_mask_blend_epi64( vh_mask, vhA[2], vhB[2] );
   casti_m512i( state,3 ) = _mm512_mask_blend_epi64( vh_mask, vhA[3], vhB[3] );
}

int scanhash_quark_8way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash64[4*8] __attribute__ ((aligned (128)));
    uint32_t vdata[20*8] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint64_t *hash64_q3 = &(hash64[3*8]);
    uint32_t *ptarget = work->target;
    const uint64_t targ64_q3 = ((uint64_t*)ptarget)[3];
    uint32_t *pdata = work->data;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 8;
    __m512i  *noncev = (__m512i*)vdata + 9;
    const int thr_id = mythr->id; 
    const bool bench = opt_benchmark;

    mm512_bswap32_intrlv80_8x64( vdata, pdata );
    *noncev = mm512_intrlv_blend_32(
                _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                  n+3, 0, n+2, 0, n+1, 0, n  , 0 ), *noncev );
    do
    {
       quark_8way_hash( hash64, vdata );

       for ( int lane = 0; lane < 8; lane++ )
       if ( unlikely( hash64_q3[ lane ] <= targ64_q3 && !bench ) )
       {
          extr_lane_8x64( lane_hash, hash64, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
       n += 8;
    } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#elif defined (QUARK_4WAY)

typedef struct {
    blake512_4way_context  blake;
    bmw512_4way_context    bmw;
    hashState_groestl      groestl;
    jh512_4way_context     jh;
    skein512_4way_context  skein;
    keccak512_4way_context keccak;
} quark_4way_ctx_holder;

quark_4way_ctx_holder quark_4way_ctx __attribute__ ((aligned (64)));

void init_quark_4way_ctx()
{
     blake512_4way_init( &quark_4way_ctx.blake );
     bmw512_4way_init( &quark_4way_ctx.bmw );
     init_groestl( &quark_4way_ctx.groestl, 64 );
     skein512_4way_init( &quark_4way_ctx.skein );
     jh512_4way_init( &quark_4way_ctx.jh );
     keccak512_4way_init( &quark_4way_ctx.keccak );
}

void quark_4way_hash( void *state, const void *input )
{
    uint64_t hash0[8] __attribute__ ((aligned (64)));
    uint64_t hash1[8] __attribute__ ((aligned (64)));
    uint64_t hash2[8] __attribute__ ((aligned (64)));
    uint64_t hash3[8] __attribute__ ((aligned (64)));
    uint64_t vhash[8*4] __attribute__ ((aligned (64)));
    uint64_t vhashA[8*4] __attribute__ ((aligned (64)));
    uint64_t vhashB[8*4] __attribute__ ((aligned (64)));
    __m256i* vh  = (__m256i*)vhash;
    __m256i* vhA = (__m256i*)vhashA;
    __m256i* vhB = (__m256i*)vhashB;
    __m256i vh_mask;
    int h_mask;
    quark_4way_ctx_holder ctx;
    const __m256i bit3_mask = m256_const1_64( 8 );
    const __m256i zero = _mm256_setzero_si256();

    memcpy( &ctx, &quark_4way_ctx, sizeof(quark_4way_ctx) );

    blake512_4way_full( &ctx.blake, vhash, input, 80 );

    bmw512_4way_update( &ctx.bmw, vhash, 64 );
    bmw512_4way_close( &ctx.bmw, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );
    h_mask = _mm256_movemask_epi8( vh_mask );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    // A
    if ( hash0[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
    if ( hash1[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
    if ( hash2[0] & 8)
       groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
    if ( hash3[0] & 8 )
       groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

    intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

    // B
    if ( likely( h_mask & 0xffffffff ) )
       skein512_4way_full( &ctx.skein, vhashB, vhash, 64 );

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    groestl512_full( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
    groestl512_full( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
    groestl512_full( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
    groestl512_full( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

    intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

    jh512_4way_update( &ctx.jh, vhash, 64 );
    jh512_4way_close( &ctx.jh, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );
    h_mask = _mm256_movemask_epi8( vh_mask );

    // A
    if ( likely( ( h_mask & 0xffffffff ) != 0xffffffff ) )
       blake512_4way_full( &ctx.blake, vhashA, vhash, 64 );
    // B
    if ( likely( h_mask & 0xffffffff ) )
    {
       bmw512_4way_init( &ctx.bmw );
       bmw512_4way_update( &ctx.bmw, vhash, 64 );
       bmw512_4way_close( &ctx.bmw, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    keccak512_4way_update( &ctx.keccak, vhash, 64 );
    keccak512_4way_close( &ctx.keccak, vhash );

    skein512_4way_full( &ctx.skein, vhash, vhash, 64 );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );
    h_mask = _mm256_movemask_epi8( vh_mask );

    // A
    if ( likely( ( h_mask & 0xffffffff ) != 0xffffffff ) )
    {
       keccak512_4way_init( &ctx.keccak );
       keccak512_4way_update( &ctx.keccak, vhash, 64 );
       keccak512_4way_close( &ctx.keccak, vhashA );
    }
    // B
    if ( likely( h_mask & 0xffffffff ) )
    {
       jh512_4way_init( &ctx.jh );
       jh512_4way_update( &ctx.jh, vhash, 64 );
       jh512_4way_close( &ctx.jh, vhashB );
    }

    // Final blend, directly to state, only need 32 bytes.
    casti_m256i( state, 0 ) = _mm256_blendv_epi8( vhA[0], vhB[0], vh_mask );
    casti_m256i( state, 1 ) = _mm256_blendv_epi8( vhA[1], vhB[1], vh_mask );
    casti_m256i( state, 2 ) = _mm256_blendv_epi8( vhA[2], vhB[2], vh_mask );
    casti_m256i( state, 3 ) = _mm256_blendv_epi8( vhA[3], vhB[3], vh_mask );
}

int scanhash_quark_4way( struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash64[4*4] __attribute__ ((aligned (64)));
    uint32_t vdata[20*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint64_t *hash64_q3 = &(hash64[3*4]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    const uint64_t targ64_q3 = ((uint64_t*)ptarget)[3];
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce - 4;
    __m256i  *noncev = (__m256i*)vdata + 9;
    const int thr_id = mythr->id;
    const bool bench = opt_benchmark;
 
    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    *noncev = mm256_intrlv_blend_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
    do
    {
       quark_4way_hash( hash64, vdata );

       for ( int lane = 0; lane < 4; lane++ )
       if ( hash64_q3[ lane ] <= targ64_q3 && !bench )
       {
          extr_lane_4x64( lane_hash, hash64, lane, 256 );
          if ( valid_hash( lane_hash, ptarget ) )
          {
             pdata[19] = bswap_32( n + lane );
             submit_solution( work, lane_hash, mythr );
          }
       }
       *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
       n += 4;
    } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );

    pdata[19] = n;
    *hashes_done = n - first_nonce;
    return 0;
}

#endif
