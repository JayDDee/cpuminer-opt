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

    blake512_8way_update( &ctx.blake, input, 80 );
    blake512_8way_close( &ctx.blake, vhash );

    bmw512_8way_update( &ctx.bmw, vhash, 64 );
    bmw512_8way_close( &ctx.bmw, vhash );

    vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], bit3_mask ),
                                       zero );

    
#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     if ( ( vh_mask & 0x0f ) != 0x0f )
     {
        groestl512_4way_init( &ctx.groestl, 64 );
        groestl512_4way_update_close( &ctx.groestl, vhashA, vhashA, 512 );
     }
     if ( ( vh_mask & 0xf0 ) != 0xf0 )
     {     
        groestl512_4way_init( &ctx.groestl, 64 );
        groestl512_4way_update_close( &ctx.groestl, vhashB, vhashB, 512 );
     }
     rintrlv_4x128_8x64( vhashC, vhashA, vhashB, 512 );

#else

    dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash, 512 );

    if ( hash0[0] & mask )
    {
       update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                               (char*)hash0, 512 );
    }
    if ( hash1[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                               (char*)hash1, 512 );
    }
    if ( hash2[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                               (char*)hash2, 512 );
    }
    if ( hash3[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                               (char*)hash3, 512 );
    }
    if ( hash4[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash4,
                                               (char*)hash4, 512 );
    }
    if ( hash5[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash5,
                                               (char*)hash5, 512 );
    }
    if ( hash6[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash6,
                                               (char*)hash6, 512 );
    }
    if ( hash7[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash7,
                                               (char*)hash7, 512 );
    }

    intrlv_8x64( vhashC, hash0, hash1, hash2, hash3, hash4, hash5, hash6,
                         hash7, 512 );

#endif

    if ( vh_mask & 0xff )
    {
       skein512_8way_update( &ctx.skein, vhash, 64 );
       skein512_8way_close( &ctx.skein, vhashB );
    }

    mm512_blend_hash_8x64( vh, vhC, vhB, vh_mask );

#if defined(__VAES__)

     rintrlv_8x64_4x128( vhashA, vhashB, vhash, 512 );

     groestl512_4way_init( &ctx.groestl, 64 );
     groestl512_4way_update_close( &ctx.groestl, vhashA, vhashA, 512 );
     groestl512_4way_init( &ctx.groestl, 64 );
     groestl512_4way_update_close( &ctx.groestl, vhashB, vhashB, 512 );

     rintrlv_4x128_8x64( vhash, vhashA, vhashB, 512 );

#else

    dintrlv_8x64( hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                  vhash, 512 );

    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash4, (char*)hash4, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash5, (char*)hash5, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash6, (char*)hash6, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash7, (char*)hash7, 512 );

    intrlv_8x64( vhash, hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
                 512 );

#endif

    jh512_8way_update( &ctx.jh, vhash, 64 );
    jh512_8way_close( &ctx.jh, vhash );

    vh_mask = _mm512_cmpeq_epi64_mask( _mm512_and_si512( vh[0], bit3_mask ),
                                       zero );

    if ( ( vh_mask & 0xff ) != 0xff )
    {
       blake512_8way_init( &ctx.blake );
       blake512_8way_update( &ctx.blake, vhash, 64 );
       blake512_8way_close( &ctx.blake, vhashA );
    }

    if ( vh_mask & 0xff )
    {
       bmw512_8way_init( &ctx.bmw );
       bmw512_8way_update( &ctx.bmw, vhash, 64 );
       bmw512_8way_close( &ctx.bmw, vhashB );
    }

    mm512_blend_hash_8x64( vh, vhA, vhB, vh_mask );

    keccak512_8way_update( &ctx.keccak, vhash, 64 );
    keccak512_8way_close( &ctx.keccak, vhash );

    skein512_8way_init( &ctx.skein );
    skein512_8way_update( &ctx.skein, vhash, 64 );
    skein512_8way_close( &ctx.skein, vhash );

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
    uint32_t hash[8*8] __attribute__ ((aligned (128)));
    uint32_t vdata[24*8] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint32_t *hash7 = &(hash[49]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    __m512i  *noncev = (__m512i*)vdata + 9;   // aligned
    int thr_id = mythr->id; 
    const uint32_t Htarg = ptarget[7];

    mm512_bswap32_intrlv80_8x64( vdata, pdata );
    do
    {
       *noncev = mm512_intrlv_blend_32( mm512_bswap_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n  , 0 ) ), *noncev );

       quark_8way_hash( hash, vdata );
       pdata[19] = n;

       for ( int i = 0; i < 8; i++ )
       if ( unlikely( hash7[ i<<1 ] <= Htarg ) )
       {
          extr_lane_8x64( lane_hash, hash, i, 256 );
          if ( likely( fulltest( lane_hash, ptarget ) && !opt_benchmark ) )
          {
            pdata[19] = n+i;
            submit_lane_solution( work, lane_hash, mythr, i );
          }
       }
       n += 8;
    } while ( ( n < max_nonce-8 ) && !work_restart[thr_id].restart );

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
    quark_4way_ctx_holder ctx;
    const __m256i bit3_mask = m256_const1_64( 8 );
    const uint32_t mask = 8;
    const __m256i zero = _mm256_setzero_si256();

    memcpy( &ctx, &quark_4way_ctx, sizeof(quark_4way_ctx) );

    blake512_4way_update( &ctx.blake, input, 80 );
    blake512_4way_close( &ctx.blake, vhash );

    bmw512_4way_update( &ctx.bmw, vhash, 64 );
    bmw512_4way_close( &ctx.bmw, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    if ( hash0[0] & mask )
    {
       update_and_final_groestl( &ctx.groestl, (char*)hash0,
                                               (char*)hash0, 512 );
    }
    if ( hash1[0] & mask )
    {
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash1,
                                               (char*)hash1, 512 );
    }
    if ( hash2[0] & mask )
    {   
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash2,
                                               (char*)hash2, 512 );
    }
    if ( hash3[0] & mask )
    {   
       reinit_groestl( &ctx.groestl );
       update_and_final_groestl( &ctx.groestl, (char*)hash3,
                                               (char*)hash3, 512 );
    }

    intrlv_4x64( vhashA, hash0, hash1, hash2, hash3, 512 );

    if ( mm256_anybits1( vh_mask ) )   
    {
       skein512_4way_update( &ctx.skein, vhash, 64 );
       skein512_4way_close( &ctx.skein, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    dintrlv_4x64( hash0, hash1, hash2, hash3, vhash, 512 );

    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash0, (char*)hash0, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash1, (char*)hash1, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash2, (char*)hash2, 512 );
    reinit_groestl( &ctx.groestl );
    update_and_final_groestl( &ctx.groestl, (char*)hash3, (char*)hash3, 512 );

    intrlv_4x64( vhash, hash0, hash1, hash2, hash3, 512 );

    jh512_4way_update( &ctx.jh, vhash, 64 );
    jh512_4way_close( &ctx.jh, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );

    if ( mm256_anybits1( vh_mask ) )   
    {
       blake512_4way_init( &ctx.blake );
       blake512_4way_update( &ctx.blake, vhash, 64 );
       blake512_4way_close( &ctx.blake, vhashA );
    }

    if ( mm256_anybits0( vh_mask ) )
    {
       bmw512_4way_init( &ctx.bmw );
       bmw512_4way_update( &ctx.bmw, vhash, 64 );
       bmw512_4way_close( &ctx.bmw, vhashB );
    }

    mm256_blend_hash_4x64( vh, vhA, vhB, vh_mask );

    keccak512_4way_update( &ctx.keccak, vhash, 64 );
    keccak512_4way_close( &ctx.keccak, vhash );

    skein512_4way_init( &ctx.skein );
    skein512_4way_update( &ctx.skein, vhash, 64 );
    skein512_4way_close( &ctx.skein, vhash );

    vh_mask = _mm256_cmpeq_epi64( _mm256_and_si256( vh[0], bit3_mask ), zero );

    if ( mm256_anybits1( vh_mask ) )    
    {
       keccak512_4way_init( &ctx.keccak );
       keccak512_4way_update( &ctx.keccak, vhash, 64 );
       keccak512_4way_close( &ctx.keccak, vhashA );
    }

    if ( mm256_anybits0( vh_mask ) )
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
    uint32_t hash[4*8] __attribute__ ((aligned (64)));
    uint32_t vdata[24*4] __attribute__ ((aligned (64)));
    uint32_t lane_hash[8] __attribute__ ((aligned (64)));
    uint32_t *hash7 = &(hash[25]);
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    __m256i  *noncev = (__m256i*)vdata + 9;   // aligned
    int thr_id = mythr->id;
    const uint32_t Htarg = ptarget[7];
 
    mm256_bswap32_intrlv80_4x64( vdata, pdata );
    do
    {
       *noncev = mm256_intrlv_blend_32( mm256_bswap_32(
                _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ) ), *noncev );

       quark_4way_hash( hash, vdata );
       pdata[19] = n;

       for ( int i = 0; i < 4; i++ )
       if ( unlikely( hash7[ i<<1 ] <= Htarg ) )
       {
          extr_lane_4x64( lane_hash, hash, i, 256 );
          if ( likely( fulltest( lane_hash, ptarget ) && !opt_benchmark ) )
          {
            pdata[19] = n+i;
            submit_lane_solution( work, lane_hash, mythr, i );
          }
       }
       n += 4;
    } while ( ( n < max_nonce ) && !work_restart[thr_id].restart );

    *hashes_done = n - first_nonce + 1;
    return 0;
}

#endif
