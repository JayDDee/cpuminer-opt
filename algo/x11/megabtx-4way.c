#include "megabtx-gate.h"

#if defined(MEGABTX_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/blake/blake512-hash.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/sha/sha512-hash.h"
#include "algo/haval/haval-hash-4way.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/gost/sph_gost.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/fugue/fugue-aesni.h"
#include "algo/fugue/fugue-hash-4way.h"

/* 4x64 interleaved megabtx.
 *
 * Every helper takes and returns the chain state as 4x64-interleaved 512 bits,
 * so the per-job slot order can select any of them in any sequence -- unlike
 * x17-4way.c, which hard-codes one sequence and can therefore amortise its
 * layout changes. Helpers whose kernel wants a different layout (2x128 for
 * luffa/cube/shavite/simd, 4x32 for shabal/haval) convert in and back out; the
 * ones this tree has no n-way kernel for (groestl, echo, fugue, whirlpool,
 * gost512) de-interleave, run four scalar calls, and re-interleave. Those five
 * are ~36% of a nonce, which caps the gain here nearer 1.5x than 4x.
 */

union _megabtx_4way_context_overlay
{
   blake512_4x64_context   blake;
   bmw512_4x64_context     bmw;
   skein512_4x64_context   skein;
   jh512_4x64_context      jh;
   keccak512_4x64_context  keccak;
   luffa_2way_context      luffa;
   cube_2way_context       cube;
   shavite512_2way_context shavite;
   simd_2way_context       simd;
   hamsi512_4x64_context   hamsi;
   shabal512_4x32_context  shabal;
   sha512_4x64_context     sha512;
   haval256_4x32_context   haval;
   hashState_groestl       groestl;
   hashState_echo          echo;
   hashState_fugue         fugue;
#if defined(FUGUE_4X128)
   fugue512_4x128_context  fugue4;
#endif
#if defined(FUGUE_2X128)
   fugue512_2x128_context  fugue2;
#endif
   sph_whirlpool_context   whirlpool;
   sph_gost512_context     gost;
};
typedef union _megabtx_4way_context_overlay megabtx_4way_context_overlay;

#define VH   uint64_t *vhash
#define CTX  megabtx_4way_context_overlay *ctx

// ---- native 4x64 -----------------------------------------------------------

static void m4_blake( CTX, VH )
{
   blake512_4x64_full( &ctx->blake, vhash, vhash, 64 );
}

static void m4_bmw( CTX, VH )
{
   bmw512_4x64_init( &ctx->bmw );
   bmw512_4x64_update( &ctx->bmw, vhash, 64 );
   bmw512_4x64_close( &ctx->bmw, vhash );
}

static void m4_skein( CTX, VH )
{
   skein512_4x64_full( &ctx->skein, vhash, vhash, 64 );
}

static void m4_jh( CTX, VH )
{
   jh512_4x64_init( &ctx->jh );
   jh512_4x64_update( &ctx->jh, vhash, 64 );
   jh512_4x64_close( &ctx->jh, vhash );
}

static void m4_keccak( CTX, VH )
{
   keccak512_4x64_init( &ctx->keccak );
   keccak512_4x64_update( &ctx->keccak, vhash, 64 );
   keccak512_4x64_close( &ctx->keccak, vhash );
}

static void m4_hamsi( CTX, VH )
{
   hamsi512_4x64_init( &ctx->hamsi );
   hamsi512_4x64_update( &ctx->hamsi, vhash, 64 );
   hamsi512_4x64_close( &ctx->hamsi, vhash );
}

static void m4_sha512( CTX, VH )
{
   sha512_4x64_init( &ctx->sha512 );
   sha512_4x64_update( &ctx->sha512, vhash, 64 );
   sha512_4x64_close( &ctx->sha512, vhash );
}

// ---- 2x128 kernels ---------------------------------------------------------

#define VIA_2X128( call )                                                     \
   uint64_t vA[8*2] __attribute__ ((aligned (64)));                           \
   uint64_t vB[8*2] __attribute__ ((aligned (64)));                           \
   rintrlv_4x64_2x128( vA, vB, vhash, 512 );                                  \
   call( vA ); call( vB );                                                    \
   rintrlv_2x128_4x64( vhash, vA, vB, 512 )

static void m4_luffa( CTX, VH )
{
   #define L(v) luffa512_2way_full( &ctx->luffa, v, v, 64 )
   VIA_2X128( L );
   #undef L
}

static void m4_cube( CTX, VH )
{
   #define C(v) cube_2way_full( &ctx->cube, v, 512, v, 64 )
   VIA_2X128( C );
   #undef C
}

static void m4_shavite( CTX, VH )
{
   #define S(v) shavite512_2way_full( &ctx->shavite, v, v, 64 )
   VIA_2X128( S );
   #undef S
}

static void m4_simd( CTX, VH )
{
   #define D(v) simd512_2way_full( &ctx->simd, v, v, 64 )
   VIA_2X128( D );
   #undef D
}

// ---- 4x32 kernels ----------------------------------------------------------

static void m4_shabal( CTX, VH )
{
   uint32_t v32[16*4] __attribute__ ((aligned (64)));
   rintrlv_4x64_4x32( v32, vhash, 512 );
   shabal512_4x32_init( &ctx->shabal );
   shabal512_4x32_update( &ctx->shabal, v32, 64 );
   shabal512_4x32_close( &ctx->shabal, v32 );
   rintrlv_4x32_4x64( vhash, v32, 512 );
}

/* haval256 digests 256 bits, so as in the 1-way path this overwrites only the
 * low 32 bytes of each lane, leaving the high 32 holding the previous writer's
 * tail. In 4x32 layout those low halves are the leading 128 bytes, so one
 * memcpy over the front reproduces it. */
static void m4_haval( CTX, VH )
{
   uint32_t v32[16*4] __attribute__ ((aligned (64)));
   uint32_t out32[8*4] __attribute__ ((aligned (64)));
   rintrlv_4x64_4x32( v32, vhash, 512 );
   haval256_4x32_init( &ctx->haval );
   haval256_4x32_update( &ctx->haval, v32, 64 );
   haval256_4x32_close( &ctx->haval, out32 );
   memcpy( v32, out32, 8*4*sizeof(uint32_t) );
   rintrlv_4x32_4x64( vhash, v32, 512 );
}

// ---- no n-way kernel in this tree: four scalar calls ------------------------

#define VIA_SCALAR( call )                                                    \
   uint64_t h0[8] __attribute__ ((aligned (64)));                             \
   uint64_t h1[8] __attribute__ ((aligned (64)));                             \
   uint64_t h2[8] __attribute__ ((aligned (64)));                             \
   uint64_t h3[8] __attribute__ ((aligned (64)));                             \
   dintrlv_4x64_512( h0, h1, h2, h3, vhash );                                 \
   call( h0 ); call( h1 ); call( h2 ); call( h3 );                            \
   intrlv_4x64_512( vhash, h0, h1, h2, h3 )

static void m4_groestl( CTX, VH )
{
   #define G(h) groestl512_full( &ctx->groestl, (char*)(h), (const char*)(h), 512 )
   VIA_SCALAR( G );
   #undef G
}

static void m4_echo( CTX, VH )
{
   #define E(h) echo_full( &ctx->echo, (BitSequence*)(h), 512, \
                           (const BitSequence*)(h), 64 )
   VIA_SCALAR( E );
   #undef E
}

// fugue has an n-way kernel: prefer 4 lanes per call, then 2, then per-lane.
static void m4_fugue( CTX, VH )
{
#if defined(FUGUE_4X128)
   uint64_t h0[8] __attribute__ ((aligned (64)));
   uint64_t h1[8] __attribute__ ((aligned (64)));
   uint64_t h2[8] __attribute__ ((aligned (64)));
   uint64_t h3[8] __attribute__ ((aligned (64)));
   dintrlv_4x64_512( h0, h1, h2, h3, vhash );
   fugue512_4x128_full( &ctx->fugue4, h0, h1, h2, h3, h0, h1, h2, h3, 64 );
   intrlv_4x64_512( vhash, h0, h1, h2, h3 );
#elif defined(FUGUE_2X128)
   uint64_t h0[8] __attribute__ ((aligned (64)));
   uint64_t h1[8] __attribute__ ((aligned (64)));
   uint64_t h2[8] __attribute__ ((aligned (64)));
   uint64_t h3[8] __attribute__ ((aligned (64)));
   dintrlv_4x64_512( h0, h1, h2, h3, vhash );
   fugue512_2x128_full( &ctx->fugue2, h0, h1, h0, h1, 64 );
   fugue512_2x128_full( &ctx->fugue2, h2, h3, h2, h3, 64 );
   intrlv_4x64_512( vhash, h0, h1, h2, h3 );
#else
   #define F(h) fugue512_full( &ctx->fugue, h, h, 64 )
   VIA_SCALAR( F );
   #undef F
#endif
}

static void m4_whirlpool( CTX, VH )
{
   #define W(h) sph_whirlpool512_full( &ctx->whirlpool, h, h, 64 )
   VIA_SCALAR( W );
   #undef W
}

static void m4_gost( CTX, VH )
{
   #define O(h) do { sph_gost512_init( &ctx->gost );          \
                     sph_gost512( &ctx->gost, h, 64 );        \
                     sph_gost512_close( &ctx->gost, h ); } while (0)
   VIA_SCALAR( O );
   #undef O
}

// ---------------------------------------------------------------------------

/* vinput: 80-byte header, 4x64 interleaved, one nonce per lane.
 * state: four 32-byte digests, lane-major (not interleaved). */
void megabtx_4x64_hash( void *state, const void *vinput, const int *perm )
{
   uint64_t vhash[8*4] __attribute__ ((aligned (64)));
   uint64_t h0[8] __attribute__ ((aligned (64)));
   uint64_t h1[8] __attribute__ ((aligned (64)));
   uint64_t h2[8] __attribute__ ((aligned (64)));
   uint64_t h3[8] __attribute__ ((aligned (64)));
   megabtx_4way_context_overlay ctx;
   int i;

   blake512_4x64_full( &ctx.blake, vhash, vinput, 80 );

   for ( i = 1; i < MEGA_SLOTS; i++ )
   {
      switch ( perm[i] )
      {
         case  1: m4_echo   ( &ctx, vhash ); m4_blake    ( &ctx, vhash ); break;
         case  2: m4_simd   ( &ctx, vhash ); m4_bmw      ( &ctx, vhash ); break;
         case  3: m4_groestl( &ctx, vhash );                              break;
         case  4: m4_whirlpool(&ctx, vhash); m4_jh       ( &ctx, vhash ); break;
         case  5: m4_gost   ( &ctx, vhash ); m4_keccak   ( &ctx, vhash ); break;
         case  6: m4_fugue  ( &ctx, vhash ); m4_skein    ( &ctx, vhash ); break;
         case  7: m4_shavite( &ctx, vhash ); m4_luffa    ( &ctx, vhash ); break;
         case  8: m4_whirlpool(&ctx, vhash); m4_cube     ( &ctx, vhash ); break;
         case  9: m4_jh     ( &ctx, vhash ); m4_shavite  ( &ctx, vhash ); break;
         case 10: m4_blake  ( &ctx, vhash ); m4_simd     ( &ctx, vhash ); break;
         case 11: m4_shabal ( &ctx, vhash ); m4_echo     ( &ctx, vhash ); break;
         case 12: m4_hamsi  ( &ctx, vhash );                              break;
         case 13: m4_bmw    ( &ctx, vhash ); m4_fugue    ( &ctx, vhash ); break;
         case 14: m4_keccak ( &ctx, vhash ); m4_shabal   ( &ctx, vhash ); break;
         case 15: m4_luffa  ( &ctx, vhash ); m4_whirlpool( &ctx, vhash ); break;
         case 16: m4_sha512 ( &ctx, vhash ); m4_haval    ( &ctx, vhash ); break;
         case 17: m4_skein  ( &ctx, vhash ); m4_groestl  ( &ctx, vhash ); break;
         case 18: m4_simd   ( &ctx, vhash ); m4_hamsi    ( &ctx, vhash ); break;
         case 19: m4_gost   ( &ctx, vhash ); m4_haval    ( &ctx, vhash ); break;
         case 20: m4_cube   ( &ctx, vhash ); m4_sha512   ( &ctx, vhash ); break;
         case 21: m4_echo   ( &ctx, vhash ); m4_shavite  ( &ctx, vhash ); break;
         case 22: m4_luffa  ( &ctx, vhash ); m4_shabal   ( &ctx, vhash ); break;
         default: break;
      }
   }

   dintrlv_4x64_512( h0, h1, h2, h3, vhash );
   memcpy( (uint8_t*)state,       h0, 32 );
   memcpy( (uint8_t*)state +  32, h1, 32 );
   memcpy( (uint8_t*)state +  64, h2, 32 );
   memcpy( (uint8_t*)state +  96, h3, 32 );
}

static __thread uint32_t s4_ntime = UINT32_MAX;
static __thread int      s4_perm[ MEGA_SLOTS ];

int scanhash_megabtx_4x64( struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20]     __attribute__ ((aligned (64)));
   uint32_t lanes[4][20]  __attribute__ ((aligned (64)));
   uint32_t vdata[20*4]   __attribute__ ((aligned (64)));
   uint8_t  digests[4*32] __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   int lane;

   /* Build the wire header exactly as the 1-way path does, then interleave the
    * four lane headers. Deliberately NOT blake512's prehash / *_le entry
    * points: those carry their own nonce and word-order convention, and blake
    * is under 2% of a nonce -- not worth that class of bug. */
   v128_bswap32_80( edata, pdata );

   if ( edata[17] != s4_ntime )
   {
      mega_permutation( s4_perm, edata[17] );
      s4_ntime = edata[17];
   }

   for ( lane = 0; lane < 4; lane++ ) memcpy( lanes[lane], edata, 80 );

   do
   {
      for ( lane = 0; lane < 4; lane++ ) lanes[lane][19] = n + lane;
      intrlv_4x64( vdata, lanes[0], lanes[1], lanes[2], lanes[3], 640 );

      megabtx_4x64_hash( digests, vdata, s4_perm );

      for ( lane = 0; lane < 4; lane++ )
      {
         const uint32_t *lane_hash = (const uint32_t*)( digests + lane*32 );
         if ( unlikely( valid_hash( lane_hash, ptarget ) && !bench ) )
         {
            pdata[19] = bswap_32( n + lane );
            submit_solution( work, lane_hash, mythr );
         }
      }
      n += 4;
   } while ( likely( n < last_nonce && !work_restart[thr_id].restart ) );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

/* Differential self-test: four different headers through the 4-way must equal
 * the 1-way on each. This is all that stands between an interleave mistake and
 * a pool rejecting every share, so it is a hard fail. */
bool megabtx_4way_selftest( void )
{
   uint32_t lanes[4][20] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4]  __attribute__ ((aligned (64)));
   uint8_t  d4[4*32]     __attribute__ ((aligned (64)));
   uint8_t  d1[32]       __attribute__ ((aligned (64)));
   int perm[ MEGA_SLOTS ];
   int t, lane, i, fails = 0;

   for ( t = 0; t < 8; t++ )
   {
      const uint32_t ntime = 1621065943u + t * 7919u;
      mega_permutation_ex( perm, ntime, MEGABTX_BASE_TIMESTAMP, MEGABTX_VAR_1 );

      for ( lane = 0; lane < 4; lane++ )
      {
         for ( i = 0; i < 20; i++ )
            lanes[lane][i] = 0x9e3779b9u * ( i + 1 ) + t * 2654435761u + lane;
         lanes[lane][17] = ntime;
      }
      intrlv_4x64( vdata, lanes[0], lanes[1], lanes[2], lanes[3], 640 );
      megabtx_4x64_hash( d4, vdata, perm );

      for ( lane = 0; lane < 4; lane++ )
      {
         megabtx_hash_perm( d1, lanes[lane], perm );
         if ( memcmp( d1, d4 + lane*32, 32 ) )
         {
            applog( LOG_ERR, "megabtx 4-way selftest FAILED: nTime %u lane %d",
                    ntime, lane );
            fails++;
         }
      }
   }

   if ( fails )
   {
      applog( LOG_ERR, "megabtx: 4-way differs from 1-way in %d of 32 lanes",
              fails );
      return false;
   }
   applog( LOG_NOTICE, "megabtx: 4-way matches 1-way on 32/32 lanes, 8 orders" );
   return true;
}

#endif // MEGABTX_4WAY
