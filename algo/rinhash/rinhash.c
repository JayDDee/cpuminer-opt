#include "rinhash-gate.h"
#include "rinhash-kat.h"
#include "algo/blake3/blake3.h"
#include "algo/argon2d/argon2d/argon2.h"
#include "algo/argon2d/argon2d/core.h"         // phase entry points, for n-way
#include "algo/keccak/keccak-hash-4way.h"      // sha3_256_prepad32
#include <string.h>
#include <stdio.h>

/* m_cost is fixed for this algo, so one thread-local block serves every hash
 * instead of the library's per-call malloc. It must be passed via
 * allocate_cbk/free_cbk; the library only skips its own allocation if those are
 * set. aligned(64) because argon2's opt.c loads blocks with vector ops and ARM's
 * mm_malloc only guarantees 16.
 * -DRINHASH_NO_TLS_MEM uses the library's allocation instead. */
#define RIN_MEM_BYTES  ( (size_t)RINHASH_M_COST * 1024 )

#if !defined(RINHASH_NO_TLS_MEM)

static __thread uint8_t rin_memory[ RIN_MEM_BYTES ]
                        __attribute__ ((aligned (64)));

static int rin_allocate( uint8_t **memory, size_t bytes )
{
   if ( bytes > RIN_MEM_BYTES ) return -1;    /* never: m_cost is fixed */
   *memory = rin_memory;
   return 0;
}

static void rin_free( uint8_t *memory, size_t bytes )
{
   /* Static storage: nothing to release. The library zeroes the block itself
    * when ARGON2_FLAG_CLEAR_MEMORY is set, which the default flags do not. */
   (void)memory; (void)bytes;
}

#endif

/* One place for the parameter block, so the scalar and n-way paths cannot
 * drift apart. */
static void rin_fill_ctx( argon2_context *ctx, uint8_t *out,
                          const uint8_t *pwd )
{
   memset( ctx, 0, sizeof *ctx );
   ctx->out     = out;
   ctx->outlen  = 32;
   ctx->pwd     = (uint8_t*)pwd;
   ctx->pwdlen  = 32;
   ctx->salt    = (uint8_t*)RINHASH_SALT;
   ctx->saltlen = (uint32_t)( sizeof(RINHASH_SALT) - 1 );
   ctx->t_cost  = RINHASH_T_COST;
   ctx->m_cost  = RINHASH_M_COST;
   ctx->lanes   = RINHASH_LANES;
   ctx->threads = RINHASH_LANES;
   ctx->version = ARGON2_VERSION_13;
   ctx->flags   = ARGON2_DEFAULT_FLAGS;
#if !defined(RINHASH_NO_TLS_MEM)
   ctx->allocate_cbk = &rin_allocate;
   ctx->free_cbk     = &rin_free;
#endif
}

void rinhash_hash( void *state, const void *input )
{
   uint8_t blake3_out[32] __attribute__ ((aligned (64)));
   uint8_t argon2_out[32] __attribute__ ((aligned (64)));
   blake3_hasher hasher;
   argon2_context ctx;

   blake3_hasher_init( &hasher );
   blake3_hasher_update( &hasher, input, 80 );
   blake3_hasher_finalize( &hasher, blake3_out, 32 );

   rin_fill_ctx( &ctx, argon2_out, blake3_out );

   if ( argon2d_ctx( &ctx ) != ARGON2_OK )
   {
      memset( state, 0xff, 32 );          // never submittable
      return;
   }

   sha3_256_prepad32( state, argon2_out );
}

/* ================== n-way batched first blocks (x86) ======================
 * `fill_first_blocks` is ~28% of a nonce and is 62 serial scalar blake2b
 * invocations: `blake2b_long(out=1024)` chains 31 of them per call, and argon2
 * uses its own vendored scalar blake2b while `fill_block` beside it is
 * vectorized. Those chains are independent ACROSS NONCES -- unlike
 * `fill_memory_blocks`, whose reference index is data-dependent -- so N nonces
 * give N independent chains for the tree's n-way blake2b. Worth ~1.21x.
 *
 * ONLY this phase is batched. `fill_memory_blocks` then runs serially per lane
 * through the single 64 KiB thread-local block, so the working set stays
 * 64 KiB + N KiB of staging instead of N x 64 KiB -- deliberate: four live
 * states are exactly the whole L2 slice on some parts.
 *
 * 8 lanes are opt-in (-DRINHASH_USE_8WAY) because the gain is inside the noise
 * floor: the ceiling is only ~1.05x once 4-way has taken the phase down to
 * ~9% of a nonce. -DRINHASH_NO_4WAY drops to scalar. The startup banner names
 * which paths a binary carries. */

#if defined(__AVX2__) && !defined(RINHASH_NO_4WAY)
#define RINHASH_4WAY 1
#endif
#if defined(SIMD512) && defined(RINHASH_USE_8WAY) && !defined(RINHASH_NO_4WAY)
#define RINHASH_8WAY 1
#endif

#if defined(RINHASH_4WAY) || defined(RINHASH_8WAY)

#include "algo/blake/blake2b-hash.h"
#include "algo/argon2d/blake2/blake2.h"        // blake2b
#include "algo/argon2d/blake2/blake2-impl.h"   // load64, as core.c uses

#define RIN_B2BOUT   64
#define RIN_LANES_4  4
#define RIN_LANES_8  8

/* argon2's load_block() is static in core.c; this is the same operation. */
static inline void rin_load_block( block *dst, const void *src )
{
   const uint8_t *in = (const uint8_t*)src;
   for ( unsigned i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++ )
      dst->v[i] = load64( in + i * 8 );
}

static inline void rin_store32le( uint8_t *p, uint32_t v )
{
   p[0] = (uint8_t)( v       ); p[1] = (uint8_t)( v >>  8 );
   p[2] = (uint8_t)( v >> 16 ); p[3] = (uint8_t)( v >> 24 );
}

/* N lanes of blake2b_long( out=1024, in=72 ), bit-identical to the scalar one.
 *
 * Both widths are generated from this one body so they cannot drift: the only
 * differences are the lane count and the n-way context type. Invocation 0
 * hashes 4+72 = 76 bytes, which blake2b_*x64_update cannot take (it consumes
 * whole 64-bit words), so it stays scalar per lane -- 1 of 31 invocations. The
 * other 30 run n-wide, and the n-way final emits the lanes already interleaved
 * the way update wants, so the chain needs no re-interleaving between steps.
 *
 * st/o are aligned(64): casti_m256i / casti_m512i store through a vector
 * lvalue, so the buffer must meet that type's alignment (32 / 64 B). A plain
 * uint64_t array does not, and an unaligned vector store segfaults. */
#define RIN_DEFINE_LONG1024( NAME, LANES, CTX, INIT, UPDATE, FINAL )           \
static void NAME( uint8_t out[LANES][ARGON2_BLOCK_SIZE],                       \
                  const uint8_t in[LANES][ARGON2_PREHASH_SEED_LENGTH] )        \
{                                                                              \
   uint8_t  first[LANES][RIN_B2BOUT];                                          \
   uint64_t st[8 * LANES] __attribute__ ((aligned (64)));                      \
   uint64_t o[8 * LANES]  __attribute__ ((aligned (64)));                      \
   uint8_t  msg[4 + ARGON2_PREHASH_SEED_LENGTH];                               \
   int l, k, w;                                                                \
                                                                               \
   rin_store32le( msg, ARGON2_BLOCK_SIZE );                                    \
   for ( l = 0; l < LANES; l++ )                                               \
   {                                                                           \
      memcpy( msg + 4, in[l], ARGON2_PREHASH_SEED_LENGTH );                    \
      blake2b( first[l], RIN_B2BOUT, msg, sizeof msg, NULL, 0 );               \
      memcpy( out[l], first[l], RIN_B2BOUT / 2 );                              \
   }                                                                           \
   for ( w = 0; w < 8; w++ )                    /* interleave chain heads */   \
      for ( l = 0; l < LANES; l++ )                                            \
         memcpy( &st[ w * LANES + l ], &first[l][ w * 8 ], 8 );                \
                                                                               \
   /* 1024 = 32 + 29*32 + 64: steps 1..29 emit 32 B/lane, step 30 emits 64,    \
    * so 31 invocations in total, exactly as the scalar version does. */        \
   for ( k = 1; k <= 30; k++ )                                                 \
   {                                                                           \
      CTX c;                                                                   \
      const int emit = ( k == 30 ) ? RIN_B2BOUT : RIN_B2BOUT / 2;              \
      const int off  = RIN_B2BOUT / 2 + ( k - 1 ) * ( RIN_B2BOUT / 2 );        \
                                                                               \
      INIT( &c, RIN_B2BOUT );                                                  \
      UPDATE( &c, st, RIN_B2BOUT );                                            \
      FINAL( &c, o );                                                          \
                                                                               \
      for ( l = 0; l < LANES; l++ )             /* de-interleave */            \
         for ( w = 0; w < emit / 8; w++ )                                      \
            memcpy( out[l] + off + w * 8, &o[ w * LANES + l ], 8 );            \
                                                                               \
      memcpy( st, o, sizeof st );                                              \
   }                                                                           \
}

/* N nonces of the whole chain. edata is the byte-swapped 20-word header; lane
 * l uses nonce n0 + l. */
#define RIN_DEFINE_HASH_NWAY( NAME, LANES, LONG1024 )                          \
static void NAME( uint8_t state[LANES][32], const uint32_t *edata,             \
                  uint32_t n0 )                                                \
{                                                                              \
   uint32_t hdr[20] __attribute__ ((aligned (64)));                            \
   uint8_t  pwd[LANES][32] __attribute__ ((aligned (64)));                     \
   uint8_t  seed[LANES][ARGON2_PREHASH_SEED_LENGTH];                           \
   uint8_t  stage[2][LANES][ARGON2_BLOCK_SIZE];                                \
   uint8_t  argon2_out[32] __attribute__ ((aligned (64)));                     \
   argon2_context ctx;                                                         \
   argon2_instance_t inst;                                                     \
   blake3_hasher hasher;                                                       \
   uint32_t memory_blocks, segment_length;                                     \
   int l, b;                                                                   \
                                                                               \
   memcpy( hdr, edata, 80 );                                                   \
   for ( l = 0; l < LANES; l++ )                                               \
   {                                                                           \
      hdr[19] = n0 + (uint32_t)l;                                              \
      blake3_hasher_init( &hasher );                                           \
      blake3_hasher_update( &hasher, hdr, 80 );                                \
      blake3_hasher_finalize( &hasher, pwd[l], 32 );                           \
   }                                                                           \
                                                                               \
   /* Geometry, exactly as argon2_ctx() derives it; same for every lane. */    \
   rin_fill_ctx( &ctx, argon2_out, pwd[0] );                                   \
   if ( validate_inputs( &ctx ) != ARGON2_OK )                                 \
   {                                                                           \
      for ( l = 0; l < LANES; l++ ) memset( state[l], 0xff, 32 );              \
      return;                                                                  \
   }                                                                           \
   memory_blocks = ctx.m_cost;                                                 \
   if ( memory_blocks < 2 * ARGON2_SYNC_POINTS * ctx.lanes )                   \
      memory_blocks = 2 * ARGON2_SYNC_POINTS * ctx.lanes;                      \
   segment_length = memory_blocks / ( ctx.lanes * ARGON2_SYNC_POINTS );        \
                                                                               \
   memset( &inst, 0, sizeof inst );                                            \
   inst.version        = ctx.version;                                          \
   inst.passes         = ctx.t_cost;                                           \
   inst.memory_blocks  = segment_length * ctx.lanes * ARGON2_SYNC_POINTS;      \
   inst.segment_length = segment_length;                                       \
   inst.lane_length    = segment_length * ARGON2_SYNC_POINTS;                  \
   inst.lanes          = ctx.lanes;                                            \
   inst.threads        = ctx.lanes;                                            \
   inst.type           = Argon2_d;                                             \
                                                                               \
   for ( l = 0; l < LANES; l++ )                 /* H0 per lane */             \
   {                                                                           \
      rin_fill_ctx( &ctx, argon2_out, pwd[l] );                                \
      initial_hash( seed[l], &ctx, Argon2_d );                                 \
      memset( seed[l] + ARGON2_PREHASH_DIGEST_LENGTH, 0,                       \
              ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH );     \
   }                                                                           \
                                                                               \
   for ( b = 0; b < 2; b++ )        /* batch: block 0 for all lanes, then 1 */ \
   {                                                                           \
      uint8_t s[LANES][ARGON2_PREHASH_SEED_LENGTH];                            \
      for ( l = 0; l < LANES; l++ )                                            \
      {                                                                        \
         memcpy( s[l], seed[l], ARGON2_PREHASH_SEED_LENGTH );                  \
         rin_store32le( s[l] + ARGON2_PREHASH_DIGEST_LENGTH, (uint32_t)b );    \
         rin_store32le( s[l] + ARGON2_PREHASH_DIGEST_LENGTH + 4, 0 );          \
      }                                                                        \
      LONG1024( stage[b],                                                      \
                (const uint8_t (*)[ARGON2_PREHASH_SEED_LENGTH])s );            \
   }                                                                           \
                                                                               \
   for ( l = 0; l < LANES; l++ )   /* serial per lane, one 64 KiB block */     \
   {                                                                           \
      rin_fill_ctx( &ctx, argon2_out, pwd[l] );                                \
      inst.context_ptr = &ctx;                                                 \
      if ( allocate_memory( &ctx, (uint8_t**)&inst.memory,                     \
                            inst.memory_blocks, sizeof(block) ) != ARGON2_OK ) \
      {                                                                        \
         memset( state[l], 0xff, 32 );                                         \
         continue;                                                             \
      }                                                                        \
      rin_load_block( &inst.memory[0], stage[0][l] );                          \
      rin_load_block( &inst.memory[1], stage[1][l] );                          \
      if ( fill_memory_blocks( &inst ) != ARGON2_OK )                          \
      {                                                                        \
         memset( state[l], 0xff, 32 );                                         \
         continue;                                                             \
      }                                                                        \
      finalize( &ctx, &inst );                   /* also runs free_cbk */      \
      sha3_256_prepad32( state[l], argon2_out );                               \
   }                                                                           \
}

#if defined(RINHASH_4WAY)
RIN_DEFINE_LONG1024( rin_b2b4_long1024, RIN_LANES_4, blake2b_4x64_ctx,
                     blake2b_4x64_init_len, blake2b_4x64_update,
                     blake2b_4x64_final_full )
RIN_DEFINE_HASH_NWAY( rinhash_hash_4way, RIN_LANES_4, rin_b2b4_long1024 )
#endif

#if defined(RINHASH_8WAY)
RIN_DEFINE_LONG1024( rin_b2b8_long1024, RIN_LANES_8, blake2b_8x64_ctx,
                     blake2b_8x64_init_len, blake2b_8x64_update,
                     blake2b_8x64_final_full )
RIN_DEFINE_HASH_NWAY( rinhash_hash_8way, RIN_LANES_8, rin_b2b8_long1024 )
#endif

#endif  // RINHASH_4WAY || RINHASH_8WAY

/* Digest and target are raw little-endian 256-bit values, so valid_hash() does
 * not apply -- it assumes the usual uint32[8] host-order layout. */
static inline int rin_hash_le_target( const uint8_t *h, const uint32_t *target )
{
   const uint8_t *t = (const uint8_t*)target;
   for ( int i = 31; i >= 0; i-- )
   {
      if ( h[i] < t[i] ) return 1;
      if ( h[i] > t[i] ) return 0;
   }
   return 1;
}

int scanhash_rinhash( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20] __attribute__ ((aligned (64)));
   uint8_t  hash[32]  __attribute__ ((aligned (64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   // BLAKE3 hashes the serialized header, so swap the work data words first;
   // the nonce then goes into the swapped buffer as a host word.
   v128_bswap32_80( edata, pdata );

#if defined(RINHASH_8WAY)
   {
      uint8_t hash8[RIN_LANES_8][32] __attribute__ ((aligned (64)));

      while ( n + RIN_LANES_8 <= last_nonce && !work_restart[thr_id].restart )
      {
         rinhash_hash_8way( hash8, edata, n );
         for ( int l = 0; l < RIN_LANES_8; l++ )
            if ( unlikely( rin_hash_le_target( hash8[l], ptarget ) && !bench ) )
            {
               pdata[19] = bswap_32( n + (uint32_t)l );
               submit_solution( work, hash8[l], mythr );
            }
         n += RIN_LANES_8;
      }
   }
#endif
#if defined(RINHASH_4WAY)
   {
      uint8_t hash4[RIN_LANES_4][32] __attribute__ ((aligned (64)));

      while ( n + RIN_LANES_4 <= last_nonce && !work_restart[thr_id].restart )
      {
         rinhash_hash_4way( hash4, edata, n );
         for ( int l = 0; l < RIN_LANES_4; l++ )
            if ( unlikely( rin_hash_le_target( hash4[l], ptarget ) && !bench ) )
            {
               pdata[19] = bswap_32( n + (uint32_t)l );
               submit_solution( work, hash4[l], mythr );
            }
         n += RIN_LANES_4;
      }
   }
#endif

   // Tail of the last group, and the whole range on a non-AVX2 build.
   while ( n < last_nonce && !work_restart[thr_id].restart )
   {
      edata[19] = n;
      rinhash_hash( hash, edata );
      if ( unlikely( rin_hash_le_target( hash, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash, mythr );
      }
      n++;
   }

   *hashes_done = n - first_nonce;
   // Host order, NOT bswapped: std_get_new_work() reads this word as a plain
   // uint32 to decide whether the range is exhausted and to advance it. A
   // swapped value tests > end_nonce, so the thread is handed its start nonce
   // again every scantime and re-submits the same shares -- "Duplicate share".
   pdata[19] = n;
   return 0;
}

/* Startup gate: real mainnet headers, each asserted twice -- digest exact, and
 * under that block's own nBits target. Either assertion alone is weaker. */
static bool rinhash_self_test( void )
{
   uint8_t got[32];
   int pass = 0;

   for ( unsigned k = 0; k < RINHASH_KAT_COUNT; k++ )
   {
      rinhash_hash( got, rinhash_kat[k].header );
      if ( memcmp( got, rinhash_kat[k].digest, 32 ) != 0 )
      {
         applog( LOG_ERR, "rinhash KAT %u (height %u): digest mismatch",
                 k, rinhash_kat[k].height );
         return false;
      }
      if ( !rin_hash_le_target( got, (const uint32_t*)rinhash_kat[k].target ) )
      {
         applog( LOG_ERR, "rinhash KAT %u (height %u): digest over target",
                 k, rinhash_kat[k].height );
         return false;
      }
      pass++;
   }

   /* Non-vacuity: one flipped nonce bit must change the digest. */
   uint8_t bad[80];
   memcpy( bad, rinhash_kat[0].header, 80 );
   bad[79] ^= 1;
   rinhash_hash( got, bad );
   if ( memcmp( got, rinhash_kat[0].digest, 32 ) == 0 )
   {
      applog( LOG_ERR, "rinhash KAT is vacuous: altered header gave the same digest" );
      return false;
   }

   /* The KAT above cannot reach the batched paths -- scanhash is their only
    * caller. Differential over DISTINCT nonces per lane, so a lane crossing
    * fails here instead of submitting a correct digest against the wrong
    * nonce. Every compiled width is tested, not just the widest: on an
    * AVX-512 build both are live, since the 4-way loop mops up what the
    * 8-way group leaves. */
#if defined(RINHASH_4WAY) || defined(RINHASH_8WAY)
   {
      uint32_t edata[20] __attribute__ ((aligned (64)));
      uint8_t  h1[32];
      const uint32_t n0 = 0x0f1e2d3cu;
      char which[24] = "";

      memcpy( edata, rinhash_kat[0].header, 80 );

#if defined(RINHASH_8WAY)
      {
         uint8_t h8[RIN_LANES_8][32] __attribute__ ((aligned (64)));
         rinhash_hash_8way( h8, edata, n0 );
         for ( int l = 0; l < RIN_LANES_8; l++ )
         {
            edata[19] = n0 + (uint32_t)l;
            rinhash_hash( h1, edata );
            if ( memcmp( h1, h8[l], 32 ) != 0 )
            {
               applog( LOG_ERR, "rinhash 8-way lane %d disagrees with the "
                                "scalar path (nonce %08x)", l,
                       n0 + (uint32_t)l );
               return false;
            }
         }
         strcat( which, "8-way" );
      }
#endif
#if defined(RINHASH_4WAY)
      {
         uint8_t h4[RIN_LANES_4][32] __attribute__ ((aligned (64)));
         memcpy( edata, rinhash_kat[0].header, 80 );
         rinhash_hash_4way( h4, edata, n0 );
         for ( int l = 0; l < RIN_LANES_4; l++ )
         {
            edata[19] = n0 + (uint32_t)l;
            rinhash_hash( h1, edata );
            if ( memcmp( h1, h4[l], 32 ) != 0 )
            {
               applog( LOG_ERR, "rinhash 4-way lane %d disagrees with the "
                                "scalar path (nonce %08x)", l,
                       n0 + (uint32_t)l );
               return false;
            }
         }
         if ( which[0] ) strcat( which, " + " );
         strcat( which, "4-way" );
      }
#endif
      applog( LOG_NOTICE, "rinhash self-test PASSED (%d real mainnet headers, "
              "genesis to height %u, digest and target; %s differential vs "
              "the scalar path, distinct nonce per lane)", pass,
              rinhash_kat[RINHASH_KAT_COUNT-1].height, which );
      return true;
   }
#else
   applog( LOG_NOTICE, "rinhash self-test PASSED (%d real mainnet headers, "
           "genesis to height %u, digest and target)", pass,
           rinhash_kat[RINHASH_KAT_COUNT-1].height );
   return true;
#endif
}

bool register_rinhash_algo( algo_gate_t* gate )
{
   if ( !rinhash_self_test() ) return false;

   gate->scanhash      = (void*)&scanhash_rinhash;
   gate->hash          = (void*)&rinhash_hash;
   gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
   opt_target_factor   = 1.0;
   return true;
}
