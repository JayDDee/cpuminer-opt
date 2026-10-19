// VerusHash 2.2 gate for cpuminer-opt.
//
// The hash chain itself lives in the vendored upstream sources (haraka.c,
// verus_clhash.cpp); this file is the cpuminer-opt integration: preimage
// assembly, the per-job cache, the per-nonce loop, and the self-test.
//
// Chain functions are transcribed from the reference verus/verusscan.cpp
// (branch Verus2.2 @ e28e183, lines 50-155) rather than reimplemented -- the
// arithmetic is consensus-critical.

#include "verus-gate.h"
#include "verus-simd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Verus and Equihash 200/9 share the wire format exactly -- 140-byte header,
 * 32-byte nonce at offset 108, same submit params and 1344-byte solution -- so
 * reuse rather than duplicate. */
#include "algo/equihash/equihash-gate.h"

/* Needs hardware AES + carryless multiply. verus-simd.h decides and pulls the
 * matching intrinsic header, so keep those includes inside the guard or targets
 * without either fail here instead of compiling out. */
#if defined(VERUS_HAVE_SIMD)

#include "haraka.h"
#include "haraka_portable.h"
#include "verus_clhash.h"
#include "verus-kat.h"

// ---------------------------------------------------------------------------
// Per-thread state.
//
// The reference malloc/frees a 9856-byte key per scanhash call and re-runs the
// 46+276 Haraka prologue every time. Both are hoisted here: the buffer is
// thread-local and persistent, and the prologue re-runs only when the
// job-constant first 1472 bytes of the preimage actually change.
// ---------------------------------------------------------------------------
/* Nonces hashed at once. Interleaving two lanes' clhash fills one lane's stalls
 * with the other's work: whole miner, all cores busy, A76 cluster +15.0%, A55
 * +0.1%, x86 -t 16 -7.6% (SMT already fills them) -- hence aarch64 only.
 * WARNING: Measure it loaded, never per core: isolated it reads A76 -7% and A55 +7%
 * *worse*. FORCE_* first, so both paths stay testable in every build. */
#if defined(FORCE_VERUS_2WAY)
#define VRS_LANES 2
#define VRS_LANES_DESC "2 nonces interleaved (forced by FORCE_VERUS_2WAY)"
#elif defined(FORCE_VERUS_1WAY)
#define VRS_LANES 1
#define VRS_LANES_DESC "1 nonce (forced by FORCE_VERUS_1WAY)"
#elif !defined(__aarch64__)
#define VRS_LANES 1
#define VRS_LANES_DESC "1 nonce (x86: SMT already supplies this parallelism)"
#else
#define VRS_LANES 2
#define VRS_LANES_DESC "2 nonces interleaved (aarch64 default)"
#endif

typedef struct {
   u128     key[VERUS_KEY_SIZE128 + VERUS_SCRATCH_U128];  /* 616 u128 = 9856 B */
#if VRS_LANES == 2
   u128     key2[VERUS_KEY_SIZE128 + VERUS_SCRATCH_U128]; /* lane 1's own copy  */
#endif
   uint8_t  half[64];                  /* VerusHashHalf output (state+15+pad)  */
   uint8_t  prefix[VERUS_PREIMAGE_MAX];/* cache tag: the job-constant bytes    */
   int      prefix_len;
   bool     warned_no_solution;
   bool     valid;
} verus_ctx_t;

static __thread verus_ctx_t *verus_ctx = NULL;

static verus_ctx_t *verus_get_ctx( void )
{
   if ( unlikely( verus_ctx == NULL ) )
   {
      /* 64-byte aligned: the key is indexed as u128 and read by aligned loads */
      if ( posix_memalign( (void**)&verus_ctx, 64, sizeof(verus_ctx_t) ) != 0 )
         return NULL;
      memset( verus_ctx, 0, sizeof(verus_ctx_t) );
   }
   return verus_ctx;
}

/* CBlockHeader::ClearNonCanonicalData(): merge-mined chains must all validate
 * the same PoW, so chain-specific fields are zeroed and anything the miner
 * varies moves into the 15 solution bytes. nVersion and nTime stay -- they are
 * shared across the merged blocks. The self-test runs this same function over a
 * real block, which is what pins these offsets. */
static void verus_clear_noncanonical( uint8_t *pre )
{
   memset( pre + 4, 0, 96 );                    /* prevhash, merkle, saplingroot */
   memset( pre + 104, 0, 4 );                   /* nBits  */
   memset( pre + 108, 0, 32 );                  /* nNonce */
   memset( pre + VERUS_BASE_SIZE + 8, 0, 64 );  /* hashPrev/BlockMMRRoot */
}

// ---------------------------------------------------------------------------
// Chain functions (transcribed from verusscan.cpp)
// ---------------------------------------------------------------------------
static void GenNewCLKey( unsigned char *seedBytes32, u128 *keyback )
{
   const int n256blks    = VERUS_KEY_SIZE >> 5;     /* 276 */
   const int nbytesExtra = VERUS_KEY_SIZE & 0x1f;   /* 0   */
   unsigned char *pkey = (unsigned char*)keyback;
   unsigned char *psrc = seedBytes32;

   for ( int i = 0; i < n256blks; i++ )
   {
      haraka256( pkey, psrc );
      psrc  = pkey;
      pkey += 32;
   }
   if ( nbytesExtra )
   {
      unsigned char buf[32];
      haraka256( buf, psrc );
      memcpy( pkey, buf, nbytesExtra );
   }
}

/* Undo the <=64 mutated key slots from the journal. Reverse order matters:
 * indices can repeat across iterations, so the oldest saved value must land
 * last. Within an iteration prandex is restored before prand, mirroring the
 * algorithm's own write order when both indices collide. */
static void FixKey( uint32_t *fixrand, uint32_t *fixrandex, u128 *keyback,
                    u128 *g_prand, u128 *g_prandex )
{
   for ( int i = 31; i > -1; i-- )
   {
      keyback[ fixrandex[i] ] = g_prandex[i];
      keyback[ fixrand[i]   ] = g_prand[i];
   }
}

static void VerusHashHalf( void *result2, unsigned char *data, int len )
{
   unsigned char _ALIGN(32) buf1[64] = {0}, buf2[64];
   unsigned char *curBuf = buf1, *result = buf2, *tmp;
   int curPos = 0;

   load_constants();
   load_constants_port();

   for ( int pos = 0; pos < len; )
   {
      int room = 32 - curPos;
      if ( len - pos >= room )
      {
         memcpy( curBuf + 32 + curPos, data + pos, room );
         haraka512( result, curBuf );
         tmp = curBuf; curBuf = result; result = tmp;
         pos += room; curPos = 0;
      }
      else
      {
         memcpy( curBuf + 32 + curPos, data + pos, len - pos );
         curPos += len - pos;
         pos = len;
      }
   }
   /* FillExtra, hand-unrolled: pad[0..15] = state[0..15], pad[16] = state[0].
    * Non-zero padding so the unused bytes are not foreknown. */
   memcpy( curBuf + 47, curBuf, 16 );
   memcpy( curBuf + 63, curBuf, 1 );
   memcpy( result2, curBuf, 64 );
}

/* Per nonce, before the clhash: only the 15 nonce bytes. Upstream also re-derives
 * curBuf[47..63] here, which is dead work while curBuf is a fresh copy of
 * ctx->half -- VerusHashHalf's FillExtra already wrote those exact bytes. (It
 * exists upstream because fill2 clobbers them, so a reused buffer needs it.) */
static inline void verus_set_nonce( unsigned char *curBuf, unsigned char *nonce )
{
   memcpy( curBuf + 32, nonce, VERUS_NONCE_SPACE );
}

/* Round constants come from the MUTATED key at a data-dependent offset -- what
 * makes VerusHash 2.x hostile to fixed-function hardware. haraka512_keyed is
 * truncated to out[28..31], enough for the target test and the reference's main
 * per-nonce saving; candidates re-do it in software to get all 32 bytes. `full`
 * is literal at every call site, so this folds. */
static inline void verus_keyed_haraka( unsigned char *hash, unsigned char *curBuf,
                                       uint64_t intermediate, u128 *data_key,
                                       const bool full )
{
   const __m128i shuf2 = _mm_setr_epi8( 1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,0 );
   const __m128i fill2 =
      _mm_shuffle_epi8( _mm_loadl_epi64( (u128*)&intermediate ), shuf2 );
   _mm_store_si128( (u128*)( &curBuf[32 + 16] ), fill2 );
   curBuf[32 + 15] = *( (unsigned char*)&intermediate );

   if ( full )
      haraka512_port_keyed( hash, curBuf, data_key + ( intermediate & 511 ) );
   else
      haraka512_keyed( hash, curBuf, data_key + ( intermediate & 511 ) );
}

/* One nonce; `hash` receives only bytes 28..31 unless `full`. */
static inline void Verus2hash( unsigned char *hash, unsigned char *curBuf,
                               unsigned char *nonce, u128 *data_key,
                               uint32_t *fixrand, uint32_t *fixrandex,
                               u128 *g_prand, u128 *g_prandex,
                               const bool full )
{
   verus_set_nonce( curBuf, nonce );

   uint64_t intermediate = verusclhashv2_2( data_key, curBuf, 511,
                                            fixrand, fixrandex,
                                            g_prand, g_prandex );

   verus_keyed_haraka( hash, curBuf, intermediate, data_key, full );
   FixKey( fixrand, fixrandex, data_key, g_prand, g_prandex );
}

#if VRS_LANES == 2
/* Two nonces. Only the clhash interleaves: the keyed Haraka needs its own lane's
 * result, and with FixKey it is ~10% of a hash. Each lane needs its own mutable
 * key -- the algorithm mutates the key as it reads it. */
static inline void Verus2hash_2way( unsigned char *hash0, unsigned char *hash1,
                                    unsigned char *curBuf0, unsigned char *curBuf1,
                                    unsigned char *nonce0, unsigned char *nonce1,
                                    u128 *key0, u128 *key1,
                                    uint32_t *fixrand0, uint32_t *fixrandex0,
                                    u128 *g_prand0, u128 *g_prandex0,
                                    uint32_t *fixrand1, uint32_t *fixrandex1,
                                    u128 *g_prand1, u128 *g_prandex1 )
{
   uint64_t intermediate[2];

   verus_set_nonce( curBuf0, nonce0 );
   verus_set_nonce( curBuf1, nonce1 );

   verusclhash_2way( key0, curBuf0, key1, curBuf1, 511,
                     fixrand0, fixrandex0, g_prand0, g_prandex0,
                     fixrand1, fixrandex1, g_prand1, g_prandex1, intermediate );

   verus_keyed_haraka( hash0, curBuf0, intermediate[0], key0, false );
   verus_keyed_haraka( hash1, curBuf1, intermediate[1], key1, false );

   FixKey( fixrand0, fixrandex0, key0, g_prand0, g_prandex0 );
   FixKey( fixrand1, fixrandex1, key1, g_prand1, g_prandex1 );
}
#endif  /* VRS_LANES == 2 */

// ---------------------------------------------------------------------------
// Full 1487-byte-preimage hash (gate->hash; also the self-test entry).
// Produces the FULL 32-byte digest by using the portable keyed Haraka, which
// unlike the AES-NI one is not truncated. Only for candidates and tests --
// the inner loop uses the truncated form.
// ---------------------------------------------------------------------------
int verushash_full( void *output, const void *preimage, int pre_len )
{
   verus_ctx_t *ctx = verus_get_ctx();
   if ( ctx == NULL ) return 0;

   uint8_t _ALIGN(32) curBuf[64];
   uint32_t fixrand[32], fixrandex[32];
   u128 *g_prand   = ctx->key + VERUS_KEY_SIZE128;
   u128 *g_prandex = ctx->key + VERUS_KEY_SIZE128 + 32;
   const uint8_t *pre = (const uint8_t*)preimage;
   const int half_len = pre_len - VERUS_NONCE_SPACE;

   VerusHashHalf( ctx->half, (unsigned char*)pre, half_len );
   GenNewCLKey( ctx->half, ctx->key );
   ctx->valid = false;                 /* this path bypasses the job cache */

   memcpy( curBuf, ctx->half, 64 );
   /* the 15 tail bytes of the preimage are the nonce space */
   Verus2hash( (unsigned char*)output, curBuf,
               (unsigned char*)pre + half_len, ctx->key,
               fixrand, fixrandex, g_prand, g_prandex, true );
   return 1;
}

// ---------------------------------------------------------------------------
// Self-test: real-block KAT + two free invariants.
//
// verus-kat.h holds a mainnet block exactly as the chain serializes it, and its
// published hash. Reproducing that hash means the whole chain, the canonical
// clearing and the nonce placement agree with consensus -- not merely with a
// vector this code produced. Only the two stage checkpoints are ours, and they
// exist so a failure names the stage instead of just the digest.
// ---------------------------------------------------------------------------
static uint64_t verus_fnv1a( const void *p, size_t n, uint64_t h )
{
   for ( size_t i = 0; i < n; i++ )
   {
      h ^= ((const uint8_t*)p)[i];
      h *= 1099511628211ULL;
   }
   return h;
}

// ---------------------------------------------------------------------------
// Emulated-primitive vectors (aarch64 without the crypto extension).
//
// The KAT below would catch a wrong emulation too, but only as "digest
// mismatch"; these name the primitive instead, and cover inputs a real block
// may not reach for hours: all zero, all ones, 0x80 (the xtime carry and the
// top-bit shift) and each quarter of the S-box index range, which is what
// selects between the four table registers.
//
// Oracles are independent of the vector code: aesenc() from haraka_portable.c,
// and a 64 step bit loop for the multiply.
// ---------------------------------------------------------------------------
#if defined(VERUS_AES_EMULATED) || defined(VERUS_PMULL_EMULATED)

#if defined(VERUS_PMULL_EMULATED)
static void verus_clmul_ref( uint64_t a, uint64_t b, uint64_t *lo,
                             uint64_t *hi )
{
   uint64_t l = 0, h = 0;
   for ( int i = 0; i < 64; i++ )
      if ( ( b >> i ) & 1 )
      {
         l ^= a << i;
         if ( i ) h ^= a >> ( 64 - i );
      }
   *lo = l; *hi = h;
}
#endif

static bool verus_emu_self_test( void )
{
   static const uint8_t fixed[5][16] = {
      { 0 },
      { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff },
      { 0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,
        0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80 },
      { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,
        0x00,0x7f,0xfe,0x3f,0xc0,0x63,0x3c,0xa5 },
      { 0x00,0x3f,0x40,0x7f,0x80,0xbf,0xc0,0xff,
        0x01,0x3e,0x41,0x7e,0x81,0xbe,0xc1,0xfe } };
   const int nfixed = 5, nrand = 4096;
   uint64_t s = 0x2545f4914f6cdd1dULL;

   for ( int v = 0; v < nfixed + nrand; v++ )
   {
      uint8_t _ALIGN(16) in[16], rk[16], got[16], want[16];

      if ( v < nfixed )
      {
         memcpy( in, fixed[v], 16 );
         memcpy( rk, fixed[ ( v + 1 ) % nfixed ], 16 );
      }
      else
         for ( int i = 0; i < 4; i++ )     /* splitmix64 */
         {
            uint64_t z = ( s += 0x9e3779b97f4a7c15ULL );
            z = ( z ^ ( z >> 30 ) ) * 0xbf58476d1ce4e5b9ULL;
            z = ( z ^ ( z >> 27 ) ) * 0x94d049bb133111ebULL;
            z ^= z >> 31;
            memcpy( ( i < 2 ? in : rk ) + ( i & 1 ) * 8, &z, 8 );
         }

#if defined(VERUS_AES_EMULATED)
      memcpy( want, in, 16 );
      aesenc( want, rk );                  /* in place, xors rk at the end */
      _mm_storeu_si128( (u128*)got, _mm_aesenc_si128( _mm_loadu_si128( (u128*)in ),
                                                      _mm_loadu_si128( (u128*)rk ) ) );
      if ( memcmp( got, want, 16 ) != 0 )
      {
         applog( LOG_ERR, "VerusHash self-test FAILED: emulated AES round "
                          "differs from the scalar reference (vector %d)", v );
         return false;
      }
#endif

#if defined(VERUS_PMULL_EMULATED)
      const u128 va = _mm_loadu_si128( (u128*)in ), vb = _mm_loadu_si128( (u128*)rk );
      uint64_t al, ah, bl, bh, rl, rh;
      memcpy( &al, in, 8 ); memcpy( &ah, in + 8, 8 );
      memcpy( &bl, rk, 8 ); memcpy( &bh, rk + 8, 8 );

      for ( int c = 0; c < 5; c++ )
      {
         switch ( c )
         {
         case 0: verus_clmul_ref( al, bl, &rl, &rh );
                 _mm_storeu_si128( (u128*)got, _mm_clmulepi64_si128( va, vb, 0x00 ) );
                 break;
         case 1: verus_clmul_ref( ah, bl, &rl, &rh );
                 _mm_storeu_si128( (u128*)got, _mm_clmulepi64_si128( va, vb, 0x01 ) );
                 break;
         case 2: verus_clmul_ref( al, bh, &rl, &rh );
                 _mm_storeu_si128( (u128*)got, _mm_clmulepi64_si128( va, vb, 0x10 ) );
                 break;
         case 3: verus_clmul_ref( ah, bh, &rl, &rh );
                 _mm_storeu_si128( (u128*)got, _mm_clmulepi64_si128( va, vb, 0x11 ) );
                 break;
         /* the sparse-constant shortcut precompReduction64_si128 takes */
         default: verus_clmul_ref( ah, 0x1b, &rl, &rh );
                 _mm_storeu_si128( (u128*)got, VRS_CLMUL_X1B( va ) );
                 break;
         }
         memcpy( want, &rl, 8 ); memcpy( want + 8, &rh, 8 );
         if ( memcmp( got, want, 16 ) != 0 )
         {
            applog( LOG_ERR, "VerusHash self-test FAILED: emulated carryless "
                             "multiply case %d differs from the scalar "
                             "reference (vector %d)", c, v );
            return false;
         }
      }
#endif
   }
   return true;
}
#endif  /* VERUS_AES_EMULATED || VERUS_PMULL_EMULATED */

bool verus_self_test( void )
{
   verus_ctx_t *ctx = verus_get_ctx();
   if ( ctx == NULL )
   {
      applog( LOG_ERR, "VerusHash: context allocation failed" );
      return false;
   }

#if defined(VERUS_AES_EMULATED) || defined(VERUS_PMULL_EMULATED)
   /* before the KAT, so a primitive failure is not reported as a digest
    * mismatch 300 Haraka calls later */
   if ( !verus_emu_self_test() ) return false;
#endif

   uint8_t _ALIGN(32) pre[VERUS_KAT_PREIMAGE];
   uint32_t fixrand[32], fixrandex[32];
   u128 *g_prand   = ctx->key + VERUS_KEY_SIZE128;
   u128 *g_prandex = ctx->key + VERUS_KEY_SIZE128 + 32;

   memcpy( pre, verus_kat_block, VERUS_KAT_PREIMAGE );
   verus_clear_noncanonical( pre );     /* solution version 8, so PBaaS */
   VerusHashHalf( ctx->half, pre, VERUS_KAT_PREIMAGE - VERUS_NONCE_SPACE );

   if ( memcmp( ctx->half, verus_kat_half, 32 ) != 0 )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: VerusHashHalf mismatch" );
      return false;
   }

   GenNewCLKey( ctx->half, ctx->key );
   const uint64_t key_fnv =
      verus_fnv1a( ctx->key, VERUS_KEY_SIZE, 1469598103934665603ULL );
   if ( key_fnv != VERUS_KAT_KEY_FNV )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: GenNewCLKey mismatch "
                       "(%016llx want %016llx)", (unsigned long long)key_fnv,
              (unsigned long long)VERUS_KAT_KEY_FNV );
      return false;
   }

   /* The block's own nonce is already in place, so the digest must come out as
    * its published hash. Both keyed-Haraka paths are exercised: the inner loop's
    * truncated one, then the candidate path's full one. */
   uint8_t *nonce = pre + VERUS_KAT_PREIMAGE - VERUS_NONCE_SPACE;
   uint8_t _ALIGN(32) curBuf[64];
   uint8_t hash[32] = {0};

   memcpy( curBuf, ctx->half, 64 );
   Verus2hash( hash, curBuf, nonce, ctx->key,
               fixrand, fixrandex, g_prand, g_prandex, false );

   if ( memcmp( hash + 28, verus_kat_hash + 28, 4 ) != 0 )
   {
      uint32_t got, want;
      memcpy( &got, hash + 28, 4 ); memcpy( &want, verus_kat_hash + 28, 4 );
      applog( LOG_ERR, "VerusHash self-test FAILED: block %d vhash[7] %08x "
                       "want %08x", VERUS_KAT_HEIGHT, got, want );
      return false;
   }
   /* invariant: the AES-NI keyed Haraka writes ONLY bytes 28..31 */
   for ( int i = 0; i < 28; i++ )
      if ( hash[i] != 0 )
      {
         applog( LOG_ERR, "VerusHash self-test FAILED: truncated Haraka wrote "
                          "byte %d -- inner loop assumption broken", i );
         return false;
      }
   /* invariant: FixKey must restore the key to pristine after every hash */
   if ( verus_fnv1a( ctx->key, VERUS_KEY_SIZE, 1469598103934665603ULL )
        != VERUS_KAT_KEY_FNV )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: FixKey did not restore the "
                       "key (journal order bug?)" );
      return false;
   }

   memcpy( curBuf, ctx->half, 64 );
   Verus2hash( hash, curBuf, nonce, ctx->key,
               fixrand, fixrandex, g_prand, g_prandex, true );

   if ( memcmp( hash, verus_kat_hash, 32 ) != 0 )
   {
      applog( LOG_ERR, "VerusHash self-test FAILED: block %d digest mismatch",
              VERUS_KAT_HEIGHT );
      return false;
   }

   ctx->valid = false;
   applog( LOG_NOTICE, "VerusHash 2.2 self-test PASSED (mainnet block %d hash "
                       "reproduced on both keyed-Haraka paths)",
           VERUS_KAT_HEIGHT );
   return true;
}

/* the 4 nonce bytes the miner varies, inside the 15-byte solution nonce space */
static inline void verus_put_nonce( uint8_t *nonceSpace, uint32_t n )
{
   nonceSpace[11] = (uint8_t)( n       ); nonceSpace[12] = (uint8_t)( n >>  8 );
   nonceSpace[13] = (uint8_t)( n >> 16 ); nonceSpace[14] = (uint8_t)( n >> 24 );
}

/* bundled so both hashing loops share one copy of the submit logic */
typedef struct {
   struct work     *work;
   uint8_t         *full;
   uint32_t        *ptarget;
   struct thr_info *mythr;
   verus_ctx_t     *ctx;
   int              half_len, pre_len, sol_size;
   uint32_t         targ32;
   bool             pbaas, bench;
} verus_cand_t;

/* Only hash[28..31] is written by the truncated keyed Haraka, so this is the
 * whole target test the reference does. A candidate is re-hashed in full so the
 * submitted digest and the share-diff stats are real. Returns true if that
 * re-hash ran, because it regenerates ctx->key. */
static bool verus_check_candidate( verus_cand_t *C, const uint8_t *hash,
                                   const uint8_t *nonceSpace, uint32_t n )
{
   if ( likely( ((const uint32_t*)hash)[7] > C->targ32 || C->bench ) )
      return false;

   uint32_t *pdata = C->work->data;
   uint8_t _ALIGN(64) fullhash[32];

   memcpy( C->full + C->half_len, nonceSpace, VERUS_NONCE_SPACE );
   verushash_full( fullhash, C->full, C->pre_len );
   C->ctx->valid = false;            /* verushash_full clobbered the cache */

   if ( valid_hash( (uint32_t*)fullhash, C->ptarget ) )
   {
      /* the pool needs the 15 nonce bytes inside the solution it gets back */
      memcpy( C->work->equihash_solution + C->sol_size - VERUS_NONCE_SPACE,
              nonceSpace, VERUS_NONCE_SPACE );

      /* Submit the header exactly as hashed: in PBaaS mode a zeroed nNonce, as
       * upstream sends, the pool taking the real nonce from the solution tail.
       * Pools reject a non-zero one. Restore after -- nNonce also holds
       * extranonce1 and the framework's range counter, and submit_work
       * deep-copies before returning. */
      uint32_t saved[8];
      memcpy( saved, pdata + 27, sizeof saved );
      if ( C->pbaas ) memset( pdata + 27, 0, sizeof saved );
      else            pdata[ VRS_NONCE_INDEX ] = n;

      submit_solution( C->work, fullhash, C->mythr );

      memcpy( pdata + 27, saved, sizeof saved );
      pdata[ VRS_NONCE_INDEX ] = n;
   }
   return true;
}

// ---------------------------------------------------------------------------
// scanhash
//
// The 1344-byte solution is supplied by the pool as mining.notify param[8];
// the miner varies only its last 15 bytes. Without one this refuses to mine
// rather than hashing a wrong preimage.
// ---------------------------------------------------------------------------
int scanhash_verus( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata   = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[ VRS_NONCE_INDEX ];
   const uint32_t targ32 = ptarget[7];
   const int thr_id = mythr->id;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   verus_ctx_t *ctx = verus_get_ctx();
   if ( ctx == NULL ) { *hashes_done = 0; return 0; }

   /* The solution comes from the pool (mining.notify param[8]), already padded
    * to the size upstream requires. Its length is NOT fixed -- pool.verus.io
    * sends 281 bytes, padded to 320. In benchmark mode substitute a
    * deterministic one so --benchmark measures the real hash; otherwise refuse
    * to mine rather than hash a wrong preimage. */
   const uint8_t *solution = work->equihash_solution;
   int sol_size = (int)work->equihash_solution_len;

   if ( solution == NULL || sol_size < 253 || sol_size > VERUS_SOLUTION_MAX )
   {
      if ( !bench )
      {
         if ( !ctx->warned_no_solution )      /* once per thread, not per call */
         {
            applog( LOG_WARNING, "VerusHash: no usable pool solution in work" );
            ctx->warned_no_solution = true;
         }
         *hashes_done = 0;
         return 0;
      }
      /* the KAT block's own solution: real descriptor, so --benchmark measures
       * the PBaaS path real jobs take */
      solution = verus_kat_block + VERUS_BASE_SIZE;
      sol_size = VERUS_KAT_PREIMAGE - VERUS_BASE_SIZE;
   }
   ctx->warned_no_solution = false;

   /* base+solution must be 15 (mod 32): one partial Haraka block with 15 free
    * bytes. If it is not, the solution was not padded and hashing it would
    * silently produce a preimage no pool will accept. */
   const int pre_len = VERUS_BASE_SIZE + sol_size;
   if ( ( pre_len % 32 ) != VERUS_NONCE_SPACE )
   {
      if ( !ctx->warned_no_solution )
      {
         applog( LOG_ERR, "VerusHash: solution size %d gives preimage %d "
                          "(%d mod 32, need %d) -- not padded",
                 sol_size, pre_len, pre_len % 32, VERUS_NONCE_SPACE );
         ctx->warned_no_solution = true;
      }
      *hashes_done = 0;
      return 0;
   }
   const int half_len = pre_len - VERUS_NONCE_SPACE;

   uint8_t _ALIGN(64) full[VERUS_PREIMAGE_MAX] = {0};
   uint8_t *sol_data = full + VERUS_HEADER_SIZE;
   uint8_t nonceSpace[VERUS_NONCE_SPACE] = {0};

   memcpy( full, pdata, VERUS_HEADER_SIZE );
   /* CompactSize, always the 3-byte form so the base stays 143 as upstream's
    * HEADER_BASESIZE assumes (hence the sol_size >= 253 check above). */
   sol_data[0] = 0xfd;
   sol_data[1] = (uint8_t)( sol_size & 0xff );
   sol_data[2] = (uint8_t)( sol_size >> 8 );
   memcpy( sol_data + 3, solution, sol_size );

   const bool pbaas = ( solution[0] >= 7 && solution[5] > 0 );
   if ( pbaas )
   {
      verus_clear_noncanonical( full );
      memcpy( nonceSpace,     &pdata[27], 7 );   /* pool extranonce1        */
      memcpy( nonceSpace + 7, &pdata[VRS_NONCESPACE_INDEX], 4 );
   }

   /* Job cache: re-run the Haraka prologue only when the job-constant bytes
    * actually change. */
   if ( !ctx->valid || ctx->prefix_len != half_len
        || memcmp( ctx->prefix, full, half_len ) != 0 )
   {
      memcpy( ctx->prefix, full, half_len );
      ctx->prefix_len = half_len;
      VerusHashHalf( ctx->half, full, half_len );
      GenNewCLKey( ctx->half, ctx->key );
      ctx->valid = true;
   }

   uint32_t fixrand[32], fixrandex[32];
   u128 *g_prand   = ctx->key + VERUS_KEY_SIZE128;
   u128 *g_prandex = ctx->key + VERUS_KEY_SIZE128 + 32;
   uint32_t n = first_nonce;

   verus_cand_t cand = { .work = work, .full = full, .ptarget = ptarget,
                         .mythr = mythr, .ctx = ctx, .half_len = half_len,
                         .pre_len = pre_len, .sol_size = sol_size,
                         .targ32 = targ32, .pbaas = pbaas, .bench = bench };

#if VRS_LANES == 2
   {
      /* Lane 1 works on its own key copy; each lane's FixKey restores its own.
       * Re-copied per call rather than per job because the candidate path
       * regenerates ctx->key -- 9856 B is ~1 us against ms of hashing. */
      uint32_t fixrand2[32], fixrandex2[32];
      u128 *g_prand2   = ctx->key2 + VERUS_KEY_SIZE128;
      u128 *g_prandex2 = ctx->key2 + VERUS_KEY_SIZE128 + 32;
      uint8_t nonceSpace2[VERUS_NONCE_SPACE];

      memcpy( ctx->key2, ctx->key, sizeof ctx->key );
      memcpy( nonceSpace2, nonceSpace, VERUS_NONCE_SPACE );

      while ( n + 1 < max_nonce && !(*restart) )
      {
         uint8_t _ALIGN(32) curBuf[64], curBuf2[64];
         /* only [28..31] is written and read; the zeroing is 3 insns/nonce GCC does
          * not elide, kept so a future reader of [0..27] gets zeros not garbage */
         uint8_t hash[32] = {0}, hash2[32] = {0};

         memcpy( curBuf,  ctx->half, 64 );
         memcpy( curBuf2, ctx->half, 64 );
         verus_put_nonce( nonceSpace,  n     );
         verus_put_nonce( nonceSpace2, n + 1 );

         Verus2hash_2way( hash, hash2, curBuf, curBuf2, nonceSpace, nonceSpace2,
                          ctx->key, ctx->key2,
                          fixrand, fixrandex, g_prand, g_prandex,
                          fixrand2, fixrandex2, g_prand2, g_prandex2 );

         /* both lanes always checked -- not `||`, which would skip lane 1 */
         const bool re0 = verus_check_candidate( &cand, hash,  nonceSpace,  n     );
         const bool re1 = verus_check_candidate( &cand, hash2, nonceSpace2, n + 1 );
         if ( re0 || re1 )
            memcpy( ctx->key2, ctx->key, sizeof ctx->key );  /* key regenerated */
         n += 2;
      }
   }
#endif

   /* The 1-way path: the whole range in a 1-lane build, or the odd tail nonce
    * after the loop above. */
   while ( n < max_nonce && !(*restart) )
   {
      uint8_t _ALIGN(32) curBuf[64];
      uint8_t hash[32] = {0};

      memcpy( curBuf, ctx->half, 64 );
      verus_put_nonce( nonceSpace, n );

      Verus2hash( hash, curBuf, nonceSpace, ctx->key,
                  fixrand, fixrandex, g_prand, g_prandex, false );

      verus_check_candidate( &cand, hash, nonceSpace, n );
      n++;
   }

   pdata[ VRS_NONCE_INDEX ] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#else   /* no hardware AES+CLMUL: stubs so the tree still builds */

int verushash_full( void *output, const void *preimage, int pre_len )
{ (void)output; (void)preimage; (void)pre_len; return 0; }

int scanhash_verus( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{ (void)work; (void)max_nonce; (void)mythr; *hashes_done = 0; return 0; }

bool verus_self_test( void ) { return false; }

#endif  /* VERUS_HAVE_SIMD */

/* The 8 KB private key buffer plus its restore journal, one per thread.
 * verus_ctx only exists behind VERUS_HAVE_SIMD; without it there is nothing to
 * free, but the function still has to compile (SSE4.2/SSE2/x64 builds). */
static void verus_thread_free( int thr_id )
{
   (void)thr_id;
#if defined(VERUS_HAVE_SIMD)
   if ( !verus_ctx ) return;
#if defined(_WIN32)
   _aligned_free( verus_ctx );
#else
   free( verus_ctx );
#endif
   verus_ctx = NULL;
#endif
}

bool register_verus_algo( algo_gate_t *gate )
{
#if !defined(VERUS_HAVE_SIMD)
   applog( LOG_ERR, "VerusHash requires hardware AES and carryless multiply; "
                    "rebuild with -march=native (x86: -maes -mpclmul, "
                    "aarch64: -march=armv8-a+crypto)" );
   (void)gate;
   return false;
#else
#if defined(VERUS_AES_EMULATED) || defined(VERUS_PMULL_EMULATED)
   /* Loud: A53/A72 cores really do lack these, but a Pi 4 building for plain
    * armv8-a when it could use +crypto is a misconfiguration, not a limit. */
   applog( LOG_WARNING, "VerusHash: emulating %s in NEON -- this core (or this "
                        "build) has no ARMv8 crypto extension, expect roughly a "
                        "quarter of the hashrate. If the CPU does have it, "
                        "rebuild with -march=armv8-a+crypto.",
#if defined(VERUS_AES_EMULATED) && defined(VERUS_PMULL_EMULATED)
           "AES and carryless multiply"
#elif defined(VERUS_AES_EMULATED)
           "AES"
#else
           "carryless multiply"
#endif
         );
#endif
   /* compile-time, but without this a 1-nonce and a 2-nonce binary are
    * indistinguishable in a log. applog does not gate LOG_DEBUG itself here. */
   if ( opt_debug )
      applog( LOG_DEBUG, "VerusHash: clhash path %s", VRS_LANES_DESC );

   if ( !verus_self_test() )
   {
      applog( LOG_ERR, "VerusHash self-test failed" );
      return false;
   }
   gate->scanhash              = (void*)&scanhash_verus;
   gate->miner_thread_free     = (void*)&verus_thread_free;
   gate->hash                  = (void*)&verushash_full;
   gate->build_extraheader     = (void*)&equihash_build_extraheader;
   gate->build_stratum_request = (void*)&equihash_build_stratum_request;
   gate->get_work_data_size    = (void*)&equihash_get_work_data_size;
   /* informational only in this tree, but must not claim an AES unit the
    * emulated build is not using */
#if defined(VERUS_AES_EMULATED)
   gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
#else
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;
#endif
   gate->ntime_index   = VRS_NTIME_INDEX;
   gate->nbits_index   = VRS_NBITS_INDEX;
   gate->nonce_index   = VRS_NONCE_INDEX;
   gate->work_cmp_size = VRS_WORK_CMP_SIZE;
   opt_target_factor   = VRS_DIFF_SCALE;   /* displayed diffs only */
   return true;
#endif
}
