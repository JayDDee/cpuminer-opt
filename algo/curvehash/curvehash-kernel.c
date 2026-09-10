/*
 * curvehash's k*G kernel -- the extracted subset of the vendored libsecp256k1.
 *
 * curvehash is eight secp256k1 scalar multiplications per nonce, so nearly all
 * of its runtime is inside the vendored library. This TU includes the vendored
 * headers but owns the call sequence, which keeps every tuning change in code
 * we maintain and lets the tree under secp256k1/ stay byte-identical to
 * upstream. Never edit the vendored source in place.
 *
 * Only k*G-plus-serialize is reached. Deliberately absent: secp256k1.c (the
 * public API), ecdsa*, ecmult* (general k*P), ecmult_const*, eckey*, num_gmp*,
 * testrand*.
 *
 * secp256k1_unity.c stays in the binary as a differential oracle: at startup
 * curvehash_self_test() runs random scalars through both and requires identical
 * 65-byte points. That is stronger than a KAT alone, because a k*G that is
 * wrong for only some scalars still yields a well-formed digest.
 */

#include "secp256k1-config.h"

#include "curvehash-kernel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* For the work-item-9 table gate only -- not on any hashing path. Resolves via
 * the build's repo-root -I, and the symbol comes from the main binary's
 * sph_sha2.o (out-of-tree harnesses link algo/sha/sph_sha2.c themselves). */
#include "algo/sha/sph_sha2.h"

/* Include via the explicit secp256k1/src/ prefix, NOT via the library's own
 * -I root. A quoted include resolves from the includer's directory first, so
 * these files then find their siblings (util.h, field.h, ...) inside the
 * vendored tree -- rather than anything of the same name that -I. might pull
 * out of the repo root. */
/* group_impl.h has `const int CURVE_B = 7;` -- no `static`, an upstream wart
 * (later libsecp256k1 made it a macro). It was harmless while exactly one TU
 * compiled the library; now that two do, it is a duplicate-symbol link error.
 * Rename ours instead of patching the vendored file. */
#define CURVE_B curvehash_kernel_CURVE_B

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/src/util.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/group_impl.h"
#include "secp256k1/src/ecmult_gen_impl.h"

static secp256k1_ecmult_gen_context curvehash_gen_ctx;
static bool curvehash_gen_ready = false;

/* Windowed generator tables, built once at registration, read-only after,
 * shared by every thread. A wider window halves the point additions per scalar
 * multiply and multiplies the table by 2^w / w:
 *
 *     w=4    64 windows    64 KB   upstream
 *     w=8    32 windows   512 KB
 *     w=16   16 windows    64 MB   default
 *
 * 16 is the widest useful width and the simplest: 256/16 is exact, so no
 * partial top window and each window is two whole bytes. 12 would need nibble
 * extraction for a smaller win, and its 5.5 MB already exceeds a small ARM L3.
 *
 * Width is chosen at RUNTIME: the 64 MB allocation can fail, and every width
 * yields the same k*G, so falling back to w=8 beats refusing to mine and cannot
 * alter a digest. -DCURVEHASH_FORCE_W8 / _W4 pin a width for A/B. */
#define CURVEHASH_W8_WINDOWS   32
#define CURVEHASH_W8_ENTRIES   256
#define CURVEHASH_W16_WINDOWS  16
#define CURVEHASH_W16_ENTRIES  65536

#if !defined(CURVEHASH_FORCE_W4) && !defined(CURVEHASH_FORCE_CT_ECMULT)
  #define CURVEHASH_USE_W8 1
  #if !defined(CURVEHASH_FORCE_W8)
    #define CURVEHASH_USE_W16 1
  #endif
#endif

#ifdef CURVEHASH_USE_W8
/* Flat, not [j][i]: one builder serves both widths, and with a power-of-two
 * entry count j*ENTRIES is a shift, so this indexes no slower than a 2D array
 * whose row length would have to differ per width. */
static secp256k1_ge_storage *curvehash_prec_w8  = NULL;
static void *curvehash_prec_w8_raw  = NULL;
#endif
#ifdef CURVEHASH_USE_W16
static secp256k1_ge_storage *curvehash_prec_w16 = NULL;
static void *curvehash_prec_w16_raw = NULL;
#endif

/* checked_malloc() calls this on OOM. The library's own default would longjmp
 * out through a callback we do not install, so give it somewhere real to go:
 * this runs once at startup, and a miner with no memory for its tables has
 * nothing useful left to do. */
static void curvehash_kernel_oom( const char *text, void *data )
{
   (void)data;
   fprintf( stderr, "curvehash kernel: %s\n", text );
   abort();
}

static const secp256k1_callback curvehash_kernel_cb =
   { curvehash_kernel_oom, NULL };

/*
 * Point addition.
 *
 * secp256k1_gej_add_ge is the branchless unified add/double formula: it
 * computes the degenerate cases unconditionally and cmovs the answer, so no
 * branch or memory access depends on the point values. gej_add_ge_var is the
 * same sum with fewer operations, but branches -- it early-outs on infinity and
 * delegates doubling to gej_double_var.
 *
 * Both yield the same affine point, so the digest is identical; they differ
 * only in timing. Taking the variable-time one is safe here for the same reason
 * the direct table index is: the scalar is SHA-256 of a PUBLIC block header, so
 * there is no secret to leak and no attacker to time.
 *
 * -DCURVEHASH_FORCE_CT_ADD restores upstream's constant-time addition.
 */
#if defined(CURVEHASH_FORCE_CT_ADD)
  #define CURVEHASH_ADD_GE( r, a, b ) secp256k1_gej_add_ge( (r), (a), (b) )
  #define CURVEHASH_ADD_DESC ", constant-time add (forced)"
#else
  #define CURVEHASH_ADD_GE( r, a, b ) secp256k1_gej_add_ge_var( (r), (a), (b), NULL )
  #define CURVEHASH_ADD_DESC ", vartime add"
#endif

/*
 * Variable-time k*G.
 *
 * Upstream reads ALL sixteen entries of every 4-bit window and cmovs the one it
 * wants, so the index leaks nothing through the cache. This indexes the entry
 * directly instead.
 *
 * !!! THIS FUNCTION IS NOT SAFE FOR SIGNING !!!
 * It leaks the scalar through the data cache, by design. That is fine here and
 * ONLY here: curvehash's scalar is SHA-256 of a *public* block header, there is
 * no secret and no attacker to time. If anything in this tree ever wants
 * secp256k1 for a signature, a key derivation, or anything with a private key,
 * it must use the pristine vendored library (secp256k1_unity.c) and NOT this
 * kernel. Using this for a real key is a key-extraction bug, not a slow path.
 *
 * Blinding is kept: it costs nothing measurable, so dropping it would deviate
 * from upstream for no gain.
 */
#ifdef CURVEHASH_USE_W8
/*
 * Build prec[j][i] = i * (2^(w*j)) * G + n_j, for j < windows.
 *
 * The n_j are upstream's "nothing up my sleeve" offsets, which exist so that
 * the i == 0 entry is a real point rather than infinity (gej_add_ge cannot take
 * an infinite b). They must cancel: n_j = 2^j * N for j < windows-1, and
 * n_last = N - 2^(windows-1) * N, so the sum is
 * (2^(windows-1) - 1)N - 2^(windows-1)N + N = 0. Upstream does this with 64
 * windows and negates at j == 62; the general analogue negates at
 * j == windows - 2.
 *
 * The batch inversion runs PER WINDOW, not over the whole table: at w=16 that
 * is 16 inversions of 65536 points rather than one of 1048576, capping the
 * transient at ~14 MB instead of ~220 MB. Identical output either way --
 * ge_set_all_gej_var is a batch of independent conversions, so the batch
 * boundaries cannot move a single point.
 *
 * Returns false only on allocation failure; the caller treats that as "fall
 * back to a narrower window", never as a hard error.
 */
static bool curvehash_build_table( secp256k1_ge_storage **out,
                                   void **out_raw,
                                   int windows, int wbits )
{
   const size_t entries = (size_t)1 << wbits;
   const size_t n = (size_t)windows * entries;
   const size_t bytes = sizeof( secp256k1_ge_storage ) * n;
   secp256k1_ge_storage *tbl = NULL;
   secp256k1_gej *precj = NULL;
   secp256k1_ge  *prec  = NULL;
   secp256k1_gej gbase, numsbase, nums_gej;
   size_t i;
   int j, ok;

   {
      static const unsigned char nums_b32[33] =
         "The scalar for this x is unknown";
      secp256k1_fe nums_x;
      secp256k1_ge nums_ge;

      ok = secp256k1_fe_set_b32( &nums_x, nums_b32 );
      if ( !ok ) return false;
      ok = secp256k1_ge_set_xo_var( &nums_ge, &nums_x, 0 );
      if ( !ok ) return false;
      secp256k1_gej_set_ge( &nums_gej, &nums_ge );
      /* Add G to make the bits in x uniformly distributed. */
      secp256k1_gej_add_ge_var( &nums_gej, &nums_gej,
                                &secp256k1_ge_const_g, NULL );
   }

   /* 64-byte alignment by hand: a ge_storage is exactly one cache line, and
    * malloc's 16-byte alignment would make ~3 of every 4 entries straddle two
    * lines -- which matters more the larger the table gets. No aligned_alloc:
    * this has to build under MinGW too. */
   *out_raw = malloc( bytes + 64 );
   /* Only one window's worth of scratch, not the whole table. */
   precj = (secp256k1_gej*)malloc( sizeof( secp256k1_gej ) * entries );
   prec  = (secp256k1_ge*) malloc( sizeof( secp256k1_ge  ) * entries );
   if ( !*out_raw || !precj || !prec )
   {
      free( *out_raw ); free( precj ); free( prec );
      *out_raw = NULL;
      return false;
   }
   tbl = (secp256k1_ge_storage*)
      ( ( (uintptr_t)*out_raw + 63 ) & ~(uintptr_t)63 );

   secp256k1_gej_set_ge( &gbase, &secp256k1_ge_const_g ); /* 2^(w*j) * G */
   numsbase = nums_gej;                                   /* 2^j * nums   */

   for ( j = 0; j < windows; j++ )
   {
      secp256k1_ge_storage *row = tbl + (size_t)j * entries;

      precj[0] = numsbase;
      for ( i = 1; i < entries; i++ )
         secp256k1_gej_add_var( &precj[i], &precj[i-1], &gbase, NULL );

      for ( i = 0; i < (size_t)wbits; i++ )    /* gbase *= 2^w */
         secp256k1_gej_double_var( &gbase, &gbase, NULL );

      secp256k1_gej_double_var( &numsbase, &numsbase, NULL );
      if ( j == windows - 2 )
      {
         secp256k1_gej_neg( &numsbase, &numsbase );
         secp256k1_gej_add_var( &numsbase, &numsbase, &nums_gej, NULL );
      }

      secp256k1_ge_set_all_gej_var( prec, precj, entries,
                                    &curvehash_kernel_cb );
      for ( i = 0; i < entries; i++ )
         secp256k1_ge_to_storage( &row[i], &prec[i] );
   }

   free( precj );
   free( prec );
   *out = tbl;
   return true;
}

/*
 * Blinding comes from the vendored context: r starts at
 * ctx->initial == -blind*G and the scalar is gn + blind, so the offsets and the
 * blind both cancel and the result is gn*G.
 *
 * Instantiated once per width rather than taking the width as an argument, so
 * the trip count and the shift stay compile-time constants and the loop still
 * unrolls. The two bodies are otherwise identical.
 *
 * WBITS must divide the scalar limb width: secp256k1_scalar_get_bits cannot
 * straddle a limb, and 8 and 16 both divide 32 and 64. A width like 12 would
 * need get_bits_var, so it is not merely a constant change.
 */
#define CURVEHASH_GEN_IMPL( NAME, WINDOWS, WBITS, TABLE )                     \
static void NAME( const secp256k1_ecmult_gen_context *ctx,                    \
                  secp256k1_gej *r, const secp256k1_scalar *gn )              \
{                                                                             \
   secp256k1_ge add;                                                          \
   secp256k1_scalar gnb;                                                      \
   int bits;                                                                  \
   int j;                                                                     \
                                                                              \
   *r = ctx->initial;                                                         \
   secp256k1_scalar_add( &gnb, gn, &ctx->blind );                             \
                                                                              \
   for ( j = 0; j < (WINDOWS); j++ )                                          \
   {                                                                          \
      bits = secp256k1_scalar_get_bits( &gnb, j * (WBITS), (WBITS) );         \
      secp256k1_ge_from_storage( &add,                                        \
         &(TABLE)[ (size_t)j * ( (size_t)1 << (WBITS) ) + (size_t)bits ] );   \
      CURVEHASH_ADD_GE( r, r, &add );                                         \
   }                                                                          \
                                                                              \
   secp256k1_ge_clear( &add );                                                \
   secp256k1_scalar_clear( &gnb );                                            \
}

CURVEHASH_GEN_IMPL( curvehash_ecmult_gen_w8, CURVEHASH_W8_WINDOWS, 8,
                    curvehash_prec_w8 )
#ifdef CURVEHASH_USE_W16
CURVEHASH_GEN_IMPL( curvehash_ecmult_gen_w16, CURVEHASH_W16_WINDOWS, 16,
                    curvehash_prec_w16 )
#endif

/* Which width actually got built. Runtime, because the w=16 allocation can
 * fail; see curvehash_kernel_init. */
static void (*curvehash_gen)( const secp256k1_ecmult_gen_context *,
                              secp256k1_gej *, const secp256k1_scalar * ) = NULL;
static int curvehash_gen_wbits = 0;
#endif   /* CURVEHASH_USE_W8 */

/*
 * Generator table gate.
 *
 * A scalar reads exactly ONE entry per window, so the startup differential's 32
 * scalars touch ~967 of w=8's 8192 entries and far less of w=16's 1048576. A
 * corrupt entry therefore yields RARE wrong hashes -- silent share loss that no
 * KAT can detect -- so hash the whole table at registration.
 *
 * The constants are SHA-256 over every entry in window-major order, 64 bytes
 * each: big-endian X of the normalized affine point, then Y. Regenerate with an
 * INDEPENDENT implementation, never this builder -- a self-checksum proves only
 * determinism. Hashing the serialization rather than raw ge_storage bytes is
 * deliberate: that layout is representation-dependent (5x52 vs 10x26), so one
 * constant per width covers every field config.
 */
static const char *const CURVEHASH_TABLE_DIGEST_W8 =
   "264d5847490d5609fa7d86505be6185fc715996dc55caeaaf2af7a1afefd2a2e";
static const char *const CURVEHASH_TABLE_DIGEST_W16 =
   "ff1dd9f6d2b455872994bdce608e6bf954a8b76b39bce30f9194a513bfb7af4c";

/* Serialise every entry and hash it. 64 B per entry: X then Y, big-endian. */
static void curvehash_table_digest( char out[65],
                                    const secp256k1_ge_storage *tbl,
                                    int windows, int wbits )
{
   const size_t n = (size_t)windows * ( (size_t)1 << wbits );
   unsigned char dig[32];
   sph_sha256_context cc;
   size_t i;
   int k;

   sph_sha256_init( &cc );
   for ( i = 0; i < n; i++ )
   {
      secp256k1_ge p;
      unsigned char buf[64];

      secp256k1_ge_from_storage( &p, &tbl[i] );
      secp256k1_fe_normalize_var( &p.x );
      secp256k1_fe_normalize_var( &p.y );
      secp256k1_fe_get_b32( buf,      &p.x );
      secp256k1_fe_get_b32( buf + 32, &p.y );
      sph_sha256( &cc, buf, 64 );
   }
   sph_sha256_close( &cc, dig );

   for ( k = 0; k < 32; k++ )
      sprintf( out + 2*k, "%02x", dig[k] );
   out[64] = '\0';
}

/* CURVEHASH_FAULT_TABLE=<index> flips one bit of that entry before hashing --
 * the negative control, runtime rather than a rebuild so it cannot rot. Test it
 * at a HIGH index: low scalar bits hit entry 0 often, so the differential may
 * already cover it, whereas the last entry of the last window is the region
 * nothing else reads. */
static bool curvehash_table_ok( secp256k1_ge_storage *tbl,
                                int windows, int wbits, const char *want )
{
   char got[65];
   const char *fault = getenv( "CURVEHASH_FAULT_TABLE" );

   if ( fault )
   {
      size_t n = (size_t)windows * ( (size_t)1 << wbits );
      size_t idx = (size_t)strtoul( fault, NULL, 0 ) % n;
      ( (unsigned char*)&tbl[idx] )[0] ^= 1;
      fprintf( stderr, "curvehash: FAULT INJECTED into table entry %zu\n", idx );
   }

   curvehash_table_digest( got, tbl, windows, wbits );
   if ( !strcmp( got, want ) )
      return true;

   fprintf( stderr, "curvehash: gen table digest MISMATCH (w=%d)\n"
                    "  built  %s\n  expect %s\n", wbits, got, want );
   return false;
}

/* Which scalar multiply the whole file uses. All three are correct and produce
 * identical points; they differ in timing behaviour and table size. */
#if defined(CURVEHASH_FORCE_CT_ECMULT)
  #define CURVEHASH_ECMULT_GEN secp256k1_ecmult_gen
#elif defined(CURVEHASH_FORCE_W4)
  #define CURVEHASH_ECMULT_GEN curvehash_ecmult_gen
#else
  /* One indirect call per round -- 8 per nonce, against ~85 us of work. */
  #define CURVEHASH_ECMULT_GEN curvehash_gen
#endif

static void curvehash_ecmult_gen( const secp256k1_ecmult_gen_context *ctx,
                                  secp256k1_gej *r, const secp256k1_scalar *gn )
{
   secp256k1_ge add;
   secp256k1_scalar gnb;
   int bits;
   int j;

   *r = ctx->initial;
   /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
   secp256k1_scalar_add( &gnb, gn, &ctx->blind );

   for ( j = 0; j < 64; j++ )
   {
      bits = secp256k1_scalar_get_bits( &gnb, j * 4, 4 );
      /* The whole point of item 2: index, do not scan. ge_from_storage sets
       * add.infinity itself. */
      secp256k1_ge_from_storage( &add, &(*ctx->prec)[j][bits] );
      CURVEHASH_ADD_GE( r, r, &add );
   }

   bits = 0;
   (void)bits;
   secp256k1_ge_clear( &add );
   secp256k1_scalar_clear( &gnb );
}

bool curvehash_kernel_init( void )
{
   if ( curvehash_gen_ready )
      return true;

   secp256k1_ecmult_gen_context_init( &curvehash_gen_ctx );
   /* Builds the 64 KB 4-bit-window table and sets up the blinding scalar. */
   secp256k1_ecmult_gen_context_build( &curvehash_gen_ctx,
                                       &curvehash_kernel_cb );
   if ( !secp256k1_ecmult_gen_context_is_built( &curvehash_gen_ctx ) )
      return false;

#ifdef CURVEHASH_USE_W8
   /* Needs the 4-bit context first: ctx->initial and ctx->blind come from the
    * build above and the wider paths reuse them. Widest table first; only an
    * allocation failure steps down, and a step down is invisible to consensus.
    */
#ifdef CURVEHASH_USE_W16
   /* CURVEHASH_NO_W16=1 skips the wide table: both the negative control for the
    * fallback and an escape hatch where 64 MB per process is unwanted. Starving
    * malloc with `ulimit -v` is no substitute -- it does not reliably fire. */
   if ( !getenv( "CURVEHASH_NO_W16" )
        && curvehash_build_table( &curvehash_prec_w16, &curvehash_prec_w16_raw,
                                  CURVEHASH_W16_WINDOWS, 16 ) )
   {
      /* Fail CLOSED, and do NOT fall back: a mismatched table is a correctness
       * fault, so quietly mining a narrower width would hide it. */
      if ( !curvehash_table_ok( curvehash_prec_w16, CURVEHASH_W16_WINDOWS, 16,
                                CURVEHASH_TABLE_DIGEST_W16 ) )
         return false;
      curvehash_gen = curvehash_ecmult_gen_w16;
      curvehash_gen_wbits = 16;
   }
#endif
   /* A flag, not `else` after the #endif: an else-if straddling a conditional
    * block reads as a bug to linters and to the next human. */
   if ( !curvehash_gen_wbits )
   {
      if ( !curvehash_build_table( &curvehash_prec_w8, &curvehash_prec_w8_raw,
                                   CURVEHASH_W8_WINDOWS, 8 ) )
         return false;
      if ( !curvehash_table_ok( curvehash_prec_w8, CURVEHASH_W8_WINDOWS, 8,
                                CURVEHASH_TABLE_DIGEST_W8 ) )
         return false;
      curvehash_gen = curvehash_ecmult_gen_w8;
      curvehash_gen_wbits = 8;
   }
#endif

   curvehash_gen_ready = true;
   return true;
}

int curvehash_kg65( unsigned char out65[65], const unsigned char sec32[32] )
{
   secp256k1_scalar sec;
   secp256k1_gej pj;
   secp256k1_ge p;
   int overflow;

   secp256k1_scalar_set_b32( &sec, sec32, &overflow );
   if ( overflow || secp256k1_scalar_is_zero( &sec ) )
      return 0;

   CURVEHASH_ECMULT_GEN( &curvehash_gen_ctx, &pj, &sec );
   secp256k1_ge_set_gej( &p, &pj );

   /* ge_set_gej leaves x/y reduced but not normalized; fe_get_b32 requires
    * normalized input. _var is fine here -- the value is public. */
   secp256k1_fe_normalize_var( &p.x );
   secp256k1_fe_normalize_var( &p.y );

   out65[0] = 0x04;
   secp256k1_fe_get_b32( out65 + 1,  &p.x );
   secp256k1_fe_get_b32( out65 + 33, &p.y );

   secp256k1_scalar_clear( &sec );
   return 1;
}

void curvehash_kg65_batch( unsigned char out65[][65],
                           const unsigned char sec32[][32],
                           int lanes, uint32_t *active )
{
   secp256k1_gej pj[CURVEHASH_MAX_LANES];
   secp256k1_fe  z [CURVEHASH_MAX_LANES];
   secp256k1_fe  zi[CURVEHASH_MAX_LANES];
   int idx[CURVEHASH_MAX_LANES];
   int cnt = 0;
   uint32_t act = *active;
   int l, k;

   if ( lanes > CURVEHASH_MAX_LANES ) lanes = CURVEHASH_MAX_LANES;

   for ( l = 0; l < lanes; l++ )
   {
      secp256k1_scalar sec;
      int overflow;

      if ( !( act & ( 1u << l ) ) )
         continue;

      secp256k1_scalar_set_b32( &sec, sec32[l], &overflow );
      if ( overflow || secp256k1_scalar_is_zero( &sec ) )
      {
         /* ~2^-128. Drop this lane and keep going: one bad scalar must not
          * cost the whole batch. */
         act &= ~( 1u << l );
         continue;
      }

      CURVEHASH_ECMULT_GEN( &curvehash_gen_ctx, &pj[l], &sec );
      z[cnt]   = pj[l].z;
      idx[cnt] = l;
      cnt++;
      secp256k1_scalar_clear( &sec );
   }

   if ( cnt )
   {
      /* The whole point of this function: ONE modular inversion for the batch,
       * plus ~3 multiplications per lane (Montgomery). Upstream's own routine,
       * the same one ge_set_all_gej_var uses to build the generator table. */
      secp256k1_fe_inv_all_var( zi, z, (size_t)cnt );

      for ( k = 0; k < cnt; k++ )
      {
         secp256k1_ge p;

         l = idx[k];
         secp256k1_ge_set_gej_zinv( &p, &pj[l], &zi[k] );
         secp256k1_fe_normalize_var( &p.x );
         secp256k1_fe_normalize_var( &p.y );
         out65[l][0] = 0x04;
         secp256k1_fe_get_b32( out65[l] + 1,  &p.x );
         secp256k1_fe_get_b32( out65[l] + 33, &p.y );
      }
   }

   *active = act;
}

const char *curvehash_kernel_config( void )
{
#if defined(CURVEHASH_FORCE_CT_ECMULT)
   /* Upstream's secp256k1_ecmult_gen, which does its own constant-time
    * addition -- CURVEHASH_ADD_GE is not on this path, so do not report it. */
   return CURVEHASH_SECP256K1_CONFIG ", constant-time gen, 4-bit window (forced)";
#elif defined(CURVEHASH_FORCE_W4)
   return CURVEHASH_SECP256K1_CONFIG ", vartime gen, 4-bit window (forced)"
          CURVEHASH_ADD_DESC;
#else
   /* Reports the width that was BUILT, not the one this binary prefers: the
    * w=16 table can fail to allocate, so naming the intended width would be
    * wrong exactly when something went wrong. The banner is what attributes an
    * accepted share to the path under test, so it has to be the truth. */
   static char buf[192];

   if ( curvehash_gen_wbits == 16 )
      snprintf( buf, sizeof( buf ), "%s, vartime gen, 16-bit window (64 MB)%s",
                CURVEHASH_SECP256K1_CONFIG, CURVEHASH_ADD_DESC );
   else if ( curvehash_gen_wbits == 8 )
      snprintf( buf, sizeof( buf ), "%s, vartime gen, 8-bit window (512 KB%s)%s",
                CURVEHASH_SECP256K1_CONFIG,
#ifdef CURVEHASH_USE_W16
                ", fell back from 16-bit: no 64 MB table",
#else
                ", forced",
#endif
                CURVEHASH_ADD_DESC );
   else
      snprintf( buf, sizeof( buf ), "%s, vartime gen, NO TABLE BUILT YET",
                CURVEHASH_SECP256K1_CONFIG );
   return buf;
#endif
}
