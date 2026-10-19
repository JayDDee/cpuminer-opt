/*
 * bc3hash's elliptic-curve kernel, on libsecp256k1's internals. A BC3Mix curve
 * multiplication is a sum of precomputed table points: the same gej_add_ge_var
 * additions as the public API, but a variable-time affine conversion shared
 * across sums. Inputs are public hash data; this is not a signing primitive.
 * Every library function is static, so nothing collides with curvehash's
 * older copy, which is the startup oracle (ec_self_test).
 */
#include <stdlib.h>
#include <string.h>

#include "bc3hash-ec.h"

/* Our autotools build defines HAVE_CONFIG_H project-wide; the vendored util.h
 * must not go looking for libsecp256k1's own config header. */
#undef HAVE_CONFIG_H

#include "secp256k1/src/util.h"
#include "secp256k1/src/int128_impl.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/group_impl.h"

/* bc3hash needs a 64-bit target anyway (__int128 in the C++ core); this pins
 * the 5x52 field, whose storage form is four little-endian 64-bit limbs. */
#if !defined(SECP256K1_WIDEMUL_INT128)
#error "bc3hash-ec.c needs the 64-bit (5x52) secp256k1 field"
#endif

static int fe_from_limbs( secp256k1_fe *r, const uint64_t v[4] )
{
   unsigned char b[32];
   for ( int i = 0; i < 4; i++ )
      for ( int j = 0; j < 8; j++ )
         b[i * 8 + j] = (unsigned char)( v[3 - i] >> ( 56 - 8 * j ) );
   return secp256k1_fe_set_b32_limit( r, b );
}

static void fe_to_limbs( uint64_t v[4], secp256k1_fe *a )
{
   secp256k1_fe_storage s;
   secp256k1_fe_normalize_var( a );
   secp256k1_fe_to_storage( &s, a );
   memcpy( v, s.n, 32 );
}

static void ge_to_affine( bc3ec_affine *out, secp256k1_ge *a )
{
   fe_to_limbs( out->x, &a->x );
   fe_to_limbs( out->y, &a->y );
}

/* Affine conversions batched per chunk: one inversion per CHUNK points. */
#define CHUNK 4096

int bc3ec_row( void *row, unsigned count, const bc3ec_affine *base,
               bc3ec_affine *next )
{
   secp256k1_ge_storage *out = (secp256k1_ge_storage*)row;
   secp256k1_fe x, y;
   secp256k1_ge b;
   secp256k1_gej acc;
   if ( !fe_from_limbs( &x, base->x ) || !fe_from_limbs( &y, base->y ) )
      return -1;
   secp256k1_ge_set_xy( &b, &x, &y );
   if ( !secp256k1_ge_is_valid_var( &b ) )
      return -1;

   secp256k1_gej *jac = malloc( CHUNK * sizeof *jac );
   secp256k1_ge *aff = malloc( CHUNK * sizeof *aff );
   if ( !jac || !aff )
   {
      free( jac );
      free( aff );
      return -2;
   }
   secp256k1_gej_set_ge( &acc, &b );
   for ( unsigned done = 0; done < count; )
   {
      const unsigned n = count - done < CHUNK ? count - done : CHUNK;
      for ( unsigned i = 0; i < n; i++ )
      {
         jac[i] = acc;
         secp256k1_gej_add_ge_var( &acc, &acc, &b, NULL );
      }
      secp256k1_ge_set_all_gej_var( aff, jac, n );
      for ( unsigned i = 0; i < n; i++ )
         secp256k1_ge_to_storage( &out[done + i], &aff[i] );
      done += n;
   }
   free( jac );
   free( aff );
   if ( next )
   {
      secp256k1_ge a;
      secp256k1_ge_set_gej_var( &a, &acc );
      ge_to_affine( next, &a );
   }
   return 0;
}

/* acc[s] = sum of the n[s] entries of pts[s], for s in [first, last). */
static void sum_scalar( secp256k1_gej *acc, const void *const pts[][BC3EC_MAX_POINTS],
                        const unsigned *n, unsigned first, unsigned last )
{
   unsigned most = 0;
   for ( unsigned s = first; s < last; s++ )
   {
      secp256k1_ge q;
      secp256k1_ge_from_storage( &q, (const secp256k1_ge_storage*)pts[s][0] );
      secp256k1_gej_set_ge( &acc[s], &q );
      if ( n[s] > most ) most = n[s];
   }
   /* Round-robin over the sums: each is a dependent chain of additions, and
    * interleaving them gives the core independent work to overlap. */
   for ( unsigned i = 1; i < most; i++ )
      for ( unsigned s = first; s < last; s++ )
         if ( i < n[s] )
         {
            secp256k1_ge q;
            secp256k1_ge_from_storage( &q, (const secp256k1_ge_storage*)pts[s][i] );
            secp256k1_gej_add_ge_var( &acc[s], &acc[s], &q, NULL );
         }
}

#if defined(__x86_64__) && defined(__AVX512F__) && defined(__AVX512IFMA__) && !defined(BC3HASH_NO_IFMA)
#define BC3EC_IFMA 1
#include <immintrin.h>
/* Eight sums at once with AVX-512 IFMA: the same point additions as
 * gej_add_ge_var (Jacobian + affine, 8M + 3S), one sum per 64-bit lane.
 *
 * 8 field elements mod p in 5x52-bit limbs. Every limb is < 2^52 after
 * each operation, because IFMA reads only the low 52 bits of its operands;
 * the value is < 2^260 and congruent, not canonical. */
typedef struct { __m512i l[5]; } vfe;
#define VFE_M52 0xFFFFFFFFFFFFFULL
#define VFE_R   0x1000003D10ULL      /* 2^260 mod p = 16 * 0x1000003D1 */

/* Limbs < 2^63 in, < 2^52 out. The first ripple's carry out (weight 2^260,
 * < 2^12) folds back into limb 0; if the second ripple carries out again,
 * the value was just above 2^260, so the rest is < 2^49 and + R fits. */
static inline __attribute__((always_inline)) void vfe_norm( vfe *a )
{
   const __m512i m = _mm512_set1_epi64( VFE_M52 ), r = _mm512_set1_epi64( VFE_R );
   for ( int pass = 0; pass < 2; pass++ )
   {
      __m512i carry = _mm512_setzero_si512();
      for ( int i = 0; i < 5; i++ )
      {
         const __m512i t = _mm512_add_epi64( a->l[i], carry );
         a->l[i] = _mm512_and_si512( t, m );
         carry = _mm512_srli_epi64( t, 52 );
      }
      a->l[0] = _mm512_madd52lo_epu64( a->l[0], carry, r );
   }
}

static inline __attribute__((always_inline)) vfe vfe_mul( const vfe *a, const vfe *b )
{
   const __m512i z = _mm512_setzero_si512(), m = _mm512_set1_epi64( VFE_M52 ),
                 r = _mm512_set1_epi64( VFE_R );
   __m512i c[10];
   for ( int k = 0; k < 10; k++ )
      c[k] = z;
   /* Column sums: at most 5 low and 5 high halves each, < 2^56. */
   for ( int i = 0; i < 5; i++ )
      for ( int j = 0; j < 5; j++ )
      {
         c[i + j] = _mm512_madd52lo_epu64( c[i + j], a->l[i], b->l[j] );
         c[i + j + 1] = _mm512_madd52hi_epu64( c[i + j + 1], a->l[i], b->l[j] );
      }
   /* To 52-bit limbs. The product is < 2^520, so nothing carries out of 9. */
   __m512i carry = z;
   for ( int k = 0; k < 10; k++ )
   {
      const __m512i t = _mm512_add_epi64( c[k], carry );
      c[k] = _mm512_and_si512( t, m );
      carry = _mm512_srli_epi64( t, 52 );
   }
   /* Fold limbs 5..9 (weight 2^260 * 2^52i == R * 2^52i): low half of h_i*R
    * at limb i, high half (< 2^37) at limb i+1. h_4's high half lands at
    * 2^260 again; that top word is < 2^37, and top*R < 2^74 needs both halves. */
   vfe o;
   for ( int i = 0; i < 5; i++ )
      o.l[i] = _mm512_madd52lo_epu64( c[i], c[i + 5], r );
   for ( int i = 0; i < 4; i++ )
      o.l[i + 1] = _mm512_madd52hi_epu64( o.l[i + 1], c[i + 5], r );
   const __m512i top = _mm512_madd52hi_epu64( z, c[9], r );
   o.l[0] = _mm512_madd52lo_epu64( o.l[0], top, r );
   o.l[1] = _mm512_madd52hi_epu64( o.l[1], top, r );
   vfe_norm( &o );
   return o;
}

static inline __attribute__((always_inline)) vfe vfe_add( const vfe *a, const vfe *b )
{
   vfe o;
   for ( int i = 0; i < 5; i++ )
      o.l[i] = _mm512_add_epi64( a->l[i], b->l[i] );
   vfe_norm( &o );
   return o;
}

/* a - b as a + 32p - b: 32p written limb-wise from p's 5x52 limbs, so every
 * limb is >= 2^52 > any limb of b and nothing goes negative. */
static inline __attribute__((always_inline)) vfe vfe_sub( const vfe *a, const vfe *b )
{
   static const uint64_t k[5] = { 32 * 0xFFFFEFFFFFC2FULL, 32 * 0xFFFFFFFFFFFFFULL,
      32 * 0xFFFFFFFFFFFFFULL, 32 * 0xFFFFFFFFFFFFFULL, 32 * 0xFFFFFFFFFFFFULL };
   vfe o;
   for ( int i = 0; i < 5; i++ )
      o.l[i] = _mm512_sub_epi64( _mm512_add_epi64( a->l[i], _mm512_set1_epi64( k[i] ) ),
                                 b->l[i] );
   vfe_norm( &o );
   return o;
}

/* x, y of eight ge_storage entries (4 little-endian 64-bit limbs each). */
static inline void vfe_load_ge( vfe *x, vfe *y, const void *const p[8] )
{
   uint64_t w[8][8] __attribute__((aligned(64)));
   for ( int k = 0; k < 8; k++ )
   {
      uint64_t e[8];
      memcpy( e, p[k], sizeof e );
      for ( int j = 0; j < 8; j++ )
         w[j][k] = e[j];
   }
   const __m512i m = _mm512_set1_epi64( VFE_M52 );
   for ( int h = 0; h < 2; h++ )
   {
      vfe *f = h ? y : x;
      const __m512i w0 = _mm512_load_si512( w[4 * h] ), w1 = _mm512_load_si512( w[4 * h + 1] ),
                    w2 = _mm512_load_si512( w[4 * h + 2] ), w3 = _mm512_load_si512( w[4 * h + 3] );
      f->l[0] = _mm512_and_si512( w0, m );
      f->l[1] = _mm512_and_si512( _mm512_or_si512( _mm512_srli_epi64( w0, 52 ), _mm512_slli_epi64( w1, 12 ) ), m );
      f->l[2] = _mm512_and_si512( _mm512_or_si512( _mm512_srli_epi64( w1, 40 ), _mm512_slli_epi64( w2, 24 ) ), m );
      f->l[3] = _mm512_and_si512( _mm512_or_si512( _mm512_srli_epi64( w2, 28 ), _mm512_slli_epi64( w3, 36 ) ), m );
      f->l[4] = _mm512_srli_epi64( w3, 16 );
   }
}

/* One lane's 5x52 value (< 2^260) to a normalized field element. */
static void lazy_to_fe( secp256k1_fe *r, const uint64_t l[5] )
{
   const uint64_t C = 0x1000003D1ULL;   /* 2^256 mod p */
   uint64_t w[4];
   w[0] = l[0] | l[1] << 52;
   w[1] = l[1] >> 12 | l[2] << 40;
   w[2] = l[2] >> 24 | l[3] << 28;
   w[3] = l[3] >> 36 | l[4] << 16;
   uint64_t add = ( l[4] >> 48 ) * C;   /* top 4 bits, < 2^37 */
   for ( int pass = 0; pass < 2 && add; pass++ )
   {
      unsigned __int128 t = (unsigned __int128)w[0] + add;
      w[0] = (uint64_t)t;
      for ( int i = 1; i < 4; i++ )
      {
         t = (unsigned __int128)w[i] + (uint64_t)( t >> 64 );
         w[i] = (uint64_t)t;
      }
      add = (uint64_t)( t >> 64 ) * C;  /* a carry out leaves w < 2^37 */
   }
   /* w >= p iff w + C carries out of 2^256; then w - p == w + C mod 2^256. */
   unsigned __int128 t = (unsigned __int128)w[0] + C;
   uint64_t v[4];
   v[0] = (uint64_t)t;
   for ( int i = 1; i < 4; i++ )
   {
      t = (unsigned __int128)w[i] + (uint64_t)( t >> 64 );
      v[i] = (uint64_t)t;
   }
   if ( t >> 64 )
      memcpy( w, v, sizeof w );
   fe_from_limbs( r, w );
}

#ifdef BC3EC_TEST_FALLBACK
long bc3ec_fallbacks = 0;            /* test builds only: proves the path ran */
#endif

/* acc[0..7] = the 8 sums starting at pts[0], n[0]. Same additions as
 * sum_scalar, as Jacobian + affine: Z = 1 at the start, so U1 = X, S1 = Y. */
static void sum8_ifma( secp256k1_gej *acc, const void *const pts[][BC3EC_MAX_POINTS],
                       const unsigned *n )
{
   const void *p[8];
   unsigned most = 0;
   for ( int s = 0; s < 8; s++ )
   {
      p[s] = pts[s][0];
      if ( n[s] > most ) most = n[s];
   }
   vfe X, Y, Z;
   vfe_load_ge( &X, &Y, p );
   Z.l[0] = _mm512_set1_epi64( 1 );
   for ( int i = 1; i < 5; i++ )
      Z.l[i] = _mm512_setzero_si512();
   for ( unsigned i = 1; i < most; i++ )
   {
      /* Lanes past their last digit add their own first entry again and
       * keep the old value: any valid address will do. */
      __mmask8 live = 0;
      for ( int s = 0; s < 8; s++ )
         if ( i < n[s] )
         {
            p[s] = pts[s][i];
            live |= (__mmask8)( 1u << s );
         }
         else
            p[s] = pts[s][0];
      vfe x2, y2;
      vfe_load_ge( &x2, &y2, p );
      const vfe z2 = vfe_mul( &Z, &Z ), z3 = vfe_mul( &z2, &Z );
      const vfe u2 = vfe_mul( &x2, &z2 ), s2 = vfe_mul( &y2, &z3 );
      const vfe h = vfe_sub( &u2, &X ), rr = vfe_sub( &s2, &Y );
      const vfe h2 = vfe_mul( &h, &h ), h3 = vfe_mul( &h2, &h ), v = vfe_mul( &X, &h2 );
      const vfe r2 = vfe_mul( &rr, &rr ), v2 = vfe_add( &v, &v ), t = vfe_add( &h3, &v2 );
      const vfe x3 = vfe_sub( &r2, &t );
      const vfe vx = vfe_sub( &v, &x3 ), a = vfe_mul( &rr, &vx ), b = vfe_mul( &Y, &h3 );
      const vfe y3 = vfe_sub( &a, &b ), z3n = vfe_mul( &Z, &h );
      for ( int k = 0; k < 5; k++ )
      {
         X.l[k] = _mm512_mask_mov_epi64( X.l[k], live, x3.l[k] );
         Y.l[k] = _mm512_mask_mov_epi64( Y.l[k], live, y3.l[k] );
         Z.l[k] = _mm512_mask_mov_epi64( Z.l[k], live, z3n.l[k] );
      }
   }
   uint64_t lx[5][8] __attribute__((aligned(64))), ly[5][8] __attribute__((aligned(64))),
            lz[5][8] __attribute__((aligned(64)));
   for ( int k = 0; k < 5; k++ )
   {
      _mm512_store_si512( lx[k], X.l[k] );
      _mm512_store_si512( ly[k], Y.l[k] );
      _mm512_store_si512( lz[k], Z.l[k] );
   }
   for ( int s = 0; s < 8; s++ )
   {
      const uint64_t ex[5] = { lx[0][s], lx[1][s], lx[2][s], lx[3][s], lx[4][s] };
      const uint64_t ey[5] = { ly[0][s], ly[1][s], ly[2][s], ly[3][s], ly[4][s] };
      const uint64_t ez[5] = { lz[0][s], lz[1][s], lz[2][s], lz[3][s], lz[4][s] };
      lazy_to_fe( &acc[s].x, ex );
      lazy_to_fe( &acc[s].y, ey );
      lazy_to_fe( &acc[s].z, ez );
      acc[s].infinity = 0;
      /* H == 0 (doubling, or a sum reaching infinity) zeroes every later Z.
       * Impossible with these tables (each partial scalar sum is in (0, n) and
       * below the next entry's), but redo such a sum with libsecp if it occurs. */
      int redo = secp256k1_fe_normalizes_to_zero_var( &acc[s].z );
#ifdef BC3EC_TEST_FALLBACK
      redo |= ( s & 3 ) == 0;
      bc3ec_fallbacks += redo;
#endif
      if ( redo )
         sum_scalar( acc, pts, n, (unsigned)s, (unsigned)s + 1 );
   }
}
#endif

int bc3ec_sum( bc3ec_affine *out, const void *const pts[][BC3EC_MAX_POINTS],
               const unsigned *n, unsigned sums )
{
   secp256k1_gej acc[BC3EC_MAX_SUMS];
   secp256k1_ge r[BC3EC_MAX_SUMS];
   if ( sums - 1 >= BC3EC_MAX_SUMS )   /* also rejects sums == 0 */
      return -1;
   unsigned s0 = 0;
#ifdef BC3EC_IFMA
   for ( ; s0 + 8 <= sums; s0 += 8 )
      sum8_ifma( &acc[s0], &pts[s0], &n[s0] );
#endif
   sum_scalar( acc, pts, n, s0, sums );
   for ( unsigned s = 0; s < sums; s++ )
      if ( secp256k1_gej_is_infinity( &acc[s] ) )
         return -1;
   secp256k1_ge_set_all_gej_var( r, acc, sums );
   for ( unsigned s = 0; s < sums; s++ )
      ge_to_affine( &out[s], &r[s] );
   return 0;
}

const char *bc3ec_config( void )
{
#ifdef BC3EC_IFMA
   return "libsecp256k1 57315a6985 internals, sums 8 at a time with AVX-512 IFMA";
#else
   return "libsecp256k1 57315a6985 internals, field 5x52 (int128)";
#endif
}
