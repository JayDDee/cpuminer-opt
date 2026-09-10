/* 4-lane fugue512 -- see fugue-hash-4way.h.
 *
 * Compress512 is a mechanical widening of the 1-way round: every operation is
 * 128-bit-lane-local, so it is v128 -> __m512i with the constant masks
 * broadcast to all four sublanes.
 *
 * Final512 needed a different layout instead: it drives 84 SMIX through col[36]
 * with modular indexing. See the layout note above that section.
 *
 * -DFUGUE_NO_NWAY_FINAL reverts Final512 to per-lane scalar.
 */

#include "fugue-hash-4way.h"

/* Constants and the 1-way Final512 are shared by both widths, so they sit
 * outside the per-width guards -- an AVX2+VAES box (Zen 2/3) enables
 * FUGUE_2X128 without FUGUE_4X128 and still needs them. */
#if defined(FUGUE_4X128) || defined(FUGUE_2X128)

#include <memory.h>
#include "fugue-aesni.h"

// Defined in fugue-aesni.c; not in its header.
void Final512( hashState_fugue *ctx, uint8_t *hashval );

static const uint64_t _supermix1a_[2] = { 0x0202010807020100, 0x0a05000f06010c0b };
static const uint64_t _supermix1b_[2] = { 0x0b0d080703060504, 0x0e0a090c050e0f0a };
static const uint64_t _supermix1c_[2] = { 0x0402060c070d0003, 0x090a060580808080 };
static const uint64_t _supermix1d_[2] = { 0x808080800f0e0d0c, 0x0f0e0d0c80808080 };
static const uint64_t _supermix2a_[2] = { 0x07020d0880808080, 0x0b06010c050e0f0a };
static const uint64_t _supermix4a_[2] = { 0x000f0a050c0b0601, 0x0302020404030e09 };
static const uint64_t _supermix4b_[2] = { 0x07020d08080e0d0d, 0x07070908050e0f0a };
static const uint64_t _supermix4c_[2] = { 0x0706050403020000, 0x0302000007060504 };
static const uint64_t _supermix7a_[2] = { 0x010c0b060d080702, 0x0904030e03000104 };
static const uint64_t _supermix7b_[2] = { 0x8080808080808080, 0x0504070605040f06 };
static const uint64_t _inv_shift_rows_[2] = { 0x0b0e0104070a0d00, 0x0306090c0f020508 };
static const uint64_t _mul2mask_[2] = { 0x000000001b1b0000, 0 };
static const uint64_t _mul4mask_[2] = { 0x000000002d361b00, 0 };
static const uint64_t _lsbmask2_[2] = { 0x0303030303030303, 0x0303030303030303 };

static const uint32_t _IV512_[24] __attribute__ ((aligned (32))) =
{  0x00000000, 0x00000000, 0x7ea50788, 0x00000000,
   0x75af16e6, 0xdbe4d3c5, 0x27b09aac, 0x00000000,
   0x17f115d9, 0x54cceeb6, 0x0b02e806, 0x00000000,
   0xd1ef924a, 0xc9e2c6aa, 0x9813b2dd, 0x00000000,
   0x3858e6ca, 0x3f207f43, 0xe778ea25, 0x00000000,
   0xd6dd1f95, 0x1dd16eda, 0x67353ee1, 0x00000000
};

#endif // FUGUE_4X128 || FUGUE_2X128

#if defined(FUGUE_4X128)

#define BC(p)  _mm512_broadcast_i32x4( _mm_load_si128( (const __m128i*)(p) ) )

// masks live in registers across the whole compress loop
static __thread __m512i M_s1a, M_s1b, M_s1c, M_s1d, M_s2a, M_s4a, M_s4b, M_s4c,
                        M_s7a, M_s7b, M_isr, M_mul2, M_mul4, M_lsb2;
static __thread int masks_ready = 0;

static void init_masks( void )
{
   M_s1a = BC(_supermix1a_);  M_s1b = BC(_supermix1b_);
   M_s1c = BC(_supermix1c_);  M_s1d = BC(_supermix1d_);
   M_s2a = BC(_supermix2a_);  M_s4a = BC(_supermix4a_);
   M_s4b = BC(_supermix4b_);  M_s4c = BC(_supermix4c_);
   M_s7a = BC(_supermix7a_);  M_s7b = BC(_supermix7b_);
   M_isr = BC(_inv_shift_rows_);
   M_mul2 = BC(_mul2mask_);   M_mul4 = BC(_mul4mask_);
   M_lsb2 = BC(_lsbmask2_);
   masks_ready = 1;
}

#define X3(a,b,c)   _mm512_ternarylogic_epi32( a, b, c, 0x96 )   // a^b^c
#define SH8(v,m)    _mm512_shuffle_epi8( v, m )
#define SH32(v,i)   _mm512_shuffle_epi32( v, i )

// zero dword 3 of every 128-bit lane
#define MASK_1000(v) _mm512_maskz_mov_epi32( 0x7777, v )

/* v128_shuffle2_32( a, b, _MM_SHUFFLE(3,0,2,1) ): dwords 0,1 from a, 2,3 from b.
 * _mm512_shuffle_ps is per-128-bit-lane, same semantics as _mm_shuffle_ps. */
#define SHUF2_3021(a,b) \
   _mm512_castps_si512( _mm512_shuffle_ps( _mm512_castsi512_ps(a), \
                                           _mm512_castsi512_ps(b), 0xc9 ) )

#define CMIX4( s1, s2, r1, r2, t1, t2 ) \
   t1 = SHUF2_3021( s1, s2 ); \
   r1 = _mm512_xor_si512( r1, t1 ); \
   r2 = _mm512_xor_si512( r2, t1 );

#define PACK_S0_4( s0, s1, t1 ) \
   s0 = _mm512_mask_blend_epi32( 0x8888, s0, SH32( s1, 0x00 ) )

#define UNPACK_S0_4( s0, s1, t1 ) \
   s1 = _mm512_mask_blend_epi32( 0x1111, s1, SH32( s0, 0xff ) ); \
   s0 = MASK_1000( s0 )

#define SUBSTITUTE_4( r0, _t2 ) \
   _t2 = SH8( r0, M_isr ); \
   _t2 = _mm512_aesenclast_epi128( _t2, _mm512_setzero_si512() )

#define SUPERMIX_4(t0, t1, t2, t3, t4)\
   t2 = t0;\
   t3 = _mm512_add_epi8( t0, t0 ); \
   t4 = _mm512_add_epi8( t3, t3 ); \
   t1 = _mm512_srli_epi16( t0, 6 ); \
   t1 = _mm512_and_si512( t1, M_lsb2 ); \
   t0 = _mm512_xor_si512( t4, SH8( M_mul4, t1 ) ); \
   t4 = SH8( t2, M_s1b ); \
   t3 = _mm512_xor_si512( t3, SH8( M_mul2, t1 ) ); \
   t1 = SH8( t4, M_s1c ); \
   t4 = _mm512_xor_si512( t4, t1 ); \
   t1 = SH8( t4, M_s1d ); \
   t4 = _mm512_xor_si512( t4, t1 ); \
   t1 = SH8( t2, M_s1a ); \
   t2 = X3( t2, t3, t0 ); \
   t2 = SH8( t2, M_s7a ); \
   t4 = X3( t4, t1, t2 ); \
   t2 = SH8( t2, M_s7b ); \
   t3 = SH8( t3, M_s2a ); \
   t1 = SH8( t0, M_s4a ); \
   t0 = SH8( t0, M_s4b ); \
   t4 = X3( t4, t2, t1 ); \
   t0 = _mm512_xor_si512( t0, t3 ); \
   t4 = X3( t4, t0, SH8( t0, M_s4c ) );

/* msgv holds the four lanes' next 32-bit message word, one per 128-bit sublane
 * at dword 0, zeros elsewhere -- i.e. the 4-way form of
 * v128_put32( v128_zero, *(uint32_t*)msg, 0 ). */
#define TIX512_4(msgv, s22, s8, s24, s27, s30, s0, s4, s7, t1, t2, t3)\
   t1 = SH32( s0, 0xf3 ); \
   s22 = _mm512_xor_si512( s22, t1 );\
   t1 = msgv; \
   s0 = _mm512_mask_blend_epi32( 0x1111, s0, t1 ); \
   t1 = _mm512_alignr_epi8( t1, _mm512_setzero_si512(), 8 ); \
   s8 = _mm512_xor_si512( s8, t1 );\
   t1 = SH32( s24, 0xf3 ); \
   s0 = _mm512_xor_si512( s0, t1 );\
   t1 = SH32( s27, 0xf3 ); \
   s4 = _mm512_xor_si512( s4, t1 );\
   t1 = SH32( s30, 0xf3 ); \
   s7 = _mm512_xor_si512( s7, t1 )

#define SUBROUND512_4_4(r1a,r1b,r1c,r1d, r2a,r2b,r2c,r2d, \
                        r3a,r3b,r3c,r3d, r4a,r4b,r4c,r4d)\
   CMIX4( r1a, r1b, r1c, r1d, _t0, _t1 );\
   PACK_S0_4( r1c, r1a, _t0 );\
   SUBSTITUTE_4( r1c, _t2 );\
   SUPERMIX_4( _t2, _t3, _t0, _t1, r1c );\
   _t0 = SH32( r1c, 0x39 ); \
   r2c = _mm512_xor_si512( r2c, _t0 );\
   _t0 = MASK_1000( _t0 ); \
   r2d = _mm512_xor_si512( r2d, _t0 );\
   UNPACK_S0_4( r1c, r1a, _t3 );\
   SUBSTITUTE_4( r2c, _t2 );\
   SUPERMIX_4( _t2, _t3, _t0, _t1, r2c );\
   _t0 = SH32( r2c, 0x39 ); \
   r3c = _mm512_xor_si512( r3c, _t0 );\
   _t0 = MASK_1000( _t0 ); \
   r3d = _mm512_xor_si512( r3d, _t0 );\
   UNPACK_S0_4( r2c, r2a, _t3 );\
   SUBSTITUTE_4( r3c, _t2 );\
   SUPERMIX_4( _t2, _t3, _t0, _t1, r3c );\
   _t0 = SH32( r3c, 0x39 ); \
   r4c = _mm512_xor_si512( r4c, _t0 );\
   _t0 = MASK_1000( _t0 ); \
   r4d = _mm512_xor_si512( r4d, _t0 );\
   UNPACK_S0_4( r3c, r3a, _t3 );\
   SUBSTITUTE_4( r4c, _t2 );\
   SUPERMIX_4( _t2, _t3, _t0, _t1, r4c );\
   UNPACK_S0_4( r4c, r4a, _t3 )

static void fugue512_4x128_init( fugue512_4x128_context *ctx )
{
   int i;
   if ( !masks_ready ) init_masks();
   ctx->base = 0;
   for ( i = 0; i < 6; i++ ) ctx->state[i] = _mm512_setzero_si512();
   for ( i = 0; i < 6; i++ )
      ctx->state[6+i] = _mm512_broadcast_i32x4(
                           _mm_load_si128( (const __m128i*)_IV512_ + i ) );
}

/* One 4-byte message word per lane per iteration, exactly as Compress512's
 * base-cycling switch does. nwords must cover the whole padded message. */
static void fugue512_4x128_compress( fugue512_4x128_context *ctx,
                                     const __m512i *msgv, unsigned nwords )
{
   __m512i _t0, _t1, _t2, _t3;
   unsigned n = nwords;
   const __m512i *m = msgv;

   switch ( ctx->base )
   {
      case 1:
         TIX512_4( *m, ctx->state[3], ctx->state[10], ctx->state[4],
                       ctx->state[5], ctx->state[ 6], ctx->state[8],
                       ctx->state[9], ctx->state[10], _t0, _t1, _t2 );
         SUBROUND512_4_4( ctx->state[8], ctx->state[9], ctx->state[7],
                          ctx->state[1], ctx->state[7], ctx->state[8],
                          ctx->state[6], ctx->state[0], ctx->state[6],
                          ctx->state[7], ctx->state[5], ctx->state[11],
                          ctx->state[5], ctx->state[6], ctx->state[4],
                          ctx->state[10] );
         ctx->base++; m++; n--;
         if ( n == 0 ) break;
         // fall through
      case 2:
         TIX512_4( *m, ctx->state[11], ctx->state[6], ctx->state[0],
                       ctx->state[ 1], ctx->state[2], ctx->state[4],
                       ctx->state[ 5], ctx->state[6], _t0, _t1, _t2 );
         SUBROUND512_4_4( ctx->state[4], ctx->state[5], ctx->state[3],
                          ctx->state[9], ctx->state[3], ctx->state[4],
                          ctx->state[2], ctx->state[8], ctx->state[2],
                          ctx->state[3], ctx->state[1], ctx->state[7],
                          ctx->state[1], ctx->state[2], ctx->state[0],
                          ctx->state[6] );
         ctx->base = 0; m++; n--;
         break;
   }

   while ( n > 0 )
   {
      TIX512_4( *m, ctx->state[ 7],ctx->state[2],ctx->state[8],ctx->state[9],
                    ctx->state[10],ctx->state[0],ctx->state[1],ctx->state[2],
                    _t0, _t1, _t2 );
      SUBROUND512_4_4( ctx->state[0],ctx->state[1],ctx->state[11],ctx->state[5],
                       ctx->state[11],ctx->state[0],ctx->state[10],ctx->state[4],
                       ctx->state[10],ctx->state[11],ctx->state[9],ctx->state[3],
                       ctx->state[9],ctx->state[10],ctx->state[8],ctx->state[2] );
      ctx->base++; m++; n--;
      if ( n == 0 ) break;

      TIX512_4( *m, ctx->state[3],ctx->state[10],ctx->state[4],ctx->state[5],
                    ctx->state[6],ctx->state[8], ctx->state[9],ctx->state[10],
                    _t0, _t1, _t2 );
      SUBROUND512_4_4( ctx->state[8],ctx->state[9],ctx->state[7],ctx->state[1],
                       ctx->state[7],ctx->state[8],ctx->state[6],ctx->state[0],
                       ctx->state[6],ctx->state[7],ctx->state[5],ctx->state[11],
                       ctx->state[5],ctx->state[6],ctx->state[4],ctx->state[10] );
      ctx->base++; m++; n--;
      if ( n == 0 ) break;

      TIX512_4( *m, ctx->state[11],ctx->state[6],ctx->state[0],ctx->state[1],
                    ctx->state[2], ctx->state[4],ctx->state[5],ctx->state[6],
                    _t0, _t1, _t2 );
      SUBROUND512_4_4( ctx->state[4],ctx->state[5],ctx->state[3],ctx->state[9],
                       ctx->state[3],ctx->state[4],ctx->state[2],ctx->state[8],
                       ctx->state[2],ctx->state[3],ctx->state[1],ctx->state[7],
                       ctx->state[1],ctx->state[2],ctx->state[0],ctx->state[6] );
      ctx->base = 0; m++; n--;
   }
}

/* Build one __m512i per message word: lane L's word at dword 0 of sublane L.
 * The 1-way code reads the message big-endian-agnostically as a raw uint32, so
 * this must too -- no byte swapping. */
static inline __m512i msg_word4( const uint8_t *i0, const uint8_t *i1,
                                 const uint8_t *i2, const uint8_t *i3, size_t o )
{
   __m128i v = _mm_setr_epi32( *(const uint32_t*)( i0 + o ),
                               *(const uint32_t*)( i1 + o ),
                               *(const uint32_t*)( i2 + o ),
                               *(const uint32_t*)( i3 + o ) );
   const __m512i idx = _mm512_setr_epi32( 0,0,0,0, 1,1,1,1, 2,2,2,2, 3,3,3,3 );
   return _mm512_maskz_permutexvar_epi32( 0x1111, idx,
                                          _mm512_broadcast_i32x4( v ) );
}


/* ------------------------------------------------------------------------
 * 4-way Final512.
 *
 * Layout: col[36] of __m128i, each holding the FOUR LANES' 32-bit value for
 * one column (column-major). Every single-column XOR is then one 128-bit op
 * covering all four lanes, with plain runtime array indices -- no unrolling
 * and no compile-time immediates anywhere.
 *
 * SMIX wants the opposite orientation (one lane's four consecutive columns per
 * 128-bit sublane), so each SMIX transposes 4x4 in, runs the 4-lane kernel
 * once, and transposes back. A 4x4 32-bit transpose is its own inverse, so one
 * macro serves both directions.
 *
 * Load-bearing invariant: `base` evolves from the round index, not the data,
 * so the column-permutation schedule is identical in every lane.
 * ------------------------------------------------------------------------ */

/* 4x4 transpose of 32-bit lanes. Self-inverse. */
#define T4x4( a0, a1, a2, a3, r0, r1, r2, r3 ) do { \
      __m128i _u0 = _mm_unpacklo_epi32( a0, a1 ); \
      __m128i _u1 = _mm_unpackhi_epi32( a0, a1 ); \
      __m128i _u2 = _mm_unpacklo_epi32( a2, a3 ); \
      __m128i _u3 = _mm_unpackhi_epi32( a2, a3 ); \
      r0 = _mm_unpacklo_epi64( _u0, _u2 ); \
      r1 = _mm_unpackhi_epi64( _u0, _u2 ); \
      r2 = _mm_unpacklo_epi64( _u1, _u3 ); \
      r3 = _mm_unpackhi_epi64( _u1, _u3 ); \
   } while (0)

#define CXOR( c, a, b )  (c)[(a)%36] = _mm_xor_si128( (c)[(a)%36], (c)[(b)%36] )

static inline void fugue4_smix( __m128i *col, unsigned base )
{
   __m128i a0 = col[(base+0)%36], a1 = col[(base+1)%36];
   __m128i a2 = col[(base+2)%36], a3 = col[(base+3)%36];
   __m128i r0, r1, r2, r3;
   __m512i v, _t0, _t1, _t2, _t3;

   T4x4( a0, a1, a2, a3, r0, r1, r2, r3 );
   v = _mm512_castsi128_si512( r0 );
   v = _mm512_inserti32x4( v, r1, 1 );
   v = _mm512_inserti32x4( v, r2, 2 );
   v = _mm512_inserti32x4( v, r3, 3 );

   SUBSTITUTE_4( v, _t2 );
   SUPERMIX_4( _t2, _t3, _t0, _t1, v );

   r0 = _mm512_extracti32x4_epi32( v, 0 );
   r1 = _mm512_extracti32x4_epi32( v, 1 );
   r2 = _mm512_extracti32x4_epi32( v, 2 );
   r3 = _mm512_extracti32x4_epi32( v, 3 );
   T4x4( r0, r1, r2, r3, a0, a1, a2, a3 );

   col[(base+0)%36] = a0; col[(base+1)%36] = a1;
   col[(base+2)%36] = a2; col[(base+3)%36] = a3;
}

static void fugue512_4x128_final( fugue512_4x128_context *ctx,
                                  void *out0, void *out1,
                                  void *out2, void *out3 )
{
   __m128i col[36] __attribute__ ((aligned (64)));
   void *outs[4] = { out0, out1, out2, out3 };
   unsigned base, i, b;

   /* state[12] -> col[36]. Each state register holds 4 columns per lane but
    * only the first THREE are live (12 x 3 = 36), exactly as the 1-way does. */
   for ( i = 0; i < 12; i++ )
   {
      __m128i s0 = _mm512_extracti32x4_epi32( ctx->state[i], 0 );
      __m128i s1 = _mm512_extracti32x4_epi32( ctx->state[i], 1 );
      __m128i s2 = _mm512_extracti32x4_epi32( ctx->state[i], 2 );
      __m128i s3 = _mm512_extracti32x4_epi32( ctx->state[i], 3 );
      __m128i r0, r1, r2;
      __m128i r3 __attribute__ ((unused));   // dead 4th column, see above
      T4x4( s0, s1, s2, s3, r0, r1, r2, r3 );
      col[3*i+0] = r0; col[3*i+1] = r1; col[3*i+2] = r2;
   }

   base = ( 36 - ( 12 * ctx->base ) ) % 36;

   for ( i = 0; i < 32; i++ )
   {
      base = ( base + 33 ) % 36;                       // ROR3
      CXOR( col, base +  0, base + 4 );
      CXOR( col, base +  1, base + 5 );
      CXOR( col, base +  2, base + 6 );
      CXOR( col, base + 18, base + 4 );
      CXOR( col, base + 19, base + 5 );
      CXOR( col, base + 20, base + 6 );
      fugue4_smix( col, base );
   }

   for ( i = 0; i < 13; i++ )
   {
      CXOR( col, base +  4, base + 0 );
      CXOR( col, base +  9, base + 0 );
      CXOR( col, base + 18, base + 0 );
      CXOR( col, base + 27, base + 0 );
      base = ( base + 27 ) % 36;                       // ROR9
      fugue4_smix( col, base );

      CXOR( col, base +  4, base + 0 );
      CXOR( col, base + 10, base + 0 );
      CXOR( col, base + 18, base + 0 );
      CXOR( col, base + 27, base + 0 );
      base = ( base + 27 ) % 36;
      fugue4_smix( col, base );

      CXOR( col, base +  4, base + 0 );
      CXOR( col, base + 10, base + 0 );
      CXOR( col, base + 19, base + 0 );
      CXOR( col, base + 27, base + 0 );
      base = ( base + 27 ) % 36;
      fugue4_smix( col, base );

      CXOR( col, base +  4, base + 0 );
      CXOR( col, base + 10, base + 0 );
      CXOR( col, base + 19, base + 0 );
      CXOR( col, base + 28, base + 0 );
      base = ( base + 28 ) % 36;                       // ROR8
      fugue4_smix( col, base );
   }

   CXOR( col, base +  4, base + 0 );
   CXOR( col, base +  9, base + 0 );
   CXOR( col, base + 18, base + 0 );
   CXOR( col, base + 27, base + 0 );

   /* Output: S1..S4, S9..S12, S18..S21, S27..S30, one 16-byte block each. */
   {
      static const unsigned offs[4] = { 1, 9, 18, 27 };
      for ( b = 0; b < 4; b++ )
      {
         unsigned o = offs[b];
         __m128i a0 = col[(base+o+0)%36], a1 = col[(base+o+1)%36];
         __m128i a2 = col[(base+o+2)%36], a3 = col[(base+o+3)%36];
         __m128i r0, r1, r2, r3;
         T4x4( a0, a1, a2, a3, r0, r1, r2, r3 );
         _mm_storeu_si128( (__m128i*)( (uint8_t*)outs[0] + b*16 ), r0 );
         _mm_storeu_si128( (__m128i*)( (uint8_t*)outs[1] + b*16 ), r1 );
         _mm_storeu_si128( (__m128i*)( (uint8_t*)outs[2] + b*16 ), r2 );
         _mm_storeu_si128( (__m128i*)( (uint8_t*)outs[3] + b*16 ), r3 );
      }
   }
}

void fugue512_4x128_full( fugue512_4x128_context *ctx,
                          void *out0, void *out1, void *out2, void *out3,
                          const void *in0, const void *in1,
                          const void *in2, const void *in3,
                          uint64_t len )
{
   /* Padding, mirroring fugue512_Update + fugue512_Final. Fugue has NO 0x80
    * terminator: a partial block is zero-filled, then exactly two 4-byte blocks
    * carrying the 64-bit bit length big-endian (fugue-aesni.c:491-513).
    * Restricted to len % 4 == 0, which is every caller in this tree. */
   __m512i msgv[ 160 ];
   uint8_t lb[8] __attribute__((aligned(16)));
   unsigned nw, i;
   uint64_t bits = len << 3;

   if ( len & 3 ) return;                       // callers never do this
   nw = (unsigned)( len >> 2 );
   if ( nw + 2 > 160 ) return;

   for ( i = 0; i < nw; i++ )
      msgv[i] = msg_word4( in0, in1, in2, in3, i*4 );

   for ( i = 0; i < 8; i++ ) lb[i] = (uint8_t)( bits >> ( 8 * (7-i) ) );
   msgv[nw    ] = msg_word4( lb, lb, lb, lb, 0 );
   msgv[nw + 1] = msg_word4( lb, lb, lb, lb, 4 );

   fugue512_4x128_init( ctx );
   fugue512_4x128_compress( ctx, msgv, nw + 2 );

#if defined(FUGUE_NO_NWAY_FINAL)
   // 1-way Final512, once per lane. Also the oracle the 4-way final is
   // differentially checked against.
   {
      /* Store rather than _mm512_extracti32x4_epi32: that intrinsic needs a
       * literal lane index, so it cannot take a loop variable. */
      v128_t lanes[12][4] __attribute__((aligned(64)));
      hashState_fugue h;
      void *outs[4] = { out0, out1, out2, out3 };
      int L, k;

      for ( k = 0; k < 12; k++ )
         _mm512_store_si512( (__m512i*)lanes[k], ctx->state[k] );

      for ( L = 0; L < 4; L++ )
      {
         h.base = ctx->base;
         h.uHashSize = 512;
         h.uBlockLength = 4;
         h.uBufferBytes = 0;
         h.processed_bits = 0;
         for ( k = 0; k < 12; k++ ) h.state[k] = lanes[k][L];
         Final512( &h, (uint8_t*)outs[L] );
      }
   }
#else
   fugue512_4x128_final( ctx, out0, out1, out2, out3 );
#endif
}

#endif // FUGUE_4X128

/* ------------------------------------------------------------------------
 * 2x128 variant: VAES without AVX-512 (Zen 2 / Zen 3), where x17 and friends
 * select their 4-way width and already use 2-lane groestl/echo.
 *
 * This mirrors the 4x128 round above one-for-one. AVX2 lacks ternarylogic, so
 * X3 becomes two xors; everything else is the same operation at 256 bits.
 * The two widths must be edited in step.
 * ------------------------------------------------------------------------ */

#if defined(FUGUE_2X128)

#define BC2(p) _mm256_broadcastsi128_si256( _mm_load_si128( (const __m128i*)(p) ) )

static __thread __m256i N_s1a, N_s1b, N_s1c, N_s1d, N_s2a, N_s4a, N_s4b, N_s4c,
                        N_s7a, N_s7b, N_isr, N_mul2, N_mul4, N_lsb2;
static __thread int masks2_ready = 0;

static void init_masks2( void )
{
   N_s1a = BC2(_supermix1a_);  N_s1b = BC2(_supermix1b_);
   N_s1c = BC2(_supermix1c_);  N_s1d = BC2(_supermix1d_);
   N_s2a = BC2(_supermix2a_);  N_s4a = BC2(_supermix4a_);
   N_s4b = BC2(_supermix4b_);  N_s4c = BC2(_supermix4c_);
   N_s7a = BC2(_supermix7a_);  N_s7b = BC2(_supermix7b_);
   N_isr = BC2(_inv_shift_rows_);
   N_mul2 = BC2(_mul2mask_);   N_mul4 = BC2(_mul4mask_);
   N_lsb2 = BC2(_lsbmask2_);
   masks2_ready = 1;
}

#define Y3(a,b,c)     _mm256_xor_si256( _mm256_xor_si256(a,b), c )
#define NSH8(v,m)     _mm256_shuffle_epi8( v, m )
#define NSH32(v,i)    _mm256_shuffle_epi32( v, i )
#define NMASK_1000(v) _mm256_blend_epi32( v, _mm256_setzero_si256(), 0x88 )
#define NSHUF2_3021(a,b) \
   _mm256_castps_si256( _mm256_shuffle_ps( _mm256_castsi256_ps(a), \
                                           _mm256_castsi256_ps(b), 0xc9 ) )

#define CMIX2( s1, s2, r1, r2, t1, t2 ) \
   t1 = NSHUF2_3021( s1, s2 ); \
   r1 = _mm256_xor_si256( r1, t1 ); \
   r2 = _mm256_xor_si256( r2, t1 );

#define PACK_S0_2( s0, s1, t1 ) \
   s0 = _mm256_blend_epi32( s0, NSH32( s1, 0x00 ), 0x88 )

#define UNPACK_S0_2( s0, s1, t1 ) \
   s1 = _mm256_blend_epi32( s1, NSH32( s0, 0xff ), 0x11 ); \
   s0 = NMASK_1000( s0 )

#define SUBSTITUTE_2( r0, _t2 ) \
   _t2 = NSH8( r0, N_isr ); \
   _t2 = _mm256_aesenclast_epi128( _t2, _mm256_setzero_si256() )

#define SUPERMIX_2(t0, t1, t2, t3, t4)\
   t2 = t0;\
   t3 = _mm256_add_epi8( t0, t0 ); \
   t4 = _mm256_add_epi8( t3, t3 ); \
   t1 = _mm256_srli_epi16( t0, 6 ); \
   t1 = _mm256_and_si256( t1, N_lsb2 ); \
   t0 = _mm256_xor_si256( t4, NSH8( N_mul4, t1 ) ); \
   t4 = NSH8( t2, N_s1b ); \
   t3 = _mm256_xor_si256( t3, NSH8( N_mul2, t1 ) ); \
   t1 = NSH8( t4, N_s1c ); \
   t4 = _mm256_xor_si256( t4, t1 ); \
   t1 = NSH8( t4, N_s1d ); \
   t4 = _mm256_xor_si256( t4, t1 ); \
   t1 = NSH8( t2, N_s1a ); \
   t2 = Y3( t2, t3, t0 ); \
   t2 = NSH8( t2, N_s7a ); \
   t4 = Y3( t4, t1, t2 ); \
   t2 = NSH8( t2, N_s7b ); \
   t3 = NSH8( t3, N_s2a ); \
   t1 = NSH8( t0, N_s4a ); \
   t0 = NSH8( t0, N_s4b ); \
   t4 = Y3( t4, t2, t1 ); \
   t0 = _mm256_xor_si256( t0, t3 ); \
   t4 = Y3( t4, t0, NSH8( t0, N_s4c ) );

#define TIX512_2(msgv, s22, s8, s24, s27, s30, s0, s4, s7, t1, t2, t3)\
   t1 = NSH32( s0, 0xf3 ); \
   s22 = _mm256_xor_si256( s22, t1 );\
   t1 = msgv; \
   s0 = _mm256_blend_epi32( s0, t1, 0x11 ); \
   t1 = _mm256_alignr_epi8( t1, _mm256_setzero_si256(), 8 ); \
   s8 = _mm256_xor_si256( s8, t1 );\
   t1 = NSH32( s24, 0xf3 ); \
   s0 = _mm256_xor_si256( s0, t1 );\
   t1 = NSH32( s27, 0xf3 ); \
   s4 = _mm256_xor_si256( s4, t1 );\
   t1 = NSH32( s30, 0xf3 ); \
   s7 = _mm256_xor_si256( s7, t1 )

#define SUBROUND512_4_2(r1a,r1b,r1c,r1d, r2a,r2b,r2c,r2d, \
                        r3a,r3b,r3c,r3d, r4a,r4b,r4c,r4d)\
   CMIX2( r1a, r1b, r1c, r1d, _t0, _t1 );\
   PACK_S0_2( r1c, r1a, _t0 );\
   SUBSTITUTE_2( r1c, _t2 );\
   SUPERMIX_2( _t2, _t3, _t0, _t1, r1c );\
   _t0 = NSH32( r1c, 0x39 ); \
   r2c = _mm256_xor_si256( r2c, _t0 );\
   _t0 = NMASK_1000( _t0 ); \
   r2d = _mm256_xor_si256( r2d, _t0 );\
   UNPACK_S0_2( r1c, r1a, _t3 );\
   SUBSTITUTE_2( r2c, _t2 );\
   SUPERMIX_2( _t2, _t3, _t0, _t1, r2c );\
   _t0 = NSH32( r2c, 0x39 ); \
   r3c = _mm256_xor_si256( r3c, _t0 );\
   _t0 = NMASK_1000( _t0 ); \
   r3d = _mm256_xor_si256( r3d, _t0 );\
   UNPACK_S0_2( r2c, r2a, _t3 );\
   SUBSTITUTE_2( r3c, _t2 );\
   SUPERMIX_2( _t2, _t3, _t0, _t1, r3c );\
   _t0 = NSH32( r3c, 0x39 ); \
   r4c = _mm256_xor_si256( r4c, _t0 );\
   _t0 = NMASK_1000( _t0 ); \
   r4d = _mm256_xor_si256( r4d, _t0 );\
   UNPACK_S0_2( r3c, r3a, _t3 );\
   SUBSTITUTE_2( r4c, _t2 );\
   SUPERMIX_2( _t2, _t3, _t0, _t1, r4c );\
   UNPACK_S0_2( r4c, r4a, _t3 )

static void fugue512_2x128_init( fugue512_2x128_context *ctx )
{
   int i;
   if ( !masks2_ready ) init_masks2();
   ctx->base = 0;
   for ( i = 0; i < 6; i++ ) ctx->state[i] = _mm256_setzero_si256();
   for ( i = 0; i < 6; i++ )
      ctx->state[6+i] = _mm256_broadcastsi128_si256(
                           _mm_load_si128( (const __m128i*)_IV512_ + i ) );
}

static void fugue512_2x128_compress( fugue512_2x128_context *ctx,
                                     const __m256i *msgv, unsigned nwords )
{
   __m256i _t0, _t1, _t2, _t3;
   unsigned n = nwords;
   const __m256i *m = msgv;

   switch ( ctx->base )
   {
      case 1:
         TIX512_2( *m, ctx->state[3], ctx->state[10], ctx->state[4],
                       ctx->state[5], ctx->state[ 6], ctx->state[8],
                       ctx->state[9], ctx->state[10], _t0, _t1, _t2 );
         SUBROUND512_4_2( ctx->state[8], ctx->state[9], ctx->state[7],
                          ctx->state[1], ctx->state[7], ctx->state[8],
                          ctx->state[6], ctx->state[0], ctx->state[6],
                          ctx->state[7], ctx->state[5], ctx->state[11],
                          ctx->state[5], ctx->state[6], ctx->state[4],
                          ctx->state[10] );
         ctx->base++; m++; n--;
         if ( n == 0 ) break;
         // fall through
      case 2:
         TIX512_2( *m, ctx->state[11], ctx->state[6], ctx->state[0],
                       ctx->state[ 1], ctx->state[2], ctx->state[4],
                       ctx->state[ 5], ctx->state[6], _t0, _t1, _t2 );
         SUBROUND512_4_2( ctx->state[4], ctx->state[5], ctx->state[3],
                          ctx->state[9], ctx->state[3], ctx->state[4],
                          ctx->state[2], ctx->state[8], ctx->state[2],
                          ctx->state[3], ctx->state[1], ctx->state[7],
                          ctx->state[1], ctx->state[2], ctx->state[0],
                          ctx->state[6] );
         ctx->base = 0; m++; n--;
         break;
   }

   while ( n > 0 )
   {
      TIX512_2( *m, ctx->state[ 7],ctx->state[2],ctx->state[8],ctx->state[9],
                    ctx->state[10],ctx->state[0],ctx->state[1],ctx->state[2],
                    _t0, _t1, _t2 );
      SUBROUND512_4_2( ctx->state[0],ctx->state[1],ctx->state[11],ctx->state[5],
                       ctx->state[11],ctx->state[0],ctx->state[10],ctx->state[4],
                       ctx->state[10],ctx->state[11],ctx->state[9],ctx->state[3],
                       ctx->state[9],ctx->state[10],ctx->state[8],ctx->state[2] );
      ctx->base++; m++; n--;
      if ( n == 0 ) break;

      TIX512_2( *m, ctx->state[3],ctx->state[10],ctx->state[4],ctx->state[5],
                    ctx->state[6],ctx->state[8], ctx->state[9],ctx->state[10],
                    _t0, _t1, _t2 );
      SUBROUND512_4_2( ctx->state[8],ctx->state[9],ctx->state[7],ctx->state[1],
                       ctx->state[7],ctx->state[8],ctx->state[6],ctx->state[0],
                       ctx->state[6],ctx->state[7],ctx->state[5],ctx->state[11],
                       ctx->state[5],ctx->state[6],ctx->state[4],ctx->state[10] );
      ctx->base++; m++; n--;
      if ( n == 0 ) break;

      TIX512_2( *m, ctx->state[11],ctx->state[6],ctx->state[0],ctx->state[1],
                    ctx->state[2], ctx->state[4],ctx->state[5],ctx->state[6],
                    _t0, _t1, _t2 );
      SUBROUND512_4_2( ctx->state[4],ctx->state[5],ctx->state[3],ctx->state[9],
                       ctx->state[3],ctx->state[4],ctx->state[2],ctx->state[8],
                       ctx->state[2],ctx->state[3],ctx->state[1],ctx->state[7],
                       ctx->state[1],ctx->state[2],ctx->state[0],ctx->state[6] );
      ctx->base = 0; m++; n--;
   }
}

static inline __m256i msg_word2( const uint8_t *i0, const uint8_t *i1, size_t o )
{
   return _mm256_setr_epi32( (int)*(const uint32_t*)( i0 + o ), 0, 0, 0,
                             (int)*(const uint32_t*)( i1 + o ), 0, 0, 0 );
}

void fugue512_2x128_full( fugue512_2x128_context *ctx,
                          void *out0, void *out1,
                          const void *in0, const void *in1, uint64_t len )
{
   __m256i msgv[ 160 ];
   uint8_t lb[8] __attribute__((aligned(16)));
   unsigned nw, i;
   uint64_t bits = len << 3;

   if ( len & 3 ) return;
   nw = (unsigned)( len >> 2 );
   if ( nw + 2 > 160 ) return;

   for ( i = 0; i < nw; i++ ) msgv[i] = msg_word2( in0, in1, i*4 );
   for ( i = 0; i < 8; i++ ) lb[i] = (uint8_t)( bits >> ( 8 * (7-i) ) );
   msgv[nw    ] = msg_word2( lb, lb, 0 );
   msgv[nw + 1] = msg_word2( lb, lb, 4 );

   fugue512_2x128_init( ctx );
   fugue512_2x128_compress( ctx, msgv, nw + 2 );

   {
      v128_t lanes[12][2] __attribute__((aligned(64)));
      hashState_fugue h;
      void *outs[2] = { out0, out1 };
      int L, k;
      for ( k = 0; k < 12; k++ )
         _mm256_store_si256( (__m256i*)lanes[k], ctx->state[k] );
      for ( L = 0; L < 2; L++ )
      {
         h.base = ctx->base;
         h.uHashSize = 512; h.uBlockLength = 4;
         h.uBufferBytes = 0; h.processed_bits = 0;
         for ( k = 0; k < 12; k++ ) h.state[k] = lanes[k][L];
         Final512( &h, (uint8_t*)outs[L] );
      }
   }
}

#endif // FUGUE_2X128
