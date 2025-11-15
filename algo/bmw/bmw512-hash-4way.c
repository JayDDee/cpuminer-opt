/* $Id: bmw.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * BMW implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "bmw-hash-4way.h"

#define LPAR   (

static const uint64_t IV512[] = {
        0x8081828384858687, 0x88898A8B8C8D8E8F,
        0x9091929394959697, 0x98999A9B9C9D9E9F,
        0xA0A1A2A3A4A5A6A7, 0xA8A9AAABACADAEAF,
        0xB0B1B2B3B4B5B6B7, 0xB8B9BABBBCBDBEBF,
        0xC0C1C2C3C4C5C6C7, 0xC8C9CACBCCCDCECF,
        0xD0D1D2D3D4D5D6D7, 0xD8D9DADBDCDDDEDF,
        0xE0E1E2E3E4E5E6E7, 0xE8E9EAEBECEDEEEF,
        0xF0F1F2F3F4F5F6F7, 0xF8F9FAFBFCFDFEFF
};

// SSE2 or NEON BMW-512 2 way 64

static const v128u64_t final_2x64[16] =
{
   { 0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0 },
   { 0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1 },
   { 0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2 },
   { 0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3 },
   { 0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4 },
   { 0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5 },
   { 0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6 },
   { 0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7 },
   { 0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8 },
   { 0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9 },
   { 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
   { 0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab },
   { 0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac },
   { 0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad },
   { 0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae },
   { 0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf }
};

#define xor4( v3, v2, v1, v0 ) \
   v128_xor( v128_xor( v3, v2 ), v128_xor( v1, v0 ) )

#define s2b0(x) \
   xor4( v128_sr64( (x), 1), v128_sl64( (x), 3), \
         v128_rol64(     (x), 4),  v128_rol64(     (x),37) )

#define s2b1(x) \
   xor4( v128_sr64( (x), 1), v128_sl64( (x), 2), \
         v128_rol64(     (x),13),  v128_rol64(     (x),43) )

#define s2b2(x) \
   xor4( v128_sr64( (x), 2), v128_sl64( (x), 1), \
         v128_rol64(     (x),19),  v128_rol64(     (x),53) )

#define s2b3(x) \
   xor4( v128_sr64( (x), 2), v128_sl64( (x), 2), \
         v128_rol64(     (x),28),  v128_rol64(     (x),59) )

#define s2b4(x) \
  v128_xor( (x), v128_sr64( (x), 1 ) )

#define s2b5(x) \
  v128_xor( (x), v128_sr64( (x), 2 ) )

#define r2b1(x)    v128_rol64( x,  5 )
#define r2b2(x)    v128_rol64( x, 11 )
#define r2b3(x)    v128_rol64( x, 27 )
#define r2b4(x)    v128_rol64( x, 32 )
#define r2b5(x)    v128_rol64( x, 37 )
#define r2b6(x)    v128_rol64( x, 43 )
#define r2b7(x)    v128_rol64( x, 53 )

#define add_elt_b( mj0, mj3, mj10, h, K ) \
  v128_xor( h, v128_add64( K, \
              v128_sub64( v128_add64( mj0, mj3 ), mj10 ) ) )

#define expand1_b( qt, i ) \
   v128_add4_64( \
      v128_add4_64( s2b1( qt[ (i)-16 ] ), s2b2( qt[ (i)-15 ] ), \
                    s2b3( qt[ (i)-14 ] ), s2b0( qt[ (i)-13 ] )), \
      v128_add4_64( s2b1( qt[ (i)-12 ] ), s2b2( qt[ (i)-11 ] ), \
                    s2b3( qt[ (i)-10 ] ), s2b0( qt[ (i)- 9 ] )), \
      v128_add4_64( s2b1( qt[ (i)- 8 ] ), s2b2( qt[ (i)- 7 ] ), \
                    s2b3( qt[ (i)- 6 ] ), s2b0( qt[ (i)- 5 ] )), \
      v128_add4_64( s2b1( qt[ (i)- 4 ] ), s2b2( qt[ (i)- 3 ] ), \
                    s2b3( qt[ (i)- 2 ] ), s2b0( qt[ (i)- 1 ] ) ) )

#define expand2_b( qt, i) \
   v128_add4_64( \
      v128_add4_64( qt[ (i)-16 ], r2b1( qt[ (i)-15 ] ), \
                    qt[ (i)-14 ], r2b2( qt[ (i)-13 ] ) ), \
      v128_add4_64( qt[ (i)-12 ], r2b3( qt[ (i)-11 ] ), \
                    qt[ (i)-10 ], r2b4( qt[ (i)- 9 ] ) ), \
      v128_add4_64( qt[ (i)- 8 ], r2b5( qt[ (i)- 7 ] ), \
                    qt[ (i)- 6 ], r2b6( qt[ (i)- 5 ] ) ), \
      v128_add4_64( qt[ (i)- 4 ], r2b7( qt[ (i)- 3 ] ), \
                     s2b4( qt[ (i)- 2 ] ), s2b5( qt[ (i)- 1 ] ) ) )

#define W2b0 \
   v128_add64( \
      v128_add64( v128_sub64( mh[ 5], mh[ 7] ), mh[10] ), \
      v128_add64( mh[13], mh[14] ) )

#define W2b1 \
   v128_add64( \
       v128_add64( v128_sub64( mh[ 6], mh[ 8] ), mh[11] ), \
       v128_sub64( mh[14], mh[15] ) )

#define W2b2 \
   v128_sub64( \
      v128_add64( v128_add64( mh[ 0], mh[ 7] ), mh[ 9] ), \
      v128_sub64( mh[12], mh[15] ) )

#define W2b3 \
   v128_sub64( \
      v128_add64( v128_sub64( mh[ 0], mh[ 1] ), mh[ 8] ), \
      v128_sub64( mh[10], mh[13] ) )

#define W2b4 \
   v128_sub64( \
      v128_add64( v128_add64( mh[ 1], mh[ 2] ), mh[ 9] ), \
      v128_add64( mh[11], mh[14] ) )

#define W2b5 \
   v128_sub64( \
      v128_add64( v128_sub64( mh[ 3], mh[ 2] ), mh[10] ), \
      v128_sub64( mh[12], mh[15] ) )

#define W2b6 \
   v128_sub64( \
      v128_sub64( v128_sub64( mh[ 4], mh[ 0] ), mh[ 3] ), \
      v128_sub64( mh[11], mh[13] ) )

#define W2b7 \
   v128_sub64( \
      v128_sub64( v128_sub64( mh[ 1], mh[ 4] ), mh[ 5] ), \
      v128_add64( mh[12], mh[14] ) )

#define W2b8 \
   v128_add64( \
      v128_sub64( v128_sub64( mh[ 2], mh[ 5] ), mh[ 6] ), \
      v128_sub64( mh[13], mh[15] ) )

#define W2b9 \
   v128_sub64( \
      v128_add64( v128_sub64( mh[ 0], mh[ 3] ), mh[ 6] ), \
      v128_sub64( mh[ 7], mh[14] ) )

#define W2b10 \
   v128_sub64( \
      v128_sub64( v128_sub64( mh[ 8], mh[ 1] ), mh[ 4] ), \
      v128_sub64( mh[ 7], mh[15] ) )

#define W2b11 \
   v128_sub64( \
      v128_sub64( v128_sub64( mh[ 8], mh[ 0] ), mh[ 2] ), \
      v128_sub64( mh[ 5], mh[ 9] ) )

#define W2b12 \
   v128_sub64( \
      v128_sub64( v128_add64( mh[ 1], mh[ 3] ), mh[ 6] ), \
      v128_sub64( mh[ 9], mh[10] ) )

#define W2b13 \
   v128_add64( \
      v128_add64( v128_add64( mh[ 2], mh[ 4] ), mh[ 7] ), \
      v128_add64( mh[10], mh[11] ) )

#define W2b14 \
   v128_sub64( \
      v128_add64( v128_sub64( mh[ 3], mh[ 5] ), mh[ 8] ), \
      v128_add64( mh[11], mh[12] ) )

#define W2b15 \
   v128_sub64( \
      v128_sub64( v128_sub64( mh[12], mh[ 4] ), mh[ 6] ), \
      v128_sub64( mh[ 9], mh[13] ) )

void compress_2x64( const v128u64_t *M, const v128u64_t H[16], v128u64_t dH[16] )
{
   v128u64_t qt[32], xl, xh;
   v128u64_t mh[16];
   int i;
   v128u64_t K = v128_64( 16 * 0x0555555555555555ULL );
   const v128u64_t Kincr = v128_64( 0x0555555555555555ULL );

   for ( i = 0; i < 16; i++ )
      mh[i] = v128_xor( M[i], H[i] );
   qt[ 0] = v128_add64( s2b0( W2b0 ), H[ 1] );
   qt[ 1] = v128_add64( s2b1( W2b1 ), H[ 2] );
   qt[ 2] = v128_add64( s2b2( W2b2 ), H[ 3] );
   qt[ 3] = v128_add64( s2b3( W2b3 ), H[ 4] );
   qt[ 4] = v128_add64( s2b4( W2b4 ), H[ 5] );
   qt[ 5] = v128_add64( s2b0( W2b5 ), H[ 6] );
   qt[ 6] = v128_add64( s2b1( W2b6 ), H[ 7] );
   qt[ 7] = v128_add64( s2b2( W2b7 ), H[ 8] );
   qt[ 8] = v128_add64( s2b3( W2b8 ), H[ 9] );
   qt[ 9] = v128_add64( s2b4( W2b9 ), H[10] );
   qt[10] = v128_add64( s2b0( W2b10), H[11] );
   qt[11] = v128_add64( s2b1( W2b11), H[12] );
   qt[12] = v128_add64( s2b2( W2b12), H[13] );
   qt[13] = v128_add64( s2b3( W2b13), H[14] );
   qt[14] = v128_add64( s2b4( W2b14), H[15] );
   qt[15] = v128_add64( s2b0( W2b15), H[ 0] );

   v128u64_t mj[16];

   mj[ 0] = v128_rol64( M[ 0],  1 );
   mj[ 1] = v128_rol64( M[ 1],  2 );
   mj[ 2] = v128_rol64( M[ 2],  3 );
   mj[ 3] = v128_rol64( M[ 3],  4 );
   mj[ 4] = v128_rol64( M[ 4],  5 );
   mj[ 5] = v128_rol64( M[ 5],  6 );
   mj[ 6] = v128_rol64( M[ 6],  7 );
   mj[ 7] = v128_rol64( M[ 7],  8 );
   mj[ 8] = v128_rol64( M[ 8],  9 );
   mj[ 9] = v128_rol64( M[ 9], 10 );
   mj[10] = v128_rol64( M[10], 11 );
   mj[11] = v128_rol64( M[11], 12 );
   mj[12] = v128_rol64( M[12], 13 );
   mj[13] = v128_rol64( M[13], 14 );
   mj[14] = v128_rol64( M[14], 15 );
   mj[15] = v128_rol64( M[15], 16 );

   qt[16] = add_elt_b( mj[ 0], mj[ 3], mj[10], H[ 7], K );
   K = v128_add64( K, Kincr );
   qt[17] = add_elt_b( mj[ 1], mj[ 4], mj[11], H[ 8], K );
   K = v128_add64( K, Kincr );
   qt[18] = add_elt_b( mj[ 2], mj[ 5], mj[12], H[ 9], K );
   K = v128_add64( K, Kincr );
   qt[19] = add_elt_b( mj[ 3], mj[ 6], mj[13], H[10], K );
   K = v128_add64( K, Kincr );
   qt[20] = add_elt_b( mj[ 4], mj[ 7], mj[14], H[11], K );
   K = v128_add64( K, Kincr );
   qt[21] = add_elt_b( mj[ 5], mj[ 8], mj[15], H[12], K );
   K = v128_add64( K, Kincr );
   qt[22] = add_elt_b( mj[ 6], mj[ 9], mj[ 0], H[13], K );
   K = v128_add64( K, Kincr );
   qt[23] = add_elt_b( mj[ 7], mj[10], mj[ 1], H[14], K );
   K = v128_add64( K, Kincr );
   qt[24] = add_elt_b( mj[ 8], mj[11], mj[ 2], H[15], K );
   K = v128_add64( K, Kincr );
   qt[25] = add_elt_b( mj[ 9], mj[12], mj[ 3], H[ 0], K );
   K = v128_add64( K, Kincr );
   qt[26] = add_elt_b( mj[10], mj[13], mj[ 4], H[ 1], K );
   K = v128_add64( K, Kincr );
   qt[27] = add_elt_b( mj[11], mj[14], mj[ 5], H[ 2], K );
   K = v128_add64( K, Kincr );
   qt[28] = add_elt_b( mj[12], mj[15], mj[ 6], H[ 3], K );
   K = v128_add64( K, Kincr );
   qt[29] = add_elt_b( mj[13], mj[ 0], mj[ 7], H[ 4], K );
   K = v128_add64( K, Kincr );
   qt[30] = add_elt_b( mj[14], mj[ 1], mj[ 8], H[ 5], K );
   K = v128_add64( K, Kincr );
   qt[31] = add_elt_b( mj[15], mj[ 2], mj[ 9], H[ 6], K );

   qt[16] = v128_add64( qt[16], expand1_b( qt, 16 ) );
   qt[17] = v128_add64( qt[17], expand1_b( qt, 17 ) );
   qt[18] = v128_add64( qt[18], expand2_b( qt, 18 ) );
   qt[19] = v128_add64( qt[19], expand2_b( qt, 19 ) );
   qt[20] = v128_add64( qt[20], expand2_b( qt, 20 ) );
   qt[21] = v128_add64( qt[21], expand2_b( qt, 21 ) );
   qt[22] = v128_add64( qt[22], expand2_b( qt, 22 ) );
   qt[23] = v128_add64( qt[23], expand2_b( qt, 23 ) );
   qt[24] = v128_add64( qt[24], expand2_b( qt, 24 ) );
   qt[25] = v128_add64( qt[25], expand2_b( qt, 25 ) );
   qt[26] = v128_add64( qt[26], expand2_b( qt, 26 ) );
   qt[27] = v128_add64( qt[27], expand2_b( qt, 27 ) );
   qt[28] = v128_add64( qt[28], expand2_b( qt, 28 ) );
   qt[29] = v128_add64( qt[29], expand2_b( qt, 29 ) );
   qt[30] = v128_add64( qt[30], expand2_b( qt, 30 ) );
   qt[31] = v128_add64( qt[31], expand2_b( qt, 31 ) );

   xl = v128_xor3( v128_xor3( qt[16], qt[17], qt[18] ),
                   v128_xor3( qt[19], qt[20], qt[21] ),
                   v128_xor(  qt[22], qt[23] ) );

   xh = v128_xor3( v128_xor3( xl,     qt[24], qt[25] ),
                   v128_xor3( qt[26], qt[27], qt[28] ),
                   v128_xor3( qt[29], qt[30], qt[31] ) );
   
#define DH1L( m, sl, sr, a, b, c ) \
   v128_add64( \
               v128_xor( M[m], \
                  v128_xor( v128_sl64( xh, sl ), \
                                    v128_sr64( qt[a], sr ) ) ), \
               v128_xor( v128_xor( xl, qt[b] ), qt[c] ) )

#define DH1R( m, sl, sr, a, b, c ) \
   v128_add64( \
               v128_xor( M[m], \
                  v128_xor( v128_sr64( xh, sl ), \
                                    v128_sl64( qt[a], sr ) ) ), \
               v128_xor( v128_xor( xl, qt[b] ), qt[c] ) )

#define DH2L( m, rl, sl, h, a, b, c ) \
   v128_add64( v128_add64( \
       v128_rol64( dH[h], rl ), \
          v128_xor( v128_xor( xh, qt[a] ), M[m] )), \
                 v128_xor( v128_sl64( xl, sl ), \
                                   v128_xor( qt[b], qt[c] ) ) );

#define DH2R( m, rl, sr, h, a, b, c ) \
   v128_add64( v128_add64( \
       v128_rol64( dH[h], rl ), \
          v128_xor( v128_xor( xh, qt[a] ), M[m] )), \
                 v128_xor( v128_sr64( xl, sr ), \
                                   v128_xor( qt[b], qt[c] ) ) );

   dH[ 0] = DH1L(  0,  5,  5, 16, 24, 0 );
   dH[ 1] = DH1R(  1,  7,  8, 17, 25, 1 );
   dH[ 2] = DH1R(  2,  5,  5, 18, 26, 2 );
   dH[ 3] = DH1R(  3,  1,  5, 19, 27, 3 );
   dH[ 4] = DH1R(  4,  3,  0, 20, 28, 4 );
   dH[ 5] = DH1L(  5,  6,  6, 21, 29, 5 );
   dH[ 6] = DH1R(  6,  4,  6, 22, 30, 6 );
   dH[ 7] = DH1R(  7, 11,  2, 23, 31, 7 );
   dH[ 8] = DH2L(  8,  9,  8,  4, 24, 23,  8 );
   dH[ 9] = DH2R(  9, 10,  6,  5, 25, 16,  9 );
   dH[10] = DH2L( 10, 11,  6,  6, 26, 17, 10 );
   dH[11] = DH2L( 11, 12,  4,  7, 27, 18, 11 );
   dH[12] = DH2R( 12, 13,  3,  0, 28, 19, 12 );
   dH[13] = DH2R( 13, 14,  4,  1, 29, 20, 13 );
   dH[14] = DH2R( 14, 15,  7,  2, 30, 21, 14 );
   dH[15] = DH2R( 15, 16,  2,  3, 31, 22, 15 );

#undef DH1L
#undef DH1R
#undef DH2L
#undef DH2R
}
static void

bmw64_2way_init( bmw_2way_big_context *sc, const uint64_t *iv )
{
   sc->H[ 0] = v128_64( 0x8081828384858687 );
   sc->H[ 1] = v128_64( 0x88898A8B8C8D8E8F );
   sc->H[ 2] = v128_64( 0x9091929394959697 );
   sc->H[ 3] = v128_64( 0x98999A9B9C9D9E9F );
   sc->H[ 4] = v128_64( 0xA0A1A2A3A4A5A6A7 );
   sc->H[ 5] = v128_64( 0xA8A9AAABACADAEAF );
   sc->H[ 6] = v128_64( 0xB0B1B2B3B4B5B6B7 );
   sc->H[ 7] = v128_64( 0xB8B9BABBBCBDBEBF );
   sc->H[ 8] = v128_64( 0xC0C1C2C3C4C5C6C7 );
   sc->H[ 9] = v128_64( 0xC8C9CACBCCCDCECF );
   sc->H[10] = v128_64( 0xD0D1D2D3D4D5D6D7 );
   sc->H[11] = v128_64( 0xD8D9DADBDCDDDEDF );
   sc->H[12] = v128_64( 0xE0E1E2E3E4E5E6E7 );
   sc->H[13] = v128_64( 0xE8E9EAEBECEDEEEF );
   sc->H[14] = v128_64( 0xF0F1F2F3F4F5F6F7 );
   sc->H[15] = v128_64( 0xF8F9FAFBFCFDFEFF );
   sc->ptr = 0;
   sc->bit_count = 0;
}

static void
bmw64_2way( bmw_2way_big_context *sc, const void *data, size_t len )
{
   v128u64_t *vdata = (v128u64_t*)data;
   v128u64_t *buf;
   v128u64_t htmp[16];
   v128u64_t *h1, *h2;
   size_t ptr;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   sc->bit_count += (uint64_t)len << 3;
   buf = sc->buf;
   ptr = sc->ptr;
   h1 = sc->H;
   h2 = htmp;
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      v128_memcpy( buf + (ptr>>3), vdata, clen >> 3 );
      vdata = vdata + (clen>>3);
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         v128u64_t *ht;
         compress_2x64( buf, h1, h2 );
         ht = h1;
         h1 = h2;
         h2 = ht;
         ptr = 0;
      }
   }
   sc->ptr = ptr;
   if ( h1 != sc->H )
        v128_memcpy( sc->H, h1, 16 );
}

static void
bmw64_2way_close( bmw_2way_big_context *sc, unsigned ub, unsigned n,
   void *dst, size_t out_size_w64)
{
   v128u64_t *buf;
   v128u64_t h1[16], h2[16], *h;
   size_t ptr, u, v;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   buf = sc->buf;
   ptr = sc->ptr;
   buf[ ptr>>3 ] = v128_64( 0x80 );
   ptr += 8;
   h = sc->H;

   if (  ptr > (buf_size - 8) )
   {
      v128_memset_zero( buf + (ptr>>3), (buf_size - ptr) >> 3 );
      compress_2x64( buf, h, h1 );
      ptr = 0;
      h = h1;
   }
   v128_memset_zero( buf + (ptr>>3), (buf_size - 8 - ptr) >> 3 );
   buf[ (buf_size - 8) >> 3 ] = v128_64( sc->bit_count + n );
   compress_2x64( buf, h, h2 );
   for ( u = 0; u < 16; u ++ )
      buf[u] = h2[u];
   compress_2x64( buf, (const v128u64_t*)final_2x64, h1 );
   for (u = 0, v = 16 - out_size_w64; u < out_size_w64; u ++, v ++)
      casti_v128u64(dst,u) = h1[v];
}

void
bmw512_2x64_init( bmw512_2x64_context *cc )
{
   bmw64_2way_init( cc, IV512 );
}

void
bmw512_2x64_update( bmw512_2x64_context *cc, const void *data, size_t len )
{
   bmw64_2way( cc, data, len );
}

void
bmw512_2x64_close( bmw512_2x64_context *cc, void *dst )
{
   bmw64_2way_close( cc, 0, 0, dst, 8 );
}

void bmw512_2x64_ctx( bmw512_2x64_context *ctx, void *dst, const void *data,
                      size_t len )
{
   bmw512_2x64_init( ctx );
   bmw512_2x64_update( ctx, data, len );
   bmw512_2x64_close( ctx, dst );
}

void bmw512_2x64( void *dst, const void *data, size_t len )
{
   bmw512_2x64_context ctx;
   bmw512_2x64_init( &ctx );
   bmw512_2x64_update( &ctx, data, len );
   bmw512_2x64_close( &ctx, dst );
}

#undef add_elt_b
#undef expand1_b
#undef expand2_b

#if defined(__AVX2__)

// BMW-512 4 way 64

#define sb0(x) \
   mm256_xor4( _mm256_srli_epi64( (x), 1), _mm256_slli_epi64( (x), 3), \
                mm256_rol_64(     (x), 4),  mm256_rol_64(     (x),37) )

#define sb1(x) \
   mm256_xor4( _mm256_srli_epi64( (x), 1), _mm256_slli_epi64( (x), 2), \
                mm256_rol_64(     (x),13),  mm256_rol_64(     (x),43) )

#define sb2(x) \
   mm256_xor4( _mm256_srli_epi64( (x), 2), _mm256_slli_epi64( (x), 1), \
                mm256_rol_64(     (x),19),  mm256_rol_64(     (x),53) )

#define sb3(x) \
   mm256_xor4( _mm256_srli_epi64( (x), 2), _mm256_slli_epi64( (x), 2), \
                mm256_rol_64(     (x),28),  mm256_rol_64(     (x),59) )

#define sb4(x) \
  _mm256_xor_si256( (x), _mm256_srli_epi64( (x), 1 ) )

#define sb5(x) \
  _mm256_xor_si256( (x), _mm256_srli_epi64( (x), 2 ) )

#define rb1(x)    mm256_rol_64( x,  5 ) 
#define rb2(x)    mm256_rol_64( x, 11 ) 
#define rb3(x)    mm256_rol_64( x, 27 ) 
#define rb4(x)    mm256_rol_64( x, 32 ) 
#define rb5(x)    mm256_rol_64( x, 37 ) 
#define rb6(x)    mm256_rol_64( x, 43 ) 
#define rb7(x)    mm256_rol_64( x, 53 ) 

#define add_elt_b( mj0, mj3, mj10, h, K ) \
  _mm256_xor_si256( h, _mm256_add_epi64( K, \
              _mm256_sub_epi64( _mm256_add_epi64( mj0, mj3 ), mj10 ) ) )

#define expand1_b( qt, i ) \
   mm256_add4_64( \
      mm256_add4_64( sb1( qt[ (i)-16 ] ), sb2( qt[ (i)-15 ] ), \
                     sb3( qt[ (i)-14 ] ), sb0( qt[ (i)-13 ] )), \
      mm256_add4_64( sb1( qt[ (i)-12 ] ), sb2( qt[ (i)-11 ] ), \
                     sb3( qt[ (i)-10 ] ), sb0( qt[ (i)- 9 ] )), \
      mm256_add4_64( sb1( qt[ (i)- 8 ] ), sb2( qt[ (i)- 7 ] ), \
                     sb3( qt[ (i)- 6 ] ), sb0( qt[ (i)- 5 ] )), \
      mm256_add4_64( sb1( qt[ (i)- 4 ] ), sb2( qt[ (i)- 3 ] ), \
                     sb3( qt[ (i)- 2 ] ), sb0( qt[ (i)- 1 ] ) ) )

#define expand2_b( qt, i) \
   mm256_add4_64( \
      mm256_add4_64( qt[ (i)-16 ], rb1( qt[ (i)-15 ] ), \
                     qt[ (i)-14 ], rb2( qt[ (i)-13 ] ) ), \
      mm256_add4_64( qt[ (i)-12 ], rb3( qt[ (i)-11 ] ), \
                     qt[ (i)-10 ], rb4( qt[ (i)- 9 ] ) ), \
      mm256_add4_64( qt[ (i)- 8 ], rb5( qt[ (i)- 7 ] ), \
                     qt[ (i)- 6 ], rb6( qt[ (i)- 5 ] ) ), \
      mm256_add4_64( qt[ (i)- 4 ], rb7( qt[ (i)- 3 ] ), \
                     sb4( qt[ (i)- 2 ] ), sb5( qt[ (i)- 1 ] ) ) )

#define Wb0 \
   _mm256_add_epi64( \
      _mm256_add_epi64( _mm256_sub_epi64( mh[ 5], mh[ 7] ), mh[10] ), \
      _mm256_add_epi64( mh[13], mh[14] ) )

#define Wb1 \
   _mm256_add_epi64( \
       _mm256_add_epi64( _mm256_sub_epi64( mh[ 6], mh[ 8] ), mh[11] ), \
       _mm256_sub_epi64( mh[14], mh[15] ) )

#define Wb2 \
   _mm256_sub_epi64( \
      _mm256_add_epi64( _mm256_add_epi64( mh[ 0], mh[ 7] ), mh[ 9] ), \
      _mm256_sub_epi64( mh[12], mh[15] ) )

#define Wb3 \
   _mm256_sub_epi64( \
      _mm256_add_epi64( _mm256_sub_epi64( mh[ 0], mh[ 1] ), mh[ 8] ), \
      _mm256_sub_epi64( mh[10], \
                        mh[13] ) )

#define Wb4 \
   _mm256_sub_epi64( \
      _mm256_add_epi64( _mm256_add_epi64( mh[ 1], mh[ 2] ), mh[ 9] ), \
      _mm256_add_epi64( mh[11], mh[14] ) )

#define Wb5 \
   _mm256_sub_epi64( \
      _mm256_add_epi64( _mm256_sub_epi64( mh[ 3], mh[ 2] ), mh[10] ), \
      _mm256_sub_epi64( mh[12], mh[15] ) )

#define Wb6 \
   _mm256_sub_epi64( \
      _mm256_sub_epi64( _mm256_sub_epi64( mh[ 4], mh[ 0] ), mh[ 3] ), \
      _mm256_sub_epi64( mh[11], mh[13] ) )

#define Wb7 \
   _mm256_sub_epi64( \
      _mm256_sub_epi64( _mm256_sub_epi64( mh[ 1], mh[ 4] ), mh[ 5] ), \
      _mm256_add_epi64( mh[12], mh[14] ) )

#define Wb8 \
   _mm256_add_epi64( \
      _mm256_sub_epi64( _mm256_sub_epi64( mh[ 2], mh[ 5] ), mh[ 6] ), \
      _mm256_sub_epi64( mh[13], mh[15] ) )

#define Wb9 \
   _mm256_sub_epi64( \
      _mm256_add_epi64( _mm256_sub_epi64( mh[ 0], mh[ 3] ), mh[ 6] ), \
      _mm256_sub_epi64( mh[ 7], mh[14] ) )

#define Wb10 \
   _mm256_sub_epi64( \
      _mm256_sub_epi64( _mm256_sub_epi64( mh[ 8], mh[ 1] ), mh[ 4] ), \
      _mm256_sub_epi64( mh[ 7], mh[15] ) )

#define Wb11 \
   _mm256_sub_epi64( \
      _mm256_sub_epi64( _mm256_sub_epi64( mh[ 8], mh[ 0] ), mh[ 2] ), \
      _mm256_sub_epi64( mh[ 5], mh[ 9] ) )

#define Wb12 \
   _mm256_sub_epi64( \
      _mm256_sub_epi64( _mm256_add_epi64( mh[ 1], mh[ 3] ), mh[ 6] ), \
      _mm256_sub_epi64( mh[ 9], mh[10] ) )

#define Wb13 \
   _mm256_add_epi64( \
      _mm256_add_epi64( _mm256_add_epi64( mh[ 2], mh[ 4] ), mh[ 7] ), \
      _mm256_add_epi64( mh[10], mh[11] ) )

#define Wb14 \
   _mm256_sub_epi64( \
      _mm256_add_epi64( _mm256_sub_epi64( mh[ 3], mh[ 5] ), mh[ 8] ), \
      _mm256_add_epi64( mh[11], mh[12] ) )

#define Wb15 \
   _mm256_sub_epi64( \
      _mm256_sub_epi64( _mm256_sub_epi64( mh[12], mh[ 4] ), mh[ 6] ), \
      _mm256_sub_epi64( mh[ 9], mh[13] ) )


void compress_big( const __m256i *M, const __m256i H[16], __m256i dH[16] )
{
   __m256i qt[32], xl, xh;
   __m256i mh[16];
   int i;

   for ( i = 0; i < 16; i++ )
      mh[i] = _mm256_xor_si256( M[i], H[i] );

   qt[ 0] = _mm256_add_epi64( sb0( Wb0 ), H[ 1] ); 
   qt[ 1] = _mm256_add_epi64( sb1( Wb1 ), H[ 2] ); 
   qt[ 2] = _mm256_add_epi64( sb2( Wb2 ), H[ 3] ); 
   qt[ 3] = _mm256_add_epi64( sb3( Wb3 ), H[ 4] ); 
   qt[ 4] = _mm256_add_epi64( sb4( Wb4 ), H[ 5] ); 
   qt[ 5] = _mm256_add_epi64( sb0( Wb5 ), H[ 6] ); 
   qt[ 6] = _mm256_add_epi64( sb1( Wb6 ), H[ 7] ); 
   qt[ 7] = _mm256_add_epi64( sb2( Wb7 ), H[ 8] ); 
   qt[ 8] = _mm256_add_epi64( sb3( Wb8 ), H[ 9] ); 
   qt[ 9] = _mm256_add_epi64( sb4( Wb9 ), H[10] ); 
   qt[10] = _mm256_add_epi64( sb0( Wb10), H[11] ); 
   qt[11] = _mm256_add_epi64( sb1( Wb11), H[12] ); 
   qt[12] = _mm256_add_epi64( sb2( Wb12), H[13] ); 
   qt[13] = _mm256_add_epi64( sb3( Wb13), H[14] );
   qt[14] = _mm256_add_epi64( sb4( Wb14), H[15] ); 
   qt[15] = _mm256_add_epi64( sb0( Wb15), H[ 0] ); 

   __m256i mj[16];

   mj[ 0] = mm256_rol_64( M[ 0],  1 );
   mj[ 1] = mm256_rol_64( M[ 1],  2 );
   mj[ 2] = mm256_rol_64( M[ 2],  3 );
   mj[ 3] = mm256_rol_64( M[ 3],  4 );
   mj[ 4] = mm256_rol_64( M[ 4],  5 );
   mj[ 5] = mm256_rol_64( M[ 5],  6 );
   mj[ 6] = mm256_rol_64( M[ 6],  7 );
   mj[ 7] = mm256_rol_64( M[ 7],  8 );
   mj[ 8] = mm256_rol_64( M[ 8],  9 );
   mj[ 9] = mm256_rol_64( M[ 9], 10 );
   mj[10] = mm256_rol_64( M[10], 11 );
   mj[11] = mm256_rol_64( M[11], 12 );
   mj[12] = mm256_rol_64( M[12], 13 );
   mj[13] = mm256_rol_64( M[13], 14 );
   mj[14] = mm256_rol_64( M[14], 15 );
   mj[15] = mm256_rol_64( M[15], 16 );

   __m256i K = _mm256_set1_epi64x( 0x5555555555555550ULL );
   static const __m256i Kincr = { 0x0555555555555555ULL, 0x0555555555555555ULL,
                                  0x0555555555555555ULL, 0x0555555555555555ULL };

   qt[16] = add_elt_b( mj[ 0], mj[ 3], mj[10], H[ 7], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[17] = add_elt_b( mj[ 1], mj[ 4], mj[11], H[ 8], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[18] = add_elt_b( mj[ 2], mj[ 5], mj[12], H[ 9], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[19] = add_elt_b( mj[ 3], mj[ 6], mj[13], H[10], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[20] = add_elt_b( mj[ 4], mj[ 7], mj[14], H[11], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[21] = add_elt_b( mj[ 5], mj[ 8], mj[15], H[12], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[22] = add_elt_b( mj[ 6], mj[ 9], mj[ 0], H[13], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[23] = add_elt_b( mj[ 7], mj[10], mj[ 1], H[14], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[24] = add_elt_b( mj[ 8], mj[11], mj[ 2], H[15], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[25] = add_elt_b( mj[ 9], mj[12], mj[ 3], H[ 0], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[26] = add_elt_b( mj[10], mj[13], mj[ 4], H[ 1], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[27] = add_elt_b( mj[11], mj[14], mj[ 5], H[ 2], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[28] = add_elt_b( mj[12], mj[15], mj[ 6], H[ 3], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[29] = add_elt_b( mj[13], mj[ 0], mj[ 7], H[ 4], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[30] = add_elt_b( mj[14], mj[ 1], mj[ 8], H[ 5], K );
   K = _mm256_add_epi64( K, Kincr );
   qt[31] = add_elt_b( mj[15], mj[ 2], mj[ 9], H[ 6], K );

   qt[16] = _mm256_add_epi64( qt[16], expand1_b( qt, 16 ) );
   qt[17] = _mm256_add_epi64( qt[17], expand1_b( qt, 17 ) );
   qt[18] = _mm256_add_epi64( qt[18], expand2_b( qt, 18 ) );
   qt[19] = _mm256_add_epi64( qt[19], expand2_b( qt, 19 ) );
   qt[20] = _mm256_add_epi64( qt[20], expand2_b( qt, 20 ) );
   qt[21] = _mm256_add_epi64( qt[21], expand2_b( qt, 21 ) );
   qt[22] = _mm256_add_epi64( qt[22], expand2_b( qt, 22 ) );
   qt[23] = _mm256_add_epi64( qt[23], expand2_b( qt, 23 ) );
   qt[24] = _mm256_add_epi64( qt[24], expand2_b( qt, 24 ) );
   qt[25] = _mm256_add_epi64( qt[25], expand2_b( qt, 25 ) );
   qt[26] = _mm256_add_epi64( qt[26], expand2_b( qt, 26 ) );
   qt[27] = _mm256_add_epi64( qt[27], expand2_b( qt, 27 ) );
   qt[28] = _mm256_add_epi64( qt[28], expand2_b( qt, 28 ) );
   qt[29] = _mm256_add_epi64( qt[29], expand2_b( qt, 29 ) );
   qt[30] = _mm256_add_epi64( qt[30], expand2_b( qt, 30 ) );
   qt[31] = _mm256_add_epi64( qt[31], expand2_b( qt, 31 ) );

   xl = _mm256_xor_si256(
           mm256_xor4( qt[16], qt[17], qt[18], qt[19] ), 
           mm256_xor4( qt[20], qt[21], qt[22], qt[23] ) ); 
   xh = _mm256_xor_si256( xl, _mm256_xor_si256( 
           mm256_xor4( qt[24], qt[25], qt[26], qt[27] ),
           mm256_xor4( qt[28], qt[29], qt[30], qt[31] ) ) );

#define DH1L( m, sl, sr, a, b, c ) \
   _mm256_add_epi64( \
               _mm256_xor_si256( M[m], \
                  _mm256_xor_si256( _mm256_slli_epi64( xh, sl ), \
                                    _mm256_srli_epi64( qt[a], sr ) ) ), \
               _mm256_xor_si256( _mm256_xor_si256( xl, qt[b] ), qt[c] ) )

#define DH1R( m, sl, sr, a, b, c ) \
   _mm256_add_epi64( \
               _mm256_xor_si256( M[m], \
                  _mm256_xor_si256( _mm256_srli_epi64( xh, sl ), \
                                    _mm256_slli_epi64( qt[a], sr ) ) ), \
               _mm256_xor_si256( _mm256_xor_si256( xl, qt[b] ), qt[c] ) )

#define DH2L( m, rl, sl, h, a, b, c ) \
   _mm256_add_epi64( _mm256_add_epi64( \
       mm256_rol_64( dH[h], rl ), \
          _mm256_xor_si256( _mm256_xor_si256( xh, qt[a] ), M[m] )), \
                 _mm256_xor_si256( _mm256_slli_epi64( xl, sl ), \
                                   _mm256_xor_si256( qt[b], qt[c] ) ) );

#define DH2R( m, rl, sr, h, a, b, c ) \
   _mm256_add_epi64( _mm256_add_epi64( \
       mm256_rol_64( dH[h], rl ), \
          _mm256_xor_si256( _mm256_xor_si256( xh, qt[a] ), M[m] )), \
                 _mm256_xor_si256( _mm256_srli_epi64( xl, sr ), \
                                   _mm256_xor_si256( qt[b], qt[c] ) ) );

   dH[ 0] = DH1L(  0,  5,  5, 16, 24, 0 );
   dH[ 1] = DH1R(  1,  7,  8, 17, 25, 1 );
   dH[ 2] = DH1R(  2,  5,  5, 18, 26, 2 );
   dH[ 3] = DH1R(  3,  1,  5, 19, 27, 3 );
   dH[ 4] = DH1R(  4,  3,  0, 20, 28, 4 );
   dH[ 5] = DH1L(  5,  6,  6, 21, 29, 5 );
   dH[ 6] = DH1R(  6,  4,  6, 22, 30, 6 );
   dH[ 7] = DH1R(  7, 11,  2, 23, 31, 7 );
   dH[ 8] = DH2L(  8,  9,  8,  4, 24, 23,  8 );
   dH[ 9] = DH2R(  9, 10,  6,  5, 25, 16,  9 );
   dH[10] = DH2L( 10, 11,  6,  6, 26, 17, 10 );
   dH[11] = DH2L( 11, 12,  4,  7, 27, 18, 11 );
   dH[12] = DH2R( 12, 13,  3,  0, 28, 19, 12 );
   dH[13] = DH2R( 13, 14,  4,  1, 29, 20, 13 );
   dH[14] = DH2R( 14, 15,  7,  2, 30, 21, 14 );
   dH[15] = DH2R( 15, 16,  2,  3, 31, 22, 15 );

#undef DH1L
#undef DH1R
#undef DH2L
#undef DH2R
}

static const __m256i final_b[16] =
{
   { 0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0,
     0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0 },
   { 0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1,
     0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1 },
   { 0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2,
     0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2 },
   { 0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3,
     0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3 },
   { 0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4,
     0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4 },
   { 0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5,
     0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5 },
   { 0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6,
     0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6 },
   { 0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7,
     0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7 },
   { 0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8,
     0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8 },
   { 0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9,
     0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9 },
   { 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
     0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
   { 0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab,
     0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab },
   { 0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac,
     0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac },
   { 0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad,
     0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad },
   { 0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae,
     0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae },
   { 0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf,
     0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf }
};

static void
bmw64_4way_init( bmw_4way_big_context *sc, const uint64_t *iv )
{
   sc->H[ 0] = _mm256_set1_epi64x( 0x8081828384858687 );
   sc->H[ 1] = _mm256_set1_epi64x( 0x88898A8B8C8D8E8F );
   sc->H[ 2] = _mm256_set1_epi64x( 0x9091929394959697 );
   sc->H[ 3] = _mm256_set1_epi64x( 0x98999A9B9C9D9E9F );
   sc->H[ 4] = _mm256_set1_epi64x( 0xA0A1A2A3A4A5A6A7 );
   sc->H[ 5] = _mm256_set1_epi64x( 0xA8A9AAABACADAEAF );
   sc->H[ 6] = _mm256_set1_epi64x( 0xB0B1B2B3B4B5B6B7 );
   sc->H[ 7] = _mm256_set1_epi64x( 0xB8B9BABBBCBDBEBF );
   sc->H[ 8] = _mm256_set1_epi64x( 0xC0C1C2C3C4C5C6C7 );
   sc->H[ 9] = _mm256_set1_epi64x( 0xC8C9CACBCCCDCECF );
   sc->H[10] = _mm256_set1_epi64x( 0xD0D1D2D3D4D5D6D7 );
   sc->H[11] = _mm256_set1_epi64x( 0xD8D9DADBDCDDDEDF );
   sc->H[12] = _mm256_set1_epi64x( 0xE0E1E2E3E4E5E6E7 );
   sc->H[13] = _mm256_set1_epi64x( 0xE8E9EAEBECEDEEEF );
   sc->H[14] = _mm256_set1_epi64x( 0xF0F1F2F3F4F5F6F7 );
   sc->H[15] = _mm256_set1_epi64x( 0xF8F9FAFBFCFDFEFF );
   sc->ptr = 0;
   sc->bit_count = 0;
}

static void
bmw64_4way( bmw_4way_big_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   __m256i htmp[16];
   __m256i *h1, *h2;
   size_t ptr;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   sc->bit_count += (uint64_t)len << 3;
   buf = sc->buf;
   ptr = sc->ptr;
   h1 = sc->H;
   h2 = htmp;
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( buf + (ptr>>3), vdata, clen >> 3 );
      vdata = vdata + (clen>>3);
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         __m256i *ht;
         compress_big( buf, h1, h2 );
         ht = h1;
         h1 = h2;
         h2 = ht;
         ptr = 0;
      }
   }
   sc->ptr = ptr;
   if ( h1 != sc->H )
        memcpy_256( sc->H, h1, 16 );
}

static void
bmw64_4way_close(bmw_4way_big_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_size_w64)
{
   __m256i *buf;
   __m256i h1[16], h2[16], *h;
   size_t ptr, u, v;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   buf = sc->buf;
   ptr = sc->ptr;
   buf[ ptr>>3 ] = _mm256_set1_epi64x( 0x80 );
   ptr += 8;
   h = sc->H;

   if (  ptr > (buf_size - 8) )
   {
      memset_zero_256( buf + (ptr>>3), (buf_size - ptr) >> 3 );
      compress_big( buf, h, h1 );
      ptr = 0;
      h = h1;
   }
   memset_zero_256( buf + (ptr>>3), (buf_size - 8 - ptr) >> 3 );
   buf[ (buf_size - 8) >> 3 ] = _mm256_set1_epi64x( sc->bit_count + n );
   compress_big( buf, h, h2 );
   for ( u = 0; u < 16; u ++ )
      buf[u] = h2[u];
   compress_big( buf, final_b, h1 );
   for (u = 0, v = 16 - out_size_w64; u < out_size_w64; u ++, v ++)
      casti_m256i(dst,u) = h1[v];
}

void
bmw512_4way_init(void *cc)
{
	bmw64_4way_init(cc, IV512);
}

void
bmw512_4way_update(void *cc, const void *data, size_t len)
{
	bmw64_4way(cc, data, len);
}

void
bmw512_4way_close(void *cc, void *dst)
{
	bmw512_4way_addbits_and_close(cc, 0, 0, dst);
}

void
bmw512_4way_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	bmw64_4way_close(cc, ub, n, dst, 8);
}

#endif  // __AVX2__

#if defined(SIMD512)

// BMW-512 8 WAY

#define s8b0(x) \
   mm512_xor4( _mm512_srli_epi64( (x), 1), _mm512_slli_epi64( (x), 3), \
                mm512_rol_64(     (x), 4),  mm512_rol_64(     (x),37) )

#define s8b1(x) \
   mm512_xor4( _mm512_srli_epi64( (x), 1), _mm512_slli_epi64( (x), 2), \
                mm512_rol_64(     (x),13),  mm512_rol_64(     (x),43) )

#define s8b2(x) \
   mm512_xor4( _mm512_srli_epi64( (x), 2), _mm512_slli_epi64( (x), 1), \
                mm512_rol_64(     (x),19),  mm512_rol_64(     (x),53) )

#define s8b3(x) \
   mm512_xor4( _mm512_srli_epi64( (x), 2), _mm512_slli_epi64( (x), 2), \
                mm512_rol_64(     (x),28),  mm512_rol_64(     (x),59) )

#define s8b4(x) \
  _mm512_xor_si512( (x), _mm512_srli_epi64( (x), 1 ) )

#define s8b5(x) \
  _mm512_xor_si512( (x), _mm512_srli_epi64( (x), 2 ) )

#define r8b1(x)    mm512_rol_64( x,  5 )
#define r8b2(x)    mm512_rol_64( x, 11 )
#define r8b3(x)    mm512_rol_64( x, 27 )
#define r8b4(x)    mm512_rol_64( x, 32 )
#define r8b5(x)    mm512_rol_64( x, 37 )
#define r8b6(x)    mm512_rol_64( x, 43 )
#define r8b7(x)    mm512_rol_64( x, 53 )

#define add_elt_b8( mj0, mj3, mj10, h, K ) \
  _mm512_xor_si512( h, _mm512_add_epi64( K, \
              _mm512_sub_epi64( _mm512_add_epi64( mj0, mj3 ), mj10 ) ) )

#define expand1_b8( qt, i ) \
   mm512_add4_64( \
      mm512_add4_64( s8b1( qt[ (i)-16 ] ), s8b2( qt[ (i)-15 ] ), \
                     s8b3( qt[ (i)-14 ] ), s8b0( qt[ (i)-13 ] )), \
      mm512_add4_64( s8b1( qt[ (i)-12 ] ), s8b2( qt[ (i)-11 ] ), \
                     s8b3( qt[ (i)-10 ] ), s8b0( qt[ (i)- 9 ] )), \
      mm512_add4_64( s8b1( qt[ (i)- 8 ] ), s8b2( qt[ (i)- 7 ] ), \
                     s8b3( qt[ (i)- 6 ] ), s8b0( qt[ (i)- 5 ] )), \
      mm512_add4_64( s8b1( qt[ (i)- 4 ] ), s8b2( qt[ (i)- 3 ] ), \
                     s8b3( qt[ (i)- 2 ] ), s8b0( qt[ (i)- 1 ] ) ) )

#define expand2_b8( qt, i) \
   mm512_add4_64( \
      mm512_add4_64( qt[ (i)-16 ], r8b1( qt[ (i)-15 ] ), \
                     qt[ (i)-14 ], r8b2( qt[ (i)-13 ] ) ), \
      mm512_add4_64( qt[ (i)-12 ], r8b3( qt[ (i)-11 ] ), \
                     qt[ (i)-10 ], r8b4( qt[ (i)- 9 ] ) ), \
      mm512_add4_64( qt[ (i)- 8 ], r8b5( qt[ (i)- 7 ] ), \
                     qt[ (i)- 6 ], r8b6( qt[ (i)- 5 ] ) ), \
      mm512_add4_64( qt[ (i)- 4 ], r8b7( qt[ (i)- 3 ] ), \
                     s8b4( qt[ (i)- 2 ] ), s8b5( qt[ (i)- 1 ] ) ) )

#define W8b0 \
   _mm512_add_epi64( \
      _mm512_add_epi64( _mm512_sub_epi64( mh[ 5], mh[ 7] ), mh[10] ), \
      _mm512_add_epi64( mh[13], mh[14] ) )

#define W8b1 \
   _mm512_add_epi64( \
         _mm512_add_epi64( _mm512_sub_epi64( mh[ 6], mh[ 8] ), mh[11] ), \
         _mm512_sub_epi64( mh[14], mh[15] ) )

#define W8b2 \
   _mm512_sub_epi64( \
      _mm512_add_epi64( _mm512_add_epi64( mh[ 0], mh[ 7] ), mh[ 9] ), \
      _mm512_sub_epi64( mh[12], mh[15] ) )

#define W8b3 \
   _mm512_sub_epi64( \
      _mm512_add_epi64( _mm512_sub_epi64( mh[ 0], mh[ 1] ), mh[ 8] ), \
      _mm512_sub_epi64( mh[10], mh[13] ) )

#define W8b4 \
   _mm512_sub_epi64( \
      _mm512_add_epi64( _mm512_add_epi64( mh[ 1], mh[ 2] ), mh[ 9] ), \
      _mm512_add_epi64( mh[11], mh[14] ) )

#define W8b5 \
   _mm512_sub_epi64( \
      _mm512_add_epi64( _mm512_sub_epi64( mh[ 3], mh[ 2] ), mh[10] ), \
      _mm512_sub_epi64( mh[12], mh[15] ) )

#define W8b6 \
   _mm512_sub_epi64( \
         _mm512_sub_epi64( _mm512_sub_epi64( mh[ 4], mh[ 0] ), mh[ 3] ), \
      _mm512_sub_epi64( mh[11], mh[13] ) )

#define W8b7 \
   _mm512_sub_epi64( \
      _mm512_sub_epi64( _mm512_sub_epi64( mh[ 1], mh[ 4] ), mh[ 5] ), \
      _mm512_add_epi64( mh[12], mh[14] ) )

#define W8b8 \
   _mm512_add_epi64( \
      _mm512_sub_epi64( _mm512_sub_epi64( mh[ 2], mh[ 5] ), mh[ 6] ), \
      _mm512_sub_epi64( mh[13], mh[15] ) )

#define W8b9 \
   _mm512_sub_epi64( \
      _mm512_add_epi64( _mm512_sub_epi64( mh[ 0], mh[ 3] ), mh[ 6] ), \
      _mm512_sub_epi64( mh[ 7], mh[14] ) )

#define W8b10 \
   _mm512_sub_epi64( \
      _mm512_sub_epi64( _mm512_sub_epi64( mh[ 8], mh[ 1] ), mh[ 4] ), \
      _mm512_sub_epi64( mh[ 7], mh[15] ) )

#define W8b11 \
   _mm512_sub_epi64( \
      _mm512_sub_epi64( _mm512_sub_epi64( mh[ 8], mh[ 0] ), mh[ 2] ), \
      _mm512_sub_epi64( mh[ 5], mh[ 9] ) )

#define W8b12 \
   _mm512_sub_epi64( \
      _mm512_sub_epi64( _mm512_add_epi64( mh[ 1], mh[ 3] ), mh[ 6] ), \
      _mm512_sub_epi64( mh[ 9], mh[10] ) )

#define W8b13 \
   _mm512_add_epi64( \
      _mm512_add_epi64( _mm512_add_epi64( mh[ 2], mh[ 4] ), mh[ 7] ), \
      _mm512_add_epi64( mh[10], mh[11] ) )

#define W8b14 \
   _mm512_sub_epi64( \
      _mm512_add_epi64( _mm512_sub_epi64( mh[ 3], mh[ 5] ), mh[ 8] ), \
      _mm512_add_epi64( mh[11], mh[12] ) )

#define W8b15 \
   _mm512_sub_epi64( \
      _mm512_sub_epi64( _mm512_sub_epi64( mh[12], mh[ 4] ), mh[ 6] ), \
      _mm512_sub_epi64( mh[ 9], mh[13] ) )

void compress_big_8way( const __m512i *M, const __m512i H[16],
                        __m512i dH[16] )
{
   __m512i qt[32], xl, xh;
   __m512i mh[16], mj[16];
   int i;

   for ( i = 0; i < 16; i++ )
      mh[i] = _mm512_xor_si512( M[i], H[i] );

   qt[ 0] = _mm512_add_epi64( s8b0( W8b0 ), H[ 1] );
   qt[ 1] = _mm512_add_epi64( s8b1( W8b1 ), H[ 2] );
   qt[ 2] = _mm512_add_epi64( s8b2( W8b2 ), H[ 3] );
   qt[ 3] = _mm512_add_epi64( s8b3( W8b3 ), H[ 4] );
   qt[ 4] = _mm512_add_epi64( s8b4( W8b4 ), H[ 5] );
   qt[ 5] = _mm512_add_epi64( s8b0( W8b5 ), H[ 6] );
   qt[ 6] = _mm512_add_epi64( s8b1( W8b6 ), H[ 7] );
   qt[ 7] = _mm512_add_epi64( s8b2( W8b7 ), H[ 8] );
   qt[ 8] = _mm512_add_epi64( s8b3( W8b8 ), H[ 9] );
   qt[ 9] = _mm512_add_epi64( s8b4( W8b9 ), H[10] );
   qt[10] = _mm512_add_epi64( s8b0( W8b10), H[11] );
   qt[11] = _mm512_add_epi64( s8b1( W8b11), H[12] );
   qt[12] = _mm512_add_epi64( s8b2( W8b12), H[13] );
   qt[13] = _mm512_add_epi64( s8b3( W8b13), H[14] );
   qt[14] = _mm512_add_epi64( s8b4( W8b14), H[15] );
   qt[15] = _mm512_add_epi64( s8b0( W8b15), H[ 0] );

   mj[ 0] = mm512_rol_64( M[ 0],  1 );
   mj[ 1] = mm512_rol_64( M[ 1],  2 );
   mj[ 2] = mm512_rol_64( M[ 2],  3 );
   mj[ 3] = mm512_rol_64( M[ 3],  4 );
   mj[ 4] = mm512_rol_64( M[ 4],  5 );
   mj[ 5] = mm512_rol_64( M[ 5],  6 );
   mj[ 6] = mm512_rol_64( M[ 6],  7 );
   mj[ 7] = mm512_rol_64( M[ 7],  8 );
   mj[ 8] = mm512_rol_64( M[ 8],  9 );
   mj[ 9] = mm512_rol_64( M[ 9], 10 );
   mj[10] = mm512_rol_64( M[10], 11 );
   mj[11] = mm512_rol_64( M[11], 12 );
   mj[12] = mm512_rol_64( M[12], 13 );
   mj[13] = mm512_rol_64( M[13], 14 );
   mj[14] = mm512_rol_64( M[14], 15 );
   mj[15] = mm512_rol_64( M[15], 16 );

   __m512i K = _mm512_set1_epi64( 0x5555555555555550ULL );
   static const __m512i Kincr = { 0x0555555555555555ULL, 0x0555555555555555ULL,
                                  0x0555555555555555ULL, 0x0555555555555555ULL,
                                  0x0555555555555555ULL, 0x0555555555555555ULL,
                                  0x0555555555555555ULL, 0x0555555555555555ULL };

   qt[16] = add_elt_b8( mj[ 0], mj[ 3], mj[10], H[ 7], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[17] = add_elt_b8( mj[ 1], mj[ 4], mj[11], H[ 8], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[18] = add_elt_b8( mj[ 2], mj[ 5], mj[12], H[ 9], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[19] = add_elt_b8( mj[ 3], mj[ 6], mj[13], H[10], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[20] = add_elt_b8( mj[ 4], mj[ 7], mj[14], H[11], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[21] = add_elt_b8( mj[ 5], mj[ 8], mj[15], H[12], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[22] = add_elt_b8( mj[ 6], mj[ 9], mj[ 0], H[13], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[23] = add_elt_b8( mj[ 7], mj[10], mj[ 1], H[14], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[24] = add_elt_b8( mj[ 8], mj[11], mj[ 2], H[15], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[25] = add_elt_b8( mj[ 9], mj[12], mj[ 3], H[ 0], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[26] = add_elt_b8( mj[10], mj[13], mj[ 4], H[ 1], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[27] = add_elt_b8( mj[11], mj[14], mj[ 5], H[ 2], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[28] = add_elt_b8( mj[12], mj[15], mj[ 6], H[ 3], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[29] = add_elt_b8( mj[13], mj[ 0], mj[ 7], H[ 4], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[30] = add_elt_b8( mj[14], mj[ 1], mj[ 8], H[ 5], K );
   K = _mm512_add_epi64( K, Kincr );
   qt[31] = add_elt_b8( mj[15], mj[ 2], mj[ 9], H[ 6], K );

   qt[16] = _mm512_add_epi64( qt[16], expand1_b8( qt, 16 ) );
   qt[17] = _mm512_add_epi64( qt[17], expand1_b8( qt, 17 ) );
   qt[18] = _mm512_add_epi64( qt[18], expand2_b8( qt, 18 ) );
   qt[19] = _mm512_add_epi64( qt[19], expand2_b8( qt, 19 ) );
   qt[20] = _mm512_add_epi64( qt[20], expand2_b8( qt, 20 ) );
   qt[21] = _mm512_add_epi64( qt[21], expand2_b8( qt, 21 ) );
   qt[22] = _mm512_add_epi64( qt[22], expand2_b8( qt, 22 ) );
   qt[23] = _mm512_add_epi64( qt[23], expand2_b8( qt, 23 ) );
   qt[24] = _mm512_add_epi64( qt[24], expand2_b8( qt, 24 ) );
   qt[25] = _mm512_add_epi64( qt[25], expand2_b8( qt, 25 ) );
   qt[26] = _mm512_add_epi64( qt[26], expand2_b8( qt, 26 ) );
   qt[27] = _mm512_add_epi64( qt[27], expand2_b8( qt, 27 ) );
   qt[28] = _mm512_add_epi64( qt[28], expand2_b8( qt, 28 ) );
   qt[29] = _mm512_add_epi64( qt[29], expand2_b8( qt, 29 ) );
   qt[30] = _mm512_add_epi64( qt[30], expand2_b8( qt, 30 ) );
   qt[31] = _mm512_add_epi64( qt[31], expand2_b8( qt, 31 ) );

   xl = mm512_xor3( mm512_xor3( qt[16], qt[17], qt[18] ),
                    mm512_xor3( qt[19], qt[20], qt[21] ),
                    _mm512_xor_si512( qt[22], qt[23] ) );

   xh = mm512_xor3( mm512_xor3( xl,     qt[24], qt[25] ),
                    mm512_xor3( qt[26], qt[27], qt[28] ),
                    mm512_xor3( qt[29], qt[30], qt[31] ) );

#define DH1L( m, sl, sr, a, b, c ) \
   _mm512_add_epi64( mm512_xor3( M[m], _mm512_slli_epi64( xh, sl ), \
                                       _mm512_srli_epi64( qt[a], sr ) ), \
                     mm512_xor3( xl, qt[b], qt[c] ) )

#define DH1R( m, sl, sr, a, b, c ) \
   _mm512_add_epi64( mm512_xor3( M[m], _mm512_srli_epi64( xh, sl ), \
                                       _mm512_slli_epi64( qt[a], sr ) ), \
                     mm512_xor3( xl, qt[b], qt[c] ) )

#define DH2L( m, rl, sl, h, a, b, c ) \
   _mm512_add_epi64( _mm512_add_epi64( \
                        mm512_rol_64( dH[h], rl ), \
                        mm512_xor3( xh, qt[a], M[m] ) ), \
                     mm512_xor3( _mm512_slli_epi64( xl, sl ), qt[b], qt[c] ) ) 

#define DH2R( m, rl, sr, h, a, b, c ) \
   _mm512_add_epi64( _mm512_add_epi64( \
                        mm512_rol_64( dH[h], rl ), \
                        mm512_xor3( xh, qt[a], M[m] ) ), \
                     mm512_xor3( _mm512_srli_epi64( xl, sr ), qt[b], qt[c] ) )


   dH[ 0] = DH1L(  0,  5,  5, 16, 24, 0 );
   dH[ 1] = DH1R(  1,  7,  8, 17, 25, 1 );
   dH[ 2] = DH1R(  2,  5,  5, 18, 26, 2 );
   dH[ 3] = DH1R(  3,  1,  5, 19, 27, 3 );
   dH[ 4] = DH1R(  4,  3,  0, 20, 28, 4 );
   dH[ 5] = DH1L(  5,  6,  6, 21, 29, 5 );
   dH[ 6] = DH1R(  6,  4,  6, 22, 30, 6 );
   dH[ 7] = DH1R(  7, 11,  2, 23, 31, 7 );
   dH[ 8] = DH2L(  8,  9,  8,  4, 24, 23,  8 );
   dH[ 9] = DH2R(  9, 10,  6,  5, 25, 16,  9 );
   dH[10] = DH2L( 10, 11,  6,  6, 26, 17, 10 );
   dH[11] = DH2L( 11, 12,  4,  7, 27, 18, 11 );
   dH[12] = DH2R( 12, 13,  3,  0, 28, 19, 12 );
   dH[13] = DH2R( 13, 14,  4,  1, 29, 20, 13 );
   dH[14] = DH2R( 14, 15,  7,  2, 30, 21, 14 );
   dH[15] = DH2R( 15, 16,  2,  3, 31, 22, 15 );

#undef DH1L
#undef DH1R
#undef DH2L
#undef DH2R
         
}

static const __m512i final_b8[16] =
{
   { 0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0,
     0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0,
     0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0,
     0xaaaaaaaaaaaaaaa0, 0xaaaaaaaaaaaaaaa0 },
   { 0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1,
     0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1,
     0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1,
     0xaaaaaaaaaaaaaaa1, 0xaaaaaaaaaaaaaaa1 },
   { 0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2,
     0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2,
     0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2,
     0xaaaaaaaaaaaaaaa2, 0xaaaaaaaaaaaaaaa2 },
   { 0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3,
     0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3,
     0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3,
     0xaaaaaaaaaaaaaaa3, 0xaaaaaaaaaaaaaaa3 },
   { 0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4,
     0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4,
     0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4,
     0xaaaaaaaaaaaaaaa4, 0xaaaaaaaaaaaaaaa4 },
   { 0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5,
     0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5,
     0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5,
     0xaaaaaaaaaaaaaaa5, 0xaaaaaaaaaaaaaaa5 },
   { 0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6,
     0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6,
     0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6,
     0xaaaaaaaaaaaaaaa6, 0xaaaaaaaaaaaaaaa6 },
   { 0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7,
     0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7,
     0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7,
     0xaaaaaaaaaaaaaaa7, 0xaaaaaaaaaaaaaaa7 },
   { 0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8,
     0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8,
     0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8,
     0xaaaaaaaaaaaaaaa8, 0xaaaaaaaaaaaaaaa8 },
   { 0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9,
     0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9,
     0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9,
     0xaaaaaaaaaaaaaaa9, 0xaaaaaaaaaaaaaaa9 },
   { 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
     0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
     0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
     0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
   { 0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab,
     0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab,
     0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab,
     0xaaaaaaaaaaaaaaab, 0xaaaaaaaaaaaaaaab },
   { 0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac,
     0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac,
     0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac,
     0xaaaaaaaaaaaaaaac, 0xaaaaaaaaaaaaaaac },
   { 0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad,
     0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad,
     0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad,
     0xaaaaaaaaaaaaaaad, 0xaaaaaaaaaaaaaaad },
   { 0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae,
     0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae,
     0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae,
     0xaaaaaaaaaaaaaaae, 0xaaaaaaaaaaaaaaae },
   { 0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf,
     0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf,
     0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf,
     0xaaaaaaaaaaaaaaaf, 0xaaaaaaaaaaaaaaaf }
};


void bmw512_8way_init( bmw512_8way_context *ctx )
//bmw64_4way_init( bmw_4way_big_context *sc, const uint64_t *iv )
{
   ctx->H[ 0] = _mm512_set1_epi64( 0x8081828384858687 );
   ctx->H[ 1] = _mm512_set1_epi64( 0x88898A8B8C8D8E8F );
   ctx->H[ 2] = _mm512_set1_epi64( 0x9091929394959697 );
   ctx->H[ 3] = _mm512_set1_epi64( 0x98999A9B9C9D9E9F );
   ctx->H[ 4] = _mm512_set1_epi64( 0xA0A1A2A3A4A5A6A7 );
   ctx->H[ 5] = _mm512_set1_epi64( 0xA8A9AAABACADAEAF );
   ctx->H[ 6] = _mm512_set1_epi64( 0xB0B1B2B3B4B5B6B7 );
   ctx->H[ 7] = _mm512_set1_epi64( 0xB8B9BABBBCBDBEBF );
   ctx->H[ 8] = _mm512_set1_epi64( 0xC0C1C2C3C4C5C6C7 );
   ctx->H[ 9] = _mm512_set1_epi64( 0xC8C9CACBCCCDCECF );
   ctx->H[10] = _mm512_set1_epi64( 0xD0D1D2D3D4D5D6D7 );
   ctx->H[11] = _mm512_set1_epi64( 0xD8D9DADBDCDDDEDF );
   ctx->H[12] = _mm512_set1_epi64( 0xE0E1E2E3E4E5E6E7 );
   ctx->H[13] = _mm512_set1_epi64( 0xE8E9EAEBECEDEEEF );
   ctx->H[14] = _mm512_set1_epi64( 0xF0F1F2F3F4F5F6F7 );
   ctx->H[15] = _mm512_set1_epi64( 0xF8F9FAFBFCFDFEFF );
   ctx->ptr = 0;
   ctx->bit_count = 0;
}

void bmw512_8way_update( bmw512_8way_context *ctx, const void *data,
                                size_t len )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf;
   __m512i htmp[16];
   __m512i *h1, *h2;
   size_t ptr;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   ctx->bit_count += len << 3;
   buf = ctx->buf;
   ptr = ctx->ptr;
   h1 = ctx->H;
   h2 = htmp;
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_512( buf + (ptr>>3), vdata, clen >> 3 );
      vdata = vdata + (clen>>3);
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         __m512i *ht;
         compress_big_8way( buf, h1, h2 );
         ht = h1;
         h1 = h2;
         h2 = ht;
         ptr = 0;
      }
   }
   ctx->ptr = ptr;
   if ( h1 != ctx->H )
        memcpy_512( ctx->H, h1, 16 );
}

void bmw512_8way_close( bmw512_8way_context *ctx, void *dst )
{
   __m512i *buf;
   __m512i h1[16], h2[16], *h;
   size_t ptr, u, v;
   const int buf_size = 128;  // bytes of one lane, compatible with len

   buf = ctx->buf;
   ptr = ctx->ptr;
   buf[ ptr>>3 ] = _mm512_set1_epi64( 0x80 );
   ptr += 8;
   h = ctx->H;

   if (  ptr > (buf_size - 8) )
   {
      memset_zero_512( buf + (ptr>>3), (buf_size - ptr) >> 3 );
      compress_big_8way( buf, h, h1 );
      ptr = 0;
      h = h1;
   }
   memset_zero_512( buf + (ptr>>3), (buf_size - 8 - ptr) >> 3 );
   buf[ (buf_size - 8) >> 3 ] = _mm512_set1_epi64( ctx->bit_count );
   compress_big_8way( buf, h, h2 );
   for ( u = 0; u < 16; u ++ )
      buf[ u ] = h2[ u ];
   compress_big_8way( buf, final_b8, h1 );
   for (u = 0, v = 8; u < 8; u ++, v ++)
      casti_m512i( dst, u ) = h1[ v ];
}

void bmw512_8way_full( bmw512_8way_context *ctx, void *out, const void *data,
                                size_t len )
{
   __m512i h1[16];
   __m512i h2[16];
   __m512i *vdata = (__m512i*)data;
   __m512i *buf = ctx->buf;
   __m512i *H = ctx->H;
   __m512i *hptr = h2;
   uint64_t bit_count = len * 8;
   size_t ptr = 0;
   size_t u, v;
   const int buf_size = 128;  // bytes of one lane, compatible with len

// Init

   H[ 0] = _mm512_set1_epi64( 0x8081828384858687 );
   H[ 1] = _mm512_set1_epi64( 0x88898A8B8C8D8E8F );
   H[ 2] = _mm512_set1_epi64( 0x9091929394959697 );
   H[ 3] = _mm512_set1_epi64( 0x98999A9B9C9D9E9F );
   H[ 4] = _mm512_set1_epi64( 0xA0A1A2A3A4A5A6A7 );
   H[ 5] = _mm512_set1_epi64( 0xA8A9AAABACADAEAF );
   H[ 6] = _mm512_set1_epi64( 0xB0B1B2B3B4B5B6B7 );
   H[ 7] = _mm512_set1_epi64( 0xB8B9BABBBCBDBEBF );
   H[ 8] = _mm512_set1_epi64( 0xC0C1C2C3C4C5C6C7 );
   H[ 9] = _mm512_set1_epi64( 0xC8C9CACBCCCDCECF );
   H[10] = _mm512_set1_epi64( 0xD0D1D2D3D4D5D6D7 );
   H[11] = _mm512_set1_epi64( 0xD8D9DADBDCDDDEDF );
   H[12] = _mm512_set1_epi64( 0xE0E1E2E3E4E5E6E7 );
   H[13] = _mm512_set1_epi64( 0xE8E9EAEBECEDEEEF );
   H[14] = _mm512_set1_epi64( 0xF0F1F2F3F4F5F6F7 );
   H[15] = _mm512_set1_epi64( 0xF8F9FAFBFCFDFEFF );

// Update

   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_512( buf + (ptr>>3), vdata, clen >> 3 );
      vdata = vdata + (clen>>3);
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         __m512i *ht;
         compress_big_8way( buf, H, hptr );
         ht = H;
         H = hptr;
         hptr = ht;
         ptr = 0;
      }
   }
   if ( H != ctx->H )
      memcpy_512( ctx->H, H, 16 );

// Close   

   buf[ ptr>>3 ] = _mm512_set1_epi64( 0x80 );
   ptr += 8;

   if (  ptr > (buf_size - 8) )
   {
      memset_zero_512( buf + (ptr>>3), (buf_size - ptr) >> 3 );
      compress_big_8way( buf, H, h1 );
      ptr = 0;
      H = h1;
   }
   memset_zero_512( buf + (ptr>>3), (buf_size - 8 - ptr) >> 3 );
   buf[ (buf_size - 8) >> 3 ] = _mm512_set1_epi64( bit_count );
   compress_big_8way( buf, H, h2 );
   for ( u = 0; u < 16; u ++ )
      buf[ u ] = h2[ u ];
   compress_big_8way( buf, final_b8, h1 );
   for ( u = 0, v = 8; u < 8; u ++, v ++ )
      casti_m512i( out, u ) = h1[ v ];
}

#endif // AVX512


