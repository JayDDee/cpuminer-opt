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

#ifdef __cplusplus
extern "C"{
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#define LPAR   (

#if defined(__SSE2__)

// BMW-256 4 way 32
/*
static const uint32_t IV256[] = {
	0x40414243, 0x44454647,
	0x48494A4B, 0x4C4D4E4F,
	0x50515253, 0x54555657,
	0x58595A5B, 0x5C5D5E5F,
	0x60616263, 0x64656667,
	0x68696A6B, 0x6C6D6E6F,
	0x70717273, 0x74757677,
	0x78797A7B, 0x7C7D7E7F
};
*/

#define ss0(x) \
   _mm_xor_si128( _mm_xor_si128( _mm_srli_epi32( (x), 1), \
                                 _mm_slli_epi32( (x), 3) ), \
                  _mm_xor_si128( mm128_rol_32( (x),  4), \
                                 mm128_rol_32( (x), 19) ) )

#define ss1(x) \
   _mm_xor_si128( _mm_xor_si128( _mm_srli_epi32( (x), 1), \
                                 _mm_slli_epi32( (x), 2) ), \
                  _mm_xor_si128( mm128_rol_32( (x),  8), \
                                 mm128_rol_32( (x), 23) ) )

#define ss2(x) \
   _mm_xor_si128( _mm_xor_si128( _mm_srli_epi32( (x), 2), \
                                 _mm_slli_epi32( (x), 1) ), \
                  _mm_xor_si128( mm128_rol_32( (x), 12), \
                                 mm128_rol_32( (x), 25) ) )

#define ss3(x) \
   _mm_xor_si128( _mm_xor_si128( _mm_srli_epi32( (x), 2), \
                                 _mm_slli_epi32( (x), 2) ), \
                  _mm_xor_si128( mm128_rol_32( (x), 15), \
                                 mm128_rol_32( (x), 29) ) )

#define ss4(x) \
  _mm_xor_si128( (x), _mm_srli_epi32( (x), 1 ) )

#define ss5(x) \
  _mm_xor_si128( (x), _mm_srli_epi32( (x), 2 ) )

#define rs1(x)    mm128_rol_32( x,  3 ) 
#define rs2(x)    mm128_rol_32( x,  7 ) 
#define rs3(x)    mm128_rol_32( x, 13 ) 
#define rs4(x)    mm128_rol_32( x, 16 ) 
#define rs5(x)    mm128_rol_32( x, 19 ) 
#define rs6(x)    mm128_rol_32( x, 23 ) 
#define rs7(x)    mm128_rol_32( x, 27 ) 

#define rol_off_32( M, j, off ) \
   mm128_rol_32( M[ ( (j) + (off) ) & 0xF ] , \
                ( ( (j) + (off) ) & 0xF ) + 1 )

#define add_elt_s( M, H, j ) \
   _mm_xor_si128( \
       _mm_add_epi32( \
             _mm_sub_epi32( _mm_add_epi32( rol_off_32( M, j, 0 ), \
                                           rol_off_32( M, j, 3 ) ), \
                            rol_off_32( M, j, 10 ) ), \
       _mm_set1_epi32( ( (j)+16 ) * SPH_C32(0x05555555UL) ) ), \
   H[ ( (j)+7 ) & 0xF ] )


#define expand1s( qt, M, H, i ) \
   _mm_add_epi32(  mm128_add4_32( \
            mm128_add4_32( ss1( qt[ (i)-16 ] ), ss2( qt[ (i)-15 ] ), \
                           ss3( qt[ (i)-14 ] ), ss0( qt[ (i)-13 ] ) ), \
            mm128_add4_32( ss1( qt[ (i)-12 ] ), ss2( qt[ (i)-11 ] ), \
                           ss3( qt[ (i)-10 ] ), ss0( qt[ (i)- 9 ] ) ), \
            mm128_add4_32( ss1( qt[ (i)- 8 ] ), ss2( qt[ (i)- 7 ] ), \
                           ss3( qt[ (i)- 6 ] ), ss0( qt[ (i)- 5 ] ) ),  \
            mm128_add4_32( ss1( qt[ (i)- 4 ] ), ss2( qt[ (i)- 3 ] ), \
                           ss3( qt[ (i)- 2 ] ), ss0( qt[ (i)- 1 ] ) ) ), \
      add_elt_s( M, H, (i)-16 ) )

#define expand2s( qt, M, H, i) \
   _mm_add_epi32( mm128_add4_32( \
            mm128_add4_32( qt[ (i)-16 ], rs1( qt[ (i)-15 ] ), \
                           qt[ (i)-14 ], rs2( qt[ (i)-13 ] ) ), \
            mm128_add4_32( qt[ (i)-12 ], rs3( qt[ (i)-11 ] ), \
                           qt[ (i)-10 ], rs4( qt[ (i)- 9 ] ) ), \
            mm128_add4_32( qt[ (i)- 8 ], rs5( qt[ (i)- 7 ] ), \
                           qt[ (i)- 6 ], rs6( qt[ (i)- 5 ] ) ), \
            mm128_add4_32( qt[ (i)- 4 ], rs7( qt[ (i)- 3 ] ), \
                           ss4( qt[ (i)- 2 ] ), ss5( qt[ (i)- 1 ] ) ) ), \
      add_elt_s( M, H, (i)-16 ) )

// Expressions are grouped using associativity to reduce CPU depenedencies,
// resulting in some sign changes compared to the reference code.

#define Ws0 \
   _mm_add_epi32( \
      _mm_add_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 5], H[ 5] ), \
                        _mm_xor_si128( M[ 7], H[ 7] ) ), \
         _mm_xor_si128( M[10], H[10] ) ), \
      _mm_add_epi32( _mm_xor_si128( M[13], H[13] ), \
                     _mm_xor_si128( M[14], H[14] ) ) )

#define Ws1 \
   _mm_add_epi32( \
       _mm_add_epi32( \
          _mm_sub_epi32( _mm_xor_si128( M[ 6], H[ 6] ), \
                         _mm_xor_si128( M[ 8], H[ 8] ) ), \
          _mm_xor_si128( M[11], H[11] ) ), \
       _mm_sub_epi32( _mm_xor_si128( M[14], H[14] ), \
                      _mm_xor_si128( M[15], H[15] ) ) )

#define Ws2 \
   _mm_sub_epi32( \
      _mm_add_epi32( \
         _mm_add_epi32( _mm_xor_si128( M[ 0], H[ 0] ), \
                        _mm_xor_si128( M[ 7], H[ 7] ) ), \
         _mm_xor_si128( M[ 9], H[ 9] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[12], H[12] ), \
                     _mm_xor_si128( M[15], H[15] ) ) )

#define Ws3 \
   _mm_sub_epi32( \
      _mm_add_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 0], H[ 0] ), \
                        _mm_xor_si128( M[ 1], H[ 1] ) ), \
         _mm_xor_si128( M[ 8], H[ 8] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[10], H[10] ), \
                     _mm_xor_si128( M[13], H[13] ) ) )

#define Ws4 \
   _mm_sub_epi32( \
      _mm_add_epi32( \
         _mm_add_epi32( _mm_xor_si128( M[ 1], H[ 1] ), \
                        _mm_xor_si128( M[ 2], H[ 2] ) ), \
         _mm_xor_si128( M[ 9], H[ 9] ) ), \
      _mm_add_epi32( _mm_xor_si128( M[11], H[11] ), \
                     _mm_xor_si128( M[14], H[14] ) ) )

#define Ws5 \
   _mm_sub_epi32( \
      _mm_add_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 3], H[ 3] ), \
                        _mm_xor_si128( M[ 2], H[ 2] ) ), \
         _mm_xor_si128( M[10], H[10] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[12], H[12] ), \
                     _mm_xor_si128( M[15], H[15] ) ) )

#define Ws6 \
   _mm_sub_epi32( \
      _mm_sub_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 4], H[ 4] ), \
                        _mm_xor_si128( M[ 0], H[ 0] ) ), \
         _mm_xor_si128( M[ 3], H[ 3] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[11], H[11] ), \
                     _mm_xor_si128( M[13], H[13] ) ) )

#define Ws7 \
   _mm_sub_epi32( \
      _mm_sub_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 1], H[ 1] ), \
                        _mm_xor_si128( M[ 4], H[ 4] ) ), \
         _mm_xor_si128( M[ 5], H[ 5] ) ), \
      _mm_add_epi32( _mm_xor_si128( M[12], H[12] ), \
                     _mm_xor_si128( M[14], H[14] ) ) )

#define Ws8 \
   _mm_add_epi32( \
      _mm_sub_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 2], H[ 2] ), \
                        _mm_xor_si128( M[ 5], H[ 5] ) ), \
         _mm_xor_si128( M[ 6], H[ 6] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[13], H[13] ), \
                     _mm_xor_si128( M[15], H[15] ) ) )
#define Ws9 \
   _mm_sub_epi32( \
      _mm_add_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 0], H[ 0] ), \
                        _mm_xor_si128( M[ 3], H[ 3] ) ), \
         _mm_xor_si128( M[ 6], H[ 6] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[ 7], H[ 7] ), \
                     _mm_xor_si128( M[14], H[14] ) ) )

#define Ws10 \
   _mm_sub_epi32( \
      _mm_sub_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 8], H[ 8] ), \
                        _mm_xor_si128( M[ 1], H[ 1] ) ), \
         _mm_xor_si128( M[ 4], H[ 4] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[ 7], H[ 7] ), \
                     _mm_xor_si128( M[15], H[15] ) ) )

#define Ws11 \
   _mm_sub_epi32( \
      _mm_sub_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 8], H[ 8] ), \
                        _mm_xor_si128( M[ 0], H[ 0] ) ), \
         _mm_xor_si128( M[ 2], H[ 2] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[ 5], H[ 5] ), \
                     _mm_xor_si128( M[ 9], H[ 9] ) ) )

#define Ws12 \
   _mm_sub_epi32( \
      _mm_sub_epi32( \
         _mm_add_epi32( _mm_xor_si128( M[ 1], H[ 1] ), \
                        _mm_xor_si128( M[ 3], H[ 3] ) ), \
         _mm_xor_si128( M[ 6], H[ 6] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[ 9], H[ 9] ), \
                     _mm_xor_si128( M[10], H[10] ) ) )

#define Ws13 \
   _mm_add_epi32( \
      _mm_add_epi32( \
         _mm_add_epi32( _mm_xor_si128( M[ 2], H[ 2] ), \
                        _mm_xor_si128( M[ 4], H[ 4] ) ), \
         _mm_xor_si128( M[ 7], H[ 7] ) ), \
      _mm_add_epi32( _mm_xor_si128( M[10], H[10] ), \
                     _mm_xor_si128( M[11], H[11] ) ) )

#define Ws14 \
   _mm_sub_epi32( \
      _mm_add_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[ 3], H[ 3] ), \
                        _mm_xor_si128( M[ 5], H[ 5] ) ), \
         _mm_xor_si128( M[ 8], H[ 8] ) ), \
      _mm_add_epi32( _mm_xor_si128( M[11], H[11] ), \
                     _mm_xor_si128( M[12], H[12] ) ) )

#define Ws15 \
   _mm_sub_epi32( \
      _mm_sub_epi32( \
         _mm_sub_epi32( _mm_xor_si128( M[12], H[12] ), \
                        _mm_xor_si128( M[ 4], H[4] ) ), \
         _mm_xor_si128( M[ 6], H[ 6] ) ), \
      _mm_sub_epi32( _mm_xor_si128( M[ 9], H[ 9] ), \
                     _mm_xor_si128( M[13], H[13] ) ) )


void compress_small( const __m128i *M, const __m128i H[16], __m128i dH[16] )
{
   __m128i qt[32], xl, xh; \

   qt[ 0] = _mm_add_epi32( ss0( Ws0 ), H[ 1] );
   qt[ 1] = _mm_add_epi32( ss1( Ws1 ), H[ 2] );
   qt[ 2] = _mm_add_epi32( ss2( Ws2 ), H[ 3] );
   qt[ 3] = _mm_add_epi32( ss3( Ws3 ), H[ 4] );
   qt[ 4] = _mm_add_epi32( ss4( Ws4 ), H[ 5] );
   qt[ 5] = _mm_add_epi32( ss0( Ws5 ), H[ 6] );
   qt[ 6] = _mm_add_epi32( ss1( Ws6 ), H[ 7] );
   qt[ 7] = _mm_add_epi32( ss2( Ws7 ), H[ 8] );
   qt[ 8] = _mm_add_epi32( ss3( Ws8 ), H[ 9] );
   qt[ 9] = _mm_add_epi32( ss4( Ws9 ), H[10] );
   qt[10] = _mm_add_epi32( ss0( Ws10), H[11] );
   qt[11] = _mm_add_epi32( ss1( Ws11), H[12] );
   qt[12] = _mm_add_epi32( ss2( Ws12), H[13] );
   qt[13] = _mm_add_epi32( ss3( Ws13), H[14] );
   qt[14] = _mm_add_epi32( ss4( Ws14), H[15] );
   qt[15] = _mm_add_epi32( ss0( Ws15), H[ 0] );
   qt[16] = expand1s( qt, M, H, 16 );
   qt[17] = expand1s( qt, M, H, 17 );
   qt[18] = expand2s( qt, M, H, 18 );
   qt[19] = expand2s( qt, M, H, 19 );
   qt[20] = expand2s( qt, M, H, 20 );
   qt[21] = expand2s( qt, M, H, 21 );
   qt[22] = expand2s( qt, M, H, 22 );
   qt[23] = expand2s( qt, M, H, 23 );
   qt[24] = expand2s( qt, M, H, 24 );
   qt[25] = expand2s( qt, M, H, 25 );
   qt[26] = expand2s( qt, M, H, 26 );
   qt[27] = expand2s( qt, M, H, 27 );
   qt[28] = expand2s( qt, M, H, 28 );
   qt[29] = expand2s( qt, M, H, 29 );
   qt[30] = expand2s( qt, M, H, 30 );
   qt[31] = expand2s( qt, M, H, 31 );

   xl = _mm_xor_si128( mm128_xor4( qt[16], qt[17], qt[18], qt[19] ),
                       mm128_xor4( qt[20], qt[21], qt[22], qt[23] ) );
   xh = _mm_xor_si128( xl, _mm_xor_si128(
                             mm128_xor4( qt[24], qt[25], qt[26], qt[27] ),
                             mm128_xor4( qt[28], qt[29], qt[30], qt[31] ) ) );

   dH[ 0] = _mm_add_epi32(
                 _mm_xor_si128( M[0],
                      _mm_xor_si128( _mm_slli_epi32( xh, 5 ),
                                     _mm_srli_epi32( qt[16], 5 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[24] ), qt[ 0] ));
   dH[ 1] = _mm_add_epi32(
                 _mm_xor_si128( M[1],
                      _mm_xor_si128( _mm_srli_epi32( xh, 7 ),
                                     _mm_slli_epi32( qt[17], 8 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[25] ), qt[ 1] ));
   dH[ 2] = _mm_add_epi32(
                 _mm_xor_si128( M[2],
                      _mm_xor_si128( _mm_srli_epi32( xh, 5 ),
                                     _mm_slli_epi32( qt[18], 5 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[26] ), qt[ 2] ));
   dH[ 3] = _mm_add_epi32(
                 _mm_xor_si128( M[3],
                      _mm_xor_si128( _mm_srli_epi32( xh, 1 ),
                                     _mm_slli_epi32( qt[19], 5 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[27] ), qt[ 3] ));
   dH[ 4] = _mm_add_epi32(
                 _mm_xor_si128( M[4],
                      _mm_xor_si128( _mm_srli_epi32( xh, 3 ),
                                     _mm_slli_epi32( qt[20], 0 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[28] ), qt[ 4] ));
   dH[ 5] = _mm_add_epi32(
                 _mm_xor_si128( M[5],
                      _mm_xor_si128( _mm_slli_epi32( xh, 6 ),
                                     _mm_srli_epi32( qt[21], 6 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[29] ), qt[ 5] ));
   dH[ 6] = _mm_add_epi32(
                 _mm_xor_si128( M[6],
                      _mm_xor_si128( _mm_srli_epi32( xh, 4 ),
                                     _mm_slli_epi32( qt[22], 6 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[30] ), qt[ 6] ));
   dH[ 7] = _mm_add_epi32(
                 _mm_xor_si128( M[7],
                      _mm_xor_si128( _mm_srli_epi32( xh, 11 ),
                                     _mm_slli_epi32( qt[23], 2 ) ) ),
                 _mm_xor_si128( _mm_xor_si128( xl, qt[31] ), qt[ 7] ));
   dH[ 8] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[4], 9 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[24] ), M[ 8] )),
                 _mm_xor_si128( _mm_slli_epi32( xl, 8 ),
                                _mm_xor_si128( qt[23], qt[ 8] ) ) );
   dH[ 9] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[5], 10 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[25] ), M[ 9] )),
                 _mm_xor_si128( _mm_srli_epi32( xl, 6 ),
                                _mm_xor_si128( qt[16], qt[ 9] ) ) );
   dH[10] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[6], 11 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[26] ), M[10] )),
                 _mm_xor_si128( _mm_slli_epi32( xl, 6 ),
                                _mm_xor_si128( qt[17], qt[10] ) ) );
   dH[11] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[7], 12 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[27] ), M[11] )),
                 _mm_xor_si128( _mm_slli_epi32( xl, 4 ),
                                _mm_xor_si128( qt[18], qt[11] ) ) );
   dH[12] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[0], 13 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[28] ), M[12] )),
                 _mm_xor_si128( _mm_srli_epi32( xl, 3 ),
                                _mm_xor_si128( qt[19], qt[12] ) ) );
   dH[13] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[1], 14 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[29] ), M[13] )),
                 _mm_xor_si128( _mm_srli_epi32( xl, 4 ),
                                _mm_xor_si128( qt[20], qt[13] ) ) );
   dH[14] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[2], 15 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[30] ), M[14] )),
                 _mm_xor_si128( _mm_srli_epi32( xl, 7 ),
                                _mm_xor_si128( qt[21], qt[14] ) ) );
   dH[15] = _mm_add_epi32( _mm_add_epi32(
                 mm128_rol_32( dH[3], 16 ),
                 _mm_xor_si128( _mm_xor_si128( xh, qt[31] ), M[15] )),
                 _mm_xor_si128( _mm_srli_epi32( xl, 2 ),
                                _mm_xor_si128( qt[22], qt[15] ) ) );
}

static const uint32_t final_s[16][4] =
{
   { 0xaaaaaaa0, 0xaaaaaaa0, 0xaaaaaaa0, 0xaaaaaaa0 },
   { 0xaaaaaaa1, 0xaaaaaaa1, 0xaaaaaaa1, 0xaaaaaaa1 },
   { 0xaaaaaaa2, 0xaaaaaaa2, 0xaaaaaaa2, 0xaaaaaaa2 },
   { 0xaaaaaaa3, 0xaaaaaaa3, 0xaaaaaaa3, 0xaaaaaaa3 },
   { 0xaaaaaaa4, 0xaaaaaaa4, 0xaaaaaaa4, 0xaaaaaaa4 },
   { 0xaaaaaaa5, 0xaaaaaaa5, 0xaaaaaaa5, 0xaaaaaaa5 },
   { 0xaaaaaaa6, 0xaaaaaaa6, 0xaaaaaaa6, 0xaaaaaaa6 },
   { 0xaaaaaaa7, 0xaaaaaaa7, 0xaaaaaaa7, 0xaaaaaaa7 },
   { 0xaaaaaaa8, 0xaaaaaaa8, 0xaaaaaaa8, 0xaaaaaaa8 },
   { 0xaaaaaaa9, 0xaaaaaaa9, 0xaaaaaaa9, 0xaaaaaaa9 },
   { 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa },
   { 0xaaaaaaab, 0xaaaaaaab, 0xaaaaaaab, 0xaaaaaaab },
   { 0xaaaaaaac, 0xaaaaaaac, 0xaaaaaaac, 0xaaaaaaac },
   { 0xaaaaaaad, 0xaaaaaaad, 0xaaaaaaad, 0xaaaaaaad },
   { 0xaaaaaaae, 0xaaaaaaae, 0xaaaaaaae, 0xaaaaaaae },
   { 0xaaaaaaaf, 0xaaaaaaaf, 0xaaaaaaaf, 0xaaaaaaaf }
};
/*
static const __m128i final_s[16] =
{
   { 0xaaaaaaa0aaaaaaa0, 0xaaaaaaa0aaaaaaa0 },
   { 0xaaaaaaa1aaaaaaa1, 0xaaaaaaa1aaaaaaa1 },
   { 0xaaaaaaa2aaaaaaa2, 0xaaaaaaa2aaaaaaa2 },
   { 0xaaaaaaa3aaaaaaa3, 0xaaaaaaa3aaaaaaa3 },
   { 0xaaaaaaa4aaaaaaa4, 0xaaaaaaa4aaaaaaa4 },
   { 0xaaaaaaa5aaaaaaa5, 0xaaaaaaa5aaaaaaa5 },
   { 0xaaaaaaa6aaaaaaa6, 0xaaaaaaa6aaaaaaa6 },
   { 0xaaaaaaa7aaaaaaa7, 0xaaaaaaa7aaaaaaa7 },
   { 0xaaaaaaa8aaaaaaa8, 0xaaaaaaa8aaaaaaa8 },
   { 0xaaaaaaa9aaaaaaa9, 0xaaaaaaa9aaaaaaa9 },
   { 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
   { 0xaaaaaaabaaaaaaab, 0xaaaaaaabaaaaaaab },
   { 0xaaaaaaacaaaaaaac, 0xaaaaaaacaaaaaaac },
   { 0xaaaaaaadaaaaaaad, 0xaaaaaaadaaaaaaad },
   { 0xaaaaaaaeaaaaaaae, 0xaaaaaaaeaaaaaaae },
   { 0xaaaaaaafaaaaaaaf, 0xaaaaaaafaaaaaaaf }
};
*/
void bmw256_4way_init( bmw256_4way_context *ctx )
{
   ctx->H[ 0] = m128_const1_64( 0x4041424340414243 );
   ctx->H[ 1] = m128_const1_64( 0x4445464744454647 );
   ctx->H[ 2] = m128_const1_64( 0x48494A4B48494A4B );
   ctx->H[ 3] = m128_const1_64( 0x4C4D4E4F4C4D4E4F );
   ctx->H[ 4] = m128_const1_64( 0x5051525350515253 );
   ctx->H[ 5] = m128_const1_64( 0x5455565754555657 );
   ctx->H[ 6] = m128_const1_64( 0x58595A5B58595A5B );
   ctx->H[ 7] = m128_const1_64( 0x5C5D5E5F5C5D5E5F );
   ctx->H[ 8] = m128_const1_64( 0x6061626360616263 );
   ctx->H[ 9] = m128_const1_64( 0x6465666764656667 );
   ctx->H[10] = m128_const1_64( 0x68696A6B68696A6B );
   ctx->H[11] = m128_const1_64( 0x6C6D6E6F6C6D6E6F );
   ctx->H[12] = m128_const1_64( 0x7071727370717273 );
   ctx->H[13] = m128_const1_64( 0x7475767774757677 );
   ctx->H[14] = m128_const1_64( 0x78797A7B78797A7B );
   ctx->H[15] = m128_const1_64( 0x7C7D7E7F7C7D7E7F );


//   for ( int i = 0; i < 16; i++ )
//      sc->H[i] = _mm_set1_epi32( iv[i] );
   ctx->ptr = 0;
   ctx->bit_count = 0;
}

static void
bmw32_4way(bmw_4way_small_context *sc, const void *data, size_t len)
{
   __m128i *vdata = (__m128i*)data;
   __m128i *buf;
   __m128i htmp[16];
   __m128i *h1, *h2;
   size_t ptr;
   const int buf_size = 64;  // bytes of one lane, compatible with len

   sc->bit_count += (sph_u32)len << 3;
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
      memcpy_128( buf + (ptr>>2), vdata, clen >> 2 );
      vdata += ( clen >> 2 );
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         __m128i *ht;
         compress_small( buf, h1, h2 );
         ht = h1;
         h1 = h2;
         h2 = ht;
         ptr = 0;
      }
   }
   sc->ptr = ptr;


   if ( h1 != sc->H )
        memcpy_128( sc->H, h1, 16 );
}

static void
bmw32_4way_close(bmw_4way_small_context *sc, unsigned ub, unsigned n,
	void *dst, size_t out_size_w32)
{
   __m128i *buf;
   __m128i h1[16], h2[16], *h;
   size_t ptr, u, v;
   const int buf_size = 64;  // bytes of one lane, compatible with len

   buf = sc->buf;
   ptr = sc->ptr;
   buf[ ptr>>2 ] = m128_const1_64( 0x0000008000000080 );
   ptr += 4;
   h = sc->H;

   // assume bit_count fits in 32 bits 
   if ( ptr > buf_size - 4 )
   {
      memset_zero_128( buf + (ptr>>2), (buf_size - ptr) >> 2 );
      compress_small( buf, h, h1 );
      ptr = 0;
      h = h1;
   }
   memset_zero_128( buf + (ptr>>2), (buf_size - 8 - ptr) >> 2 );
   buf[ (buf_size - 8) >> 2 ] = _mm_set1_epi32( sc->bit_count + n );
   buf[ (buf_size - 4) >> 2 ] = m128_zero;
   compress_small( buf, h, h2 );

   for ( u = 0; u < 16; u ++ )
      buf[u] = h2[u];

   compress_small( buf, (__m128i*)final_s, h1 );

   for (u = 0, v = 16 - out_size_w32; u < out_size_w32; u ++, v ++)
      casti_m128i( dst, u ) = h1[v];
}

/*
void
bmw256_4way_init(void *cc)
{
	bmw32_4way_init(cc, IV256);
}
*/

void
bmw256_4way_update(void *cc, const void *data, size_t len)
{
	bmw32_4way(cc, data, len);
}

void
bmw256_4way_close(void *cc, void *dst)
{
	bmw256_4way_addbits_and_close(cc, 0, 0, dst);
}

void
bmw256_4way_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	bmw32_4way_close(cc, ub, n, dst, 8);
}

#endif   // __SSE2__

#if defined(__AVX2__)

// BMW-256 8 way 32

// copied from bmw512 4 way.
// change sizes to 32, macro names from b to s, shift constants.
// all the XORs ae good.


#define s8s0(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi32( (x), 1), \
                                       _mm256_slli_epi32( (x), 3) ), \
                     _mm256_xor_si256( mm256_rol_32( (x),  4), \
                                       mm256_rol_32( (x), 19) ) )

#define s8s1(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi32( (x), 1), \
                                       _mm256_slli_epi32( (x), 2) ), \
                     _mm256_xor_si256( mm256_rol_32( (x), 8), \
                                       mm256_rol_32( (x), 23) ) )

#define s8s2(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi32( (x), 2), \
                                       _mm256_slli_epi32( (x), 1) ), \
                     _mm256_xor_si256( mm256_rol_32( (x), 12), \
                                       mm256_rol_32( (x), 25) ) )

#define s8s3(x) \
   _mm256_xor_si256( _mm256_xor_si256( _mm256_srli_epi32( (x), 2), \
                                       _mm256_slli_epi32( (x), 2) ), \
                     _mm256_xor_si256( mm256_rol_32( (x), 15), \
                                       mm256_rol_32( (x), 29) ) )

#define s8s4(x) \
  _mm256_xor_si256( (x), _mm256_srli_epi32( (x), 1 ) )

#define s8s5(x) \
  _mm256_xor_si256( (x), _mm256_srli_epi32( (x), 2 ) )

#define r8s1(x)    mm256_rol_32( x,  3 ) 
#define r8s2(x)    mm256_rol_32( x,  7 ) 
#define r8s3(x)    mm256_rol_32( x, 13 ) 
#define r8s4(x)    mm256_rol_32( x, 16 ) 
#define r8s5(x)    mm256_rol_32( x, 19 ) 
#define r8s6(x)    mm256_rol_32( x, 23 ) 
#define r8s7(x)    mm256_rol_32( x, 27 ) 

#define mm256_rol_off_32( M, j, off ) \
   mm256_rol_32( M[ ( (j) + (off) ) & 0xF ] , \
                  ( ( (j) + (off) ) & 0xF ) + 1 )

#define add_elt_s8( M, H, j ) \
   _mm256_xor_si256( \
      _mm256_add_epi32( \
            _mm256_sub_epi32( _mm256_add_epi32( mm256_rol_off_32( M, j, 0 ), \
                                                mm256_rol_off_32( M, j, 3 ) ), \
                             mm256_rol_off_32( M, j, 10 ) ), \
            _mm256_set1_epi32( ( (j) + 16 ) * 0x05555555UL ) ), \
       H[ ( (j)+7 ) & 0xF ] )

#define expand1s8( qt, M, H, i ) \
   _mm256_add_epi32( \
      _mm256_add_epi32( \
         _mm256_add_epi32( \
             _mm256_add_epi32( \
                _mm256_add_epi32( s8s1( qt[ (i)-16 ] ), \
                                  s8s2( qt[ (i)-15 ] ) ), \
                _mm256_add_epi32( s8s3( qt[ (i)-14 ] ), \
                                  s8s0( qt[ (i)-13 ] ) ) ), \
             _mm256_add_epi32( \
                _mm256_add_epi32( s8s1( qt[ (i)-12 ] ), \
                                  s8s2( qt[ (i)-11 ] ) ), \
                _mm256_add_epi32( s8s3( qt[ (i)-10 ] ), \
                                  s8s0( qt[ (i)- 9 ] ) ) ) ), \
         _mm256_add_epi32( \
             _mm256_add_epi32( \
                _mm256_add_epi32( s8s1( qt[ (i)- 8 ] ), \
                                  s8s2( qt[ (i)- 7 ] ) ), \
                _mm256_add_epi32( s8s3( qt[ (i)- 6 ] ), \
                                  s8s0( qt[ (i)- 5 ] ) ) ), \
             _mm256_add_epi32( \
                _mm256_add_epi32( s8s1( qt[ (i)- 4 ] ), \
                                  s8s2( qt[ (i)- 3 ] ) ), \
                _mm256_add_epi32( s8s3( qt[ (i)- 2 ] ), \
                                  s8s0( qt[ (i)- 1 ] ) ) ) ) ), \
      add_elt_s8( M, H, (i)-16 ) )

#define expand2s8( qt, M, H, i) \
   _mm256_add_epi32( \
      mm256_add4_32( \
          mm256_add4_32( qt[ (i)-16 ], r8s1( qt[ (i)-15 ] ), \
                         qt[ (i)-14 ], r8s2( qt[ (i)-13 ] ) ), \
          mm256_add4_32( qt[ (i)-12 ], r8s3( qt[ (i)-11 ] ), \
                         qt[ (i)-10 ], r8s4( qt[ (i)- 9 ] ) ), \
          mm256_add4_32( qt[ (i)- 8 ], r8s5( qt[ (i)- 7 ] ), \
                         qt[ (i)- 6 ], r8s6( qt[ (i)- 5 ] ) ), \
          mm256_add4_32( qt[ (i)- 4 ], r8s7( qt[ (i)- 3 ] ), \
                         s8s4( qt[ (i)- 2 ] ), s8s5( qt[ (i)- 1 ] ) ) ), \
      add_elt_s8( M, H, (i)-16 ) )


#define W8s0 \
   _mm256_add_epi32( \
      _mm256_add_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 5], H[ 5] ), \
                           _mm256_xor_si256( M[ 7], H[ 7] ) ), \
         _mm256_xor_si256( M[10], H[10] ) ), \
      _mm256_add_epi32( _mm256_xor_si256( M[13], H[13] ), \
                        _mm256_xor_si256( M[14], H[14] ) ) )

#define W8s1 \
   _mm256_add_epi32( \
       _mm256_add_epi32( \
          _mm256_sub_epi32( _mm256_xor_si256( M[ 6], H[ 6] ), \
                            _mm256_xor_si256( M[ 8], H[ 8] ) ), \
          _mm256_xor_si256( M[11], H[11] ) ), \
       _mm256_sub_epi32( _mm256_xor_si256( M[14], H[14] ), \
                         _mm256_xor_si256( M[15], H[15] ) ) )

#define W8s2 \
   _mm256_sub_epi32( \
      _mm256_add_epi32( \
         _mm256_add_epi32( _mm256_xor_si256( M[ 0], H[ 0] ), \
                           _mm256_xor_si256( M[ 7], H[ 7] ) ), \
         _mm256_xor_si256( M[ 9], H[ 9] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[12], H[12] ), \
                        _mm256_xor_si256( M[15], H[15] ) ) )

#define W8s3 \
   _mm256_sub_epi32( \
      _mm256_add_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 0], H[ 0] ), \
                           _mm256_xor_si256( M[ 1], H[ 1] ) ), \
         _mm256_xor_si256( M[ 8], H[ 8] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[10], H[10] ), \
                        _mm256_xor_si256( M[13], H[13] ) ) )

#define W8s4 \
   _mm256_sub_epi32( \
      _mm256_add_epi32( \
         _mm256_add_epi32( _mm256_xor_si256( M[ 1], H[ 1] ), \
                           _mm256_xor_si256( M[ 2], H[ 2] ) ), \
         _mm256_xor_si256( M[ 9], H[ 9] ) ), \
      _mm256_add_epi32( _mm256_xor_si256( M[11], H[11] ), \
                        _mm256_xor_si256( M[14], H[14] ) ) )

#define W8s5 \
   _mm256_sub_epi32( \
      _mm256_add_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 3], H[ 3] ), \
                           _mm256_xor_si256( M[ 2], H[ 2] ) ), \
         _mm256_xor_si256( M[10], H[10] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[12], H[12] ), \
                        _mm256_xor_si256( M[15], H[15] ) ) )

#define W8s6 \
   _mm256_sub_epi32( \
      _mm256_sub_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 4], H[ 4] ), \
                           _mm256_xor_si256( M[ 0], H[ 0] ) ), \
         _mm256_xor_si256( M[ 3], H[ 3] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[11], H[11] ), \
                        _mm256_xor_si256( M[13], H[13] ) ) )

#define W8s7 \
   _mm256_sub_epi32( \
      _mm256_sub_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 1], H[ 1] ), \
                           _mm256_xor_si256( M[ 4], H[ 4] ) ), \
         _mm256_xor_si256( M[ 5], H[ 5] ) ), \
      _mm256_add_epi32( _mm256_xor_si256( M[12], H[12] ), \
                        _mm256_xor_si256( M[14], H[14] ) ) )

#define W8s8 \
   _mm256_add_epi32( \
      _mm256_sub_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 2], H[ 2] ), \
                           _mm256_xor_si256( M[ 5], H[ 5] ) ), \
         _mm256_xor_si256( M[ 6], H[ 6] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[13], H[13] ), \
                        _mm256_xor_si256( M[15], H[15] ) ) )

#define W8s9 \
   _mm256_sub_epi32( \
      _mm256_add_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 0], H[ 0] ), \
                           _mm256_xor_si256( M[ 3], H[ 3] ) ), \
         _mm256_xor_si256( M[ 6], H[ 6] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[ 7], H[ 7] ), \
                        _mm256_xor_si256( M[14], H[14] ) ) )

#define W8s10 \
   _mm256_sub_epi32( \
      _mm256_sub_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 8], H[ 8] ), \
                           _mm256_xor_si256( M[ 1], H[ 1] ) ), \
         _mm256_xor_si256( M[ 4], H[ 4] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[ 7], H[ 7] ), \
                        _mm256_xor_si256( M[15], H[15] ) ) )

#define W8s11 \
   _mm256_sub_epi32( \
      _mm256_sub_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 8], H[ 8] ), \
                           _mm256_xor_si256( M[ 0], H[ 0] ) ), \
         _mm256_xor_si256( M[ 2], H[ 2] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[ 5], H[ 5] ), \
                        _mm256_xor_si256( M[ 9], H[ 9] ) ) )

#define W8s12 \
   _mm256_sub_epi32( \
      _mm256_sub_epi32( \
         _mm256_add_epi32( _mm256_xor_si256( M[ 1], H[ 1] ), \
                           _mm256_xor_si256( M[ 3], H[ 3] ) ), \
         _mm256_xor_si256( M[ 6], H[ 6] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[ 9], H[ 9] ), \
                        _mm256_xor_si256( M[10], H[10] ) ) )

#define W8s13 \
   _mm256_add_epi32( \
      _mm256_add_epi32( \
         _mm256_add_epi32( _mm256_xor_si256( M[ 2], H[ 2] ), \
                           _mm256_xor_si256( M[ 4], H[ 4] ) ), \
         _mm256_xor_si256( M[ 7], H[ 7] ) ), \
      _mm256_add_epi32( _mm256_xor_si256( M[10], H[10] ), \
                        _mm256_xor_si256( M[11], H[11] ) ) )

#define W8s14 \
   _mm256_sub_epi32( \
      _mm256_add_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[ 3], H[ 3] ), \
                           _mm256_xor_si256( M[ 5], H[ 5] ) ), \
         _mm256_xor_si256( M[ 8], H[ 8] ) ), \
      _mm256_add_epi32( _mm256_xor_si256( M[11], H[11] ), \
                        _mm256_xor_si256( M[12], H[12] ) ) )

#define W8s15 \
   _mm256_sub_epi32( \
      _mm256_sub_epi32( \
         _mm256_sub_epi32( _mm256_xor_si256( M[12], H[12] ), \
                           _mm256_xor_si256( M[ 4], H[4] ) ), \
         _mm256_xor_si256( M[ 6], H[ 6] ) ), \
      _mm256_sub_epi32( _mm256_xor_si256( M[ 9], H[ 9] ), \
                        _mm256_xor_si256( M[13], H[13] ) ) )


void compress_small_8way( const __m256i *M, const __m256i H[16],
	                  __m256i dH[16] )
{
   __m256i qt[32], xl, xh;

   qt[ 0] = _mm256_add_epi32( s8s0( W8s0 ), H[ 1] );
   qt[ 1] = _mm256_add_epi32( s8s1( W8s1 ), H[ 2] );
   qt[ 2] = _mm256_add_epi32( s8s2( W8s2 ), H[ 3] );
   qt[ 3] = _mm256_add_epi32( s8s3( W8s3 ), H[ 4] );
   qt[ 4] = _mm256_add_epi32( s8s4( W8s4 ), H[ 5] );
   qt[ 5] = _mm256_add_epi32( s8s0( W8s5 ), H[ 6] );
   qt[ 6] = _mm256_add_epi32( s8s1( W8s6 ), H[ 7] );
   qt[ 7] = _mm256_add_epi32( s8s2( W8s7 ), H[ 8] );
   qt[ 8] = _mm256_add_epi32( s8s3( W8s8 ), H[ 9] );
   qt[ 9] = _mm256_add_epi32( s8s4( W8s9 ), H[10] );
   qt[10] = _mm256_add_epi32( s8s0( W8s10), H[11] );
   qt[11] = _mm256_add_epi32( s8s1( W8s11), H[12] );
   qt[12] = _mm256_add_epi32( s8s2( W8s12), H[13] );
   qt[13] = _mm256_add_epi32( s8s3( W8s13), H[14] );
   qt[14] = _mm256_add_epi32( s8s4( W8s14), H[15] );
   qt[15] = _mm256_add_epi32( s8s0( W8s15), H[ 0] );
   qt[16] = expand1s8( qt, M, H, 16 );
   qt[17] = expand1s8( qt, M, H, 17 );
   qt[18] = expand2s8( qt, M, H, 18 );
   qt[19] = expand2s8( qt, M, H, 19 );
   qt[20] = expand2s8( qt, M, H, 20 );
   qt[21] = expand2s8( qt, M, H, 21 );
   qt[22] = expand2s8( qt, M, H, 22 );
   qt[23] = expand2s8( qt, M, H, 23 );
   qt[24] = expand2s8( qt, M, H, 24 );
   qt[25] = expand2s8( qt, M, H, 25 );
   qt[26] = expand2s8( qt, M, H, 26 );
   qt[27] = expand2s8( qt, M, H, 27 );
   qt[28] = expand2s8( qt, M, H, 28 );
   qt[29] = expand2s8( qt, M, H, 29 );
   qt[30] = expand2s8( qt, M, H, 30 );
   qt[31] = expand2s8( qt, M, H, 31 );

   xl = mm256_xor3( mm256_xor3( qt[16], qt[17], qt[18] ),
                    mm256_xor3( qt[19], qt[20], qt[21] ),
                    _mm256_xor_si256( qt[22], qt[23] ) );

   xh = mm256_xor3( mm256_xor3( xl,     qt[24], qt[25] ),
                    mm256_xor3( qt[26], qt[27], qt[28] ),
                    mm256_xor3( qt[29], qt[30], qt[31] ) );

#define DH1L( m, sl, sr, a, b, c ) \
   _mm256_add_epi32( mm256_xor3( M[m], _mm256_slli_epi32( xh, sl ), \
                                       _mm256_srli_epi32( qt[a], sr ) ), \
                     mm256_xor3( xl, qt[b], qt[c] ) )

#define DH1R( m, sl, sr, a, b, c ) \
   _mm256_add_epi32( mm256_xor3( M[m], _mm256_srli_epi32( xh, sl ), \
                                       _mm256_slli_epi32( qt[a], sr ) ), \
                     mm256_xor3( xl, qt[b], qt[c] ) )

#define DH2L( m, rl, sl, h, a, b, c ) \
   _mm256_add_epi32( _mm256_add_epi32( \
                        mm256_rol_32( dH[h], rl ), \
                        mm256_xor3( xh, qt[a], M[m] ) ), \
                     mm256_xor3( _mm256_slli_epi32( xl, sl ), qt[b], qt[c] ) ) 

#define DH2R( m, rl, sr, h, a, b, c ) \
   _mm256_add_epi32( _mm256_add_epi32( \
                        mm256_rol_32( dH[h], rl ), \
                        mm256_xor3( xh, qt[a], M[m] ) ), \
                     mm256_xor3( _mm256_srli_epi32( xl, sr ), qt[b], qt[c] ) )

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

static const __m256i final_s8[16] =
{
    { 0xaaaaaaa0aaaaaaa0, 0xaaaaaaa0aaaaaaa0,
      0xaaaaaaa0aaaaaaa0, 0xaaaaaaa0aaaaaaa0 },
    { 0xaaaaaaa1aaaaaaa1, 0xaaaaaaa1aaaaaaa1,
      0xaaaaaaa1aaaaaaa1, 0xaaaaaaa1aaaaaaa1 },
    { 0xaaaaaaa2aaaaaaa2, 0xaaaaaaa2aaaaaaa2,
      0xaaaaaaa2aaaaaaa2, 0xaaaaaaa2aaaaaaa2 },
    { 0xaaaaaaa3aaaaaaa3, 0xaaaaaaa3aaaaaaa3,
      0xaaaaaaa3aaaaaaa3, 0xaaaaaaa3aaaaaaa3 },
    { 0xaaaaaaa4aaaaaaa4, 0xaaaaaaa4aaaaaaa4,
      0xaaaaaaa4aaaaaaa4, 0xaaaaaaa4aaaaaaa4 },
    { 0xaaaaaaa5aaaaaaa5, 0xaaaaaaa5aaaaaaa5,
      0xaaaaaaa5aaaaaaa5, 0xaaaaaaa5aaaaaaa5 },
    { 0xaaaaaaa6aaaaaaa6, 0xaaaaaaa6aaaaaaa6,
      0xaaaaaaa6aaaaaaa6, 0xaaaaaaa6aaaaaaa6 },
    { 0xaaaaaaa7aaaaaaa7, 0xaaaaaaa7aaaaaaa7,
      0xaaaaaaa7aaaaaaa7, 0xaaaaaaa7aaaaaaa7 },
    { 0xaaaaaaa8aaaaaaa8, 0xaaaaaaa8aaaaaaa8,
      0xaaaaaaa8aaaaaaa8, 0xaaaaaaa8aaaaaaa8 },
    { 0xaaaaaaa9aaaaaaa9, 0xaaaaaaa9aaaaaaa9,
      0xaaaaaaa9aaaaaaa9, 0xaaaaaaa9aaaaaaa9 },
    { 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
      0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
    { 0xaaaaaaabaaaaaaab, 0xaaaaaaabaaaaaaab,
      0xaaaaaaabaaaaaaab, 0xaaaaaaabaaaaaaab },
    { 0xaaaaaaacaaaaaaac, 0xaaaaaaacaaaaaaac,
      0xaaaaaaacaaaaaaac, 0xaaaaaaacaaaaaaac },
    { 0xaaaaaaadaaaaaaad, 0xaaaaaaadaaaaaaad,
      0xaaaaaaadaaaaaaad, 0xaaaaaaadaaaaaaad },
    { 0xaaaaaaaeaaaaaaae, 0xaaaaaaaeaaaaaaae,
      0xaaaaaaaeaaaaaaae, 0xaaaaaaaeaaaaaaae },
    { 0xaaaaaaafaaaaaaaf, 0xaaaaaaafaaaaaaaf,
      0xaaaaaaafaaaaaaaf, 0xaaaaaaafaaaaaaaf }
};

void bmw256_8way_init( bmw256_8way_context *ctx )
{
   ctx->H[ 0] = m256_const1_64( 0x4041424340414243 );
   ctx->H[ 1] = m256_const1_64( 0x4445464744454647 );
   ctx->H[ 2] = m256_const1_64( 0x48494A4B48494A4B );
   ctx->H[ 3] = m256_const1_64( 0x4C4D4E4F4C4D4E4F );
   ctx->H[ 4] = m256_const1_64( 0x5051525350515253 );
   ctx->H[ 5] = m256_const1_64( 0x5455565754555657 );
   ctx->H[ 6] = m256_const1_64( 0x58595A5B58595A5B );
   ctx->H[ 7] = m256_const1_64( 0x5C5D5E5F5C5D5E5F );
   ctx->H[ 8] = m256_const1_64( 0x6061626360616263 );
   ctx->H[ 9] = m256_const1_64( 0x6465666764656667 );
   ctx->H[10] = m256_const1_64( 0x68696A6B68696A6B );
   ctx->H[11] = m256_const1_64( 0x6C6D6E6F6C6D6E6F );
   ctx->H[12] = m256_const1_64( 0x7071727370717273 );
   ctx->H[13] = m256_const1_64( 0x7475767774757677 );
   ctx->H[14] = m256_const1_64( 0x78797A7B78797A7B );
   ctx->H[15] = m256_const1_64( 0x7C7D7E7F7C7D7E7F );
   ctx->ptr       = 0;
   ctx->bit_count = 0;
}

void bmw256_8way_update( bmw256_8way_context *ctx, const void *data,
                         size_t len )
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   __m256i htmp[16];
   __m256i *h1, *h2;
   size_t ptr;
   const int buf_size = 64;  // bytes of one lane, compatible with len

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
      memcpy_256( buf + (ptr>>2), vdata, clen >> 2 );
      vdata = vdata + (clen>>2);
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         __m256i *ht;
         compress_small_8way( buf, h1, h2 );
         ht = h1;
         h1 = h2;
         h2 = ht;
         ptr = 0;
      }
   }
   ctx->ptr = ptr;

   if ( h1 != ctx->H )
        memcpy_256( ctx->H, h1, 16 );
}

void bmw256_8way_close( bmw256_8way_context *ctx, void *dst )
{
   __m256i *buf;
   __m256i h1[16], h2[16], *h;
   size_t ptr, u, v;
   const int buf_size = 64;  // bytes of one lane, compatible with len

   buf = ctx->buf;
   ptr = ctx->ptr;
   buf[ ptr>>2 ] = m256_const1_64( 0x0000008000000080 );
   ptr += 4;
   h = ctx->H;

   if (  ptr > (buf_size - 4) )
   {
      memset_zero_256( buf + (ptr>>2), (buf_size - ptr) >> 2 );
      compress_small_8way( buf, h, h1 );
      ptr = 0;
      h = h1;
   }
   memset_zero_256( buf + (ptr>>2), (buf_size - 8 - ptr) >> 2 );
   buf[ (buf_size - 8) >> 2 ] = _mm256_set1_epi32( ctx->bit_count );
   buf[ (buf_size - 4) >> 2 ] = m256_zero;

   compress_small_8way( buf, h, h2 );

   for ( u = 0; u < 16; u ++ )
      buf[u] = h2[u];

   compress_small_8way( buf, final_s8, h1 );
   for (u = 0, v = 16 - 8; u < 8; u ++, v ++)
      casti_m256i(dst,u) = h1[v];
}


#endif // __AVX2__

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// BMW-256 16 way 32


#define s16s0(x) \
   mm512_xor4( _mm512_srli_epi32( (x), 1), \
                _mm512_slli_epi32( (x), 3), \
                mm512_rol_32( (x),  4), \
                mm512_rol_32( (x), 19) )

#define s16s1(x) \
   mm512_xor4( _mm512_srli_epi32( (x), 1), \
                _mm512_slli_epi32( (x), 2), \
                mm512_rol_32( (x), 8), \
                mm512_rol_32( (x), 23) )

#define s16s2(x) \
   mm512_xor4( _mm512_srli_epi32( (x), 2), \
               _mm512_slli_epi32( (x), 1), \
               mm512_rol_32( (x), 12), \
               mm512_rol_32( (x), 25) )

#define s16s3(x) \
   mm512_xor4( _mm512_srli_epi32( (x), 2), \
               _mm512_slli_epi32( (x), 2), \
               mm512_rol_32( (x), 15), \
               mm512_rol_32( (x), 29) )

#define s16s4(x) \
  _mm512_xor_si512( (x), _mm512_srli_epi32( (x), 1 ) )

#define s16s5(x) \
  _mm512_xor_si512( (x), _mm512_srli_epi32( (x), 2 ) )

#define r16s1(x)    mm512_rol_32( x,  3 ) 
#define r16s2(x)    mm512_rol_32( x,  7 ) 
#define r16s3(x)    mm512_rol_32( x, 13 ) 
#define r16s4(x)    mm512_rol_32( x, 16 ) 
#define r16s5(x)    mm512_rol_32( x, 19 ) 
#define r16s6(x)    mm512_rol_32( x, 23 ) 
#define r16s7(x)    mm512_rol_32( x, 27 ) 

#define mm512_rol_off_32( M, j, off ) \
   mm512_rol_32( M[ ( (j) + (off) ) & 0xF ] , \
                  ( ( (j) + (off) ) & 0xF ) + 1 )

#define add_elt_s16( M, H, j ) \
   _mm512_xor_si512( \
      _mm512_add_epi32( \
            _mm512_sub_epi32( _mm512_add_epi32( mm512_rol_off_32( M, j, 0 ), \
                                                mm512_rol_off_32( M, j, 3 ) ), \
                             mm512_rol_off_32( M, j, 10 ) ), \
            _mm512_set1_epi32( ( (j) + 16 ) * 0x05555555UL ) ), \
       H[ ( (j)+7 ) & 0xF ] )

#define expand1s16( qt, M, H, i ) \
   _mm512_add_epi32( add_elt_s16( M, H, (i)-16 ), \
                     mm512_add4_32( mm512_add4_32( s16s1( qt[ (i)-16 ] ), \
                                                   s16s2( qt[ (i)-15 ] ), \
                                                   s16s3( qt[ (i)-14 ] ), \
                                                   s16s0( qt[ (i)-13 ] ) ), \
                                    mm512_add4_32( s16s1( qt[ (i)-12 ] ), \
                                                   s16s2( qt[ (i)-11 ] ), \
                                                   s16s3( qt[ (i)-10 ] ), \
                                                   s16s0( qt[ (i)- 9 ] ) ), \
                                    mm512_add4_32( s16s1( qt[ (i)- 8 ] ), \
                                                   s16s2( qt[ (i)- 7 ] ), \
                                                   s16s3( qt[ (i)- 6 ] ), \
                                                   s16s0( qt[ (i)- 5 ] ) ), \
                                    mm512_add4_32( s16s1( qt[ (i)- 4 ] ), \
                                                   s16s2( qt[ (i)- 3 ] ), \
                                                   s16s3( qt[ (i)- 2 ] ), \
                                                   s16s0( qt[ (i)- 1 ] ) ) ) )

#define expand2s16( qt, M, H, i) \
   _mm512_add_epi32( add_elt_s16( M, H, (i)-16 ), \
      mm512_add4_32( mm512_add4_32( qt[ (i)-16 ], \
                                    r16s1( qt[ (i)-15 ] ), \
                                    qt[ (i)-14 ], \
                                    r16s2( qt[ (i)-13 ] ) ), \
                     mm512_add4_32( qt[ (i)-12 ], \
                                    r16s3( qt[ (i)-11 ] ), \
                                    qt[ (i)-10 ], \
                                    r16s4( qt[ (i)- 9 ] ) ), \
                     mm512_add4_32( qt[ (i)- 8 ], \
                                    r16s5( qt[ (i)- 7 ] ), \
                                    qt[ (i)- 6 ], \
                                    r16s6( qt[ (i)- 5 ] ) ), \
                     mm512_add4_32( qt[ (i)- 4 ], \
                                    r16s7( qt[ (i)- 3 ] ), \
                                    s16s4( qt[ (i)- 2 ] ), \
                                    s16s5( qt[ (i)- 1 ] ) ) ) )


#define W16s0 \
   _mm512_add_epi32( \
      _mm512_add_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 5], H[ 5] ), \
                           _mm512_xor_si512( M[ 7], H[ 7] ) ), \
         _mm512_xor_si512( M[10], H[10] ) ), \
      _mm512_add_epi32( _mm512_xor_si512( M[13], H[13] ), \
                        _mm512_xor_si512( M[14], H[14] ) ) )

#define W16s1 \
   _mm512_add_epi32( \
       _mm512_add_epi32( \
          _mm512_sub_epi32( _mm512_xor_si512( M[ 6], H[ 6] ), \
                            _mm512_xor_si512( M[ 8], H[ 8] ) ), \
          _mm512_xor_si512( M[11], H[11] ) ), \
       _mm512_sub_epi32( _mm512_xor_si512( M[14], H[14] ), \
                         _mm512_xor_si512( M[15], H[15] ) ) )

#define W16s2 \
   _mm512_sub_epi32( \
      _mm512_add_epi32( \
         _mm512_add_epi32( _mm512_xor_si512( M[ 0], H[ 0] ), \
                           _mm512_xor_si512( M[ 7], H[ 7] ) ), \
         _mm512_xor_si512( M[ 9], H[ 9] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[12], H[12] ), \
                        _mm512_xor_si512( M[15], H[15] ) ) )

#define W16s3 \
   _mm512_sub_epi32( \
      _mm512_add_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 0], H[ 0] ), \
                           _mm512_xor_si512( M[ 1], H[ 1] ) ), \
         _mm512_xor_si512( M[ 8], H[ 8] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[10], H[10] ), \
                        _mm512_xor_si512( M[13], H[13] ) ) )

#define W16s4 \
   _mm512_sub_epi32( \
      _mm512_add_epi32( \
         _mm512_add_epi32( _mm512_xor_si512( M[ 1], H[ 1] ), \
                           _mm512_xor_si512( M[ 2], H[ 2] ) ), \
         _mm512_xor_si512( M[ 9], H[ 9] ) ), \
      _mm512_add_epi32( _mm512_xor_si512( M[11], H[11] ), \
                        _mm512_xor_si512( M[14], H[14] ) ) )

#define W16s5 \
   _mm512_sub_epi32( \
      _mm512_add_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 3], H[ 3] ), \
                           _mm512_xor_si512( M[ 2], H[ 2] ) ), \
         _mm512_xor_si512( M[10], H[10] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[12], H[12] ), \
                        _mm512_xor_si512( M[15], H[15] ) ) )

#define W16s6 \
   _mm512_sub_epi32( \
      _mm512_sub_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 4], H[ 4] ), \
                           _mm512_xor_si512( M[ 0], H[ 0] ) ), \
         _mm512_xor_si512( M[ 3], H[ 3] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[11], H[11] ), \
                        _mm512_xor_si512( M[13], H[13] ) ) )

#define W16s7 \
   _mm512_sub_epi32( \
      _mm512_sub_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 1], H[ 1] ), \
                           _mm512_xor_si512( M[ 4], H[ 4] ) ), \
         _mm512_xor_si512( M[ 5], H[ 5] ) ), \
      _mm512_add_epi32( _mm512_xor_si512( M[12], H[12] ), \
                        _mm512_xor_si512( M[14], H[14] ) ) )

#define W16s8 \
   _mm512_add_epi32( \
      _mm512_sub_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 2], H[ 2] ), \
                           _mm512_xor_si512( M[ 5], H[ 5] ) ), \
         _mm512_xor_si512( M[ 6], H[ 6] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[13], H[13] ), \
                        _mm512_xor_si512( M[15], H[15] ) ) )

#define W16s9 \
   _mm512_sub_epi32( \
      _mm512_add_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 0], H[ 0] ), \
                           _mm512_xor_si512( M[ 3], H[ 3] ) ), \
         _mm512_xor_si512( M[ 6], H[ 6] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[ 7], H[ 7] ), \
                        _mm512_xor_si512( M[14], H[14] ) ) )

#define W16s10 \
   _mm512_sub_epi32( \
      _mm512_sub_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 8], H[ 8] ), \
                           _mm512_xor_si512( M[ 1], H[ 1] ) ), \
         _mm512_xor_si512( M[ 4], H[ 4] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[ 7], H[ 7] ), \
                        _mm512_xor_si512( M[15], H[15] ) ) )

#define W16s11 \
   _mm512_sub_epi32( \
      _mm512_sub_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 8], H[ 8] ), \
                           _mm512_xor_si512( M[ 0], H[ 0] ) ), \
         _mm512_xor_si512( M[ 2], H[ 2] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[ 5], H[ 5] ), \
                        _mm512_xor_si512( M[ 9], H[ 9] ) ) )

#define W16s12 \
   _mm512_sub_epi32( \
      _mm512_sub_epi32( \
         _mm512_add_epi32( _mm512_xor_si512( M[ 1], H[ 1] ), \
                           _mm512_xor_si512( M[ 3], H[ 3] ) ), \
         _mm512_xor_si512( M[ 6], H[ 6] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[ 9], H[ 9] ), \
                        _mm512_xor_si512( M[10], H[10] ) ) )

#define W16s13 \
   _mm512_add_epi32( \
      _mm512_add_epi32( \
         _mm512_add_epi32( _mm512_xor_si512( M[ 2], H[ 2] ), \
                           _mm512_xor_si512( M[ 4], H[ 4] ) ), \
         _mm512_xor_si512( M[ 7], H[ 7] ) ), \
      _mm512_add_epi32( _mm512_xor_si512( M[10], H[10] ), \
                        _mm512_xor_si512( M[11], H[11] ) ) )

#define W16s14 \
   _mm512_sub_epi32( \
      _mm512_add_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[ 3], H[ 3] ), \
                           _mm512_xor_si512( M[ 5], H[ 5] ) ), \
         _mm512_xor_si512( M[ 8], H[ 8] ) ), \
      _mm512_add_epi32( _mm512_xor_si512( M[11], H[11] ), \
                        _mm512_xor_si512( M[12], H[12] ) ) )

#define W16s15 \
   _mm512_sub_epi32( \
      _mm512_sub_epi32( \
         _mm512_sub_epi32( _mm512_xor_si512( M[12], H[12] ), \
                           _mm512_xor_si512( M[ 4], H[4] ) ), \
         _mm512_xor_si512( M[ 6], H[ 6] ) ), \
      _mm512_sub_epi32( _mm512_xor_si512( M[ 9], H[ 9] ), \
                        _mm512_xor_si512( M[13], H[13] ) ) )

void compress_small_16way( const __m512i *M, const __m512i H[16],
                     __m512i dH[16] )
{
   __m512i qt[32], xl, xh;

   qt[ 0] = _mm512_add_epi32( s16s0( W16s0 ), H[ 1] );
   qt[ 1] = _mm512_add_epi32( s16s1( W16s1 ), H[ 2] );
   qt[ 2] = _mm512_add_epi32( s16s2( W16s2 ), H[ 3] );
   qt[ 3] = _mm512_add_epi32( s16s3( W16s3 ), H[ 4] );
   qt[ 4] = _mm512_add_epi32( s16s4( W16s4 ), H[ 5] );
   qt[ 5] = _mm512_add_epi32( s16s0( W16s5 ), H[ 6] );
   qt[ 6] = _mm512_add_epi32( s16s1( W16s6 ), H[ 7] );
   qt[ 7] = _mm512_add_epi32( s16s2( W16s7 ), H[ 8] );
   qt[ 8] = _mm512_add_epi32( s16s3( W16s8 ), H[ 9] );
   qt[ 9] = _mm512_add_epi32( s16s4( W16s9 ), H[10] );
   qt[10] = _mm512_add_epi32( s16s0( W16s10), H[11] );
   qt[11] = _mm512_add_epi32( s16s1( W16s11), H[12] );
   qt[12] = _mm512_add_epi32( s16s2( W16s12), H[13] );
   qt[13] = _mm512_add_epi32( s16s3( W16s13), H[14] );
   qt[14] = _mm512_add_epi32( s16s4( W16s14), H[15] );
   qt[15] = _mm512_add_epi32( s16s0( W16s15), H[ 0] );
   qt[16] = expand1s16( qt, M, H, 16 );
   qt[17] = expand1s16( qt, M, H, 17 );
   qt[18] = expand2s16( qt, M, H, 18 );
   qt[19] = expand2s16( qt, M, H, 19 );
   qt[20] = expand2s16( qt, M, H, 20 );
   qt[21] = expand2s16( qt, M, H, 21 );
   qt[22] = expand2s16( qt, M, H, 22 );
   qt[23] = expand2s16( qt, M, H, 23 );
   qt[24] = expand2s16( qt, M, H, 24 );
   qt[25] = expand2s16( qt, M, H, 25 );
   qt[26] = expand2s16( qt, M, H, 26 );
   qt[27] = expand2s16( qt, M, H, 27 );
   qt[28] = expand2s16( qt, M, H, 28 );
   qt[29] = expand2s16( qt, M, H, 29 );
   qt[30] = expand2s16( qt, M, H, 30 );
   qt[31] = expand2s16( qt, M, H, 31 );

   xl = mm512_xor3( mm512_xor3( qt[16], qt[17], qt[18] ),
                    mm512_xor3( qt[19], qt[20], qt[21] ),
                    _mm512_xor_si512( qt[22], qt[23] ) );

   xh = mm512_xor3( mm512_xor3( xl,     qt[24], qt[25] ),
                    mm512_xor3( qt[26], qt[27], qt[28] ),
                    mm512_xor3( qt[29], qt[30], qt[31] ) );

#define DH1L( m, sl, sr, a, b, c ) \
   _mm512_add_epi32( mm512_xor3( M[m], _mm512_slli_epi32( xh, sl ), \
                                       _mm512_srli_epi32( qt[a], sr ) ), \
                     mm512_xor3( xl, qt[b], qt[c] ) )

#define DH1R( m, sl, sr, a, b, c ) \
   _mm512_add_epi32( mm512_xor3( M[m], _mm512_srli_epi32( xh, sl ), \
                                       _mm512_slli_epi32( qt[a], sr ) ), \
                     mm512_xor3( xl, qt[b], qt[c] ) )

#define DH2L( m, rl, sl, h, a, b, c ) \
   _mm512_add_epi32( _mm512_add_epi32( \
                        mm512_rol_32( dH[h], rl ), \
                        mm512_xor3( xh, qt[a], M[m] ) ), \
                     mm512_xor3( _mm512_slli_epi32( xl, sl ), qt[b], qt[c] ) ) 

#define DH2R( m, rl, sr, h, a, b, c ) \
   _mm512_add_epi32( _mm512_add_epi32( \
                        mm512_rol_32( dH[h], rl ), \
                        mm512_xor3( xh, qt[a], M[m] ) ), \
                     mm512_xor3( _mm512_srli_epi32( xl, sr ), qt[b], qt[c] ) )

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

static const __m512i final_s16[16] =
{
    { 0xaaaaaaa0aaaaaaa0, 0xaaaaaaa0aaaaaaa0,
      0xaaaaaaa0aaaaaaa0, 0xaaaaaaa0aaaaaaa0,
      0xaaaaaaa0aaaaaaa0, 0xaaaaaaa0aaaaaaa0,
      0xaaaaaaa0aaaaaaa0, 0xaaaaaaa0aaaaaaa0 },
    { 0xaaaaaaa1aaaaaaa1, 0xaaaaaaa1aaaaaaa1,
      0xaaaaaaa1aaaaaaa1, 0xaaaaaaa1aaaaaaa1,
      0xaaaaaaa1aaaaaaa1, 0xaaaaaaa1aaaaaaa1,
      0xaaaaaaa1aaaaaaa1, 0xaaaaaaa1aaaaaaa1 },
    { 0xaaaaaaa2aaaaaaa2, 0xaaaaaaa2aaaaaaa2,
      0xaaaaaaa2aaaaaaa2, 0xaaaaaaa2aaaaaaa2,
      0xaaaaaaa2aaaaaaa2, 0xaaaaaaa2aaaaaaa2,
      0xaaaaaaa2aaaaaaa2, 0xaaaaaaa2aaaaaaa2 },
    { 0xaaaaaaa3aaaaaaa3, 0xaaaaaaa3aaaaaaa3,
      0xaaaaaaa3aaaaaaa3, 0xaaaaaaa3aaaaaaa3,
      0xaaaaaaa3aaaaaaa3, 0xaaaaaaa3aaaaaaa3,
      0xaaaaaaa3aaaaaaa3, 0xaaaaaaa3aaaaaaa3 },
    { 0xaaaaaaa4aaaaaaa4, 0xaaaaaaa4aaaaaaa4,
      0xaaaaaaa4aaaaaaa4, 0xaaaaaaa4aaaaaaa4,
      0xaaaaaaa4aaaaaaa4, 0xaaaaaaa4aaaaaaa4,
      0xaaaaaaa4aaaaaaa4, 0xaaaaaaa4aaaaaaa4 },
    { 0xaaaaaaa5aaaaaaa5, 0xaaaaaaa5aaaaaaa5,
      0xaaaaaaa5aaaaaaa5, 0xaaaaaaa5aaaaaaa5,
      0xaaaaaaa5aaaaaaa5, 0xaaaaaaa5aaaaaaa5,
      0xaaaaaaa5aaaaaaa5, 0xaaaaaaa5aaaaaaa5 },
    { 0xaaaaaaa6aaaaaaa6, 0xaaaaaaa6aaaaaaa6,
      0xaaaaaaa6aaaaaaa6, 0xaaaaaaa6aaaaaaa6,
      0xaaaaaaa6aaaaaaa6, 0xaaaaaaa6aaaaaaa6,
      0xaaaaaaa6aaaaaaa6, 0xaaaaaaa6aaaaaaa6 },
    { 0xaaaaaaa7aaaaaaa7, 0xaaaaaaa7aaaaaaa7,
      0xaaaaaaa7aaaaaaa7, 0xaaaaaaa7aaaaaaa7,
      0xaaaaaaa7aaaaaaa7, 0xaaaaaaa7aaaaaaa7,
      0xaaaaaaa7aaaaaaa7, 0xaaaaaaa7aaaaaaa7 },
    { 0xaaaaaaa8aaaaaaa8, 0xaaaaaaa8aaaaaaa8,
      0xaaaaaaa8aaaaaaa8, 0xaaaaaaa8aaaaaaa8,
      0xaaaaaaa8aaaaaaa8, 0xaaaaaaa8aaaaaaa8,
      0xaaaaaaa8aaaaaaa8, 0xaaaaaaa8aaaaaaa8 },
    { 0xaaaaaaa9aaaaaaa9, 0xaaaaaaa9aaaaaaa9,
      0xaaaaaaa9aaaaaaa9, 0xaaaaaaa9aaaaaaa9,
      0xaaaaaaa9aaaaaaa9, 0xaaaaaaa9aaaaaaa9,
      0xaaaaaaa9aaaaaaa9, 0xaaaaaaa9aaaaaaa9 },
    { 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
      0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
      0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa,
      0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa },
    { 0xaaaaaaabaaaaaaab, 0xaaaaaaabaaaaaaab,
      0xaaaaaaabaaaaaaab, 0xaaaaaaabaaaaaaab,
      0xaaaaaaabaaaaaaab, 0xaaaaaaabaaaaaaab,
      0xaaaaaaabaaaaaaab, 0xaaaaaaabaaaaaaab },
    { 0xaaaaaaacaaaaaaac, 0xaaaaaaacaaaaaaac,
      0xaaaaaaacaaaaaaac, 0xaaaaaaacaaaaaaac,
      0xaaaaaaacaaaaaaac, 0xaaaaaaacaaaaaaac,
      0xaaaaaaacaaaaaaac, 0xaaaaaaacaaaaaaac },
    { 0xaaaaaaadaaaaaaad, 0xaaaaaaadaaaaaaad,
      0xaaaaaaadaaaaaaad, 0xaaaaaaadaaaaaaad,
      0xaaaaaaadaaaaaaad, 0xaaaaaaadaaaaaaad,
      0xaaaaaaadaaaaaaad, 0xaaaaaaadaaaaaaad },
    { 0xaaaaaaaeaaaaaaae, 0xaaaaaaaeaaaaaaae,
      0xaaaaaaaeaaaaaaae, 0xaaaaaaaeaaaaaaae,
      0xaaaaaaaeaaaaaaae, 0xaaaaaaaeaaaaaaae,
      0xaaaaaaaeaaaaaaae, 0xaaaaaaaeaaaaaaae },
    { 0xaaaaaaafaaaaaaaf, 0xaaaaaaafaaaaaaaf,
      0xaaaaaaafaaaaaaaf, 0xaaaaaaafaaaaaaaf,
      0xaaaaaaafaaaaaaaf, 0xaaaaaaafaaaaaaaf,
      0xaaaaaaafaaaaaaaf, 0xaaaaaaafaaaaaaaf }
};


void bmw256_16way_init( bmw256_16way_context *ctx )
{
   ctx->H[ 0] = m512_const1_64( 0x4041424340414243 );
   ctx->H[ 1] = m512_const1_64( 0x4445464744454647 );
   ctx->H[ 2] = m512_const1_64( 0x48494A4B48494A4B );
   ctx->H[ 3] = m512_const1_64( 0x4C4D4E4F4C4D4E4F );
   ctx->H[ 4] = m512_const1_64( 0x5051525350515253 );
   ctx->H[ 5] = m512_const1_64( 0x5455565754555657 );
   ctx->H[ 6] = m512_const1_64( 0x58595A5B58595A5B );
   ctx->H[ 7] = m512_const1_64( 0x5C5D5E5F5C5D5E5F );
   ctx->H[ 8] = m512_const1_64( 0x6061626360616263 );
   ctx->H[ 9] = m512_const1_64( 0x6465666764656667 );
   ctx->H[10] = m512_const1_64( 0x68696A6B68696A6B );
   ctx->H[11] = m512_const1_64( 0x6C6D6E6F6C6D6E6F );
   ctx->H[12] = m512_const1_64( 0x7071727370717273 );
   ctx->H[13] = m512_const1_64( 0x7475767774757677 );
   ctx->H[14] = m512_const1_64( 0x78797A7B78797A7B );
   ctx->H[15] = m512_const1_64( 0x7C7D7E7F7C7D7E7F );
   ctx->ptr       = 0;
   ctx->bit_count = 0;
}

void bmw256_16way_update( bmw256_16way_context *ctx, const void *data,
                          size_t len )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf;
   __m512i htmp[16];
   __m512i *h1, *h2;
   size_t ptr;
   const int buf_size = 64;  // bytes of one lane, compatible with len

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
      memcpy_512( buf + (ptr>>2), vdata, clen >> 2 );
      vdata = vdata + (clen>>2);
      len -= clen;
      ptr += clen;
      if ( ptr == buf_size )
      {
         __m512i *ht;
         compress_small_16way( buf, h1, h2 );
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

void bmw256_16way_close( bmw256_16way_context *ctx, void *dst )
{
   __m512i *buf;
   __m512i h1[16], h2[16], *h;
   size_t ptr, u, v;
   const int buf_size = 64;  // bytes of one lane, compatible with len

   buf = ctx->buf;
   ptr = ctx->ptr;
   buf[ ptr>>2 ] = m512_const1_64( 0x0000008000000080 );
   ptr += 4;
   h = ctx->H;

   if (  ptr > (buf_size - 4) )
   {
      memset_zero_512( buf + (ptr>>2), (buf_size - ptr) >> 2 );
      compress_small_16way( buf, h, h1 );
      ptr = 0;
      h = h1;
   }
   memset_zero_512( buf + (ptr>>2), (buf_size - 8 - ptr) >> 2 );
   buf[ (buf_size - 8) >> 2 ] = _mm512_set1_epi32( ctx->bit_count );
   buf[ (buf_size - 4) >> 2 ] = m512_zero;

   compress_small_16way( buf, h, h2 );

   for ( u = 0; u < 16; u ++ )
      buf[u] = h2[u];

   compress_small_16way( buf, final_s16, h1 );
   for (u = 0, v = 16 - 8; u < 8; u ++, v ++)
      casti_m512i(dst,u) = h1[v];
}


#endif // AVX512


#ifdef __cplusplus
}
#endif

