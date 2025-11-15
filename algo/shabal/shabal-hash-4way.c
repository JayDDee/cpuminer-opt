/* $Id: shabal.c 175 2010-05-07 16:03:20Z tp $ */
/*
 * Shabal implementation.
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
#include "shabal-hash-4way.h"

#if defined(SIMD512)

#define DECL_STATE16   \
   __m512i A0, A1, A2, A3, A4, A5, A6, A7, \
           A8, A9, AA, AB; \
   __m512i B0, B1, B2, B3, B4, B5, B6, B7, \
           B8, B9, BA, BB, BC, BD, BE, BF; \
   __m512i C0, C1, C2, C3, C4, C5, C6, C7, \
           C8, C9, CA, CB, CC, CD, CE, CF; \
   __m512i M0, M1, M2, M3, M4, M5, M6, M7, \
           M8, M9, MA, MB, MC, MD, ME, MF; \
   uint32_t Wlow, Whigh;

#define READ_STATE16(state) do \
{ \
   if ( (state)->state_loaded ) \
   { \
      A0 = (state)->A[0]; \
      A1 = (state)->A[1]; \
      A2 = (state)->A[2]; \
      A3 = (state)->A[3]; \
      A4 = (state)->A[4]; \
      A5 = (state)->A[5]; \
      A6 = (state)->A[6]; \
      A7 = (state)->A[7]; \
      A8 = (state)->A[8]; \
      A9 = (state)->A[9]; \
      AA = (state)->A[10]; \
      AB = (state)->A[11]; \
      B0 = (state)->B[0]; \
      B1 = (state)->B[1]; \
      B2 = (state)->B[2]; \
      B3 = (state)->B[3]; \
      B4 = (state)->B[4]; \
      B5 = (state)->B[5]; \
      B6 = (state)->B[6]; \
      B7 = (state)->B[7]; \
      B8 = (state)->B[8]; \
      B9 = (state)->B[9]; \
      BA = (state)->B[10]; \
      BB = (state)->B[11]; \
      BC = (state)->B[12]; \
      BD = (state)->B[13]; \
      BE = (state)->B[14]; \
      BF = (state)->B[15]; \
      C0 = (state)->C[0]; \
      C1 = (state)->C[1]; \
      C2 = (state)->C[2]; \
      C3 = (state)->C[3]; \
      C4 = (state)->C[4]; \
      C5 = (state)->C[5]; \
      C6 = (state)->C[6]; \
      C7 = (state)->C[7]; \
      C8 = (state)->C[8]; \
      C9 = (state)->C[9]; \
      CA = (state)->C[10]; \
      CB = (state)->C[11]; \
      CC = (state)->C[12]; \
      CD = (state)->C[13]; \
      CE = (state)->C[14]; \
      CF = (state)->C[15]; \
   } \
   else \
   { \
       (state)->state_loaded = true; \
       A0 = v512_64( 0x20728DFD20728DFD ); \
       A1 = v512_64( 0x46C0BD5346C0BD53 ); \
       A2 = v512_64( 0xE782B699E782B699 ); \
       A3 = v512_64( 0x5530463255304632 ); \
       A4 = v512_64( 0x71B4EF9071B4EF90 ); \
       A5 = v512_64( 0x0EA9E82C0EA9E82C ); \
       A6 = v512_64( 0xDBB930F1DBB930F1 ); \
       A7 = v512_64( 0xFAD06B8BFAD06B8B ); \
       A8 = v512_64( 0xBE0CAE40BE0CAE40 ); \
       A9 = v512_64( 0x8BD144108BD14410 ); \
       AA = v512_64( 0x76D2ADAC76D2ADAC ); \
       AB = v512_64( 0x28ACAB7F28ACAB7F ); \
       B0 = v512_64( 0xC1099CB7C1099CB7 ); \
       B1 = v512_64( 0x07B385F307B385F3 ); \
       B2 = v512_64( 0xE7442C26E7442C26 ); \
       B3 = v512_64( 0xCC8AD640CC8AD640 ); \
       B4 = v512_64( 0xEB6F56C7EB6F56C7 ); \
       B5 = v512_64( 0x1EA81AA91EA81AA9 ); \
       B6 = v512_64( 0x73B9D31473B9D314 ); \
       B7 = v512_64( 0x1DE85D081DE85D08 ); \
       B8 = v512_64( 0x48910A5A48910A5A ); \
       B9 = v512_64( 0x893B22DB893B22DB ); \
       BA = v512_64( 0xC5A0DF44C5A0DF44 ); \
       BB = v512_64( 0xBBC4324EBBC4324E ); \
       BC = v512_64( 0x72D2F24072D2F240 ); \
       BD = v512_64( 0x75941D9975941D99 ); \
       BE = v512_64( 0x6D8BDE826D8BDE82 ); \
       BF = v512_64( 0xA1A7502BA1A7502B ); \
       C0 = v512_64( 0xD9BF68D1D9BF68D1 ); \
       C1 = v512_64( 0x58BAD75058BAD750 ); \
       C2 = v512_64( 0x56028CB256028CB2 ); \
       C3 = v512_64( 0x8134F3598134F359 ); \
       C4 = v512_64( 0xB5D469D8B5D469D8 ); \
       C5 = v512_64( 0x941A8CC2941A8CC2 ); \
       C6 = v512_64( 0x418B2A6E418B2A6E ); \
       C7 = v512_64( 0x0405278004052780 ); \
       C8 = v512_64( 0x7F07D7877F07D787 ); \
       C9 = v512_64( 0x5194358F5194358F ); \
       CA = v512_64( 0x3C60D6653C60D665 ); \
       CB = v512_64( 0xBE97D79ABE97D79A ); \
       CC = v512_64( 0x950C3434950C3434 ); \
       CD = v512_64( 0xAED9A06DAED9A06D ); \
       CE = v512_64( 0x2537DC8D2537DC8D ); \
       CF = v512_64( 0x7CDB59697CDB5969 ); \
   } \
   Wlow = (state)->Wlow; \
   Whigh = (state)->Whigh; \
} while (0)

#define WRITE_STATE16(state)   do { \
      (state)->A[0] = A0; \
      (state)->A[1] = A1; \
      (state)->A[2] = A2; \
      (state)->A[3] = A3; \
      (state)->A[4] = A4; \
      (state)->A[5] = A5; \
      (state)->A[6] = A6; \
      (state)->A[7] = A7; \
      (state)->A[8] = A8; \
      (state)->A[9] = A9; \
      (state)->A[10] = AA; \
      (state)->A[11] = AB; \
      (state)->B[0] = B0; \
      (state)->B[1] = B1; \
      (state)->B[2] = B2; \
      (state)->B[3] = B3; \
      (state)->B[4] = B4; \
      (state)->B[5] = B5; \
      (state)->B[6] = B6; \
      (state)->B[7] = B7; \
      (state)->B[8] = B8; \
      (state)->B[9] = B9; \
      (state)->B[10] = BA; \
      (state)->B[11] = BB; \
      (state)->B[12] = BC; \
      (state)->B[13] = BD; \
      (state)->B[14] = BE; \
      (state)->B[15] = BF; \
      (state)->C[0] = C0; \
      (state)->C[1] = C1; \
      (state)->C[2] = C2; \
      (state)->C[3] = C3; \
      (state)->C[4] = C4; \
      (state)->C[5] = C5; \
      (state)->C[6] = C6; \
      (state)->C[7] = C7; \
      (state)->C[8] = C8; \
      (state)->C[9] = C9; \
      (state)->C[10] = CA; \
      (state)->C[11] = CB; \
      (state)->C[12] = CC; \
      (state)->C[13] = CD; \
      (state)->C[14] = CE; \
      (state)->C[15] = CF; \
      (state)->Wlow = Wlow; \
      (state)->Whigh = Whigh; \
   } while (0)

#define DECODE_BLOCK16 \
do { \
   M0 = buf[ 0]; \
   M1 = buf[ 1]; \
   M2 = buf[ 2]; \
   M3 = buf[ 3]; \
   M4 = buf[ 4]; \
   M5 = buf[ 5]; \
   M6 = buf[ 6]; \
   M7 = buf[ 7]; \
   M8 = buf[ 8]; \
   M9 = buf[ 9]; \
   MA = buf[10]; \
   MB = buf[11]; \
   MC = buf[12]; \
   MD = buf[13]; \
   ME = buf[14]; \
   MF = buf[15]; \
} while (0)

#define INPUT_BLOCK_ADD16 \
do { \
    B0 = _mm512_add_epi32( B0, M0 );\
    B1 = _mm512_add_epi32( B1, M1 );\
    B2 = _mm512_add_epi32( B2, M2 );\
    B3 = _mm512_add_epi32( B3, M3 );\
    B4 = _mm512_add_epi32( B4, M4 );\
    B5 = _mm512_add_epi32( B5, M5 );\
    B6 = _mm512_add_epi32( B6, M6 );\
    B7 = _mm512_add_epi32( B7, M7 );\
    B8 = _mm512_add_epi32( B8, M8 );\
    B9 = _mm512_add_epi32( B9, M9 );\
    BA = _mm512_add_epi32( BA, MA );\
    BB = _mm512_add_epi32( BB, MB );\
    BC = _mm512_add_epi32( BC, MC );\
    BD = _mm512_add_epi32( BD, MD );\
    BE = _mm512_add_epi32( BE, ME );\
    BF = _mm512_add_epi32( BF, MF );\
} while (0)

#define INPUT_BLOCK_SUB16 \
do { \
    C0 = _mm512_sub_epi32( C0, M0 ); \
    C1 = _mm512_sub_epi32( C1, M1 ); \
    C2 = _mm512_sub_epi32( C2, M2 ); \
    C3 = _mm512_sub_epi32( C3, M3 ); \
    C4 = _mm512_sub_epi32( C4, M4 ); \
    C5 = _mm512_sub_epi32( C5, M5 ); \
    C6 = _mm512_sub_epi32( C6, M6 ); \
    C7 = _mm512_sub_epi32( C7, M7 ); \
    C8 = _mm512_sub_epi32( C8, M8 ); \
    C9 = _mm512_sub_epi32( C9, M9 ); \
    CA = _mm512_sub_epi32( CA, MA ); \
    CB = _mm512_sub_epi32( CB, MB ); \
    CC = _mm512_sub_epi32( CC, MC ); \
    CD = _mm512_sub_epi32( CD, MD ); \
    CE = _mm512_sub_epi32( CE, ME ); \
    CF = _mm512_sub_epi32( CF, MF ); \
} while (0)

#define XOR_W16 \
do { \
   A0 = _mm512_xor_si512( A0, v512_32( Wlow ) ); \
   A1 = _mm512_xor_si512( A1, v512_32( Whigh ) ); \
} while (0)

#define mm512_swap1024_512( v1, v2 ) \
   v1 = _mm512_xor_si512( v1, v2 ); \
   v2 = _mm512_xor_si512( v1, v2 ); \
   v1 = _mm512_xor_si512( v1, v2 );

#define SWAP_BC16 \
do { \
    mm512_swap1024_512( B0, C0 ); \
    mm512_swap1024_512( B1, C1 ); \
    mm512_swap1024_512( B2, C2 ); \
    mm512_swap1024_512( B3, C3 ); \
    mm512_swap1024_512( B4, C4 ); \
    mm512_swap1024_512( B5, C5 ); \
    mm512_swap1024_512( B6, C6 ); \
    mm512_swap1024_512( B7, C7 ); \
    mm512_swap1024_512( B8, C8 ); \
    mm512_swap1024_512( B9, C9 ); \
    mm512_swap1024_512( BA, CA ); \
    mm512_swap1024_512( BB, CB ); \
    mm512_swap1024_512( BC, CC ); \
    mm512_swap1024_512( BD, CD ); \
    mm512_swap1024_512( BE, CE ); \
    mm512_swap1024_512( BF, CF ); \
} while (0)

static inline __m512i v512_mult_x3( const __m512i x )
{
   return _mm512_add_epi32( x, _mm512_slli_epi32( x, 1 ) );
}

static inline __m512i v512_mult_x5( const __m512i x )
{
   return _mm512_add_epi32( x, _mm512_slli_epi32( x, 2 ) );
}

#define PERM_ELT16( xa0, xa1, xb0, xb1, xb2, xb3, xc, xm ) \
do { \
   xa0 = mm512_xor3( xa0, xc, \
                     v512_mult_x5( mm512_rol_32( xa1, 15 ) ) ); \
   xb0 = mm512_rol_32( xb0, 1 ); \
   xa0 = mm512_xor3( xm, xb1, \
                     mm512_xorandnot( v512_mult_x3( xa0 ), xb3, xb2 ) ); \
   xb0 = mm512_nxor( xa0, xb0 ); \
} while (0)

#define PERM_STEP_0_16  do { \
      PERM_ELT16( A0, AB, B0, BD, B9, B6, C8, M0 ); \
      PERM_ELT16( A1, A0, B1, BE, BA, B7, C7, M1 ); \
      PERM_ELT16( A2, A1, B2, BF, BB, B8, C6, M2 ); \
      PERM_ELT16( A3, A2, B3, B0, BC, B9, C5, M3 ); \
      PERM_ELT16( A4, A3, B4, B1, BD, BA, C4, M4 ); \
      PERM_ELT16( A5, A4, B5, B2, BE, BB, C3, M5 ); \
      PERM_ELT16( A6, A5, B6, B3, BF, BC, C2, M6 ); \
      PERM_ELT16( A7, A6, B7, B4, B0, BD, C1, M7 ); \
      PERM_ELT16( A8, A7, B8, B5, B1, BE, C0, M8 ); \
      PERM_ELT16( A9, A8, B9, B6, B2, BF, CF, M9 ); \
      PERM_ELT16( AA, A9, BA, B7, B3, B0, CE, MA ); \
      PERM_ELT16( AB, AA, BB, B8, B4, B1, CD, MB ); \
      PERM_ELT16( A0, AB, BC, B9, B5, B2, CC, MC ); \
      PERM_ELT16( A1, A0, BD, BA, B6, B3, CB, MD ); \
      PERM_ELT16( A2, A1, BE, BB, B7, B4, CA, ME ); \
      PERM_ELT16( A3, A2, BF, BC, B8, B5, C9, MF ); \
} while (0)

#define PERM_STEP_1_16   do { \
      PERM_ELT16( A4, A3, B0, BD, B9, B6, C8, M0 ); \
      PERM_ELT16( A5, A4, B1, BE, BA, B7, C7, M1 ); \
      PERM_ELT16( A6, A5, B2, BF, BB, B8, C6, M2 ); \
      PERM_ELT16( A7, A6, B3, B0, BC, B9, C5, M3 ); \
      PERM_ELT16( A8, A7, B4, B1, BD, BA, C4, M4 ); \
      PERM_ELT16( A9, A8, B5, B2, BE, BB, C3, M5 ); \
      PERM_ELT16( AA, A9, B6, B3, BF, BC, C2, M6 ); \
      PERM_ELT16( AB, AA, B7, B4, B0, BD, C1, M7 ); \
      PERM_ELT16( A0, AB, B8, B5, B1, BE, C0, M8 ); \
      PERM_ELT16( A1, A0, B9, B6, B2, BF, CF, M9 ); \
      PERM_ELT16( A2, A1, BA, B7, B3, B0, CE, MA ); \
      PERM_ELT16( A3, A2, BB, B8, B4, B1, CD, MB ); \
      PERM_ELT16( A4, A3, BC, B9, B5, B2, CC, MC ); \
      PERM_ELT16( A5, A4, BD, BA, B6, B3, CB, MD ); \
      PERM_ELT16( A6, A5, BE, BB, B7, B4, CA, ME ); \
      PERM_ELT16( A7, A6, BF, BC, B8, B5, C9, MF ); \
} while (0)

#define PERM_STEP_2_16  do { \
      PERM_ELT16( A8, A7, B0, BD, B9, B6, C8, M0 ); \
      PERM_ELT16( A9, A8, B1, BE, BA, B7, C7, M1 ); \
      PERM_ELT16( AA, A9, B2, BF, BB, B8, C6, M2 ); \
      PERM_ELT16( AB, AA, B3, B0, BC, B9, C5, M3 ); \
      PERM_ELT16( A0, AB, B4, B1, BD, BA, C4, M4 ); \
      PERM_ELT16( A1, A0, B5, B2, BE, BB, C3, M5 ); \
      PERM_ELT16( A2, A1, B6, B3, BF, BC, C2, M6 ); \
      PERM_ELT16( A3, A2, B7, B4, B0, BD, C1, M7 ); \
      PERM_ELT16( A4, A3, B8, B5, B1, BE, C0, M8 ); \
      PERM_ELT16( A5, A4, B9, B6, B2, BF, CF, M9 ); \
      PERM_ELT16( A6, A5, BA, B7, B3, B0, CE, MA ); \
      PERM_ELT16( A7, A6, BB, B8, B4, B1, CD, MB ); \
      PERM_ELT16( A8, A7, BC, B9, B5, B2, CC, MC ); \
      PERM_ELT16( A9, A8, BD, BA, B6, B3, CB, MD ); \
      PERM_ELT16( AA, A9, BE, BB, B7, B4, CA, ME ); \
      PERM_ELT16( AB, AA, BF, BC, B8, B5, C9, MF ); \
} while (0)

#define APPLY_P16 \
do { \
    B0 = mm512_ror_32( B0, 15 ); \
    B1 = mm512_ror_32( B1, 15 ); \
    B2 = mm512_ror_32( B2, 15 ); \
    B3 = mm512_ror_32( B3, 15 ); \
    B4 = mm512_ror_32( B4, 15 ); \
    B5 = mm512_ror_32( B5, 15 ); \
    B6 = mm512_ror_32( B6, 15 ); \
    B7 = mm512_ror_32( B7, 15 ); \
    B8 = mm512_ror_32( B8, 15 ); \
    B9 = mm512_ror_32( B9, 15 ); \
    BA = mm512_ror_32( BA, 15 ); \
    BB = mm512_ror_32( BB, 15 ); \
    BC = mm512_ror_32( BC, 15 ); \
    BD = mm512_ror_32( BD, 15 ); \
    BE = mm512_ror_32( BE, 15 ); \
    BF = mm512_ror_32( BF, 15 ); \
    PERM_STEP_0_16; \
    PERM_STEP_1_16; \
    PERM_STEP_2_16; \
    AB = _mm512_add_epi32( AB, C6 ); \
    AA = _mm512_add_epi32( AA, C5 ); \
    A9 = _mm512_add_epi32( A9, C4 ); \
    A8 = _mm512_add_epi32( A8, C3 ); \
    A7 = _mm512_add_epi32( A7, C2 ); \
    A6 = _mm512_add_epi32( A6, C1 ); \
    A5 = _mm512_add_epi32( A5, C0 ); \
    A4 = _mm512_add_epi32( A4, CF ); \
    A3 = _mm512_add_epi32( A3, CE ); \
    A2 = _mm512_add_epi32( A2, CD ); \
    A1 = _mm512_add_epi32( A1, CC ); \
    A0 = _mm512_add_epi32( A0, CB ); \
    AB = _mm512_add_epi32( AB, CA ); \
    AA = _mm512_add_epi32( AA, C9 ); \
    A9 = _mm512_add_epi32( A9, C8 ); \
    A8 = _mm512_add_epi32( A8, C7 ); \
    A7 = _mm512_add_epi32( A7, C6 ); \
    A6 = _mm512_add_epi32( A6, C5 ); \
    A5 = _mm512_add_epi32( A5, C4 ); \
    A4 = _mm512_add_epi32( A4, C3 ); \
    A3 = _mm512_add_epi32( A3, C2 ); \
    A2 = _mm512_add_epi32( A2, C1 ); \
    A1 = _mm512_add_epi32( A1, C0 ); \
    A0 = _mm512_add_epi32( A0, CF ); \
    AB = _mm512_add_epi32( AB, CE ); \
    AA = _mm512_add_epi32( AA, CD ); \
    A9 = _mm512_add_epi32( A9, CC ); \
    A8 = _mm512_add_epi32( A8, CB ); \
    A7 = _mm512_add_epi32( A7, CA ); \
    A6 = _mm512_add_epi32( A6, C9 ); \
    A5 = _mm512_add_epi32( A5, C8 ); \
    A4 = _mm512_add_epi32( A4, C7 ); \
    A3 = _mm512_add_epi32( A3, C6 ); \
    A2 = _mm512_add_epi32( A2, C5 ); \
    A1 = _mm512_add_epi32( A1, C4 ); \
    A0 = _mm512_add_epi32( A0, C3 ); \
} while (0)

#define INCR_W16   do { \
      if ( ( Wlow = Wlow + 1 ) == 0 ) \
         Whigh = Whigh + 1; \
   } while (0)

static void
shabal_16x32_init( void *cc, unsigned size )
{
   shabal_16x32_context *sc = (shabal_16x32_context*)cc;

   if ( size == 512 )
   { // copy immediate constants directly to working registers later.
       sc->state_loaded = false;
   }
   else
   {
       sc->state_loaded = true;
       sc->A[ 0] = v512_64( 0x52F8455252F84552 );
       sc->A[ 1] = v512_64( 0xE54B7999E54B7999 );
       sc->A[ 2] = v512_64( 0x2D8EE3EC2D8EE3EC );
       sc->A[ 3] = v512_64( 0xB9645191B9645191 );
       sc->A[ 4] = v512_64( 0xE0078B86E0078B86 );
       sc->A[ 5] = v512_64( 0xBB7C44C9BB7C44C9 );
       sc->A[ 6] = v512_64( 0xD2B5C1CAD2B5C1CA );
       sc->A[ 7] = v512_64( 0xB0D2EB8CB0D2EB8C );
       sc->A[ 8] = v512_64( 0x14CE5A4514CE5A45 );
       sc->A[ 9] = v512_64( 0x22AF50DC22AF50DC );
       sc->A[10] = v512_64( 0xEFFDBC6BEFFDBC6B );
       sc->A[11] = v512_64( 0xEB21B74AEB21B74A );

       sc->B[ 0] = v512_64( 0xB555C6EEB555C6EE );
       sc->B[ 1] = v512_64( 0x3E7105963E710596 );
       sc->B[ 2] = v512_64( 0xA72A652FA72A652F );
       sc->B[ 3] = v512_64( 0x9301515F9301515F );
       sc->B[ 4] = v512_64( 0xDA28C1FADA28C1FA );
       sc->B[ 5] = v512_64( 0x696FD868696FD868 );
       sc->B[ 6] = v512_64( 0x9CB6BF729CB6BF72 );
       sc->B[ 7] = v512_64( 0x0AFE40020AFE4002 );
       sc->B[ 8] = v512_64( 0xA6E03615A6E03615 );
       sc->B[ 9] = v512_64( 0x5138C1D45138C1D4 );
       sc->B[10] = v512_64( 0xBE216306BE216306 );
       sc->B[11] = v512_64( 0xB38B8890B38B8890 );
       sc->B[12] = v512_64( 0x3EA8B96B3EA8B96B );
       sc->B[13] = v512_64( 0x3299ACE43299ACE4 );
       sc->B[14] = v512_64( 0x30924DD430924DD4 );
       sc->B[15] = v512_64( 0x55CB34A555CB34A5 );

       sc->C[ 0] = v512_64( 0xB405F031B405F031 );
       sc->C[ 1] = v512_64( 0xC4233EBAC4233EBA );
       sc->C[ 2] = v512_64( 0xB3733979B3733979 );
       sc->C[ 3] = v512_64( 0xC0DD9D55C0DD9D55 );
       sc->C[ 4] = v512_64( 0xC51C28AEC51C28AE );
       sc->C[ 5] = v512_64( 0xA327B8E1A327B8E1 );
       sc->C[ 6] = v512_64( 0x56C5616756C56167 );
       sc->C[ 7] = v512_64( 0xED614433ED614433 );
       sc->C[ 8] = v512_64( 0x88B59D6088B59D60 );
       sc->C[ 9] = v512_64( 0x60E2CEBA60E2CEBA );
       sc->C[10] = v512_64( 0x758B4B8B758B4B8B );
       sc->C[11] = v512_64( 0x83E82A7F83E82A7F );
       sc->C[12] = v512_64( 0xBC968828BC968828 );
       sc->C[13] = v512_64( 0xE6E00BF7E6E00BF7 );
       sc->C[14] = v512_64( 0xBA839E55BA839E55 );
       sc->C[15] = v512_64( 0x9B491C609B491C60 );
   }
    sc->Wlow = 1;
    sc->Whigh = 0;
    sc->ptr = 0;
}

static void
shabal_16x32_core( void *cc, const unsigned char *data, size_t len )
{
   shabal_16x32_context *sc = (shabal_16x32_context*)cc;
    __m512i *buf;
    __m512i *vdata = (__m512i*)data;
   const int buf_size = 64;
   size_t ptr;
   DECL_STATE16

   buf = sc->buf;
   ptr = sc->ptr;

   if ( len < (buf_size - ptr ) )
   {
      memcpy_512( buf + (ptr>>2), vdata, len>>2 );
      ptr += len;
      sc->ptr = ptr;
      return;
   }

   READ_STATE16( sc );

   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_512( buf + (ptr>>2), vdata, clen>>2 );

      ptr += clen;
      vdata += clen>>2;
      len -= clen;
      if ( ptr == buf_size )
      {
         DECODE_BLOCK16;
         INPUT_BLOCK_ADD16;
         XOR_W16;
         APPLY_P16;
         INPUT_BLOCK_SUB16;
         SWAP_BC16;
         INCR_W16;
         ptr = 0;
      }
   }
   WRITE_STATE16(sc);
   sc->ptr = ptr;
}

static void
shabal_16x32_close( void *cc, unsigned ub, unsigned n, void *dst,
                   unsigned size_words )
{
   shabal_16x32_context *sc = (shabal_16x32_context*)cc;
    __m512i *buf;
   const int buf_size = 64;
   size_t ptr;
   int i;
   unsigned z, zz;
   DECL_STATE16

   buf = sc->buf;
   ptr = sc->ptr;
   z = 0x80 >> n;
   zz = ((ub & -z) | z) & 0xFF;
   buf[ptr>>2] = v512_32( zz );
   memset_zero_512( buf + (ptr>>2) + 1, ( (buf_size - ptr) >> 2 ) - 1 );
   READ_STATE16(sc);
   DECODE_BLOCK16;
   INPUT_BLOCK_ADD16;
   XOR_W16;
   APPLY_P16;

   for ( i = 0; i < 3; i ++ )
   {
      SWAP_BC16;
      XOR_W16;
      APPLY_P16;
   }

   __m512i *d = (__m512i*)dst;
   if ( size_words == 16 )   // 512
   {
      d[ 0] = B0; d[ 1] = B1; d[ 2] = B2; d[ 3] = B3;
      d[ 4] = B4; d[ 5] = B5; d[ 6] = B6; d[ 7] = B7;
      d[ 8] = B8; d[ 9] = B9; d[10] = BA; d[11] = BB;
      d[12] = BC; d[13] = BD; d[14] = BE; d[15] = BF;
   }
   else    // 256
   {
      d[ 0] = B8; d[ 1] = B9; d[ 2] = BA; d[ 3] = BB;
      d[ 4] = BC; d[ 5] = BD; d[ 6] = BE; d[ 7] = BF;
   }
}

void
shabal256_16x32_init( void *cc )
{
   shabal_16x32_init(cc, 256);
}

void
shabal256_16x32_update( void *cc, const void *data, size_t len )
{
   shabal_16x32_core( cc, data, len );
}

void
shabal256_16x32_close( void *cc, void *dst )
{
   shabal_16x32_close(cc, 0, 0, dst, 8);
}

void
shabal512_16x32_init(void *cc)
{
   shabal_16x32_init(cc, 512);
}

void
shabal512_16x32_update(void *cc, const void *data, size_t len)
{
   shabal_16x32_core(cc, data, len);
}

void
shabal512_16x32_close(void *cc, void *dst)
{
   shabal_16x32_close(cc, 0, 0, dst, 16);
}

#endif

#if defined(__AVX2__)

#define DECL_STATE8   \
   __m256i A0, A1, A2, A3, A4, A5, A6, A7, \
           A8, A9, AA, AB; \
   __m256i B0, B1, B2, B3, B4, B5, B6, B7, \
           B8, B9, BA, BB, BC, BD, BE, BF; \
   __m256i C0, C1, C2, C3, C4, C5, C6, C7, \
           C8, C9, CA, CB, CC, CD, CE, CF; \
   __m256i M0, M1, M2, M3, M4, M5, M6, M7, \
           M8, M9, MA, MB, MC, MD, ME, MF; \
   uint32_t Wlow, Whigh;

#define READ_STATE8(state) do \
{ \
   if ( (state)->state_loaded ) \
   { \
      A0 = (state)->A[0]; \
      A1 = (state)->A[1]; \
      A2 = (state)->A[2]; \
      A3 = (state)->A[3]; \
      A4 = (state)->A[4]; \
      A5 = (state)->A[5]; \
      A6 = (state)->A[6]; \
      A7 = (state)->A[7]; \
      A8 = (state)->A[8]; \
      A9 = (state)->A[9]; \
      AA = (state)->A[10]; \
      AB = (state)->A[11]; \
      B0 = (state)->B[0]; \
      B1 = (state)->B[1]; \
      B2 = (state)->B[2]; \
      B3 = (state)->B[3]; \
      B4 = (state)->B[4]; \
      B5 = (state)->B[5]; \
      B6 = (state)->B[6]; \
      B7 = (state)->B[7]; \
      B8 = (state)->B[8]; \
      B9 = (state)->B[9]; \
      BA = (state)->B[10]; \
      BB = (state)->B[11]; \
      BC = (state)->B[12]; \
      BD = (state)->B[13]; \
      BE = (state)->B[14]; \
      BF = (state)->B[15]; \
      C0 = (state)->C[0]; \
      C1 = (state)->C[1]; \
      C2 = (state)->C[2]; \
      C3 = (state)->C[3]; \
      C4 = (state)->C[4]; \
      C5 = (state)->C[5]; \
      C6 = (state)->C[6]; \
      C7 = (state)->C[7]; \
      C8 = (state)->C[8]; \
      C9 = (state)->C[9]; \
      CA = (state)->C[10]; \
      CB = (state)->C[11]; \
      CC = (state)->C[12]; \
      CD = (state)->C[13]; \
      CE = (state)->C[14]; \
      CF = (state)->C[15]; \
   } \
   else \
   { \
       (state)->state_loaded = true; \
       A0 = v256_64( 0x20728DFD20728DFD ); \
       A1 = v256_64( 0x46C0BD5346C0BD53 ); \
       A2 = v256_64( 0xE782B699E782B699 ); \
       A3 = v256_64( 0x5530463255304632 ); \
       A4 = v256_64( 0x71B4EF9071B4EF90 ); \
       A5 = v256_64( 0x0EA9E82C0EA9E82C ); \
       A6 = v256_64( 0xDBB930F1DBB930F1 ); \
       A7 = v256_64( 0xFAD06B8BFAD06B8B ); \
       A8 = v256_64( 0xBE0CAE40BE0CAE40 ); \
       A9 = v256_64( 0x8BD144108BD14410 ); \
       AA = v256_64( 0x76D2ADAC76D2ADAC ); \
       AB = v256_64( 0x28ACAB7F28ACAB7F ); \
       B0 = v256_64( 0xC1099CB7C1099CB7 ); \
       B1 = v256_64( 0x07B385F307B385F3 ); \
       B2 = v256_64( 0xE7442C26E7442C26 ); \
       B3 = v256_64( 0xCC8AD640CC8AD640 ); \
       B4 = v256_64( 0xEB6F56C7EB6F56C7 ); \
       B5 = v256_64( 0x1EA81AA91EA81AA9 ); \
       B6 = v256_64( 0x73B9D31473B9D314 ); \
       B7 = v256_64( 0x1DE85D081DE85D08 ); \
       B8 = v256_64( 0x48910A5A48910A5A ); \
       B9 = v256_64( 0x893B22DB893B22DB ); \
       BA = v256_64( 0xC5A0DF44C5A0DF44 ); \
       BB = v256_64( 0xBBC4324EBBC4324E ); \
       BC = v256_64( 0x72D2F24072D2F240 ); \
       BD = v256_64( 0x75941D9975941D99 ); \
       BE = v256_64( 0x6D8BDE826D8BDE82 ); \
       BF = v256_64( 0xA1A7502BA1A7502B ); \
       C0 = v256_64( 0xD9BF68D1D9BF68D1 ); \
       C1 = v256_64( 0x58BAD75058BAD750 ); \
       C2 = v256_64( 0x56028CB256028CB2 ); \
       C3 = v256_64( 0x8134F3598134F359 ); \
       C4 = v256_64( 0xB5D469D8B5D469D8 ); \
       C5 = v256_64( 0x941A8CC2941A8CC2 ); \
       C6 = v256_64( 0x418B2A6E418B2A6E ); \
       C7 = v256_64( 0x0405278004052780 ); \
       C8 = v256_64( 0x7F07D7877F07D787 ); \
       C9 = v256_64( 0x5194358F5194358F ); \
       CA = v256_64( 0x3C60D6653C60D665 ); \
       CB = v256_64( 0xBE97D79ABE97D79A ); \
       CC = v256_64( 0x950C3434950C3434 ); \
       CD = v256_64( 0xAED9A06DAED9A06D ); \
       CE = v256_64( 0x2537DC8D2537DC8D ); \
       CF = v256_64( 0x7CDB59697CDB5969 ); \
   } \
   Wlow = (state)->Wlow; \
   Whigh = (state)->Whigh; \
} while (0)

#define WRITE_STATE8(state)   do { \
      (state)->A[0] = A0; \
      (state)->A[1] = A1; \
      (state)->A[2] = A2; \
      (state)->A[3] = A3; \
      (state)->A[4] = A4; \
      (state)->A[5] = A5; \
      (state)->A[6] = A6; \
      (state)->A[7] = A7; \
      (state)->A[8] = A8; \
      (state)->A[9] = A9; \
      (state)->A[10] = AA; \
      (state)->A[11] = AB; \
      (state)->B[0] = B0; \
      (state)->B[1] = B1; \
      (state)->B[2] = B2; \
      (state)->B[3] = B3; \
      (state)->B[4] = B4; \
      (state)->B[5] = B5; \
      (state)->B[6] = B6; \
      (state)->B[7] = B7; \
      (state)->B[8] = B8; \
      (state)->B[9] = B9; \
      (state)->B[10] = BA; \
      (state)->B[11] = BB; \
      (state)->B[12] = BC; \
      (state)->B[13] = BD; \
      (state)->B[14] = BE; \
      (state)->B[15] = BF; \
      (state)->C[0] = C0; \
      (state)->C[1] = C1; \
      (state)->C[2] = C2; \
      (state)->C[3] = C3; \
      (state)->C[4] = C4; \
      (state)->C[5] = C5; \
      (state)->C[6] = C6; \
      (state)->C[7] = C7; \
      (state)->C[8] = C8; \
      (state)->C[9] = C9; \
      (state)->C[10] = CA; \
      (state)->C[11] = CB; \
      (state)->C[12] = CC; \
      (state)->C[13] = CD; \
      (state)->C[14] = CE; \
      (state)->C[15] = CF; \
      (state)->Wlow = Wlow; \
      (state)->Whigh = Whigh; \
   } while (0)

#define DECODE_BLOCK8 \
do { \
   M0 = buf[ 0]; \
   M1 = buf[ 1]; \
   M2 = buf[ 2]; \
   M3 = buf[ 3]; \
   M4 = buf[ 4]; \
   M5 = buf[ 5]; \
   M6 = buf[ 6]; \
   M7 = buf[ 7]; \
   M8 = buf[ 8]; \
   M9 = buf[ 9]; \
   MA = buf[10]; \
   MB = buf[11]; \
   MC = buf[12]; \
   MD = buf[13]; \
   ME = buf[14]; \
   MF = buf[15]; \
} while (0)

#define INPUT_BLOCK_ADD8 \
do { \
    B0 = _mm256_add_epi32( B0, M0 );\
    B1 = _mm256_add_epi32( B1, M1 );\
    B2 = _mm256_add_epi32( B2, M2 );\
    B3 = _mm256_add_epi32( B3, M3 );\
    B4 = _mm256_add_epi32( B4, M4 );\
    B5 = _mm256_add_epi32( B5, M5 );\
    B6 = _mm256_add_epi32( B6, M6 );\
    B7 = _mm256_add_epi32( B7, M7 );\
    B8 = _mm256_add_epi32( B8, M8 );\
    B9 = _mm256_add_epi32( B9, M9 );\
    BA = _mm256_add_epi32( BA, MA );\
    BB = _mm256_add_epi32( BB, MB );\
    BC = _mm256_add_epi32( BC, MC );\
    BD = _mm256_add_epi32( BD, MD );\
    BE = _mm256_add_epi32( BE, ME );\
    BF = _mm256_add_epi32( BF, MF );\
} while (0)

#define INPUT_BLOCK_SUB8 \
do { \
    C0 = _mm256_sub_epi32( C0, M0 ); \
    C1 = _mm256_sub_epi32( C1, M1 ); \
    C2 = _mm256_sub_epi32( C2, M2 ); \
    C3 = _mm256_sub_epi32( C3, M3 ); \
    C4 = _mm256_sub_epi32( C4, M4 ); \
    C5 = _mm256_sub_epi32( C5, M5 ); \
    C6 = _mm256_sub_epi32( C6, M6 ); \
    C7 = _mm256_sub_epi32( C7, M7 ); \
    C8 = _mm256_sub_epi32( C8, M8 ); \
    C9 = _mm256_sub_epi32( C9, M9 ); \
    CA = _mm256_sub_epi32( CA, MA ); \
    CB = _mm256_sub_epi32( CB, MB ); \
    CC = _mm256_sub_epi32( CC, MC ); \
    CD = _mm256_sub_epi32( CD, MD ); \
    CE = _mm256_sub_epi32( CE, ME ); \
    CF = _mm256_sub_epi32( CF, MF ); \
} while (0)

#define XOR_W8 \
do { \
   A0 = _mm256_xor_si256( A0, v256_32( Wlow ) ); \
   A1 = _mm256_xor_si256( A1, v256_32( Whigh ) ); \
} while (0)

#define mm256_swap512_256( v1, v2 ) \
   v1 = _mm256_xor_si256( v1, v2 ); \
   v2 = _mm256_xor_si256( v1, v2 ); \
   v1 = _mm256_xor_si256( v1, v2 );

#define SWAP_BC8 \
do { \
    mm256_swap512_256( B0, C0 ); \
    mm256_swap512_256( B1, C1 ); \
    mm256_swap512_256( B2, C2 ); \
    mm256_swap512_256( B3, C3 ); \
    mm256_swap512_256( B4, C4 ); \
    mm256_swap512_256( B5, C5 ); \
    mm256_swap512_256( B6, C6 ); \
    mm256_swap512_256( B7, C7 ); \
    mm256_swap512_256( B8, C8 ); \
    mm256_swap512_256( B9, C9 ); \
    mm256_swap512_256( BA, CA ); \
    mm256_swap512_256( BB, CB ); \
    mm256_swap512_256( BC, CC ); \
    mm256_swap512_256( BD, CD ); \
    mm256_swap512_256( BE, CE ); \
    mm256_swap512_256( BF, CF ); \
} while (0)

static inline __m256i v256_mult_x3( const __m256i x )
{
   return _mm256_add_epi32( x, _mm256_slli_epi32( x, 1 ) );
}

static inline __m256i v256_mult_x5( const __m256i x )
{
   return _mm256_add_epi32( x, _mm256_slli_epi32( x, 2 ) );
}

#define PERM_ELT8( xa0, xa1, xb0, xb1, xb2, xb3, xc, xm ) \
do { \
   xa0 = mm256_xor3( xa0, xc, \
                     v256_mult_x5( mm256_rol_32( xa1, 15 ) ) ); \
   xb0 = mm256_rol_32( xb0, 1 ); \
   xa0 = mm256_xor3( xm, xb1, \
                     mm256_xorandnot( v256_mult_x3( xa0 ), xb3, xb2 ) ); \
   xb0 = mm256_nxor( xa0, xb0 ); \
} while (0)

#define PERM_STEP_0_8   do { \
      PERM_ELT8( A0, AB, B0, BD, B9, B6, C8, M0 ); \
      PERM_ELT8( A1, A0, B1, BE, BA, B7, C7, M1 ); \
      PERM_ELT8( A2, A1, B2, BF, BB, B8, C6, M2 ); \
      PERM_ELT8( A3, A2, B3, B0, BC, B9, C5, M3 ); \
      PERM_ELT8( A4, A3, B4, B1, BD, BA, C4, M4 ); \
      PERM_ELT8( A5, A4, B5, B2, BE, BB, C3, M5 ); \
      PERM_ELT8( A6, A5, B6, B3, BF, BC, C2, M6 ); \
      PERM_ELT8( A7, A6, B7, B4, B0, BD, C1, M7 ); \
      PERM_ELT8( A8, A7, B8, B5, B1, BE, C0, M8 ); \
      PERM_ELT8( A9, A8, B9, B6, B2, BF, CF, M9 ); \
      PERM_ELT8( AA, A9, BA, B7, B3, B0, CE, MA ); \
      PERM_ELT8( AB, AA, BB, B8, B4, B1, CD, MB ); \
      PERM_ELT8( A0, AB, BC, B9, B5, B2, CC, MC ); \
      PERM_ELT8( A1, A0, BD, BA, B6, B3, CB, MD ); \
      PERM_ELT8( A2, A1, BE, BB, B7, B4, CA, ME ); \
      PERM_ELT8( A3, A2, BF, BC, B8, B5, C9, MF ); \
} while (0)

#define PERM_STEP_1_8   do { \
      PERM_ELT8( A4, A3, B0, BD, B9, B6, C8, M0 ); \
      PERM_ELT8( A5, A4, B1, BE, BA, B7, C7, M1 ); \
      PERM_ELT8( A6, A5, B2, BF, BB, B8, C6, M2 ); \
      PERM_ELT8( A7, A6, B3, B0, BC, B9, C5, M3 ); \
      PERM_ELT8( A8, A7, B4, B1, BD, BA, C4, M4 ); \
      PERM_ELT8( A9, A8, B5, B2, BE, BB, C3, M5 ); \
      PERM_ELT8( AA, A9, B6, B3, BF, BC, C2, M6 ); \
      PERM_ELT8( AB, AA, B7, B4, B0, BD, C1, M7 ); \
      PERM_ELT8( A0, AB, B8, B5, B1, BE, C0, M8 ); \
      PERM_ELT8( A1, A0, B9, B6, B2, BF, CF, M9 ); \
      PERM_ELT8( A2, A1, BA, B7, B3, B0, CE, MA ); \
      PERM_ELT8( A3, A2, BB, B8, B4, B1, CD, MB ); \
      PERM_ELT8( A4, A3, BC, B9, B5, B2, CC, MC ); \
      PERM_ELT8( A5, A4, BD, BA, B6, B3, CB, MD ); \
      PERM_ELT8( A6, A5, BE, BB, B7, B4, CA, ME ); \
      PERM_ELT8( A7, A6, BF, BC, B8, B5, C9, MF ); \
} while (0)

#define PERM_STEP_2_8   do { \
      PERM_ELT8( A8, A7, B0, BD, B9, B6, C8, M0 ); \
      PERM_ELT8( A9, A8, B1, BE, BA, B7, C7, M1 ); \
      PERM_ELT8( AA, A9, B2, BF, BB, B8, C6, M2 ); \
      PERM_ELT8( AB, AA, B3, B0, BC, B9, C5, M3 ); \
      PERM_ELT8( A0, AB, B4, B1, BD, BA, C4, M4 ); \
      PERM_ELT8( A1, A0, B5, B2, BE, BB, C3, M5 ); \
      PERM_ELT8( A2, A1, B6, B3, BF, BC, C2, M6 ); \
      PERM_ELT8( A3, A2, B7, B4, B0, BD, C1, M7 ); \
      PERM_ELT8( A4, A3, B8, B5, B1, BE, C0, M8 ); \
      PERM_ELT8( A5, A4, B9, B6, B2, BF, CF, M9 ); \
      PERM_ELT8( A6, A5, BA, B7, B3, B0, CE, MA ); \
      PERM_ELT8( A7, A6, BB, B8, B4, B1, CD, MB ); \
      PERM_ELT8( A8, A7, BC, B9, B5, B2, CC, MC ); \
      PERM_ELT8( A9, A8, BD, BA, B6, B3, CB, MD ); \
      PERM_ELT8( AA, A9, BE, BB, B7, B4, CA, ME ); \
      PERM_ELT8( AB, AA, BF, BC, B8, B5, C9, MF ); \
} while (0)

#define APPLY_P8 \
do { \
    B0 = mm256_ror_32( B0, 15 ); \
    B1 = mm256_ror_32( B1, 15 ); \
    B2 = mm256_ror_32( B2, 15 ); \
    B3 = mm256_ror_32( B3, 15 ); \
    B4 = mm256_ror_32( B4, 15 ); \
    B5 = mm256_ror_32( B5, 15 ); \
    B6 = mm256_ror_32( B6, 15 ); \
    B7 = mm256_ror_32( B7, 15 ); \
    B8 = mm256_ror_32( B8, 15 ); \
    B9 = mm256_ror_32( B9, 15 ); \
    BA = mm256_ror_32( BA, 15 ); \
    BB = mm256_ror_32( BB, 15 ); \
    BC = mm256_ror_32( BC, 15 ); \
    BD = mm256_ror_32( BD, 15 ); \
    BE = mm256_ror_32( BE, 15 ); \
    BF = mm256_ror_32( BF, 15 ); \
    PERM_STEP_0_8; \
    PERM_STEP_1_8; \
    PERM_STEP_2_8; \
    AB = _mm256_add_epi32( AB, C6 ); \
    AA = _mm256_add_epi32( AA, C5 ); \
    A9 = _mm256_add_epi32( A9, C4 ); \
    A8 = _mm256_add_epi32( A8, C3 ); \
    A7 = _mm256_add_epi32( A7, C2 ); \
    A6 = _mm256_add_epi32( A6, C1 ); \
    A5 = _mm256_add_epi32( A5, C0 ); \
    A4 = _mm256_add_epi32( A4, CF ); \
    A3 = _mm256_add_epi32( A3, CE ); \
    A2 = _mm256_add_epi32( A2, CD ); \
    A1 = _mm256_add_epi32( A1, CC ); \
    A0 = _mm256_add_epi32( A0, CB ); \
    AB = _mm256_add_epi32( AB, CA ); \
    AA = _mm256_add_epi32( AA, C9 ); \
    A9 = _mm256_add_epi32( A9, C8 ); \
    A8 = _mm256_add_epi32( A8, C7 ); \
    A7 = _mm256_add_epi32( A7, C6 ); \
    A6 = _mm256_add_epi32( A6, C5 ); \
    A5 = _mm256_add_epi32( A5, C4 ); \
    A4 = _mm256_add_epi32( A4, C3 ); \
    A3 = _mm256_add_epi32( A3, C2 ); \
    A2 = _mm256_add_epi32( A2, C1 ); \
    A1 = _mm256_add_epi32( A1, C0 ); \
    A0 = _mm256_add_epi32( A0, CF ); \
    AB = _mm256_add_epi32( AB, CE ); \
    AA = _mm256_add_epi32( AA, CD ); \
    A9 = _mm256_add_epi32( A9, CC ); \
    A8 = _mm256_add_epi32( A8, CB ); \
    A7 = _mm256_add_epi32( A7, CA ); \
    A6 = _mm256_add_epi32( A6, C9 ); \
    A5 = _mm256_add_epi32( A5, C8 ); \
    A4 = _mm256_add_epi32( A4, C7 ); \
    A3 = _mm256_add_epi32( A3, C6 ); \
    A2 = _mm256_add_epi32( A2, C5 ); \
    A1 = _mm256_add_epi32( A1, C4 ); \
    A0 = _mm256_add_epi32( A0, C3 ); \
} while (0)

static void
shabal_8x32_init( void *cc, unsigned size )
{
   shabal_8x32_context *sc = (shabal_8x32_context*)cc;

   if ( size == 512 )
   { // copy immediate constants directly to working registers later.
       sc->state_loaded = false;
   }
   else
   {  // No users
       sc->state_loaded = true;
       sc->A[ 0] = v256_64( 0x52F8455252F84552 );
       sc->A[ 1] = v256_64( 0xE54B7999E54B7999 );
       sc->A[ 2] = v256_64( 0x2D8EE3EC2D8EE3EC );
       sc->A[ 3] = v256_64( 0xB9645191B9645191 );
       sc->A[ 4] = v256_64( 0xE0078B86E0078B86 );
       sc->A[ 5] = v256_64( 0xBB7C44C9BB7C44C9 );
       sc->A[ 6] = v256_64( 0xD2B5C1CAD2B5C1CA );
       sc->A[ 7] = v256_64( 0xB0D2EB8CB0D2EB8C );
       sc->A[ 8] = v256_64( 0x14CE5A4514CE5A45 );
       sc->A[ 9] = v256_64( 0x22AF50DC22AF50DC );
       sc->A[10] = v256_64( 0xEFFDBC6BEFFDBC6B );
       sc->A[11] = v256_64( 0xEB21B74AEB21B74A );

       sc->B[ 0] = v256_64( 0xB555C6EEB555C6EE );
       sc->B[ 1] = v256_64( 0x3E7105963E710596 );
       sc->B[ 2] = v256_64( 0xA72A652FA72A652F );
       sc->B[ 3] = v256_64( 0x9301515F9301515F );
       sc->B[ 4] = v256_64( 0xDA28C1FADA28C1FA );
       sc->B[ 5] = v256_64( 0x696FD868696FD868 );
       sc->B[ 6] = v256_64( 0x9CB6BF729CB6BF72 );
       sc->B[ 7] = v256_64( 0x0AFE40020AFE4002 );
       sc->B[ 8] = v256_64( 0xA6E03615A6E03615 );
       sc->B[ 9] = v256_64( 0x5138C1D45138C1D4 );
       sc->B[10] = v256_64( 0xBE216306BE216306 );
       sc->B[11] = v256_64( 0xB38B8890B38B8890 );
       sc->B[12] = v256_64( 0x3EA8B96B3EA8B96B );
       sc->B[13] = v256_64( 0x3299ACE43299ACE4 );
       sc->B[14] = v256_64( 0x30924DD430924DD4 );
       sc->B[15] = v256_64( 0x55CB34A555CB34A5 );

       sc->C[ 0] = v256_64( 0xB405F031B405F031 );
       sc->C[ 1] = v256_64( 0xC4233EBAC4233EBA );
       sc->C[ 2] = v256_64( 0xB3733979B3733979 );
       sc->C[ 3] = v256_64( 0xC0DD9D55C0DD9D55 );
       sc->C[ 4] = v256_64( 0xC51C28AEC51C28AE );
       sc->C[ 5] = v256_64( 0xA327B8E1A327B8E1 );
       sc->C[ 6] = v256_64( 0x56C5616756C56167 );
       sc->C[ 7] = v256_64( 0xED614433ED614433 );
       sc->C[ 8] = v256_64( 0x88B59D6088B59D60 );
       sc->C[ 9] = v256_64( 0x60E2CEBA60E2CEBA );
       sc->C[10] = v256_64( 0x758B4B8B758B4B8B );
       sc->C[11] = v256_64( 0x83E82A7F83E82A7F );
       sc->C[12] = v256_64( 0xBC968828BC968828 );
       sc->C[13] = v256_64( 0xE6E00BF7E6E00BF7 );
       sc->C[14] = v256_64( 0xBA839E55BA839E55 );
       sc->C[15] = v256_64( 0x9B491C609B491C60 );
   }
    sc->Wlow = 1;
    sc->Whigh = 0;
    sc->ptr = 0;
}

static void
shabal_8x32_core( void *cc, const unsigned char *data, size_t len )
{
   shabal_8x32_context *sc = (shabal_8x32_context*)cc;
    __m256i *buf;
    __m256i *vdata = (__m256i*)data;
   const int buf_size = 64;
   size_t ptr;
   DECL_STATE8

   buf = sc->buf;
   ptr = sc->ptr;

   if ( len < (buf_size - ptr ) )
   {
      memcpy_256( buf + (ptr>>2), vdata, len>>2 );
      ptr += len;
      sc->ptr = ptr;
      return;
   }

   READ_STATE8( sc );

   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( buf + (ptr>>2), vdata, clen>>2 );

      ptr += clen;
      vdata += clen>>2;
      len -= clen;
      if ( ptr == buf_size )
      {
         DECODE_BLOCK8;
         INPUT_BLOCK_ADD8;
         XOR_W8;
         APPLY_P8;
         INPUT_BLOCK_SUB8;
         SWAP_BC8;
         if ( ( Wlow = Wlow + 1 ) == 0 )
            Whigh = Whigh + 1; 
         ptr = 0;
      }
   }
   WRITE_STATE8(sc);
   sc->ptr = ptr;
}

static void
shabal_8x32_close( void *cc, unsigned ub, unsigned n, void *dst,
                   unsigned size_words )
{
   shabal_8x32_context *sc = (shabal_8x32_context*)cc;
    __m256i *buf;
   const int buf_size = 64;
   size_t ptr;
   int i;
   unsigned z, zz;
   DECL_STATE8

   buf = sc->buf;
   ptr = sc->ptr;
   z = 0x80 >> n;
   zz = ((ub & -z) | z) & 0xFF;
   buf[ptr>>2] = v256_32( zz );
   memset_zero_256( buf + (ptr>>2) + 1, ( (buf_size - ptr) >> 2 ) - 1 );
   READ_STATE8(sc);
   DECODE_BLOCK8;
   INPUT_BLOCK_ADD8;
   XOR_W8;
   APPLY_P8;

   for ( i = 0; i < 3; i ++ )
   {
      SWAP_BC8;
      XOR_W8;
      APPLY_P8;
   }

   __m256i *d = (__m256i*)dst;
   if ( size_words == 16 )   // 512
   {
      d[ 0] = B0; d[ 1] = B1; d[ 2] = B2; d[ 3] = B3;
      d[ 4] = B4; d[ 5] = B5; d[ 6] = B6; d[ 7] = B7;
      d[ 8] = B8; d[ 9] = B9; d[10] = BA; d[11] = BB;
      d[12] = BC; d[13] = BD; d[14] = BE; d[15] = BF;
   }
   else    // 256
   {
      d[ 0] = B8; d[ 1] = B9; d[ 2] = BA; d[ 3] = BB;
      d[ 4] = BC; d[ 5] = BD; d[ 6] = BE; d[ 7] = BF;
   }
}

void
shabal256_8x32_init( void *cc )
{
   shabal_8x32_init(cc, 256);
}

void
shabal256_8x32_update( void *cc, const void *data, size_t len )
{
   shabal_8x32_core( cc, data, len );
}

void
shabal256_8x32_close( void *cc, void *dst )
{
   shabal_8x32_close(cc, 0, 0, dst, 8);
}

void
shabal512_8x32_init(void *cc)
{
   shabal_8x32_init(cc, 512);
}

void
shabal512_8x32_update(void *cc, const void *data, size_t len)
{
   shabal_8x32_core(cc, data, len);
}

void
shabal512_8x32_close(void *cc, void *dst)
{
   shabal_8x32_close(cc, 0, 0, dst, 16);
}

#endif  // AVX2

#if defined(__SSE2__) || defined(__ARM_NEON)

#define DECL_STATE   \
	v128u32_t A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, AA, AB; \
	v128u32_t B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, BA, BB, BC, BD, BE, BF; \
	v128u32_t C0, C1, C2, C3, C4, C5, C6, C7, C8, C9, CA, CB, CC, CD, CE, CF; \
	v128u32_t M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, MA, MB, MC, MD, ME, MF; \
   uint32_t Wlow, Whigh;

#define READ_STATE( state ) \
{ \
   if ( (state)->state_loaded ) \
   { \
      A0 = (state)->A[0]; \
		A1 = (state)->A[1]; \
		A2 = (state)->A[2]; \
		A3 = (state)->A[3]; \
		A4 = (state)->A[4]; \
		A5 = (state)->A[5]; \
		A6 = (state)->A[6]; \
		A7 = (state)->A[7]; \
		A8 = (state)->A[8]; \
		A9 = (state)->A[9]; \
		AA = (state)->A[10]; \
		AB = (state)->A[11]; \
		B0 = (state)->B[0]; \
		B1 = (state)->B[1]; \
		B2 = (state)->B[2]; \
		B3 = (state)->B[3]; \
		B4 = (state)->B[4]; \
		B5 = (state)->B[5]; \
		B6 = (state)->B[6]; \
		B7 = (state)->B[7]; \
		B8 = (state)->B[8]; \
		B9 = (state)->B[9]; \
		BA = (state)->B[10]; \
		BB = (state)->B[11]; \
		BC = (state)->B[12]; \
		BD = (state)->B[13]; \
		BE = (state)->B[14]; \
		BF = (state)->B[15]; \
		C0 = (state)->C[0]; \
		C1 = (state)->C[1]; \
		C2 = (state)->C[2]; \
		C3 = (state)->C[3]; \
		C4 = (state)->C[4]; \
		C5 = (state)->C[5]; \
		C6 = (state)->C[6]; \
		C7 = (state)->C[7]; \
		C8 = (state)->C[8]; \
		C9 = (state)->C[9]; \
		CA = (state)->C[10]; \
		CB = (state)->C[11]; \
		CC = (state)->C[12]; \
		CD = (state)->C[13]; \
		CE = (state)->C[14]; \
		CF = (state)->C[15]; \
   } \
   else \
   { \
       (state)->state_loaded = true; \
       A0 = v128_64( 0x20728DFD20728DFD ); \
       A1 = v128_64( 0x46C0BD5346C0BD53 ); \
       A2 = v128_64( 0xE782B699E782B699 ); \
       A3 = v128_64( 0x5530463255304632 ); \
       A4 = v128_64( 0x71B4EF9071B4EF90 ); \
       A5 = v128_64( 0x0EA9E82C0EA9E82C ); \
       A6 = v128_64( 0xDBB930F1DBB930F1 ); \
       A7 = v128_64( 0xFAD06B8BFAD06B8B ); \
       A8 = v128_64( 0xBE0CAE40BE0CAE40 ); \
       A9 = v128_64( 0x8BD144108BD14410 ); \
       AA = v128_64( 0x76D2ADAC76D2ADAC ); \
       AB = v128_64( 0x28ACAB7F28ACAB7F ); \
       B0 = v128_64( 0xC1099CB7C1099CB7 ); \
       B1 = v128_64( 0x07B385F307B385F3 ); \
       B2 = v128_64( 0xE7442C26E7442C26 ); \
       B3 = v128_64( 0xCC8AD640CC8AD640 ); \
       B4 = v128_64( 0xEB6F56C7EB6F56C7 ); \
       B5 = v128_64( 0x1EA81AA91EA81AA9 ); \
       B6 = v128_64( 0x73B9D31473B9D314 ); \
       B7 = v128_64( 0x1DE85D081DE85D08 ); \
       B8 = v128_64( 0x48910A5A48910A5A ); \
       B9 = v128_64( 0x893B22DB893B22DB ); \
       BA = v128_64( 0xC5A0DF44C5A0DF44 ); \
       BB = v128_64( 0xBBC4324EBBC4324E ); \
       BC = v128_64( 0x72D2F24072D2F240 ); \
       BD = v128_64( 0x75941D9975941D99 ); \
       BE = v128_64( 0x6D8BDE826D8BDE82 ); \
       BF = v128_64( 0xA1A7502BA1A7502B ); \
       C0 = v128_64( 0xD9BF68D1D9BF68D1 ); \
       C1 = v128_64( 0x58BAD75058BAD750 ); \
       C2 = v128_64( 0x56028CB256028CB2 ); \
       C3 = v128_64( 0x8134F3598134F359 ); \
       C4 = v128_64( 0xB5D469D8B5D469D8 ); \
       C5 = v128_64( 0x941A8CC2941A8CC2 ); \
       C6 = v128_64( 0x418B2A6E418B2A6E ); \
       C7 = v128_64( 0x0405278004052780 ); \
       C8 = v128_64( 0x7F07D7877F07D787 ); \
       C9 = v128_64( 0x5194358F5194358F ); \
       CA = v128_64( 0x3C60D6653C60D665 ); \
       CB = v128_64( 0xBE97D79ABE97D79A ); \
       CC = v128_64( 0x950C3434950C3434 ); \
       CD = v128_64( 0xAED9A06DAED9A06D ); \
       CE = v128_64( 0x2537DC8D2537DC8D ); \
       CF = v128_64( 0x7CDB59697CDB5969 ); \
   } \
   Wlow = (state)->Wlow; \
   Whigh = (state)->Whigh; \
} 

#define WRITE_STATE(state) \
{ \
		(state)->A[0] = A0; \
		(state)->A[1] = A1; \
		(state)->A[2] = A2; \
		(state)->A[3] = A3; \
		(state)->A[4] = A4; \
		(state)->A[5] = A5; \
		(state)->A[6] = A6; \
		(state)->A[7] = A7; \
		(state)->A[8] = A8; \
		(state)->A[9] = A9; \
		(state)->A[10] = AA; \
		(state)->A[11] = AB; \
		(state)->B[0] = B0; \
		(state)->B[1] = B1; \
		(state)->B[2] = B2; \
		(state)->B[3] = B3; \
		(state)->B[4] = B4; \
		(state)->B[5] = B5; \
		(state)->B[6] = B6; \
		(state)->B[7] = B7; \
		(state)->B[8] = B8; \
		(state)->B[9] = B9; \
		(state)->B[10] = BA; \
		(state)->B[11] = BB; \
		(state)->B[12] = BC; \
		(state)->B[13] = BD; \
		(state)->B[14] = BE; \
		(state)->B[15] = BF; \
		(state)->C[0] = C0; \
		(state)->C[1] = C1; \
		(state)->C[2] = C2; \
		(state)->C[3] = C3; \
		(state)->C[4] = C4; \
		(state)->C[5] = C5; \
		(state)->C[6] = C6; \
		(state)->C[7] = C7; \
		(state)->C[8] = C8; \
		(state)->C[9] = C9; \
		(state)->C[10] = CA; \
		(state)->C[11] = CB; \
		(state)->C[12] = CC; \
		(state)->C[13] = CD; \
		(state)->C[14] = CE; \
		(state)->C[15] = CF; \
		(state)->Wlow = Wlow; \
		(state)->Whigh = Whigh; \
} 

#define DECODE_BLOCK \
{ \
   M0 = buf[ 0]; \
   M1 = buf[ 1]; \
   M2 = buf[ 2]; \
   M3 = buf[ 3]; \
   M4 = buf[ 4]; \
   M5 = buf[ 5]; \
   M6 = buf[ 6]; \
   M7 = buf[ 7]; \
   M8 = buf[ 8]; \
   M9 = buf[ 9]; \
   MA = buf[10]; \
   MB = buf[11]; \
   MC = buf[12]; \
   MD = buf[13]; \
   ME = buf[14]; \
   MF = buf[15]; \
}

#define INPUT_BLOCK_ADD \
{ \
    B0 = v128_add32( B0, M0 );\
    B1 = v128_add32( B1, M1 );\
    B2 = v128_add32( B2, M2 );\
    B3 = v128_add32( B3, M3 );\
    B4 = v128_add32( B4, M4 );\
    B5 = v128_add32( B5, M5 );\
    B6 = v128_add32( B6, M6 );\
    B7 = v128_add32( B7, M7 );\
    B8 = v128_add32( B8, M8 );\
    B9 = v128_add32( B9, M9 );\
    BA = v128_add32( BA, MA );\
    BB = v128_add32( BB, MB );\
    BC = v128_add32( BC, MC );\
    BD = v128_add32( BD, MD );\
    BE = v128_add32( BE, ME );\
    BF = v128_add32( BF, MF );\
}

#define INPUT_BLOCK_SUB \
{ \
     C0 = v128_sub32( C0, M0 ); \
    C1 = v128_sub32( C1, M1 ); \
    C2 = v128_sub32( C2, M2 ); \
    C3 = v128_sub32( C3, M3 ); \
    C4 = v128_sub32( C4, M4 ); \
    C5 = v128_sub32( C5, M5 ); \
    C6 = v128_sub32( C6, M6 ); \
    C7 = v128_sub32( C7, M7 ); \
    C8 = v128_sub32( C8, M8 ); \
    C9 = v128_sub32( C9, M9 ); \
    CA = v128_sub32( CA, MA ); \
    CB = v128_sub32( CB, MB ); \
    CC = v128_sub32( CC, MC ); \
    CD = v128_sub32( CD, MD ); \
    CE = v128_sub32( CE, ME ); \
    CF = v128_sub32( CF, MF ); \
}

#define XOR_W \
{ \
   A0 = v128_xor( A0, v128_32( Wlow ) ); \
   A1 = v128_xor( A1, v128_32( Whigh ) ); \
}

#define v128_swap256_128( v1, v2 ) \
   v1 = v128_xor( v1, v2 ); \
   v2 = v128_xor( v1, v2 ); \
   v1 = v128_xor( v1, v2 );

#define SWAP_BC \
{ \
    v128_swap256_128( B0, C0 ); \
    v128_swap256_128( B1, C1 ); \
    v128_swap256_128( B2, C2 ); \
    v128_swap256_128( B3, C3 ); \
    v128_swap256_128( B4, C4 ); \
    v128_swap256_128( B5, C5 ); \
    v128_swap256_128( B6, C6 ); \
    v128_swap256_128( B7, C7 ); \
    v128_swap256_128( B8, C8 ); \
    v128_swap256_128( B9, C9 ); \
    v128_swap256_128( BA, CA ); \
    v128_swap256_128( BB, CB ); \
    v128_swap256_128( BC, CC ); \
    v128_swap256_128( BD, CD ); \
    v128_swap256_128( BE, CE ); \
    v128_swap256_128( BF, CF ); \
}

static inline v128_t v128_mult_x3( const v128_t x )
{
   return v128_add32( x, v128_sl32( x, 1 ) );
}

static inline v128_t v128_mult_x5( const v128_t x )
{
   return v128_add32( x, v128_sl32( x, 2 ) );
}

#define PERM_ELT( xa0, xa1, xb0, xb1, xb2, xb3, xc, xm ) \
{ \
   xa0 = v128_xor3( xm, xb1, v128_xorandnot( \
                               v128_mult_x3( v128_xor3( xa0, xc, \
                                   v128_mult_x5( v128_rol32( xa1, 15 ) ) ) ), \
                               xb3, xb2 ) ); \
   xb0 = v128_not( v128_xor( xa0, v128_rol32( xb0, 1 ) ) ); \
}

#define PERM_STEP_0 \
{ \
		PERM_ELT(A0, AB, B0, BD, B9, B6, C8, M0); \
		PERM_ELT(A1, A0, B1, BE, BA, B7, C7, M1); \
		PERM_ELT(A2, A1, B2, BF, BB, B8, C6, M2); \
		PERM_ELT(A3, A2, B3, B0, BC, B9, C5, M3); \
		PERM_ELT(A4, A3, B4, B1, BD, BA, C4, M4); \
		PERM_ELT(A5, A4, B5, B2, BE, BB, C3, M5); \
		PERM_ELT(A6, A5, B6, B3, BF, BC, C2, M6); \
		PERM_ELT(A7, A6, B7, B4, B0, BD, C1, M7); \
		PERM_ELT(A8, A7, B8, B5, B1, BE, C0, M8); \
		PERM_ELT(A9, A8, B9, B6, B2, BF, CF, M9); \
		PERM_ELT(AA, A9, BA, B7, B3, B0, CE, MA); \
		PERM_ELT(AB, AA, BB, B8, B4, B1, CD, MB); \
		PERM_ELT(A0, AB, BC, B9, B5, B2, CC, MC); \
		PERM_ELT(A1, A0, BD, BA, B6, B3, CB, MD); \
		PERM_ELT(A2, A1, BE, BB, B7, B4, CA, ME); \
		PERM_ELT(A3, A2, BF, BC, B8, B5, C9, MF); \
}

#define PERM_STEP_1 \
{ \
		PERM_ELT(A4, A3, B0, BD, B9, B6, C8, M0); \
		PERM_ELT(A5, A4, B1, BE, BA, B7, C7, M1); \
		PERM_ELT(A6, A5, B2, BF, BB, B8, C6, M2); \
		PERM_ELT(A7, A6, B3, B0, BC, B9, C5, M3); \
		PERM_ELT(A8, A7, B4, B1, BD, BA, C4, M4); \
		PERM_ELT(A9, A8, B5, B2, BE, BB, C3, M5); \
		PERM_ELT(AA, A9, B6, B3, BF, BC, C2, M6); \
		PERM_ELT(AB, AA, B7, B4, B0, BD, C1, M7); \
		PERM_ELT(A0, AB, B8, B5, B1, BE, C0, M8); \
		PERM_ELT(A1, A0, B9, B6, B2, BF, CF, M9); \
		PERM_ELT(A2, A1, BA, B7, B3, B0, CE, MA); \
		PERM_ELT(A3, A2, BB, B8, B4, B1, CD, MB); \
		PERM_ELT(A4, A3, BC, B9, B5, B2, CC, MC); \
		PERM_ELT(A5, A4, BD, BA, B6, B3, CB, MD); \
		PERM_ELT(A6, A5, BE, BB, B7, B4, CA, ME); \
		PERM_ELT(A7, A6, BF, BC, B8, B5, C9, MF); \
}

#define PERM_STEP_2 \
{ \
		PERM_ELT(A8, A7, B0, BD, B9, B6, C8, M0); \
		PERM_ELT(A9, A8, B1, BE, BA, B7, C7, M1); \
		PERM_ELT(AA, A9, B2, BF, BB, B8, C6, M2); \
		PERM_ELT(AB, AA, B3, B0, BC, B9, C5, M3); \
		PERM_ELT(A0, AB, B4, B1, BD, BA, C4, M4); \
		PERM_ELT(A1, A0, B5, B2, BE, BB, C3, M5); \
		PERM_ELT(A2, A1, B6, B3, BF, BC, C2, M6); \
		PERM_ELT(A3, A2, B7, B4, B0, BD, C1, M7); \
		PERM_ELT(A4, A3, B8, B5, B1, BE, C0, M8); \
		PERM_ELT(A5, A4, B9, B6, B2, BF, CF, M9); \
		PERM_ELT(A6, A5, BA, B7, B3, B0, CE, MA); \
		PERM_ELT(A7, A6, BB, B8, B4, B1, CD, MB); \
		PERM_ELT(A8, A7, BC, B9, B5, B2, CC, MC); \
		PERM_ELT(A9, A8, BD, BA, B6, B3, CB, MD); \
		PERM_ELT(AA, A9, BE, BB, B7, B4, CA, ME); \
		PERM_ELT(AB, AA, BF, BC, B8, B5, C9, MF); \
}

#define APPLY_P \
{ \
    B0 = v128_ror32( B0, 15 ); \
    B1 = v128_ror32( B1, 15 ); \
    B2 = v128_ror32( B2, 15 ); \
    B3 = v128_ror32( B3, 15 ); \
    B4 = v128_ror32( B4, 15 ); \
    B5 = v128_ror32( B5, 15 ); \
    B6 = v128_ror32( B6, 15 ); \
    B7 = v128_ror32( B7, 15 ); \
    B8 = v128_ror32( B8, 15 ); \
    B9 = v128_ror32( B9, 15 ); \
    BA = v128_ror32( BA, 15 ); \
    BB = v128_ror32( BB, 15 ); \
    BC = v128_ror32( BC, 15 ); \
    BD = v128_ror32( BD, 15 ); \
    BE = v128_ror32( BE, 15 ); \
    BF = v128_ror32( BF, 15 ); \
    PERM_STEP_0; \
    PERM_STEP_1; \
    PERM_STEP_2; \
    AB = v128_add32( AB, C6 ); \
    AA = v128_add32( AA, C5 ); \
    A9 = v128_add32( A9, C4 ); \
    A8 = v128_add32( A8, C3 ); \
    A7 = v128_add32( A7, C2 ); \
    A6 = v128_add32( A6, C1 ); \
    A5 = v128_add32( A5, C0 ); \
    A4 = v128_add32( A4, CF ); \
    A3 = v128_add32( A3, CE ); \
    A2 = v128_add32( A2, CD ); \
    A1 = v128_add32( A1, CC ); \
    A0 = v128_add32( A0, CB ); \
    AB = v128_add32( AB, CA ); \
    AA = v128_add32( AA, C9 ); \
    A9 = v128_add32( A9, C8 ); \
    A8 = v128_add32( A8, C7 ); \
    A7 = v128_add32( A7, C6 ); \
    A6 = v128_add32( A6, C5 ); \
    A5 = v128_add32( A5, C4 ); \
    A4 = v128_add32( A4, C3 ); \
    A3 = v128_add32( A3, C2 ); \
    A2 = v128_add32( A2, C1 ); \
    A1 = v128_add32( A1, C0 ); \
    A0 = v128_add32( A0, CF ); \
    AB = v128_add32( AB, CE ); \
    AA = v128_add32( AA, CD ); \
    A9 = v128_add32( A9, CC ); \
    A8 = v128_add32( A8, CB ); \
    A7 = v128_add32( A7, CA ); \
    A6 = v128_add32( A6, C9 ); \
    A5 = v128_add32( A5, C8 ); \
    A4 = v128_add32( A4, C7 ); \
    A3 = v128_add32( A3, C6 ); \
    A2 = v128_add32( A2, C5 ); \
    A1 = v128_add32( A1, C4 ); \
    A0 = v128_add32( A0, C3 ); \
}

/*
static const sph_u32 A_init_256[] = {
	C32(0x52F84552), C32(0xE54B7999), C32(0x2D8EE3EC), C32(0xB9645191),
	C32(0xE0078B86), C32(0xBB7C44C9), C32(0xD2B5C1CA), C32(0xB0D2EB8C),
	C32(0x14CE5A45), C32(0x22AF50DC), C32(0xEFFDBC6B), C32(0xEB21B74A)
};

static const sph_u32 B_init_256[] = {
	C32(0xB555C6EE), C32(0x3E710596), C32(0xA72A652F), C32(0x9301515F),
	C32(0xDA28C1FA), C32(0x696FD868), C32(0x9CB6BF72), C32(0x0AFE4002),
	C32(0xA6E03615), C32(0x5138C1D4), C32(0xBE216306), C32(0xB38B8890),
	C32(0x3EA8B96B), C32(0x3299ACE4), C32(0x30924DD4), C32(0x55CB34A5)
};

static const sph_u32 C_init_256[] = {
	C32(0xB405F031), C32(0xC4233EBA), C32(0xB3733979), C32(0xC0DD9D55),
	C32(0xC51C28AE), C32(0xA327B8E1), C32(0x56C56167), C32(0xED614433),
	C32(0x88B59D60), C32(0x60E2CEBA), C32(0x758B4B8B), C32(0x83E82A7F),
	C32(0xBC968828), C32(0xE6E00BF7), C32(0xBA839E55), C32(0x9B491C60)
};

static const sph_u32 A_init_512[] = {
	C32(0x20728DFD), C32(0x46C0BD53), C32(0xE782B699), C32(0x55304632),
	C32(0x71B4EF90), C32(0x0EA9E82C), C32(0xDBB930F1), C32(0xFAD06B8B),
	C32(0xBE0CAE40), C32(0x8BD14410), C32(0x76D2ADAC), C32(0x28ACAB7F)
};

static const sph_u32 B_init_512[] = {
	C32(0xC1099CB7), C32(0x07B385F3), C32(0xE7442C26), C32(0xCC8AD640),
	C32(0xEB6F56C7), C32(0x1EA81AA9), C32(0x73B9D314), C32(0x1DE85D08),
	C32(0x48910A5A), C32(0x893B22DB), C32(0xC5A0DF44), C32(0xBBC4324E),
	C32(0x72D2F240), C32(0x75941D99), C32(0x6D8BDE82), C32(0xA1A7502B)
};

static const sph_u32 C_init_512[] = {
	C32(0xD9BF68D1), C32(0x58BAD750), C32(0x56028CB2), C32(0x8134F359),
	C32(0xB5D469D8), C32(0x941A8CC2), C32(0x418B2A6E), C32(0x04052780),
	C32(0x7F07D787), C32(0x5194358F), C32(0x3C60D665), C32(0xBE97D79A),
	C32(0x950C3434), C32(0xAED9A06D), C32(0x2537DC8D), C32(0x7CDB5969)
};
*/

static void
shabal_4x32_init( void *cc, unsigned size )
{
   shabal_4x32_context *sc = (shabal_4x32_context*)cc;

   if ( size == 512 )
   { // copy immediate constants directly to working registers later.
       sc->state_loaded = false;
/*
       sc->A[ 0] = v128_64( 0x20728DFD20728DFD );
       sc->A[ 1] = v128_64( 0x46C0BD5346C0BD53 );
       sc->A[ 2] = v128_64( 0xE782B699E782B699 );
       sc->A[ 3] = v128_64( 0x5530463255304632 );
       sc->A[ 4] = v128_64( 0x71B4EF9071B4EF90 );
       sc->A[ 5] = v128_64( 0x0EA9E82C0EA9E82C );
       sc->A[ 6] = v128_64( 0xDBB930F1DBB930F1 );
       sc->A[ 7] = v128_64( 0xFAD06B8BFAD06B8B );
       sc->A[ 8] = v128_64( 0xBE0CAE40BE0CAE40 );
       sc->A[ 9] = v128_64( 0x8BD144108BD14410 );
       sc->A[10] = v128_64( 0x76D2ADAC76D2ADAC );
       sc->A[11] = v128_64( 0x28ACAB7F28ACAB7F );

       sc->B[ 0] = v128_64( 0xC1099CB7C1099CB7 );
       sc->B[ 1] = v128_64( 0x07B385F307B385F3 );
       sc->B[ 2] = v128_64( 0xE7442C26E7442C26 );
       sc->B[ 3] = v128_64( 0xCC8AD640CC8AD640 );
       sc->B[ 4] = v128_64( 0xEB6F56C7EB6F56C7 );
       sc->B[ 5] = v128_64( 0x1EA81AA91EA81AA9 );
       sc->B[ 6] = v128_64( 0x73B9D31473B9D314 );
       sc->B[ 7] = v128_64( 0x1DE85D081DE85D08 );
       sc->B[ 8] = v128_64( 0x48910A5A48910A5A );
       sc->B[ 9] = v128_64( 0x893B22DB893B22DB );
       sc->B[10] = v128_64( 0xC5A0DF44C5A0DF44 );
       sc->B[11] = v128_64( 0xBBC4324EBBC4324E );
       sc->B[12] = v128_64( 0x72D2F24072D2F240 );
       sc->B[13] = v128_64( 0x75941D9975941D99 );
       sc->B[14] = v128_64( 0x6D8BDE826D8BDE82 );
       sc->B[15] = v128_64( 0xA1A7502BA1A7502B );

       sc->C[ 0] = v128_64( 0xD9BF68D1D9BF68D1 );
       sc->C[ 1] = v128_64( 0x58BAD75058BAD750 );
       sc->C[ 2] = v128_64( 0x56028CB256028CB2 );
       sc->C[ 3] = v128_64( 0x8134F3598134F359 );
       sc->C[ 4] = v128_64( 0xB5D469D8B5D469D8 );
       sc->C[ 5] = v128_64( 0x941A8CC2941A8CC2 );
       sc->C[ 6] = v128_64( 0x418B2A6E418B2A6E );
       sc->C[ 7] = v128_64( 0x0405278004052780 );
       sc->C[ 8] = v128_64( 0x7F07D7877F07D787 );
       sc->C[ 9] = v128_64( 0x5194358F5194358F );
       sc->C[10] = v128_64( 0x3C60D6653C60D665 );
       sc->C[11] = v128_64( 0xBE97D79ABE97D79A );
       sc->C[12] = v128_64( 0x950C3434950C3434 );
       sc->C[13] = v128_64( 0xAED9A06DAED9A06D );
       sc->C[14] = v128_64( 0x2537DC8D2537DC8D );
       sc->C[15] = v128_64( 0x7CDB59697CDB5969 );
*/
   }
   else
   {  // No users
       sc->state_loaded = true;
       sc->A[ 0] = v128_64( 0x52F8455252F84552 );
       sc->A[ 1] = v128_64( 0xE54B7999E54B7999 );
       sc->A[ 2] = v128_64( 0x2D8EE3EC2D8EE3EC );
       sc->A[ 3] = v128_64( 0xB9645191B9645191 );
       sc->A[ 4] = v128_64( 0xE0078B86E0078B86 );
       sc->A[ 5] = v128_64( 0xBB7C44C9BB7C44C9 );
       sc->A[ 6] = v128_64( 0xD2B5C1CAD2B5C1CA );
       sc->A[ 7] = v128_64( 0xB0D2EB8CB0D2EB8C );
       sc->A[ 8] = v128_64( 0x14CE5A4514CE5A45 );
       sc->A[ 9] = v128_64( 0x22AF50DC22AF50DC );
       sc->A[10] = v128_64( 0xEFFDBC6BEFFDBC6B );
       sc->A[11] = v128_64( 0xEB21B74AEB21B74A );

       sc->B[ 0] = v128_64( 0xB555C6EEB555C6EE );
       sc->B[ 1] = v128_64( 0x3E7105963E710596 );
       sc->B[ 2] = v128_64( 0xA72A652FA72A652F );
       sc->B[ 3] = v128_64( 0x9301515F9301515F );
       sc->B[ 4] = v128_64( 0xDA28C1FADA28C1FA );
       sc->B[ 5] = v128_64( 0x696FD868696FD868 );
       sc->B[ 6] = v128_64( 0x9CB6BF729CB6BF72 );
       sc->B[ 7] = v128_64( 0x0AFE40020AFE4002 );
       sc->B[ 8] = v128_64( 0xA6E03615A6E03615 );
       sc->B[ 9] = v128_64( 0x5138C1D45138C1D4 );
       sc->B[10] = v128_64( 0xBE216306BE216306 );
       sc->B[11] = v128_64( 0xB38B8890B38B8890 );
       sc->B[12] = v128_64( 0x3EA8B96B3EA8B96B );
       sc->B[13] = v128_64( 0x3299ACE43299ACE4 );
       sc->B[14] = v128_64( 0x30924DD430924DD4 );
       sc->B[15] = v128_64( 0x55CB34A555CB34A5 );

       sc->C[ 0] = v128_64( 0xB405F031B405F031 );
       sc->C[ 1] = v128_64( 0xC4233EBAC4233EBA );
       sc->C[ 2] = v128_64( 0xB3733979B3733979 );
       sc->C[ 3] = v128_64( 0xC0DD9D55C0DD9D55 );
       sc->C[ 4] = v128_64( 0xC51C28AEC51C28AE );
       sc->C[ 5] = v128_64( 0xA327B8E1A327B8E1 );
       sc->C[ 6] = v128_64( 0x56C5616756C56167 );
       sc->C[ 7] = v128_64( 0xED614433ED614433 );
       sc->C[ 8] = v128_64( 0x88B59D6088B59D60 );
       sc->C[ 9] = v128_64( 0x60E2CEBA60E2CEBA );
       sc->C[10] = v128_64( 0x758B4B8B758B4B8B );
       sc->C[11] = v128_64( 0x83E82A7F83E82A7F );
       sc->C[12] = v128_64( 0xBC968828BC968828 );
       sc->C[13] = v128_64( 0xE6E00BF7E6E00BF7 );
       sc->C[14] = v128_64( 0xBA839E55BA839E55 );
       sc->C[15] = v128_64( 0x9B491C609B491C60 );
   }
    sc->Wlow = 1;
    sc->Whigh = 0;
    sc->ptr = 0;
}

static void
shabal_4x32_core( void *cc, const unsigned char *data, size_t len )
{
   shabal_4x32_context *sc = (shabal_4x32_context*)cc;
    v128_t *buf;
    v128_t *vdata = (v128_t*)data;
   const int buf_size = 64;  
   size_t ptr;
   DECL_STATE

   buf = sc->buf;
   ptr = sc->ptr;

   if ( len < (buf_size - ptr ) )
   {
      v128_memcpy( buf + (ptr>>2), vdata, len>>2 );
      ptr += len;
      sc->ptr = ptr;
      return;
   }
   

   READ_STATE(sc);

   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      v128_memcpy( buf + (ptr>>2), vdata, clen>>2 );

      ptr += clen;
      vdata += clen>>2;
      len -= clen;
      if ( ptr == buf_size )
      {
         DECODE_BLOCK;
         INPUT_BLOCK_ADD;
         XOR_W;
         APPLY_P;
         INPUT_BLOCK_SUB;
         SWAP_BC;
         if ( ( Wlow = Wlow + 1 ) == 0 )
            Whigh = Whigh + 1;
         ptr = 0;
      }
   }
   WRITE_STATE(sc);
   sc->ptr = ptr;
}

static void
shabal_4x32_close( void *cc, unsigned ub, unsigned n, void *dst,
                   unsigned size_words )
{
   shabal_4x32_context *sc = (shabal_4x32_context*)cc;
    v128_t *buf;
   const int buf_size = 64;
   size_t ptr;
   int i;
   unsigned z, zz;
   DECL_STATE

   buf = sc->buf;
   ptr = sc->ptr;
   z = 0x80 >> n;
   zz = ((ub & -z) | z) & 0xFF;
   buf[ptr>>2] = v128_32( zz );
   v128_memset_zero( buf + (ptr>>2) + 1, ( (buf_size - ptr) >> 2 ) - 1 );
   READ_STATE(sc);
   DECODE_BLOCK;
   INPUT_BLOCK_ADD;
   XOR_W;
   APPLY_P;

   for ( i = 0; i < 3; i ++ )
   {
      SWAP_BC;
      XOR_W;
      APPLY_P;
   }

   v128_t *d = (v128_t*)dst;
   if ( size_words == 16 )   // 512
   {
      d[ 0] = B0; d[ 1] = B1; d[ 2] = B2; d[ 3] = B3;
      d[ 4] = B4; d[ 5] = B5; d[ 6] = B6; d[ 7] = B7;
      d[ 8] = B8; d[ 9] = B9; d[10] = BA; d[11] = BB;
      d[12] = BC; d[13] = BD; d[14] = BE; d[15] = BF;
   }
   else    // 256
   {
      d[ 0] = B8; d[ 1] = B9; d[ 2] = BA; d[ 3] = BB;
      d[ 4] = BC; d[ 5] = BD; d[ 6] = BE; d[ 7] = BF;
   }
}

void
shabal256_4x32_init( void *cc )
{
	shabal_4x32_init(cc, 256);
}

void
shabal256_4x32_update( void *cc, const void *data, size_t len )
{
	shabal_4x32_core( cc, data, len );
}

void
shabal256_4x32_close( void *cc, void *dst )
{
	shabal_4x32_close(cc, 0, 0, dst, 8);
}

void
shabal512_4x32_init(void *cc)
{
	shabal_4x32_init(cc, 512);
}

void
shabal512_4x32_update(void *cc, const void *data, size_t len)
{
	shabal_4x32_core(cc, data, len);
}

void
shabal512_4x32_close(void *cc, void *dst)
{
	shabal_4x32_close(cc, 0, 0, dst, 16);
}

#endif


