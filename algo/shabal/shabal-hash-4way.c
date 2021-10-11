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

#ifdef __SSE4_1__

#include "shabal-hash-4way.h"
#ifdef __cplusplus
extern "C"{
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

/*
 * Part of this code was automatically generated (the part between
 * the "BEGIN" and "END" markers).
 */

#define sM    16

#define C32   SPH_C32
#define T32   SPH_T32

#define O1   13
#define O2    9
#define O3    6


#if defined(__AVX2__)

#define DECL_STATE8   \
   __m256i A00, A01, A02, A03, A04, A05, A06, A07, \
           A08, A09, A0A, A0B; \
   __m256i B0, B1, B2, B3, B4, B5, B6, B7, \
           B8, B9, BA, BB, BC, BD, BE, BF; \
   __m256i C0, C1, C2, C3, C4, C5, C6, C7, \
           C8, C9, CA, CB, CC, CD, CE, CF; \
   __m256i M0, M1, M2, M3, M4, M5, M6, M7, \
           M8, M9, MA, MB, MC, MD, ME, MF; \
   const __m256i FIVE  = _mm256_set1_epi32( 5 ); \
   const __m256i THREE = _mm256_set1_epi32( 3 ); \
   sph_u32 Wlow, Whigh;

#define READ_STATE8(state) do \
{ \
   if ( (state)->state_loaded ) \
   { \
      A00 = (state)->A[0]; \
      A01 = (state)->A[1]; \
      A02 = (state)->A[2]; \
      A03 = (state)->A[3]; \
      A04 = (state)->A[4]; \
      A05 = (state)->A[5]; \
      A06 = (state)->A[6]; \
      A07 = (state)->A[7]; \
      A08 = (state)->A[8]; \
      A09 = (state)->A[9]; \
      A0A = (state)->A[10]; \
      A0B = (state)->A[11]; \
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
       A00 = m256_const1_64( 0x20728DFD20728DFD ); \
       A01 = m256_const1_64( 0x46C0BD5346C0BD53 ); \
       A02 = m256_const1_64( 0xE782B699E782B699 ); \
       A03 = m256_const1_64( 0x5530463255304632 ); \
       A04 = m256_const1_64( 0x71B4EF9071B4EF90 ); \
       A05 = m256_const1_64( 0x0EA9E82C0EA9E82C ); \
       A06 = m256_const1_64( 0xDBB930F1DBB930F1 ); \
       A07 = m256_const1_64( 0xFAD06B8BFAD06B8B ); \
       A08 = m256_const1_64( 0xBE0CAE40BE0CAE40 ); \
       A09 = m256_const1_64( 0x8BD144108BD14410 ); \
       A0A = m256_const1_64( 0x76D2ADAC76D2ADAC ); \
       A0B = m256_const1_64( 0x28ACAB7F28ACAB7F ); \
       B0 = m256_const1_64( 0xC1099CB7C1099CB7 ); \
       B1 = m256_const1_64( 0x07B385F307B385F3 ); \
       B2 = m256_const1_64( 0xE7442C26E7442C26 ); \
       B3 = m256_const1_64( 0xCC8AD640CC8AD640 ); \
       B4 = m256_const1_64( 0xEB6F56C7EB6F56C7 ); \
       B5 = m256_const1_64( 0x1EA81AA91EA81AA9 ); \
       B6 = m256_const1_64( 0x73B9D31473B9D314 ); \
       B7 = m256_const1_64( 0x1DE85D081DE85D08 ); \
       B8 = m256_const1_64( 0x48910A5A48910A5A ); \
       B9 = m256_const1_64( 0x893B22DB893B22DB ); \
       BA = m256_const1_64( 0xC5A0DF44C5A0DF44 ); \
       BB = m256_const1_64( 0xBBC4324EBBC4324E ); \
       BC = m256_const1_64( 0x72D2F24072D2F240 ); \
       BD = m256_const1_64( 0x75941D9975941D99 ); \
       BE = m256_const1_64( 0x6D8BDE826D8BDE82 ); \
       BF = m256_const1_64( 0xA1A7502BA1A7502B ); \
       C0 = m256_const1_64( 0xD9BF68D1D9BF68D1 ); \
       C1 = m256_const1_64( 0x58BAD75058BAD750 ); \
       C2 = m256_const1_64( 0x56028CB256028CB2 ); \
       C3 = m256_const1_64( 0x8134F3598134F359 ); \
       C4 = m256_const1_64( 0xB5D469D8B5D469D8 ); \
       C5 = m256_const1_64( 0x941A8CC2941A8CC2 ); \
       C6 = m256_const1_64( 0x418B2A6E418B2A6E ); \
       C7 = m256_const1_64( 0x0405278004052780 ); \
       C8 = m256_const1_64( 0x7F07D7877F07D787 ); \
       C9 = m256_const1_64( 0x5194358F5194358F ); \
       CA = m256_const1_64( 0x3C60D6653C60D665 ); \
       CB = m256_const1_64( 0xBE97D79ABE97D79A ); \
       CC = m256_const1_64( 0x950C3434950C3434 ); \
       CD = m256_const1_64( 0xAED9A06DAED9A06D ); \
       CE = m256_const1_64( 0x2537DC8D2537DC8D ); \
       CF = m256_const1_64( 0x7CDB59697CDB5969 ); \
   } \
   Wlow = (state)->Wlow; \
   Whigh = (state)->Whigh; \
} while (0)

#define WRITE_STATE8(state)   do { \
      (state)->A[0] = A00; \
      (state)->A[1] = A01; \
      (state)->A[2] = A02; \
      (state)->A[3] = A03; \
      (state)->A[4] = A04; \
      (state)->A[5] = A05; \
      (state)->A[6] = A06; \
      (state)->A[7] = A07; \
      (state)->A[8] = A08; \
      (state)->A[9] = A09; \
      (state)->A[10] = A0A; \
      (state)->A[11] = A0B; \
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
   A00 = _mm256_xor_si256( A00, _mm256_set1_epi32( Wlow ) ); \
   A01 = _mm256_xor_si256( A01, _mm256_set1_epi32( Whigh ) ); \
} while (0)

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

#define PERM_ELT8(xa0, xa1, xb0, xb1, xb2, xb3, xc, xm) \
do { \
   xa0 = mm256_xor3( xm, xb1, _mm256_xor_si256(  \
            _mm256_andnot_si256( xb3, xb2 ), \
            _mm256_mullo_epi32( mm256_xor3( xa0, xc, \
               _mm256_mullo_epi32( mm256_rol_32( xa1, 15 ), \
                                   FIVE ) ), THREE ) ) ); \
   xb0 = mm256_xnor( xa0, mm256_rol_32( xb0, 1 ) ); \
} while (0)

#define PERM_STEP_0_8   do { \
      PERM_ELT8(A00, A0B, B0, BD, B9, B6, C8, M0); \
      PERM_ELT8(A01, A00, B1, BE, BA, B7, C7, M1); \
      PERM_ELT8(A02, A01, B2, BF, BB, B8, C6, M2); \
      PERM_ELT8(A03, A02, B3, B0, BC, B9, C5, M3); \
      PERM_ELT8(A04, A03, B4, B1, BD, BA, C4, M4); \
      PERM_ELT8(A05, A04, B5, B2, BE, BB, C3, M5); \
      PERM_ELT8(A06, A05, B6, B3, BF, BC, C2, M6); \
      PERM_ELT8(A07, A06, B7, B4, B0, BD, C1, M7); \
      PERM_ELT8(A08, A07, B8, B5, B1, BE, C0, M8); \
      PERM_ELT8(A09, A08, B9, B6, B2, BF, CF, M9); \
      PERM_ELT8(A0A, A09, BA, B7, B3, B0, CE, MA); \
      PERM_ELT8(A0B, A0A, BB, B8, B4, B1, CD, MB); \
      PERM_ELT8(A00, A0B, BC, B9, B5, B2, CC, MC); \
      PERM_ELT8(A01, A00, BD, BA, B6, B3, CB, MD); \
      PERM_ELT8(A02, A01, BE, BB, B7, B4, CA, ME); \
      PERM_ELT8(A03, A02, BF, BC, B8, B5, C9, MF); \
   } while (0)

#define PERM_STEP_1_8   do { \
      PERM_ELT8(A04, A03, B0, BD, B9, B6, C8, M0); \
      PERM_ELT8(A05, A04, B1, BE, BA, B7, C7, M1); \
      PERM_ELT8(A06, A05, B2, BF, BB, B8, C6, M2); \
      PERM_ELT8(A07, A06, B3, B0, BC, B9, C5, M3); \
      PERM_ELT8(A08, A07, B4, B1, BD, BA, C4, M4); \
      PERM_ELT8(A09, A08, B5, B2, BE, BB, C3, M5); \
      PERM_ELT8(A0A, A09, B6, B3, BF, BC, C2, M6); \
      PERM_ELT8(A0B, A0A, B7, B4, B0, BD, C1, M7); \
      PERM_ELT8(A00, A0B, B8, B5, B1, BE, C0, M8); \
      PERM_ELT8(A01, A00, B9, B6, B2, BF, CF, M9); \
      PERM_ELT8(A02, A01, BA, B7, B3, B0, CE, MA); \
      PERM_ELT8(A03, A02, BB, B8, B4, B1, CD, MB); \
      PERM_ELT8(A04, A03, BC, B9, B5, B2, CC, MC); \
      PERM_ELT8(A05, A04, BD, BA, B6, B3, CB, MD); \
      PERM_ELT8(A06, A05, BE, BB, B7, B4, CA, ME); \
      PERM_ELT8(A07, A06, BF, BC, B8, B5, C9, MF); \
   } while (0)

#define PERM_STEP_2_8   do { \
      PERM_ELT8(A08, A07, B0, BD, B9, B6, C8, M0); \
      PERM_ELT8(A09, A08, B1, BE, BA, B7, C7, M1); \
      PERM_ELT8(A0A, A09, B2, BF, BB, B8, C6, M2); \
      PERM_ELT8(A0B, A0A, B3, B0, BC, B9, C5, M3); \
      PERM_ELT8(A00, A0B, B4, B1, BD, BA, C4, M4); \
      PERM_ELT8(A01, A00, B5, B2, BE, BB, C3, M5); \
      PERM_ELT8(A02, A01, B6, B3, BF, BC, C2, M6); \
      PERM_ELT8(A03, A02, B7, B4, B0, BD, C1, M7); \
      PERM_ELT8(A04, A03, B8, B5, B1, BE, C0, M8); \
      PERM_ELT8(A05, A04, B9, B6, B2, BF, CF, M9); \
      PERM_ELT8(A06, A05, BA, B7, B3, B0, CE, MA); \
      PERM_ELT8(A07, A06, BB, B8, B4, B1, CD, MB); \
      PERM_ELT8(A08, A07, BC, B9, B5, B2, CC, MC); \
      PERM_ELT8(A09, A08, BD, BA, B6, B3, CB, MD); \
      PERM_ELT8(A0A, A09, BE, BB, B7, B4, CA, ME); \
      PERM_ELT8(A0B, A0A, BF, BC, B8, B5, C9, MF); \
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
    A0B = _mm256_add_epi32( A0B, C6 ); \
    A0A = _mm256_add_epi32( A0A, C5 ); \
    A09 = _mm256_add_epi32( A09, C4 ); \
    A08 = _mm256_add_epi32( A08, C3 ); \
    A07 = _mm256_add_epi32( A07, C2 ); \
    A06 = _mm256_add_epi32( A06, C1 ); \
    A05 = _mm256_add_epi32( A05, C0 ); \
    A04 = _mm256_add_epi32( A04, CF ); \
    A03 = _mm256_add_epi32( A03, CE ); \
    A02 = _mm256_add_epi32( A02, CD ); \
    A01 = _mm256_add_epi32( A01, CC ); \
    A00 = _mm256_add_epi32( A00, CB ); \
    A0B = _mm256_add_epi32( A0B, CA ); \
    A0A = _mm256_add_epi32( A0A, C9 ); \
    A09 = _mm256_add_epi32( A09, C8 ); \
    A08 = _mm256_add_epi32( A08, C7 ); \
    A07 = _mm256_add_epi32( A07, C6 ); \
    A06 = _mm256_add_epi32( A06, C5 ); \
    A05 = _mm256_add_epi32( A05, C4 ); \
    A04 = _mm256_add_epi32( A04, C3 ); \
    A03 = _mm256_add_epi32( A03, C2 ); \
    A02 = _mm256_add_epi32( A02, C1 ); \
    A01 = _mm256_add_epi32( A01, C0 ); \
    A00 = _mm256_add_epi32( A00, CF ); \
    A0B = _mm256_add_epi32( A0B, CE ); \
    A0A = _mm256_add_epi32( A0A, CD ); \
    A09 = _mm256_add_epi32( A09, CC ); \
    A08 = _mm256_add_epi32( A08, CB ); \
    A07 = _mm256_add_epi32( A07, CA ); \
    A06 = _mm256_add_epi32( A06, C9 ); \
    A05 = _mm256_add_epi32( A05, C8 ); \
    A04 = _mm256_add_epi32( A04, C7 ); \
    A03 = _mm256_add_epi32( A03, C6 ); \
    A02 = _mm256_add_epi32( A02, C5 ); \
    A01 = _mm256_add_epi32( A01, C4 ); \
    A00 = _mm256_add_epi32( A00, C3 ); \
} while (0)

#define INCR_W8   do { \
      if ((Wlow = T32(Wlow + 1)) == 0) \
         Whigh = T32(Whigh + 1); \
   } while (0)

static void
shabal_8way_init( void *cc, unsigned size )
{
   shabal_8way_context *sc = (shabal_8way_context*)cc;

   if ( size == 512 )
   { // copy immediate constants directly to working registers later.
       sc->state_loaded = false;
   }
   else
   {  // No users
       sc->state_loaded = true;
       sc->A[ 0] = m256_const1_64( 0x52F8455252F84552 );
       sc->A[ 1] = m256_const1_64( 0xE54B7999E54B7999 );
       sc->A[ 2] = m256_const1_64( 0x2D8EE3EC2D8EE3EC );
       sc->A[ 3] = m256_const1_64( 0xB9645191B9645191 );
       sc->A[ 4] = m256_const1_64( 0xE0078B86E0078B86 );
       sc->A[ 5] = m256_const1_64( 0xBB7C44C9BB7C44C9 );
       sc->A[ 6] = m256_const1_64( 0xD2B5C1CAD2B5C1CA );
       sc->A[ 7] = m256_const1_64( 0xB0D2EB8CB0D2EB8C );
       sc->A[ 8] = m256_const1_64( 0x14CE5A4514CE5A45 );
       sc->A[ 9] = m256_const1_64( 0x22AF50DC22AF50DC );
       sc->A[10] = m256_const1_64( 0xEFFDBC6BEFFDBC6B );
       sc->A[11] = m256_const1_64( 0xEB21B74AEB21B74A );

       sc->B[ 0] = m256_const1_64( 0xB555C6EEB555C6EE );
       sc->B[ 1] = m256_const1_64( 0x3E7105963E710596 );
       sc->B[ 2] = m256_const1_64( 0xA72A652FA72A652F );
       sc->B[ 3] = m256_const1_64( 0x9301515F9301515F );
       sc->B[ 4] = m256_const1_64( 0xDA28C1FADA28C1FA );
       sc->B[ 5] = m256_const1_64( 0x696FD868696FD868 );
       sc->B[ 6] = m256_const1_64( 0x9CB6BF729CB6BF72 );
       sc->B[ 7] = m256_const1_64( 0x0AFE40020AFE4002 );
       sc->B[ 8] = m256_const1_64( 0xA6E03615A6E03615 );
       sc->B[ 9] = m256_const1_64( 0x5138C1D45138C1D4 );
       sc->B[10] = m256_const1_64( 0xBE216306BE216306 );
       sc->B[11] = m256_const1_64( 0xB38B8890B38B8890 );
       sc->B[12] = m256_const1_64( 0x3EA8B96B3EA8B96B );
       sc->B[13] = m256_const1_64( 0x3299ACE43299ACE4 );
       sc->B[14] = m256_const1_64( 0x30924DD430924DD4 );
       sc->B[15] = m256_const1_64( 0x55CB34A555CB34A5 );

       sc->C[ 0] = m256_const1_64( 0xB405F031B405F031 );
       sc->C[ 1] = m256_const1_64( 0xC4233EBAC4233EBA );
       sc->C[ 2] = m256_const1_64( 0xB3733979B3733979 );
       sc->C[ 3] = m256_const1_64( 0xC0DD9D55C0DD9D55 );
       sc->C[ 4] = m256_const1_64( 0xC51C28AEC51C28AE );
       sc->C[ 5] = m256_const1_64( 0xA327B8E1A327B8E1 );
       sc->C[ 6] = m256_const1_64( 0x56C5616756C56167 );
       sc->C[ 7] = m256_const1_64( 0xED614433ED614433 );
       sc->C[ 8] = m256_const1_64( 0x88B59D6088B59D60 );
       sc->C[ 9] = m256_const1_64( 0x60E2CEBA60E2CEBA );
       sc->C[10] = m256_const1_64( 0x758B4B8B758B4B8B );
       sc->C[11] = m256_const1_64( 0x83E82A7F83E82A7F );
       sc->C[12] = m256_const1_64( 0xBC968828BC968828 );
       sc->C[13] = m256_const1_64( 0xE6E00BF7E6E00BF7 );
       sc->C[14] = m256_const1_64( 0xBA839E55BA839E55 );
       sc->C[15] = m256_const1_64( 0x9B491C609B491C60 );
   }
    sc->Wlow = 1;
    sc->Whigh = 0;
    sc->ptr = 0;
}

static void
shabal_8way_core( void *cc, const unsigned char *data, size_t len )
{
   shabal_8way_context *sc = (shabal_8way_context*)cc;
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
         INCR_W8;
         ptr = 0;
      }
   }
   WRITE_STATE8(sc);
   sc->ptr = ptr;
}

static void
shabal_8way_close( void *cc, unsigned ub, unsigned n, void *dst,
                   unsigned size_words )
{
   shabal_8way_context *sc = (shabal_8way_context*)cc;
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
   buf[ptr>>2] = _mm256_set1_epi32( zz );
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
shabal256_8way_init( void *cc )
{
   shabal_8way_init(cc, 256);
}

void
shabal256_8way_update( void *cc, const void *data, size_t len )
{
   shabal_8way_core( cc, data, len );
}

void
shabal256_8way_close( void *cc, void *dst )
{
   shabal_8way_close(cc, 0, 0, dst, 8);
}

void
shabal256_8way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                  void *dst )
{
   shabal_8way_close(cc, ub, n, dst, 8);
}

void
shabal512_8way_init(void *cc)
{
   shabal_8way_init(cc, 512);
}

void
shabal512_8way_update(void *cc, const void *data, size_t len)
{
   shabal_8way_core(cc, data, len);
}

void
shabal512_8way_close(void *cc, void *dst)
{
   shabal_8way_close(cc, 0, 0, dst, 16);
}

void
shabal512_8way_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
   shabal_8way_close(cc, ub, n, dst, 16);
}


#endif  // AVX2

/*
 * We copy the state into local variables, so that the compiler knows
 * that it can optimize them at will.
 */


#define DECL_STATE   \
	__m128i A00, A01, A02, A03, A04, A05, A06, A07, \
	        A08, A09, A0A, A0B; \
	__m128i B0, B1, B2, B3, B4, B5, B6, B7, \
	        B8, B9, BA, BB, BC, BD, BE, BF; \
	__m128i C0, C1, C2, C3, C4, C5, C6, C7, \
	        C8, C9, CA, CB, CC, CD, CE, CF; \
	__m128i M0, M1, M2, M3, M4, M5, M6, M7, \
	        M8, M9, MA, MB, MC, MD, ME, MF; \
   const __m128i FIVE  = _mm_set1_epi32( 5 ); \
   const __m128i THREE = _mm_set1_epi32( 3 ); \
   sph_u32 Wlow, Whigh;

#define READ_STATE(state) do \
{ \
   if ( (state)->state_loaded ) \
   { \
      A00 = (state)->A[0]; \
		A01 = (state)->A[1]; \
		A02 = (state)->A[2]; \
		A03 = (state)->A[3]; \
		A04 = (state)->A[4]; \
		A05 = (state)->A[5]; \
		A06 = (state)->A[6]; \
		A07 = (state)->A[7]; \
		A08 = (state)->A[8]; \
		A09 = (state)->A[9]; \
		A0A = (state)->A[10]; \
		A0B = (state)->A[11]; \
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
       A00 = m128_const1_64( 0x20728DFD20728DFD ); \
       A01 = m128_const1_64( 0x46C0BD5346C0BD53 ); \
       A02 = m128_const1_64( 0xE782B699E782B699 ); \
       A03 = m128_const1_64( 0x5530463255304632 ); \
       A04 = m128_const1_64( 0x71B4EF9071B4EF90 ); \
       A05 = m128_const1_64( 0x0EA9E82C0EA9E82C ); \
       A06 = m128_const1_64( 0xDBB930F1DBB930F1 ); \
       A07 = m128_const1_64( 0xFAD06B8BFAD06B8B ); \
       A08 = m128_const1_64( 0xBE0CAE40BE0CAE40 ); \
       A09 = m128_const1_64( 0x8BD144108BD14410 ); \
       A0A = m128_const1_64( 0x76D2ADAC76D2ADAC ); \
       A0B = m128_const1_64( 0x28ACAB7F28ACAB7F ); \
       B0 = m128_const1_64( 0xC1099CB7C1099CB7 ); \
       B1 = m128_const1_64( 0x07B385F307B385F3 ); \
       B2 = m128_const1_64( 0xE7442C26E7442C26 ); \
       B3 = m128_const1_64( 0xCC8AD640CC8AD640 ); \
       B4 = m128_const1_64( 0xEB6F56C7EB6F56C7 ); \
       B5 = m128_const1_64( 0x1EA81AA91EA81AA9 ); \
       B6 = m128_const1_64( 0x73B9D31473B9D314 ); \
       B7 = m128_const1_64( 0x1DE85D081DE85D08 ); \
       B8 = m128_const1_64( 0x48910A5A48910A5A ); \
       B9 = m128_const1_64( 0x893B22DB893B22DB ); \
       BA = m128_const1_64( 0xC5A0DF44C5A0DF44 ); \
       BB = m128_const1_64( 0xBBC4324EBBC4324E ); \
       BC = m128_const1_64( 0x72D2F24072D2F240 ); \
       BD = m128_const1_64( 0x75941D9975941D99 ); \
       BE = m128_const1_64( 0x6D8BDE826D8BDE82 ); \
       BF = m128_const1_64( 0xA1A7502BA1A7502B ); \
       C0 = m128_const1_64( 0xD9BF68D1D9BF68D1 ); \
       C1 = m128_const1_64( 0x58BAD75058BAD750 ); \
       C2 = m128_const1_64( 0x56028CB256028CB2 ); \
       C3 = m128_const1_64( 0x8134F3598134F359 ); \
       C4 = m128_const1_64( 0xB5D469D8B5D469D8 ); \
       C5 = m128_const1_64( 0x941A8CC2941A8CC2 ); \
       C6 = m128_const1_64( 0x418B2A6E418B2A6E ); \
       C7 = m128_const1_64( 0x0405278004052780 ); \
       C8 = m128_const1_64( 0x7F07D7877F07D787 ); \
       C9 = m128_const1_64( 0x5194358F5194358F ); \
       CA = m128_const1_64( 0x3C60D6653C60D665 ); \
       CB = m128_const1_64( 0xBE97D79ABE97D79A ); \
       CC = m128_const1_64( 0x950C3434950C3434 ); \
       CD = m128_const1_64( 0xAED9A06DAED9A06D ); \
       CE = m128_const1_64( 0x2537DC8D2537DC8D ); \
       CF = m128_const1_64( 0x7CDB59697CDB5969 ); \
   } \
   Wlow = (state)->Wlow; \
   Whigh = (state)->Whigh; \
} while (0)

#define WRITE_STATE(state)   do { \
		(state)->A[0] = A00; \
		(state)->A[1] = A01; \
		(state)->A[2] = A02; \
		(state)->A[3] = A03; \
		(state)->A[4] = A04; \
		(state)->A[5] = A05; \
		(state)->A[6] = A06; \
		(state)->A[7] = A07; \
		(state)->A[8] = A08; \
		(state)->A[9] = A09; \
		(state)->A[10] = A0A; \
		(state)->A[11] = A0B; \
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

#define DECODE_BLOCK \
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

#define INPUT_BLOCK_ADD \
do { \
    B0 = _mm_add_epi32( B0, M0 );\
    B1 = _mm_add_epi32( B1, M1 );\
    B2 = _mm_add_epi32( B2, M2 );\
    B3 = _mm_add_epi32( B3, M3 );\
    B4 = _mm_add_epi32( B4, M4 );\
    B5 = _mm_add_epi32( B5, M5 );\
    B6 = _mm_add_epi32( B6, M6 );\
    B7 = _mm_add_epi32( B7, M7 );\
    B8 = _mm_add_epi32( B8, M8 );\
    B9 = _mm_add_epi32( B9, M9 );\
    BA = _mm_add_epi32( BA, MA );\
    BB = _mm_add_epi32( BB, MB );\
    BC = _mm_add_epi32( BC, MC );\
    BD = _mm_add_epi32( BD, MD );\
    BE = _mm_add_epi32( BE, ME );\
    BF = _mm_add_epi32( BF, MF );\
} while (0)

#define INPUT_BLOCK_SUB \
do { \
    C0 = _mm_sub_epi32( C0, M0 ); \
    C1 = _mm_sub_epi32( C1, M1 ); \
    C2 = _mm_sub_epi32( C2, M2 ); \
    C3 = _mm_sub_epi32( C3, M3 ); \
    C4 = _mm_sub_epi32( C4, M4 ); \
    C5 = _mm_sub_epi32( C5, M5 ); \
    C6 = _mm_sub_epi32( C6, M6 ); \
    C7 = _mm_sub_epi32( C7, M7 ); \
    C8 = _mm_sub_epi32( C8, M8 ); \
    C9 = _mm_sub_epi32( C9, M9 ); \
    CA = _mm_sub_epi32( CA, MA ); \
    CB = _mm_sub_epi32( CB, MB ); \
    CC = _mm_sub_epi32( CC, MC ); \
    CD = _mm_sub_epi32( CD, MD ); \
    CE = _mm_sub_epi32( CE, ME ); \
    CF = _mm_sub_epi32( CF, MF ); \
} while (0)

#define XOR_W \
do { \
   A00 = _mm_xor_si128( A00, _mm_set1_epi32( Wlow ) ); \
   A01 = _mm_xor_si128( A01, _mm_set1_epi32( Whigh ) ); \
} while (0)


/*
#define SWAP(v1, v2)   do { \
		sph_u32 tmp = (v1); \
		(v1) = (v2); \
		(v2) = tmp; \
	} while (0)
*/

#define SWAP_BC \
do { \
    mm128_swap256_128( B0, C0 ); \
    mm128_swap256_128( B1, C1 ); \
    mm128_swap256_128( B2, C2 ); \
    mm128_swap256_128( B3, C3 ); \
    mm128_swap256_128( B4, C4 ); \
    mm128_swap256_128( B5, C5 ); \
    mm128_swap256_128( B6, C6 ); \
    mm128_swap256_128( B7, C7 ); \
    mm128_swap256_128( B8, C8 ); \
    mm128_swap256_128( B9, C9 ); \
    mm128_swap256_128( BA, CA ); \
    mm128_swap256_128( BB, CB ); \
    mm128_swap256_128( BC, CC ); \
    mm128_swap256_128( BD, CD ); \
    mm128_swap256_128( BE, CE ); \
    mm128_swap256_128( BF, CF ); \
} while (0)

/*
#define PERM_ELT(xa0, xa1, xb0, xb1, xb2, xb3, xc, xm) \
do { \
  __m128i t1 = _mm_mullo_epi32(  mm_rol_32( xa1, 15 ),\
                                   _mm_set1_epi32(5UL) ) \
  __m128i t2 = _mm_xor_si128( xa0, xc ); \
  xb0 = mm_not( _mm_xor_si256( xa0, mm_rol_32( xb0, 1 ) ) ); \
  xa0 = mm_xor4( xm, xb1, _mm_andnot_si128( xb3, xb2 ), \
              _mm_xor_si128( t2, \
                      _mm_mullo_epi32( t1, _mm_set1_epi32(5UL) ) ) ) \
*/

#define PERM_ELT(xa0, xa1, xb0, xb1, xb2, xb3, xc, xm) \
do { \
   xa0 = _mm_xor_si128( xm, _mm_xor_si128( xb1, _mm_xor_si128(  \
            _mm_andnot_si128( xb3, xb2 ), \
            _mm_mullo_epi32( _mm_xor_si128( xa0, _mm_xor_si128( xc, \
               _mm_mullo_epi32(  mm128_rol_32( xa1, 15 ), FIVE ) \
                   ) ), THREE ) ) ) ); \
   xb0 = mm128_not( _mm_xor_si128( xa0, mm128_rol_32( xb0, 1 ) ) ); \
} while (0)

#define PERM_STEP_0   do { \
		PERM_ELT(A00, A0B, B0, BD, B9, B6, C8, M0); \
		PERM_ELT(A01, A00, B1, BE, BA, B7, C7, M1); \
		PERM_ELT(A02, A01, B2, BF, BB, B8, C6, M2); \
		PERM_ELT(A03, A02, B3, B0, BC, B9, C5, M3); \
		PERM_ELT(A04, A03, B4, B1, BD, BA, C4, M4); \
		PERM_ELT(A05, A04, B5, B2, BE, BB, C3, M5); \
		PERM_ELT(A06, A05, B6, B3, BF, BC, C2, M6); \
		PERM_ELT(A07, A06, B7, B4, B0, BD, C1, M7); \
		PERM_ELT(A08, A07, B8, B5, B1, BE, C0, M8); \
		PERM_ELT(A09, A08, B9, B6, B2, BF, CF, M9); \
		PERM_ELT(A0A, A09, BA, B7, B3, B0, CE, MA); \
		PERM_ELT(A0B, A0A, BB, B8, B4, B1, CD, MB); \
		PERM_ELT(A00, A0B, BC, B9, B5, B2, CC, MC); \
		PERM_ELT(A01, A00, BD, BA, B6, B3, CB, MD); \
		PERM_ELT(A02, A01, BE, BB, B7, B4, CA, ME); \
		PERM_ELT(A03, A02, BF, BC, B8, B5, C9, MF); \
	} while (0)

#define PERM_STEP_1   do { \
		PERM_ELT(A04, A03, B0, BD, B9, B6, C8, M0); \
		PERM_ELT(A05, A04, B1, BE, BA, B7, C7, M1); \
		PERM_ELT(A06, A05, B2, BF, BB, B8, C6, M2); \
		PERM_ELT(A07, A06, B3, B0, BC, B9, C5, M3); \
		PERM_ELT(A08, A07, B4, B1, BD, BA, C4, M4); \
		PERM_ELT(A09, A08, B5, B2, BE, BB, C3, M5); \
		PERM_ELT(A0A, A09, B6, B3, BF, BC, C2, M6); \
		PERM_ELT(A0B, A0A, B7, B4, B0, BD, C1, M7); \
		PERM_ELT(A00, A0B, B8, B5, B1, BE, C0, M8); \
		PERM_ELT(A01, A00, B9, B6, B2, BF, CF, M9); \
		PERM_ELT(A02, A01, BA, B7, B3, B0, CE, MA); \
		PERM_ELT(A03, A02, BB, B8, B4, B1, CD, MB); \
		PERM_ELT(A04, A03, BC, B9, B5, B2, CC, MC); \
		PERM_ELT(A05, A04, BD, BA, B6, B3, CB, MD); \
		PERM_ELT(A06, A05, BE, BB, B7, B4, CA, ME); \
		PERM_ELT(A07, A06, BF, BC, B8, B5, C9, MF); \
	} while (0)

#define PERM_STEP_2   do { \
		PERM_ELT(A08, A07, B0, BD, B9, B6, C8, M0); \
		PERM_ELT(A09, A08, B1, BE, BA, B7, C7, M1); \
		PERM_ELT(A0A, A09, B2, BF, BB, B8, C6, M2); \
		PERM_ELT(A0B, A0A, B3, B0, BC, B9, C5, M3); \
		PERM_ELT(A00, A0B, B4, B1, BD, BA, C4, M4); \
		PERM_ELT(A01, A00, B5, B2, BE, BB, C3, M5); \
		PERM_ELT(A02, A01, B6, B3, BF, BC, C2, M6); \
		PERM_ELT(A03, A02, B7, B4, B0, BD, C1, M7); \
		PERM_ELT(A04, A03, B8, B5, B1, BE, C0, M8); \
		PERM_ELT(A05, A04, B9, B6, B2, BF, CF, M9); \
		PERM_ELT(A06, A05, BA, B7, B3, B0, CE, MA); \
		PERM_ELT(A07, A06, BB, B8, B4, B1, CD, MB); \
		PERM_ELT(A08, A07, BC, B9, B5, B2, CC, MC); \
		PERM_ELT(A09, A08, BD, BA, B6, B3, CB, MD); \
		PERM_ELT(A0A, A09, BE, BB, B7, B4, CA, ME); \
		PERM_ELT(A0B, A0A, BF, BC, B8, B5, C9, MF); \
	} while (0)

#define APPLY_P \
do { \
    B0 = mm128_ror_32( B0, 15 ); \
    B1 = mm128_ror_32( B1, 15 ); \
    B2 = mm128_ror_32( B2, 15 ); \
    B3 = mm128_ror_32( B3, 15 ); \
    B4 = mm128_ror_32( B4, 15 ); \
    B5 = mm128_ror_32( B5, 15 ); \
    B6 = mm128_ror_32( B6, 15 ); \
    B7 = mm128_ror_32( B7, 15 ); \
    B8 = mm128_ror_32( B8, 15 ); \
    B9 = mm128_ror_32( B9, 15 ); \
    BA = mm128_ror_32( BA, 15 ); \
    BB = mm128_ror_32( BB, 15 ); \
    BC = mm128_ror_32( BC, 15 ); \
    BD = mm128_ror_32( BD, 15 ); \
    BE = mm128_ror_32( BE, 15 ); \
    BF = mm128_ror_32( BF, 15 ); \
    PERM_STEP_0; \
    PERM_STEP_1; \
    PERM_STEP_2; \
    A0B = _mm_add_epi32( A0B, C6 ); \
    A0A = _mm_add_epi32( A0A, C5 ); \
    A09 = _mm_add_epi32( A09, C4 ); \
    A08 = _mm_add_epi32( A08, C3 ); \
    A07 = _mm_add_epi32( A07, C2 ); \
    A06 = _mm_add_epi32( A06, C1 ); \
    A05 = _mm_add_epi32( A05, C0 ); \
    A04 = _mm_add_epi32( A04, CF ); \
    A03 = _mm_add_epi32( A03, CE ); \
    A02 = _mm_add_epi32( A02, CD ); \
    A01 = _mm_add_epi32( A01, CC ); \
    A00 = _mm_add_epi32( A00, CB ); \
    A0B = _mm_add_epi32( A0B, CA ); \
    A0A = _mm_add_epi32( A0A, C9 ); \
    A09 = _mm_add_epi32( A09, C8 ); \
    A08 = _mm_add_epi32( A08, C7 ); \
    A07 = _mm_add_epi32( A07, C6 ); \
    A06 = _mm_add_epi32( A06, C5 ); \
    A05 = _mm_add_epi32( A05, C4 ); \
    A04 = _mm_add_epi32( A04, C3 ); \
    A03 = _mm_add_epi32( A03, C2 ); \
    A02 = _mm_add_epi32( A02, C1 ); \
    A01 = _mm_add_epi32( A01, C0 ); \
    A00 = _mm_add_epi32( A00, CF ); \
    A0B = _mm_add_epi32( A0B, CE ); \
    A0A = _mm_add_epi32( A0A, CD ); \
    A09 = _mm_add_epi32( A09, CC ); \
    A08 = _mm_add_epi32( A08, CB ); \
    A07 = _mm_add_epi32( A07, CA ); \
    A06 = _mm_add_epi32( A06, C9 ); \
    A05 = _mm_add_epi32( A05, C8 ); \
    A04 = _mm_add_epi32( A04, C7 ); \
    A03 = _mm_add_epi32( A03, C6 ); \
    A02 = _mm_add_epi32( A02, C5 ); \
    A01 = _mm_add_epi32( A01, C4 ); \
    A00 = _mm_add_epi32( A00, C3 ); \
} while (0)

#define INCR_W   do { \
		if ((Wlow = T32(Wlow + 1)) == 0) \
			Whigh = T32(Whigh + 1); \
	} while (0)

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
shabal_4way_init( void *cc, unsigned size )
{
   shabal_4way_context *sc = (shabal_4way_context*)cc;

   if ( size == 512 )
   { // copy immediate constants directly to working registers later.
       sc->state_loaded = false;
/*
       sc->A[ 0] = m128_const1_64( 0x20728DFD20728DFD );
       sc->A[ 1] = m128_const1_64( 0x46C0BD5346C0BD53 );
       sc->A[ 2] = m128_const1_64( 0xE782B699E782B699 );
       sc->A[ 3] = m128_const1_64( 0x5530463255304632 );
       sc->A[ 4] = m128_const1_64( 0x71B4EF9071B4EF90 );
       sc->A[ 5] = m128_const1_64( 0x0EA9E82C0EA9E82C );
       sc->A[ 6] = m128_const1_64( 0xDBB930F1DBB930F1 );
       sc->A[ 7] = m128_const1_64( 0xFAD06B8BFAD06B8B );
       sc->A[ 8] = m128_const1_64( 0xBE0CAE40BE0CAE40 );
       sc->A[ 9] = m128_const1_64( 0x8BD144108BD14410 );
       sc->A[10] = m128_const1_64( 0x76D2ADAC76D2ADAC );
       sc->A[11] = m128_const1_64( 0x28ACAB7F28ACAB7F );

       sc->B[ 0] = m128_const1_64( 0xC1099CB7C1099CB7 );
       sc->B[ 1] = m128_const1_64( 0x07B385F307B385F3 );
       sc->B[ 2] = m128_const1_64( 0xE7442C26E7442C26 );
       sc->B[ 3] = m128_const1_64( 0xCC8AD640CC8AD640 );
       sc->B[ 4] = m128_const1_64( 0xEB6F56C7EB6F56C7 );
       sc->B[ 5] = m128_const1_64( 0x1EA81AA91EA81AA9 );
       sc->B[ 6] = m128_const1_64( 0x73B9D31473B9D314 );
       sc->B[ 7] = m128_const1_64( 0x1DE85D081DE85D08 );
       sc->B[ 8] = m128_const1_64( 0x48910A5A48910A5A );
       sc->B[ 9] = m128_const1_64( 0x893B22DB893B22DB );
       sc->B[10] = m128_const1_64( 0xC5A0DF44C5A0DF44 );
       sc->B[11] = m128_const1_64( 0xBBC4324EBBC4324E );
       sc->B[12] = m128_const1_64( 0x72D2F24072D2F240 );
       sc->B[13] = m128_const1_64( 0x75941D9975941D99 );
       sc->B[14] = m128_const1_64( 0x6D8BDE826D8BDE82 );
       sc->B[15] = m128_const1_64( 0xA1A7502BA1A7502B );

       sc->C[ 0] = m128_const1_64( 0xD9BF68D1D9BF68D1 );
       sc->C[ 1] = m128_const1_64( 0x58BAD75058BAD750 );
       sc->C[ 2] = m128_const1_64( 0x56028CB256028CB2 );
       sc->C[ 3] = m128_const1_64( 0x8134F3598134F359 );
       sc->C[ 4] = m128_const1_64( 0xB5D469D8B5D469D8 );
       sc->C[ 5] = m128_const1_64( 0x941A8CC2941A8CC2 );
       sc->C[ 6] = m128_const1_64( 0x418B2A6E418B2A6E );
       sc->C[ 7] = m128_const1_64( 0x0405278004052780 );
       sc->C[ 8] = m128_const1_64( 0x7F07D7877F07D787 );
       sc->C[ 9] = m128_const1_64( 0x5194358F5194358F );
       sc->C[10] = m128_const1_64( 0x3C60D6653C60D665 );
       sc->C[11] = m128_const1_64( 0xBE97D79ABE97D79A );
       sc->C[12] = m128_const1_64( 0x950C3434950C3434 );
       sc->C[13] = m128_const1_64( 0xAED9A06DAED9A06D );
       sc->C[14] = m128_const1_64( 0x2537DC8D2537DC8D );
       sc->C[15] = m128_const1_64( 0x7CDB59697CDB5969 );
*/
   }
   else
   {  // No users
       sc->state_loaded = true;
       sc->A[ 0] = m128_const1_64( 0x52F8455252F84552 );
       sc->A[ 1] = m128_const1_64( 0xE54B7999E54B7999 );
       sc->A[ 2] = m128_const1_64( 0x2D8EE3EC2D8EE3EC );
       sc->A[ 3] = m128_const1_64( 0xB9645191B9645191 );
       sc->A[ 4] = m128_const1_64( 0xE0078B86E0078B86 );
       sc->A[ 5] = m128_const1_64( 0xBB7C44C9BB7C44C9 );
       sc->A[ 6] = m128_const1_64( 0xD2B5C1CAD2B5C1CA );
       sc->A[ 7] = m128_const1_64( 0xB0D2EB8CB0D2EB8C );
       sc->A[ 8] = m128_const1_64( 0x14CE5A4514CE5A45 );
       sc->A[ 9] = m128_const1_64( 0x22AF50DC22AF50DC );
       sc->A[10] = m128_const1_64( 0xEFFDBC6BEFFDBC6B );
       sc->A[11] = m128_const1_64( 0xEB21B74AEB21B74A );

       sc->B[ 0] = m128_const1_64( 0xB555C6EEB555C6EE );
       sc->B[ 1] = m128_const1_64( 0x3E7105963E710596 );
       sc->B[ 2] = m128_const1_64( 0xA72A652FA72A652F );
       sc->B[ 3] = m128_const1_64( 0x9301515F9301515F );
       sc->B[ 4] = m128_const1_64( 0xDA28C1FADA28C1FA );
       sc->B[ 5] = m128_const1_64( 0x696FD868696FD868 );
       sc->B[ 6] = m128_const1_64( 0x9CB6BF729CB6BF72 );
       sc->B[ 7] = m128_const1_64( 0x0AFE40020AFE4002 );
       sc->B[ 8] = m128_const1_64( 0xA6E03615A6E03615 );
       sc->B[ 9] = m128_const1_64( 0x5138C1D45138C1D4 );
       sc->B[10] = m128_const1_64( 0xBE216306BE216306 );
       sc->B[11] = m128_const1_64( 0xB38B8890B38B8890 );
       sc->B[12] = m128_const1_64( 0x3EA8B96B3EA8B96B );
       sc->B[13] = m128_const1_64( 0x3299ACE43299ACE4 );
       sc->B[14] = m128_const1_64( 0x30924DD430924DD4 );
       sc->B[15] = m128_const1_64( 0x55CB34A555CB34A5 );

       sc->C[ 0] = m128_const1_64( 0xB405F031B405F031 );
       sc->C[ 1] = m128_const1_64( 0xC4233EBAC4233EBA );
       sc->C[ 2] = m128_const1_64( 0xB3733979B3733979 );
       sc->C[ 3] = m128_const1_64( 0xC0DD9D55C0DD9D55 );
       sc->C[ 4] = m128_const1_64( 0xC51C28AEC51C28AE );
       sc->C[ 5] = m128_const1_64( 0xA327B8E1A327B8E1 );
       sc->C[ 6] = m128_const1_64( 0x56C5616756C56167 );
       sc->C[ 7] = m128_const1_64( 0xED614433ED614433 );
       sc->C[ 8] = m128_const1_64( 0x88B59D6088B59D60 );
       sc->C[ 9] = m128_const1_64( 0x60E2CEBA60E2CEBA );
       sc->C[10] = m128_const1_64( 0x758B4B8B758B4B8B );
       sc->C[11] = m128_const1_64( 0x83E82A7F83E82A7F );
       sc->C[12] = m128_const1_64( 0xBC968828BC968828 );
       sc->C[13] = m128_const1_64( 0xE6E00BF7E6E00BF7 );
       sc->C[14] = m128_const1_64( 0xBA839E55BA839E55 );
       sc->C[15] = m128_const1_64( 0x9B491C609B491C60 );
   }
    sc->Wlow = 1;
    sc->Whigh = 0;
    sc->ptr = 0;
}

static void
shabal_4way_core( void *cc, const unsigned char *data, size_t len )
{
   shabal_4way_context *sc = (shabal_4way_context*)cc;
    __m128i *buf;
    __m128i *vdata = (__m128i*)data;
   const int buf_size = 64;  
   size_t ptr;
   DECL_STATE

   buf = sc->buf;
   ptr = sc->ptr;

   if ( len < (buf_size - ptr ) )
   {
      memcpy_128( buf + (ptr>>2), vdata, len>>2 );
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
      memcpy_128( buf + (ptr>>2), vdata, clen>>2 );

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
         INCR_W;
         ptr = 0;
      }
   }
   WRITE_STATE(sc);
   sc->ptr = ptr;
}

static void
shabal_4way_close( void *cc, unsigned ub, unsigned n, void *dst,
                   unsigned size_words )
{
   shabal_4way_context *sc = (shabal_4way_context*)cc;
    __m128i *buf;
   const int buf_size = 64;
   size_t ptr;
   int i;
   unsigned z, zz;
   DECL_STATE

   buf = sc->buf;
   ptr = sc->ptr;
   z = 0x80 >> n;
   zz = ((ub & -z) | z) & 0xFF;
   buf[ptr>>2] = _mm_set1_epi32( zz );
   memset_zero_128( buf + (ptr>>2) + 1, ( (buf_size - ptr) >> 2 ) - 1 );
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

   __m128i *d = (__m128i*)dst;
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
shabal256_4way_init( void *cc )
{
	shabal_4way_init(cc, 256);
}

void
shabal256_4way_update( void *cc, const void *data, size_t len )
{
	shabal_4way_core( cc, data, len );
}

void
shabal256_4way_close( void *cc, void *dst )
{
	shabal_4way_close(cc, 0, 0, dst, 8);
}

void
shabal256_4way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                  void *dst )
{
	shabal_4way_close(cc, ub, n, dst, 8);
}

void
shabal512_4way_init(void *cc)
{
	shabal_4way_init(cc, 512);
}

void
shabal512_4way_update(void *cc, const void *data, size_t len)
{
	shabal_4way_core(cc, data, len);
}

void
shabal512_4way_close(void *cc, void *dst)
{
	shabal_4way_close(cc, 0, 0, dst, 16);
}

void
shabal512_4way_addbits_and_close(void *cc, unsigned ub, unsigned n, void *dst)
{
	shabal_4way_close(cc, ub, n, dst, 16);
}
#ifdef __cplusplus
}
#endif

#endif
