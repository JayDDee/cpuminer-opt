#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "simd-hash-2way.h"

#if defined (__AVX2__)

union _m256_v16 {
  uint16_t u16[16];
  __m256i v256;
};
typedef union _m256_v16 m256_v16;

// imported from simd_iv.h

uint32_t SIMD_IV_512[] = { 0x0ba16b95, 0x72f999ad, 0x9fecc2ae, 0xba3264fc,
                           0x5e894929, 0x8e9f30e5, 0x2f1daa37, 0xf0f2c558,
                           0xac506643, 0xa90635a5, 0xe25b878b, 0xaab7878f,
                           0x88817f7a, 0x0a02892b, 0x559a7550, 0x598f657e,
                           0x7eef60a1, 0x6b70e3e8, 0x9c1714d1, 0xb958e2a8,
                           0xab02675e, 0xed1c014f, 0xcd8d65bb, 0xfdb7a257,
                           0x09254899, 0xd699c7bc, 0x9019b6dc, 0x2b9022e4,
                           0x8fa14956, 0x21bf9bd3, 0xb94d0943, 0x6ffddc22 };

// targetted
/* Twiddle tables */

static const m256_v16 FFT64_Twiddle[] =
{
    {{ 1,    2,    4,    8,   16,   32,   64,  128,
       1,    2,    4,    8,   16,   32,   64,  128 }},
    {{ 1,   60,    2,  120,    4,  -17,    8,  -34,
       1,   60,    2,  120,    4,  -17,    8,  -34 }},
    {{ 1,  120,    8,  -68,   64,  -30,   -2,   17,
       1,  120,    8,  -68,   64,  -30,   -2,   17 }},
    {{ 1,   46,   60,  -67,    2,   92,  120,  123,
       1,   46,   60,  -67,    2,   92,  120,  123 }},
    {{ 1,   92,  -17,  -22,   32,  117,  -30,   67,
       1,   92,  -17,  -22,   32,  117,  -30,   67 }},
    {{ 1,  -67,  120,  -73,    8,  -22,  -68,  -70,
       1,  -67,  120,  -73,    8,  -22,  -68,  -70 }},
    {{ 1,  123,  -34,  -70,  128,   67,   17,   35,
       1,  123,  -34,  -70,  128,   67,   17,   35 }},
};

static const m256_v16 FFT128_Twiddle[] =
{
    {{   1, -118,   46,  -31,   60,  116,  -67,  -61,
         1, -118,   46,  -31,   60,  116,  -67,  -61 }},
    {{   2,   21,   92,  -62,  120,  -25,  123, -122,
         2,   21,   92,  -62,  120,  -25,  123, -122 }},
    {{   4,   42,  -73, -124,  -17,  -50,  -11,   13,
         4,   42,  -73, -124,  -17,  -50,  -11,   13 }},
    {{   8,   84,  111,    9,  -34, -100,  -22,   26,
         8,   84,  111,    9,  -34, -100,  -22,   26 }},
    {{  16,  -89,  -35,   18,  -68,   57,  -44,   52,
        16,  -89,  -35,   18,  -68,   57,  -44,   52 }},
    {{  32,   79,  -70,   36,  121,  114,  -88,  104,
        32,   79,  -70,   36,  121,  114,  -88,  104 }},
    {{  64,  -99,  117,   72,  -15,  -29,   81,  -49,
        64,  -99,  117,   72,  -15,  -29,   81,  -49 }},
    {{ 128,   59,  -23, -113,  -30,  -58,  -95,  -98,
       128,   59,  -23, -113,  -30,  -58,  -95,  -98 }},
};

static const m256_v16 FFT256_Twiddle[] =
{
    {{   1,   41, -118,   45,   46,   87,  -31,   14,
         1,   41, -118,   45,   46,   87,  -31,   14 }},
    {{  60, -110,  116, -127,  -67,   80,  -61,   69,
        60, -110,  116, -127,  -67,   80,  -61,   69 }},
    {{   2,   82,   21,   90,   92,  -83,  -62,   28,
         2,   82,   21,   90,   92,  -83,  -62,   28 }},
    {{ 120,   37,  -25,    3,  123,  -97, -122, -119,
       120,   37,  -25,    3,  123,  -97, -122, -119 }},
    {{   4,  -93,   42,  -77,  -73,   91, -124,   56,
         4,  -93,   42,  -77,  -73,   91, -124,   56 }},
    {{ -17,   74,  -50,    6,  -11,   63,   13,   19,
       -17,   74,  -50,    6,  -11,   63,   13,   19 }},
    {{   8,   71,   84,  103,  111,  -75,    9,  112,
         8,   71,   84,  103,  111,  -75,    9,  112 }},
    {{ -34, -109, -100,   12,  -22,  126,   26,   38,
       -34, -109, -100,   12,  -22,  126,   26,   38 }},
    {{  16, -115,  -89,  -51,  -35,  107,   18,  -33,
        16, -115,  -89,  -51,  -35,  107,   18,  -33 }},
    {{ -68,   39,   57,   24,  -44,   -5,   52,   76,
       -68,   39,   57,   24,  -44,   -5,   52,   76 }},
    {{  32,   27,   79, -102,  -70,  -43,   36,  -66,
        32,   27,   79, -102,  -70,  -43,   36,  -66 }},
    {{ 121,   78,  114,   48,  -88,  -10,  104, -105,
       121,   78,  114,   48,  -88,  -10,  104, -105 }},
    {{  64,   54,  -99,   53,  117,  -86,   72,  125,
        64,   54,  -99,   53,  117,  -86,   72,  125 }},
    {{ -15, -101,  -29,   96,   81,  -20,  -49,   47,
       -15, -101,  -29,   96,   81,  -20,  -49,   47 }},
    {{ 128,  108,   59,  106,  -23,   85, -113,   -7,
       128,  108,   59,  106,  -23,   85, -113,   -7 }},
    {{ -30,   55,  -58,  -65,  -95,  -40,  -98,   94,
       -30,   55,  -58,  -65,  -95,  -40,  -98,   94 }}
};

// generic 
#define SHUFXOR_1 0xb1          /* 0b10110001 */
#define SHUFXOR_2 0x4e          /* 0b01001110 */
#define SHUFXOR_3 0x1b          /* 0b00011011 */

#define CAT(x, y) x##y
#define XCAT(x,y) CAT(x,y)

#define SUM7_00 0
#define SUM7_01 1
#define SUM7_02 2
#define SUM7_03 3
#define SUM7_04 4
#define SUM7_05 5
#define SUM7_06 6

#define SUM7_10 1
#define SUM7_11 2
#define SUM7_12 3
#define SUM7_13 4
#define SUM7_14 5
#define SUM7_15 6
#define SUM7_16 0

#define SUM7_20 2
#define SUM7_21 3
#define SUM7_22 4
#define SUM7_23 5
#define SUM7_24 6
#define SUM7_25 0
#define SUM7_26 1

#define SUM7_30 3
#define SUM7_31 4
#define SUM7_32 5
#define SUM7_33 6
#define SUM7_34 0
#define SUM7_35 1
#define SUM7_36 2

#define SUM7_40 4
#define SUM7_41 5
#define SUM7_42 6
#define SUM7_43 0
#define SUM7_44 1
#define SUM7_45 2
#define SUM7_46 3

#define SUM7_50 5
#define SUM7_51 6
#define SUM7_52 0
#define SUM7_53 1
#define SUM7_54 2
#define SUM7_55 3
#define SUM7_56 4

#define SUM7_60 6
#define SUM7_61 0
#define SUM7_62 1
#define SUM7_63 2
#define SUM7_64 3
#define SUM7_65 4
#define SUM7_66 5

#define PERM(z,d,a,shufxor) XCAT(PERM_,XCAT(SUM7_##z,PERM_START))(d,a,shufxor)

#define PERM_0(d,a,shufxor) /* XOR 1 */ \
do { \
    d##l = shufxor( a##l, 1 ); \
    d##h = shufxor( a##h, 1 ); \
 } while(0)

#define PERM_1(d,a,shufxor) /* XOR 6 */ \
do { \
    d##l = shufxor( a##h, 2 ); \
    d##h = shufxor( a##l, 2 ); \
} while(0)

#define PERM_2(d,a,shufxor) /* XOR 2 */ \
do { \
    d##l = shufxor( a##l, 2 ); \
    d##h = shufxor( a##h, 2 ); \
} while(0)

#define PERM_3(d,a,shufxor) /* XOR 3 */ \
do { \
    d##l = shufxor( a##l, 3 ); \
    d##h = shufxor( a##h, 3 ); \
} while(0)

#define PERM_4(d,a,shufxor) /* XOR 5 */ \
do { \
    d##l = shufxor( a##h, 1 ); \
    d##h = shufxor( a##l, 1 ); \
} while(0)

#define PERM_5(d,a,shufxor) /* XOR 7 */ \
do { \
    d##l = shufxor( a##h, 3 ); \
    d##h = shufxor( a##l, 3 ); \
} while(0)

#define PERM_6(d,a,shufxor) /* XOR 4 */ \
do { \
    d##l = a##h; \
    d##h = a##l; \
} while(0)


// targetted
#define shufxor2w(x,s) _mm256_shuffle_epi32( x, XCAT( SHUFXOR_, s ))

#define REDUCE(x) \
  _mm256_sub_epi16( _mm256_and_si256( x, m256_const1_64( \
                         0x00ff00ff00ff00ff ) ), _mm256_srai_epi16( x, 8 ) )

#define EXTRA_REDUCE_S(x)\
  _mm256_sub_epi16( x, _mm256_and_si256( \
             m256_const1_64( 0x0101010101010101 ), \
             _mm256_cmpgt_epi16( x, m256_const1_64( 0x0080008000800080 ) ) ) )

#define REDUCE_FULL_S( x )  EXTRA_REDUCE_S( REDUCE (x ) )

//#define DO_REDUCE( i )      X(i) = REDUCE( X(i) )

#define DO_REDUCE_FULL_S(i) \
do { \
    X(i) = REDUCE( X(i) );                        \
    X(i) = EXTRA_REDUCE_S( X(i) );                \
} while(0)



#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

////////////////////////////////////
//
// SIMD 4 way AVX512

union _m512_v16 {
  uint16_t u16[32];
  __m512i v512;
};
typedef union _m512_v16 m512_v16;

static const m512_v16 FFT64_Twiddle4w[] =
{
    {{ 1,    2,    4,    8,   16,   32,   64,  128,
       1,    2,    4,    8,   16,   32,   64,  128,
       1,    2,    4,    8,   16,   32,   64,  128,
       1,    2,    4,    8,   16,   32,   64,  128 }},
    {{ 1,   60,    2,  120,    4,  -17,    8,  -34,
       1,   60,    2,  120,    4,  -17,    8,  -34,
       1,   60,    2,  120,    4,  -17,    8,  -34,
       1,   60,    2,  120,    4,  -17,    8,  -34 }},
    {{ 1,  120,    8,  -68,   64,  -30,   -2,   17,
       1,  120,    8,  -68,   64,  -30,   -2,   17,
       1,  120,    8,  -68,   64,  -30,   -2,   17,
       1,  120,    8,  -68,   64,  -30,   -2,   17 }},
    {{ 1,   46,   60,  -67,    2,   92,  120,  123,
       1,   46,   60,  -67,    2,   92,  120,  123,
       1,   46,   60,  -67,    2,   92,  120,  123,
       1,   46,   60,  -67,    2,   92,  120,  123 }},
    {{ 1,   92,  -17,  -22,   32,  117,  -30,   67,
       1,   92,  -17,  -22,   32,  117,  -30,   67,
       1,   92,  -17,  -22,   32,  117,  -30,   67,
       1,   92,  -17,  -22,   32,  117,  -30,   67 }},
    {{ 1,  -67,  120,  -73,    8,  -22,  -68,  -70,
       1,  -67,  120,  -73,    8,  -22,  -68,  -70,
       1,  -67,  120,  -73,    8,  -22,  -68,  -70,
       1,  -67,  120,  -73,    8,  -22,  -68,  -70 }},
    {{ 1,  123,  -34,  -70,  128,   67,   17,   35,
       1,  123,  -34,  -70,  128,   67,   17,   35,
       1,  123,  -34,  -70,  128,   67,   17,   35,
       1,  123,  -34,  -70,  128,   67,   17,   35 }},
};

static const m512_v16 FFT128_Twiddle4w[] =
{
    {{   1, -118,   46,  -31,   60,  116,  -67,  -61,
         1, -118,   46,  -31,   60,  116,  -67,  -61,
         1, -118,   46,  -31,   60,  116,  -67,  -61,
         1, -118,   46,  -31,   60,  116,  -67,  -61 }},
    {{   2,   21,   92,  -62,  120,  -25,  123, -122,
         2,   21,   92,  -62,  120,  -25,  123, -122,
         2,   21,   92,  -62,  120,  -25,  123, -122,
         2,   21,   92,  -62,  120,  -25,  123, -122 }},
    {{   4,   42,  -73, -124,  -17,  -50,  -11,   13,
         4,   42,  -73, -124,  -17,  -50,  -11,   13,
         4,   42,  -73, -124,  -17,  -50,  -11,   13,
         4,   42,  -73, -124,  -17,  -50,  -11,   13 }},
    {{   8,   84,  111,    9,  -34, -100,  -22,   26,
         8,   84,  111,    9,  -34, -100,  -22,   26,
         8,   84,  111,    9,  -34, -100,  -22,   26,
         8,   84,  111,    9,  -34, -100,  -22,   26 }},
    {{  16,  -89,  -35,   18,  -68,   57,  -44,   52,
        16,  -89,  -35,   18,  -68,   57,  -44,   52,
        16,  -89,  -35,   18,  -68,   57,  -44,   52,
        16,  -89,  -35,   18,  -68,   57,  -44,   52 }},
    {{  32,   79,  -70,   36,  121,  114,  -88,  104,
        32,   79,  -70,   36,  121,  114,  -88,  104,
        32,   79,  -70,   36,  121,  114,  -88,  104,
        32,   79,  -70,   36,  121,  114,  -88,  104 }},
    {{  64,  -99,  117,   72,  -15,  -29,   81,  -49,
        64,  -99,  117,   72,  -15,  -29,   81,  -49,
        64,  -99,  117,   72,  -15,  -29,   81,  -49,
        64,  -99,  117,   72,  -15,  -29,   81,  -49 }},
    {{ 128,   59,  -23, -113,  -30,  -58,  -95,  -98,
       128,   59,  -23, -113,  -30,  -58,  -95,  -98,
       128,   59,  -23, -113,  -30,  -58,  -95,  -98,
       128,   59,  -23, -113,  -30,  -58,  -95,  -98 }},
};

static const m512_v16 FFT256_Twiddle4w[] =
{
    {{   1,   41, -118,   45,   46,   87,  -31,   14,
         1,   41, -118,   45,   46,   87,  -31,   14,
         1,   41, -118,   45,   46,   87,  -31,   14,
         1,   41, -118,   45,   46,   87,  -31,   14 }},
    {{  60, -110,  116, -127,  -67,   80,  -61,   69,
        60, -110,  116, -127,  -67,   80,  -61,   69,
        60, -110,  116, -127,  -67,   80,  -61,   69,
        60, -110,  116, -127,  -67,   80,  -61,   69 }},
    {{   2,   82,   21,   90,   92,  -83,  -62,   28,
         2,   82,   21,   90,   92,  -83,  -62,   28,
         2,   82,   21,   90,   92,  -83,  -62,   28,
         2,   82,   21,   90,   92,  -83,  -62,   28 }},
    {{ 120,   37,  -25,    3,  123,  -97, -122, -119,
       120,   37,  -25,    3,  123,  -97, -122, -119,
       120,   37,  -25,    3,  123,  -97, -122, -119,
       120,   37,  -25,    3,  123,  -97, -122, -119 }},
    {{   4,  -93,   42,  -77,  -73,   91, -124,   56,
         4,  -93,   42,  -77,  -73,   91, -124,   56,
         4,  -93,   42,  -77,  -73,   91, -124,   56,
         4,  -93,   42,  -77,  -73,   91, -124,   56 }},
    {{ -17,   74,  -50,    6,  -11,   63,   13,   19,
       -17,   74,  -50,    6,  -11,   63,   13,   19,
       -17,   74,  -50,    6,  -11,   63,   13,   19,
       -17,   74,  -50,    6,  -11,   63,   13,   19 }},
    {{   8,   71,   84,  103,  111,  -75,    9,  112,
         8,   71,   84,  103,  111,  -75,    9,  112,
         8,   71,   84,  103,  111,  -75,    9,  112,
         8,   71,   84,  103,  111,  -75,    9,  112 }},
    {{ -34, -109, -100,   12,  -22,  126,   26,   38,
       -34, -109, -100,   12,  -22,  126,   26,   38,
       -34, -109, -100,   12,  -22,  126,   26,   38,
       -34, -109, -100,   12,  -22,  126,   26,   38 }},
    {{  16, -115,  -89,  -51,  -35,  107,   18,  -33,
        16, -115,  -89,  -51,  -35,  107,   18,  -33,
        16, -115,  -89,  -51,  -35,  107,   18,  -33,
        16, -115,  -89,  -51,  -35,  107,   18,  -33 }},
    {{ -68,   39,   57,   24,  -44,   -5,   52,   76,
       -68,   39,   57,   24,  -44,   -5,   52,   76,
       -68,   39,   57,   24,  -44,   -5,   52,   76,
       -68,   39,   57,   24,  -44,   -5,   52,   76 }},
    {{  32,   27,   79, -102,  -70,  -43,   36,  -66,
        32,   27,   79, -102,  -70,  -43,   36,  -66,
        32,   27,   79, -102,  -70,  -43,   36,  -66,
        32,   27,   79, -102,  -70,  -43,   36,  -66 }},
    {{ 121,   78,  114,   48,  -88,  -10,  104, -105,
       121,   78,  114,   48,  -88,  -10,  104, -105,
       121,   78,  114,   48,  -88,  -10,  104, -105,
       121,   78,  114,   48,  -88,  -10,  104, -105 }},
    {{  64,   54,  -99,   53,  117,  -86,   72,  125,
        64,   54,  -99,   53,  117,  -86,   72,  125,
        64,   54,  -99,   53,  117,  -86,   72,  125,
        64,   54,  -99,   53,  117,  -86,   72,  125 }},
    {{ -15, -101,  -29,   96,   81,  -20,  -49,   47,
       -15, -101,  -29,   96,   81,  -20,  -49,   47,
       -15, -101,  -29,   96,   81,  -20,  -49,   47,
       -15, -101,  -29,   96,   81,  -20,  -49,   47 }},
    {{ 128,  108,   59,  106,  -23,   85, -113,   -7,
       128,  108,   59,  106,  -23,   85, -113,   -7,
       128,  108,   59,  106,  -23,   85, -113,   -7,
       128,  108,   59,  106,  -23,   85, -113,   -7 }},
    {{ -30,   55,  -58,  -65,  -95,  -40,  -98,   94,
       -30,   55,  -58,  -65,  -95,  -40,  -98,   94,
       -30,   55,  -58,  -65,  -95,  -40,  -98,   94,
       -30,   55,  -58,  -65,  -95,  -40,  -98,   94 }}
};

#define shufxor4w(x,s) _mm512_shuffle_epi32( x, XCAT( SHUFXOR_, s ))

#define REDUCE4w(x) \
  _mm512_sub_epi16( _mm512_and_si512( x, m512_const1_64( \
                         0x00ff00ff00ff00ff ) ), _mm512_srai_epi16( x, 8 ) )

#define EXTRA_REDUCE_S4w(x)\
  _mm512_sub_epi16( x, _mm512_and_si512( \
             m512_const1_64( 0x0101010101010101 ), \
             _mm512_movm_epi16( _mm512_cmpgt_epi16_mask( \
                               x, m512_const1_64( 0x0080008000800080 ) ) ) ) )

// generic, except it calls targetted macros
#define REDUCE_FULL_S4w( x )  EXTRA_REDUCE_S4w( REDUCE4w (x ) )

//#define DO_REDUCE4w( i )      X(i) = REDUCE4w( X(i) )

#define DO_REDUCE_FULL_S4w(i) \
do { \
    X(i) = REDUCE4w( X(i) );                        \
    X(i) = EXTRA_REDUCE_S4w( X(i) );                \
} while(0)


// targetted
void fft64_4way( void *a )
{
  __m512i* const A = a;
  register __m512i X0, X1, X2, X3, X4, X5, X6, X7;

// generic
#define X(i) X##i

  X0 = A[0];
  X1 = A[1];
  X2 = A[2];
  X3 = A[3];
  X4 = A[4];
  X5 = A[5];
  X6 = A[6];
  X7 = A[7];

#define DO_REDUCE(i)   X(i) = REDUCE4w( X(i) )

   // Begin with 8 parallels DIF FFT_8
   //
   // FFT_8 using w=4 as 8th root of unity
   //  Unrolled decimation in frequency (DIF) radix-2 NTT.
   //  Output data is in revbin_permuted order.

  static const int w[] = {0, 2, 4, 6};
//   __m256i *Twiddle = (__m256i*)FFT64_Twiddle;


// targetted  
#define BUTTERFLY_0( i,j ) \
do { \
    __m512i v = X(j); \
    X(j) = _mm512_add_epi16( X(i), X(j) ); \
    X(i) = _mm512_sub_epi16( X(i), v ); \
} while(0)

#define BUTTERFLY_N( i,j,n ) \
do { \
    __m512i v = X(j); \
    X(j) = _mm512_add_epi16( X(i), X(j) ); \
    X(i) = _mm512_slli_epi16( _mm512_sub_epi16( X(i), v ), w[n] ); \
} while(0)

  BUTTERFLY_0( 0, 4 );
  BUTTERFLY_N( 1, 5, 1 );
  BUTTERFLY_N( 2, 6, 2 );
  BUTTERFLY_N( 3, 7, 3 );

  DO_REDUCE( 2 );
  DO_REDUCE( 3 );

  BUTTERFLY_0( 0, 2 );
  BUTTERFLY_0( 4, 6 );
  BUTTERFLY_N( 1, 3, 2 );
  BUTTERFLY_N( 5, 7, 2 );

  DO_REDUCE( 1 );

  BUTTERFLY_0( 0, 1 );
  BUTTERFLY_0( 2, 3 );
  BUTTERFLY_0( 4, 5 );
  BUTTERFLY_0( 6, 7 );

  /* We don't need to reduce X(7) */
  DO_REDUCE_FULL_S4w( 0 );
  DO_REDUCE_FULL_S4w( 1 );
  DO_REDUCE_FULL_S4w( 2 );
  DO_REDUCE_FULL_S4w( 3 );
  DO_REDUCE_FULL_S4w( 4 );
  DO_REDUCE_FULL_S4w( 5 );
  DO_REDUCE_FULL_S4w( 6 );

#undef BUTTERFLY_0
#undef BUTTERFLY_N

// twiddle is hard coded  T[0] = m512_const2_64( {128,64,32,16}, {8,4,2,1} )  
  // Multiply by twiddle factors
//  X(6) = _mm512_mullo_epi16( X(6), m512_const2_64( 0x0080004000200010,
//                                                   0x0008000400020001 );
//  X(5) = _mm512_mullo_epi16( X(5), m512_const2_64( 0xffdc0008ffef0004,
//                                                   0x00780002003c0001 );


  X(6) = _mm512_mullo_epi16( X(6), FFT64_Twiddle4w[0].v512 );
  X(5) = _mm512_mullo_epi16( X(5), FFT64_Twiddle4w[1].v512 );
  X(4) = _mm512_mullo_epi16( X(4), FFT64_Twiddle4w[2].v512 );
  X(3) = _mm512_mullo_epi16( X(3), FFT64_Twiddle4w[3].v512 );
  X(2) = _mm512_mullo_epi16( X(2), FFT64_Twiddle4w[4].v512 );
  X(1) = _mm512_mullo_epi16( X(1), FFT64_Twiddle4w[5].v512 );
  X(0) = _mm512_mullo_epi16( X(0), FFT64_Twiddle4w[6].v512 );

  // Transpose the FFT state with a revbin order permutation
  // on the rows and the column.
  // This will make the full FFT_64 in order.
#define INTERLEAVE(i,j) \
  do { \
    __m512i t1= X(i); \
    __m512i t2= X(j); \
    X(i) = _mm512_unpacklo_epi16( t1, t2 ); \
    X(j) = _mm512_unpackhi_epi16( t1, t2 ); \
  } while(0)

  INTERLEAVE( 1, 0 );
  INTERLEAVE( 3, 2 );
  INTERLEAVE( 5, 4 );
  INTERLEAVE( 7, 6 );

  INTERLEAVE( 2, 0 );
  INTERLEAVE( 3, 1 );
  INTERLEAVE( 6, 4 );
  INTERLEAVE( 7, 5 );

  INTERLEAVE( 4, 0 );
  INTERLEAVE( 5, 1 );
  INTERLEAVE( 6, 2 );
  INTERLEAVE( 7, 3 );

#undef INTERLEAVE

#define BUTTERFLY_0( i,j ) \
do { \
   __m512i u = X(j); \
   X(j) = _mm512_sub_epi16( X(j), X(i) ); \
   X(i) = _mm512_add_epi16( u, X(i) ); \
} while(0)


#define BUTTERFLY_N( i,j,n ) \
do { \
   __m512i u = X(j); \
   X(i) = _mm512_slli_epi16( X(i), w[n] ); \
   X(j) = _mm512_sub_epi16( X(j), X(i) ); \
   X(i) = _mm512_add_epi16( u, X(i) ); \
} while(0)

  DO_REDUCE( 0 );
  DO_REDUCE( 1 );
  DO_REDUCE( 2 );
  DO_REDUCE( 3 );
  DO_REDUCE( 4 );
  DO_REDUCE( 5 );
  DO_REDUCE( 6 );
  DO_REDUCE( 7 );

  BUTTERFLY_0( 0, 1 );
  BUTTERFLY_0( 2, 3 );
  BUTTERFLY_0( 4, 5 );
  BUTTERFLY_0( 6, 7 );

  BUTTERFLY_0( 0, 2 );
  BUTTERFLY_0( 4, 6 );
  BUTTERFLY_N( 1, 3, 2 );
  BUTTERFLY_N( 5, 7, 2 );

  DO_REDUCE( 3 );

  BUTTERFLY_0( 0, 4 );
  BUTTERFLY_N( 1, 5, 1 );
  BUTTERFLY_N( 2, 6, 2 );
  BUTTERFLY_N( 3, 7, 3 );

  DO_REDUCE_FULL_S4w( 0 );
  DO_REDUCE_FULL_S4w( 1 );
  DO_REDUCE_FULL_S4w( 2 );
  DO_REDUCE_FULL_S4w( 3 );
  DO_REDUCE_FULL_S4w( 4 );
  DO_REDUCE_FULL_S4w( 5 );
  DO_REDUCE_FULL_S4w( 6 );
  DO_REDUCE_FULL_S4w( 7 );

#undef BUTTERFLY_0
#undef BUTTERFLY_N
#undef DO_REDUCE

  A[0] = X0;
  A[1] = X1;
  A[2] = X2;
  A[3] = X3;
  A[4] = X4;
  A[5] = X5;
  A[6] = X6;
  A[7] = X7;

#undef X
}

void fft128_4way( void *a )
{
  int i;
  // Temp space to help for interleaving in the end
  __m512i B[8];
  __m512i *A = (__m512i*) a;
//  __m256i *Twiddle = (__m256i*)FFT128_Twiddle;

  /* Size-2 butterflies */
  for ( i = 0; i<8; i++ )
  {
    B[ i ]   = _mm512_add_epi16( A[ i ], A[ i+8 ] );
    B[ i ]   = REDUCE_FULL_S4w( B[ i ] );
    A[ i+8 ] = _mm512_sub_epi16( A[ i ], A[ i+8 ] );
    A[ i+8 ] = REDUCE_FULL_S4w( A[ i+8 ] );
    A[ i+8 ] = _mm512_mullo_epi16( A[ i+8 ], FFT128_Twiddle4w[i].v512 );
    A[ i+8 ] = REDUCE_FULL_S4w( A[ i+8 ] );
  }

  fft64_4way( B );
  fft64_4way( A+8 );

  /* Transposi (i.e. interleave) */
  for ( i = 0; i < 8; i++ )
  {
    A[ 2*i   ] = _mm512_unpacklo_epi16( B[ i ], A[ i+8 ] );
    A[ 2*i+1 ] = _mm512_unpackhi_epi16( B[ i ], A[ i+8 ] );
  }
}

void fft128_4way_msg( uint16_t *a, const uint8_t *x, int final )
{
  const __m512i zero = _mm512_setzero_si512();
  static const m512_v16 Tweak =      {{ 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,1,
                                        0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,1 }};
  static const m512_v16 FinalTweak = {{ 0,0,0,0,0,1,0,1, 0,0,0,0,0,1,0,1,
                                        0,0,0,0,0,1,0,1, 0,0,0,0,0,1,0,1 }};

  __m512i *X = (__m512i*)x;
  __m512i *A = (__m512i*)a;
//  __m256i *Twiddle = (__m256i*)FFT128_Twiddle;

#define UNPACK( i ) \
do { \
    __m512i t = X[i]; \
    A[2*i]   = _mm512_unpacklo_epi8( t, zero ); \
    A[2*i+8] = _mm512_mullo_epi16( A[2*i], FFT128_Twiddle4w[2*i].v512 ); \
    A[2*i+8] = REDUCE4w(A[2*i+8]); \
    A[2*i+1] = _mm512_unpackhi_epi8( t, zero ); \
    A[2*i+9] = _mm512_mullo_epi16(A[2*i+1], FFT128_Twiddle4w[2*i+1].v512 ); \
    A[2*i+9] = REDUCE4w(A[2*i+9]); \
} while(0)

    // This allows to tweak the last butterflies to introduce X^127
#define UNPACK_TWEAK( i,tw ) \
do { \
    __m512i t = X[i]; \
    __m512i tmp; \
    A[2*i]   = _mm512_unpacklo_epi8( t, zero ); \
    A[2*i+8] = _mm512_mullo_epi16( A[ 2*i ], FFT128_Twiddle4w[ 2*i ].v512 ); \
    A[2*i+8] = REDUCE4w( A[ 2*i+8 ] ); \
    tmp      = _mm512_unpackhi_epi8( t, zero ); \
    A[2*i+1] = _mm512_add_epi16( tmp, tw ); \
    A[2*i+9] = _mm512_mullo_epi16( _mm512_sub_epi16( tmp, tw ), \
                                   FFT128_Twiddle4w[ 2*i+1 ].v512 );\
    A[2*i+9] = REDUCE4w( A[ 2*i+9 ] );                       \
} while(0)

  UNPACK( 0 );
  UNPACK( 1 );
  UNPACK( 2 );
  if ( final )
    UNPACK_TWEAK( 3, FinalTweak.v512 );
  else
    UNPACK_TWEAK( 3, Tweak.v512 );

#undef UNPACK
#undef UNPACK_TWEAK

  fft64_4way( a );
  fft64_4way( a+256 );
}

void fft256_4way_msg( uint16_t *a, const uint8_t *x, int final )
{
  const __m512i zero = _mm512_setzero_si512();
  static const m512_v16 Tweak      = {{ 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,1,
                                        0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,1 }};
  static const m512_v16 FinalTweak = {{ 0,0,0,0,0,1,0,1, 0,0,0,0,0,1,0,1,
                                        0,0,0,0,0,1,0,1, 0,0,0,0,0,1,0,1 }};

  __m512i *X = (__m512i*)x;
  __m512i *A = (__m512i*)a;
//  __m256i *Twiddle = (__m256i*)FFT256_Twiddle;

#define UNPACK( i ) \
do { \
    __m512i t = X[i]; \
    A[ 2*i      ] = _mm512_unpacklo_epi8( t, zero ); \
    A[ 2*i + 16 ] = _mm512_mullo_epi16( A[ 2*i ], \
                                        FFT256_Twiddle4w[ 2*i ].v512 ); \
    A[ 2*i + 16 ] = REDUCE4w( A[ 2*i + 16 ] ); \
    A[ 2*i +  1 ] = _mm512_unpackhi_epi8( t, zero ); \
    A[ 2*i + 17 ] = _mm512_mullo_epi16( A[ 2*i + 1 ], \
                                        FFT256_Twiddle4w[ 2*i + 1 ].v512 ); \
    A[ 2*i + 17 ] = REDUCE4w( A[ 2*i + 17 ] ); \
} while(0)

   // This allows to tweak the last butterflies to introduce X^127
#define UNPACK_TWEAK( i,tw ) \
do { \
    __m512i t = X[i]; \
    __m512i tmp; \
    A[ 2*i      ] = _mm512_unpacklo_epi8( t, zero ); \
    A[ 2*i + 16 ] = _mm512_mullo_epi16( A[ 2*i ], \
                                        FFT256_Twiddle4w[ 2*i ].v512 ); \
    A[ 2*i + 16 ] = REDUCE4w( A[ 2*i + 16 ] ); \
    tmp           = _mm512_unpackhi_epi8( t, zero ); \
    A[ 2*i +  1 ] = _mm512_add_epi16( tmp, tw ); \
    A[ 2*i + 17 ] = _mm512_mullo_epi16( _mm512_sub_epi16( tmp, tw ), \
                                        FFT256_Twiddle4w[ 2*i + 1 ].v512 ); \
  } while(0)

  UNPACK( 0 );
  UNPACK( 1 );
  UNPACK( 2 );
  UNPACK( 3 );
  UNPACK( 4 );
  UNPACK( 5 );
  UNPACK( 6 );
  if ( final )
    UNPACK_TWEAK( 7, FinalTweak.v512 );
  else
    UNPACK_TWEAK( 7, Tweak.v512 );

#undef UNPACK
#undef UNPACK_TWEAK

  fft128_4way( a );
  fft128_4way( a+512 );
}

#define c1_16_512( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

void rounds512_4way( uint32_t *state, const uint8_t *msg, uint16_t *fft )
{
  register __m512i S0l, S1l, S2l, S3l;
  register __m512i S0h, S1h, S2h, S3h;
  __m512i *S = (__m512i*) state;
  __m512i *M = (__m512i*) msg;
  __m512i *W = (__m512i*) fft;

  static const m512_v16 code[] = { c1_16_512(185), c1_16_512(233) };

  S0l = _mm512_xor_si512( S[0], M[0] );
  S0h = _mm512_xor_si512( S[1], M[1] );
  S1l = _mm512_xor_si512( S[2], M[2] );
  S1h = _mm512_xor_si512( S[3], M[3] );
  S2l = _mm512_xor_si512( S[4], M[4] );
  S2h = _mm512_xor_si512( S[5], M[5] );
  S3l = _mm512_xor_si512( S[6], M[6] );
  S3h = _mm512_xor_si512( S[7], M[7] );

// targetted, local macros don't need a unique name
#define S(i) S##i

#define F_0( B, C, D ) _mm512_ternarylogic_epi32( B, C, D, 0xca )
#define F_1( B, C, D ) _mm512_ternarylogic_epi32( B, C, D, 0xe8 )  

/*  
#define F_0(B, C, D) \
   _mm512_xor_si512( _mm512_and_si512( _mm512_xor_si512( C,D ), B ), D )
#define F_1(B, C, D) \
   _mm512_or_si512( _mm512_and_si512( D, C ),\
                    _mm512_and_si512( _mm512_or_si512( D,C ), B ) )
*/

#define Fl(a,b,c,fun) F_##fun (a##l,b##l,c##l)
#define Fh(a,b,c,fun) F_##fun (a##h,b##h,c##h)

  // We split the round function in two halfes
  // so as to insert some independent computations in between

// generic
#if 0
#define SUM7_00 0
#define SUM7_01 1
#define SUM7_02 2
#define SUM7_03 3
#define SUM7_04 4
#define SUM7_05 5
#define SUM7_06 6

#define SUM7_10 1
#define SUM7_11 2
#define SUM7_12 3
#define SUM7_13 4
#define SUM7_14 5
#define SUM7_15 6
#define SUM7_16 0

#define SUM7_20 2
#define SUM7_21 3
#define SUM7_22 4
#define SUM7_23 5
#define SUM7_24 6
#define SUM7_25 0
#define SUM7_26 1

#define SUM7_30 3
#define SUM7_31 4
#define SUM7_32 5
#define SUM7_33 6
#define SUM7_34 0
#define SUM7_35 1
#define SUM7_36 2

#define SUM7_40 4
#define SUM7_41 5
#define SUM7_42 6
#define SUM7_43 0
#define SUM7_44 1
#define SUM7_45 2
#define SUM7_46 3

#define SUM7_50 5
#define SUM7_51 6
#define SUM7_52 0
#define SUM7_53 1
#define SUM7_54 2
#define SUM7_55 3
#define SUM7_56 4

#define SUM7_60 6
#define SUM7_61 0
#define SUM7_62 1
#define SUM7_63 2
#define SUM7_64 3
#define SUM7_65 4
#define SUM7_66 5

#define PERM(z,d,a) XCAT(PERM_,XCAT(SUM7_##z,PERM_START))(d,a)

#define PERM_0(d,a) /* XOR 1 */ \
do { \
    d##l = shufxor( a##l, 1 ); \
    d##h = shufxor( a##h, 1 ); \
 } while(0)

#define PERM_1(d,a) /* XOR 6 */ \
do { \
    d##l = shufxor( a##h, 2 ); \
    d##h = shufxor( a##l, 2 ); \
} while(0)

#define PERM_2(d,a) /* XOR 2 */ \
do { \
    d##l = shufxor( a##l, 2 ); \
    d##h = shufxor( a##h, 2 ); \
} while(0)

#define PERM_3(d,a) /* XOR 3 */ \
do { \
    d##l = shufxor( a##l, 3 ); \
    d##h = shufxor( a##h, 3 ); \
} while(0)

#define PERM_4(d,a) /* XOR 5 */ \
do { \
    d##l = shufxor( a##h, 1 ); \
    d##h = shufxor( a##l, 1 ); \
} while(0)

#define PERM_5(d,a) /* XOR 7 */ \
do { \
    d##l = shufxor( a##h, 3 ); \
    d##h = shufxor( a##l, 3 ); \
} while(0)

#define PERM_6(d,a) /* XOR 4 */ \
do { \
    d##l = a##h; \
    d##h = a##l; \
} while(0)
#endif

// targetted
  
#define STEP_1_(a,b,c,d,w,fun,r,s,z) \
do { \
    TTl  = Fl( a,b,c,fun ); \
    TTh  = Fh( a,b,c,fun ); \
    a##l = mm512_rol_32( a##l, r ); \
    a##h = mm512_rol_32( a##h, r ); \
    w##l = _mm512_add_epi32( w##l, d##l ); \
    w##h = _mm512_add_epi32( w##h, d##h ); \
    TTl  = _mm512_add_epi32( TTl, w##l ); \
    TTh  = _mm512_add_epi32( TTh, w##h ); \
    TTl  = mm512_rol_32( TTl, s ); \
    TTh  = mm512_rol_32( TTh, s ); \
    PERM( z,d,a, shufxor4w ); \
} while(0)

#define STEP_1( a,b,c,d,w,fun,r,s,z )   STEP_1_( a,b,c,d,w,fun,r,s,z )

#define STEP_2_( a,b,c,d,w,fun,r,s ) \
do { \
    d##l = _mm512_add_epi32( d##l, TTl ); \
    d##h = _mm512_add_epi32( d##h, TTh ); \
} while(0)

#define STEP_2( a,b,c,d,w,fun,r,s )  STEP_2_( a,b,c,d,w,fun,r,s )

#define STEP( a,b,c,d,w1,w2,fun,r,s,z ) \
do { \
    register __m512i TTl, TTh, Wl=w1, Wh=w2; \
    STEP_1( a,b,c,d,W,fun,r,s,z ); \
    STEP_2( a,b,c,d,W,fun,r,s ); \
} while(0);

#define MSG_l(x) (2*(x))
#define MSG_h(x) (2*(x)+1)

#define MSG( w,hh,ll,u,z ) \
do { \
    int a = MSG_##u(hh); \
    int b = MSG_##u(ll); \
    w##l = _mm512_unpacklo_epi16( W[a], W[b] ); \
    w##l = _mm512_mullo_epi16( w##l, code[z].v512 ); \
    w##h = _mm512_unpackhi_epi16( W[a], W[b]) ; \
    w##h = _mm512_mullo_epi16( w##h, code[z].v512 ); \
} while(0)
  
#define ROUND( h0,l0,u0,h1,l1,u1,h2,l2,u2,h3,l3,u3,fun,r,s,t,u,z ) \
do { \
    register __m512i W0l, W1l, W2l, W3l, TTl; \
    register __m512i W0h, W1h, W2h, W3h, TTh; \
    MSG( W0, h0, l0, u0, z ); \
    STEP_1( S(0), S(1), S(2), S(3), W0, fun, r, s, 0 ); \
    MSG( W1, h1, l1, u1, z ); \
    STEP_2( S(0), S(1), S(2), S(3), W0, fun, r, s ); \
    STEP_1( S(3), S(0), S(1), S(2), W1, fun, s, t, 1 ); \
    MSG( W2,h2,l2,u2,z ); \
    STEP_2( S(3), S(0), S(1), S(2), W1, fun, s, t ); \
    STEP_1( S(2), S(3), S(0), S(1), W2, fun, t, u, 2 ); \
    MSG( W3,h3,l3,u3,z ); \
    STEP_2( S(2), S(3), S(0), S(1), W2, fun, t, u ); \
    STEP_1( S(1), S(2), S(3), S(0), W3, fun, u, r, 3 ); \
    STEP_2( S(1), S(2), S(3), S(0), W3, fun, u, r ); \
} while(0)

   // 4 rounds with code 185
#define PERM_START 0
   ROUND(  2, 10, l,  3, 11, l,  0,  8, l,  1,  9, l, 0, 3,  23, 17, 27, 0);
#undef PERM_START
#define PERM_START 4
   ROUND(  3, 11, h,  2, 10, h,  1,  9, h,  0,  8, h, 1, 3,  23, 17, 27, 0);
#undef PERM_START
#define PERM_START 1
   ROUND(  7, 15, h,  5, 13, h,  6, 14, l,  4, 12, l, 0, 28, 19, 22, 7,  0);
#undef PERM_START
#define PERM_START 5
   ROUND(  4, 12, h,  6, 14, h,  5, 13, l,  7, 15, l, 1, 28, 19, 22, 7,  0);
#undef PERM_START

   // 4 rounds with code 233
#define PERM_START 2
   ROUND(  0,  4, h,  1,  5, l,  3,  7, h,  2,  6, l, 0, 29,  9, 15,  5, 1);
#undef PERM_START
#define PERM_START 6
   ROUND(  3,  7, l,  2,  6, h,  0,  4, l,  1,  5, h, 1, 29,  9, 15,  5, 1);
#undef PERM_START
#define PERM_START 3
   ROUND( 11, 15, l,  8, 12, l,  8, 12, h, 11, 15, h, 0,  4, 13, 10, 25, 1);
#undef PERM_START
#define PERM_START 0
   ROUND(  9, 13, h, 10, 14, h, 10, 14, l,  9, 13, l, 1,  4, 13, 10, 25, 1);
#undef PERM_START

   // 1 round as feed-forward
#define PERM_START 4
   STEP( S(0), S(1), S(2), S(3), S[0], S[1], 0,  4, 13, 0 );
   STEP( S(3), S(0), S(1), S(2), S[2], S[3], 0, 13, 10, 1 );
   STEP( S(2), S(3), S(0), S(1), S[4], S[5], 0, 10, 25, 2 );
   STEP( S(1), S(2), S(3), S(0), S[6], S[7], 0, 25,  4, 3 );

   S[0] = S0l;  S[1] = S0h;  S[2] = S1l;  S[3] = S1h;
   S[4] = S2l;  S[5] = S2h;  S[6] = S3l;  S[7] = S3h;

#undef PERM_START
#undef STEP_1
#undef STEP_1_
#undef STEP_2
#undef STEP_2_
#undef STEP
#undef ROUND
#undef S
#undef F_0
#undef F_1
#undef Fl
#undef Fh
#undef MSG_l
#undef MSG_h
#undef MSG
}

void SIMD_4way_Compress( simd_4way_context *state, const void *m, int final )
{
   m512_v16 Y[32];
   uint16_t *y = (uint16_t*) Y[0].u16;

   fft256_4way_msg( y, m, final );

   rounds512_4way( state->A, m, y );
}

// imported from nist.c

int simd_4way_init( simd_4way_context *state, int hashbitlen )
{
  __m512i *A = (__m512i*)state->A;
  int n = 8;

  state->hashbitlen = hashbitlen;
  state->n_feistels = n;
  state->blocksize = 128*8;
  state->count = 0;

  for ( int i = 0; i < 8; i++ )
       A[i] = _mm512_set4_epi32( SIMD_IV_512[4*i+3], SIMD_IV_512[4*i+2],
                                 SIMD_IV_512[4*i+1], SIMD_IV_512[4*i+0] );
  return 0;
}

int simd_4way_update( simd_4way_context *state, const void *data,
                             int databitlen )
{
  int bs      = state->blocksize;
  int current = state->count & (bs - 1);

  while ( databitlen > 0 )
  {
    if ( ( current == 0 ) && ( databitlen >= bs ) )
    {
       // We can hash the data directly from the input buffer.
      SIMD_4way_Compress( state, data, 0 );
      databitlen -= bs;
      data += 4*(bs/8);
      state->count += bs;
    }
    else
    {
       // Copy a chunk of data to the buffer
      int len = bs - current;
      if ( databitlen < len )
      {
        memcpy( state->buffer + 4 * (current/8), data, 4 * (databitlen/8) );
        state->count += databitlen;
        return 0;
      }
      else
      {
        memcpy( state->buffer + 4 * (current / 8), data, 4 * (len / 8) );
        state->count += len;
        databitlen -= len;
        data += 4*(len/8);
        current = 0;
        SIMD_4way_Compress( state, state->buffer, 0 );
      }
    }
  }
  return 0;
}

int simd_4way_close( simd_4way_context *state, void *hashval )
{
  uint64_t l;
  int current = state->count & (state->blocksize - 1);
  int i;
  int isshort = 1;

  // If there is still some data in the buffer, hash it
  if ( current )
  {
    current = ( current+7 ) / 8;
    memset( state->buffer + 4*current, 0, 4*( state->blocksize/8 - current ) );
    SIMD_4way_Compress( state, state->buffer, 0 );
  }

  //* Input the message length as the last block
  memset( state->buffer, 0, 4*(state->blocksize / 8) );
  l = state->count;
  for ( i = 0; i < 8; i++ )
  {
    state->buffer[ i    ] = l & 0xff;
    state->buffer[ i+16 ] = l & 0xff;
    state->buffer[ i+32 ] = l & 0xff;
    state->buffer[ i+48 ] = l & 0xff;
    l >>= 8;
  }
  if ( state->count < 16384 )
    isshort = 2;

  SIMD_4way_Compress( state, state->buffer, isshort );
  memcpy( hashval, state->A, 4*(state->hashbitlen / 8) );

  return 0;
}

int simd_4way_update_close( simd_4way_context *state, void *hashval,
                            const void *data, int databitlen )
{
  int current, i;
  int bs = state->blocksize;  // bits in one lane
  int isshort = 1;
  uint64_t l;

  current = state->count & (bs - 1);

  while ( databitlen > 0 )
  {
    if ( current == 0 && databitlen >= bs )
    {
      // We can hash the data directly from the input buffer.
      SIMD_4way_Compress( state, data, 0 );
      databitlen -= bs;
      data += 4*( bs/8 );
      state->count += bs;
    }
    else
    {
      // Copy a chunk of data to the buffer
      int len = bs - current;
      if ( databitlen < len )
      {
        memcpy( state->buffer + 4*( current/8 ), data, 4*( (databitlen)/8 ) );
        state->count += databitlen;
        break;
      }
      else
      {
        memcpy( state->buffer + 4*(current/8), data, 4*(len/8) );
        state->count += len;
        databitlen -= len;
        data += 4*( len/8 );
        current = 0;
        SIMD_4way_Compress( state, state->buffer, 0 );
      }
    }
  }

  current = state->count & (state->blocksize - 1);

  // If there is still some data in the buffer, hash it
  if ( current )
  {
    current = current / 8;
    memset( state->buffer + 4*current, 0, 4*( state->blocksize/8 - current) );
    SIMD_4way_Compress( state, state->buffer, 0 );
  }

  //* Input the message length as the last block
  memset( state->buffer, 0, 4*( state->blocksize/8 ) );
  l = state->count;
  for ( i = 0; i < 8; i++ )
  {
    state->buffer[ i    ] = l & 0xff;
    state->buffer[ i+16 ] = l & 0xff;
    state->buffer[ i+32 ] = l & 0xff;
    state->buffer[ i+48 ] = l & 0xff;
    l >>= 8;
  }
  if ( state->count < 16384 )
    isshort = 2;

  SIMD_4way_Compress( state, state->buffer, isshort );
  memcpy( hashval, state->A, 4*( state->hashbitlen / 8 ) );
  return 0;
}

int simd512_4way_full( simd_4way_context *state, void *hashval,
                    const void *data, int datalen )
{
  __m512i *A = (__m512i*)state->A;

  state->hashbitlen = 512;
  state->n_feistels = 8;
  state->blocksize = 128*8;
  state->count = 0;

  for ( int i = 0; i < 8; i++ )
       A[i] = _mm512_set4_epi32( SIMD_IV_512[4*i+3], SIMD_IV_512[4*i+2],
                                 SIMD_IV_512[4*i+1], SIMD_IV_512[4*i+0] );

  int current, i;
  int bs = state->blocksize;  // bits in one lane
  int isshort = 1;
  uint64_t l;
  int databitlen = datalen * 8;

  current = state->count & (bs - 1);

  while ( databitlen > 0 )
  {
    if ( current == 0 && databitlen >= bs )
    {
      // We can hash the data directly from the input buffer.
      SIMD_4way_Compress( state, data, 0 );
      databitlen -= bs;
      data += 4*( bs/8 );
      state->count += bs;
    }
    else
    {
      // Copy a chunk of data to the buffer
      int len = bs - current;
      if ( databitlen < len )
      {
        memcpy( state->buffer + 4*( current/8 ), data, 4*( (databitlen)/8 ) );
        state->count += databitlen;
        break;
      }
      else
      {
        memcpy( state->buffer + 4*(current/8), data, 4*(len/8) );
        state->count += len;
        databitlen -= len;
        data += 4*( len/8 );
        current = 0;
        SIMD_4way_Compress( state, state->buffer, 0 );
      }
    }
  }

  current = state->count & (state->blocksize - 1);

  // If there is still some data in the buffer, hash it
  if ( current )
  {
    current = current / 8;
    memset( state->buffer + 4*current, 0, 4*( state->blocksize/8 - current) );
    SIMD_4way_Compress( state, state->buffer, 0 );
  }

  //* Input the message length as the last block
  memset( state->buffer, 0, 4*( state->blocksize/8 ) );
  l = state->count;
  for ( i = 0; i < 8; i++ )
  {
    state->buffer[ i    ] = l & 0xff;
    state->buffer[ i+16 ] = l & 0xff;
    state->buffer[ i+32 ] = l & 0xff;
    state->buffer[ i+48 ] = l & 0xff;
    l >>= 8;
  }
  if ( state->count < 16384 )
    isshort = 2;

  SIMD_4way_Compress( state, state->buffer, isshort );
  memcpy( hashval, state->A, 4*( state->hashbitlen / 8 ) );
  return 0;
}



#endif // AVX512

////////////////////////////////////
//
// SIMD 2 way AVX2

void fft64_2way( void *a )
{
  __m256i* const A = a;
  register __m256i X0, X1, X2, X3, X4, X5, X6, X7;

#define X(i) X##i

  X0 = A[0];
  X1 = A[1];
  X2 = A[2];
  X3 = A[3];
  X4 = A[4];
  X5 = A[5];
  X6 = A[6];
  X7 = A[7];

#define DO_REDUCE(i)   X(i) = REDUCE( X(i) )

   // Begin with 8 parallels DIF FFT_8
   //
   // FFT_8 using w=4 as 8th root of unity
   //  Unrolled decimation in frequency (DIF) radix-2 NTT.
   //  Output data is in revbin_permuted order.

  static const int w[] = {0, 2, 4, 6};
//   __m256i *Twiddle = (__m256i*)FFT64_Twiddle;


#define BUTTERFLY_0( i,j ) \
do { \
    __m256i v = X(j); \
    X(j) = _mm256_add_epi16( X(i), X(j) ); \
    X(i) = _mm256_sub_epi16( X(i), v ); \
} while(0)

#define BUTTERFLY_N( i,j,n ) \
do { \
    __m256i v = X(j); \
    X(j) = _mm256_add_epi16( X(i), X(j) ); \
    X(i) = _mm256_slli_epi16( _mm256_sub_epi16( X(i), v ), w[n] ); \
} while(0)

  BUTTERFLY_0( 0, 4 );
  BUTTERFLY_N( 1, 5, 1 );
  BUTTERFLY_N( 2, 6, 2 );
  BUTTERFLY_N( 3, 7, 3 );

  DO_REDUCE( 2 );
  DO_REDUCE( 3 );

  BUTTERFLY_0( 0, 2 );
  BUTTERFLY_0( 4, 6 );
  BUTTERFLY_N( 1, 3, 2 );
  BUTTERFLY_N( 5, 7, 2 );

  DO_REDUCE( 1 );

  BUTTERFLY_0( 0, 1 );
  BUTTERFLY_0( 2, 3 );
  BUTTERFLY_0( 4, 5 );
  BUTTERFLY_0( 6, 7 );

  /* We don't need to reduce X(7) */
  DO_REDUCE_FULL_S( 0 );
  DO_REDUCE_FULL_S( 1 );
  DO_REDUCE_FULL_S( 2 );
  DO_REDUCE_FULL_S( 3 );
  DO_REDUCE_FULL_S( 4 );
  DO_REDUCE_FULL_S( 5 );
  DO_REDUCE_FULL_S( 6 );

#undef BUTTERFLY_0
#undef BUTTERFLY_N

  // Multiply by twiddle factors
  X(6) = _mm256_mullo_epi16( X(6), FFT64_Twiddle[0].v256 );
  X(5) = _mm256_mullo_epi16( X(5), FFT64_Twiddle[1].v256 );
  X(4) = _mm256_mullo_epi16( X(4), FFT64_Twiddle[2].v256 );
  X(3) = _mm256_mullo_epi16( X(3), FFT64_Twiddle[3].v256 );
  X(2) = _mm256_mullo_epi16( X(2), FFT64_Twiddle[4].v256 );
  X(1) = _mm256_mullo_epi16( X(1), FFT64_Twiddle[5].v256 );
  X(0) = _mm256_mullo_epi16( X(0), FFT64_Twiddle[6].v256 );

  // Transpose the FFT state with a revbin order permutation
  // on the rows and the column.
  // This will make the full FFT_64 in order.
#define INTERLEAVE(i,j) \
  do { \
    __m256i t1= X(i); \
    __m256i t2= X(j); \
    X(i) = _mm256_unpacklo_epi16( t1, t2 ); \
    X(j) = _mm256_unpackhi_epi16( t1, t2 ); \
  } while(0)

  INTERLEAVE( 1, 0 );
  INTERLEAVE( 3, 2 );
  INTERLEAVE( 5, 4 );
  INTERLEAVE( 7, 6 );

  INTERLEAVE( 2, 0 );
  INTERLEAVE( 3, 1 );
  INTERLEAVE( 6, 4 );
  INTERLEAVE( 7, 5 );

  INTERLEAVE( 4, 0 );
  INTERLEAVE( 5, 1 );
  INTERLEAVE( 6, 2 );
  INTERLEAVE( 7, 3 );

#undef INTERLEAVE

   //Finish with 8 parallels DIT FFT_8
   //FFT_8 using w=4 as 8th root of unity
   // Unrolled decimation in time (DIT) radix-2 NTT.
   // Input data is in revbin_permuted order.

#define BUTTERFLY_0( i,j ) \
do { \
   __m256i u = X(j); \
   X(j) = _mm256_sub_epi16( X(j), X(i) ); \
   X(i) = _mm256_add_epi16( u, X(i) ); \
} while(0)


#define BUTTERFLY_N( i,j,n ) \
do { \
   __m256i u = X(j); \
   X(i) = _mm256_slli_epi16( X(i), w[n] ); \
   X(j) = _mm256_sub_epi16( X(j), X(i) ); \
   X(i) = _mm256_add_epi16( u, X(i) ); \
} while(0)

  DO_REDUCE( 0 );
  DO_REDUCE( 1 );
  DO_REDUCE( 2 );
  DO_REDUCE( 3 );
  DO_REDUCE( 4 );
  DO_REDUCE( 5 );
  DO_REDUCE( 6 );
  DO_REDUCE( 7 );

  BUTTERFLY_0( 0, 1 );
  BUTTERFLY_0( 2, 3 );
  BUTTERFLY_0( 4, 5 );
  BUTTERFLY_0( 6, 7 );

  BUTTERFLY_0( 0, 2 );
  BUTTERFLY_0( 4, 6 );
  BUTTERFLY_N( 1, 3, 2 );
  BUTTERFLY_N( 5, 7, 2 );

  DO_REDUCE( 3 );

  BUTTERFLY_0( 0, 4 );
  BUTTERFLY_N( 1, 5, 1 );
  BUTTERFLY_N( 2, 6, 2 );
  BUTTERFLY_N( 3, 7, 3 );

  DO_REDUCE_FULL_S( 0 );
  DO_REDUCE_FULL_S( 1 );
  DO_REDUCE_FULL_S( 2 );
  DO_REDUCE_FULL_S( 3 );
  DO_REDUCE_FULL_S( 4 );
  DO_REDUCE_FULL_S( 5 );
  DO_REDUCE_FULL_S( 6 );
  DO_REDUCE_FULL_S( 7 );

#undef BUTTERFLY_0
#undef BUTTERFLY_N
#undef DO_REDUCE

  A[0] = X0;
  A[1] = X1;
  A[2] = X2;
  A[3] = X3;
  A[4] = X4;
  A[5] = X5;
  A[6] = X6;
  A[7] = X7;

#undef X
}

void fft128_2way( void *a )
{
  int i;
  // Temp space to help for interleaving in the end
  __m256i B[8];
  __m256i *A = (__m256i*) a;
//  __m256i *Twiddle = (__m256i*)FFT128_Twiddle;

  /* Size-2 butterflies */
  for ( i = 0; i<8; i++ )
  {
    B[ i ]   = _mm256_add_epi16( A[ i ], A[ i+8 ] );
    B[ i ]   = REDUCE_FULL_S( B[ i ] );
    A[ i+8 ] = _mm256_sub_epi16( A[ i ], A[ i+8 ] );
    A[ i+8 ] = REDUCE_FULL_S( A[ i+8 ] );
    A[ i+8 ] = _mm256_mullo_epi16( A[ i+8 ], FFT128_Twiddle[i].v256 );
    A[ i+8 ] = REDUCE_FULL_S( A[ i+8 ] );
  }

  fft64_2way( B );
  fft64_2way( A+8 );

  /* Transpose (i.e. interleave) */
  for ( i = 0; i < 8; i++ )
  {
    A[ 2*i   ] = _mm256_unpacklo_epi16( B[ i ], A[ i+8 ] );
    A[ 2*i+1 ] = _mm256_unpackhi_epi16( B[ i ], A[ i+8 ] );
  }
}

void fft128_2way_msg( uint16_t *a, const uint8_t *x, int final )
{
  const __m256i zero = _mm256_setzero_si256();
  static const m256_v16 Tweak      = {{ 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,1, }};
  static const m256_v16 FinalTweak = {{ 0,0,0,0,0,1,0,1, 0,0,0,0,0,1,0,1, }};

  __m256i *X = (__m256i*)x;
  __m256i *A = (__m256i*)a;
//  __m256i *Twiddle = (__m256i*)FFT128_Twiddle;

#define UNPACK( i ) \
do { \
    __m256i t = X[i]; \
    A[2*i]   = _mm256_unpacklo_epi8( t, zero ); \
    A[2*i+8] = _mm256_mullo_epi16( A[2*i], FFT128_Twiddle[2*i].v256 ); \
    A[2*i+8] = REDUCE(A[2*i+8]); \
    A[2*i+1] = _mm256_unpackhi_epi8( t, zero ); \
    A[2*i+9] = _mm256_mullo_epi16(A[2*i+1], FFT128_Twiddle[2*i+1].v256 ); \
    A[2*i+9] = REDUCE(A[2*i+9]); \
} while(0)

    // This allows to tweak the last butterflies to introduce X^127
#define UNPACK_TWEAK( i,tw ) \
do { \
    __m256i t = X[i]; \
    __m256i tmp; \
    A[2*i]   = _mm256_unpacklo_epi8( t, zero ); \
    A[2*i+8] = _mm256_mullo_epi16( A[ 2*i ], FFT128_Twiddle[ 2*i ].v256 ); \
    A[2*i+8] = REDUCE( A[ 2*i+8 ] ); \
    tmp      = _mm256_unpackhi_epi8( t, zero ); \
    A[2*i+1] = _mm256_add_epi16( tmp, tw ); \
    A[2*i+9] = _mm256_mullo_epi16( _mm256_sub_epi16( tmp, tw ), \
                                   FFT128_Twiddle[ 2*i+1 ].v256 );\
    A[2*i+9] = REDUCE( A[ 2*i+9 ] );                       \
} while(0)

  UNPACK( 0 );
  UNPACK( 1 );
  UNPACK( 2 );
  if ( final )
    UNPACK_TWEAK( 3, FinalTweak.v256 );
  else
    UNPACK_TWEAK( 3, Tweak.v256 );

#undef UNPACK
#undef UNPACK_TWEAK

  fft64_2way( a );
  fft64_2way( a+128 );
}

void fft256_2way_msg( uint16_t *a, const uint8_t *x, int final )
{
  const __m256i zero = _mm256_setzero_si256();
  static const m256_v16 Tweak      = {{ 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,1, }};
  static const m256_v16 FinalTweak = {{ 0,0,0,0,0,1,0,1, 0,0,0,0,0,1,0,1, }};

  __m256i *X = (__m256i*)x;
  __m256i *A = (__m256i*)a;
//  __m256i *Twiddle = (__m256i*)FFT256_Twiddle;

#define UNPACK( i ) \
do { \
    __m256i t = X[i]; \
    A[ 2*i      ] = _mm256_unpacklo_epi8( t, zero ); \
    A[ 2*i + 16 ] = _mm256_mullo_epi16( A[ 2*i ], \
                                        FFT256_Twiddle[ 2*i ].v256 ); \
    A[ 2*i + 16 ] = REDUCE( A[ 2*i + 16 ] ); \
    A[ 2*i +  1 ] = _mm256_unpackhi_epi8( t, zero ); \
    A[ 2*i + 17 ] = _mm256_mullo_epi16( A[ 2*i + 1 ], \
                                        FFT256_Twiddle[ 2*i + 1 ].v256 ); \
    A[ 2*i + 17 ] = REDUCE( A[ 2*i + 17 ] ); \
} while(0)

   // This allows to tweak the last butterflies to introduce X^127
#define UNPACK_TWEAK( i,tw ) \
do { \
    __m256i t = X[i]; \
    __m256i tmp; \
    A[ 2*i      ] = _mm256_unpacklo_epi8( t, zero ); \
    A[ 2*i + 16 ] = _mm256_mullo_epi16( A[ 2*i ], \
                                        FFT256_Twiddle[ 2*i ].v256 ); \
    A[ 2*i + 16 ] = REDUCE( A[ 2*i + 16 ] ); \
    tmp           = _mm256_unpackhi_epi8( t, zero ); \
    A[ 2*i +  1 ] = _mm256_add_epi16( tmp, tw ); \
    A[ 2*i + 17 ] = _mm256_mullo_epi16( _mm256_sub_epi16( tmp, tw ), \
                                        FFT256_Twiddle[ 2*i + 1 ].v256 ); \
  } while(0)

  UNPACK( 0 );
  UNPACK( 1 );
  UNPACK( 2 );
  UNPACK( 3 );
  UNPACK( 4 );
  UNPACK( 5 );
  UNPACK( 6 );
  if ( final )
    UNPACK_TWEAK( 7, FinalTweak.v256 );
  else
    UNPACK_TWEAK( 7, Tweak.v256 );

#undef UNPACK
#undef UNPACK_TWEAK

  fft128_2way( a );
  fft128_2way( a+256 );

}

#define c1_16( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

void rounds512_2way( uint32_t *state, const uint8_t *msg, uint16_t *fft )
{
  register __m256i S0l, S1l, S2l, S3l;
  register __m256i S0h, S1h, S2h, S3h;
  __m256i *S = (__m256i*) state;
  __m256i *M = (__m256i*) msg;
  __m256i *W = (__m256i*) fft;
  static const m256_v16 code[] = { c1_16(185), c1_16(233) };
  

  S0l = _mm256_xor_si256( S[0], M[0] );
  S0h = _mm256_xor_si256( S[1], M[1] );
  S1l = _mm256_xor_si256( S[2], M[2] );
  S1h = _mm256_xor_si256( S[3], M[3] );
  S2l = _mm256_xor_si256( S[4], M[4] );
  S2h = _mm256_xor_si256( S[5], M[5] );
  S3l = _mm256_xor_si256( S[6], M[6] );
  S3h = _mm256_xor_si256( S[7], M[7] );

#define S(i) S##i

#define F_0(B, C, D) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( C,D ), B ), D )
#define F_1(B, C, D) \
   _mm256_or_si256( _mm256_and_si256( D, C ),\
                    _mm256_and_si256( _mm256_or_si256( D,C ), B ) )

#define Fl(a,b,c,fun) F_##fun (a##l,b##l,c##l)
#define Fh(a,b,c,fun) F_##fun (a##h,b##h,c##h)

  // We split the round function in two halfes
  // so as to insert some independent computations in between
#if 0
#define SUM7_00 0
#define SUM7_01 1
#define SUM7_02 2
#define SUM7_03 3
#define SUM7_04 4
#define SUM7_05 5
#define SUM7_06 6

#define SUM7_10 1
#define SUM7_11 2
#define SUM7_12 3
#define SUM7_13 4
#define SUM7_14 5
#define SUM7_15 6
#define SUM7_16 0

#define SUM7_20 2
#define SUM7_21 3
#define SUM7_22 4
#define SUM7_23 5
#define SUM7_24 6
#define SUM7_25 0
#define SUM7_26 1

#define SUM7_30 3
#define SUM7_31 4
#define SUM7_32 5
#define SUM7_33 6
#define SUM7_34 0
#define SUM7_35 1
#define SUM7_36 2

#define SUM7_40 4
#define SUM7_41 5
#define SUM7_42 6
#define SUM7_43 0
#define SUM7_44 1
#define SUM7_45 2
#define SUM7_46 3

#define SUM7_50 5
#define SUM7_51 6
#define SUM7_52 0
#define SUM7_53 1
#define SUM7_54 2
#define SUM7_55 3
#define SUM7_56 4

#define SUM7_60 6
#define SUM7_61 0
#define SUM7_62 1
#define SUM7_63 2
#define SUM7_64 3
#define SUM7_65 4
#define SUM7_66 5

#define PERM(z,d,a) XCAT(PERM_,XCAT(SUM7_##z,PERM_START))(d,a)

#define PERM_0(d,a) /* XOR 1 */ \
do { \
    d##l = shufxor( a##l, 1 ); \
    d##h = shufxor( a##h, 1 ); \
 } while(0)

#define PERM_1(d,a) /* XOR 6 */ \
do { \
    d##l = shufxor( a##h, 2 ); \
    d##h = shufxor( a##l, 2 ); \
} while(0)

#define PERM_2(d,a) /* XOR 2 */ \
do { \
    d##l = shufxor( a##l, 2 ); \
    d##h = shufxor( a##h, 2 ); \
} while(0)

#define PERM_3(d,a) /* XOR 3 */ \
do { \
    d##l = shufxor( a##l, 3 ); \
    d##h = shufxor( a##h, 3 ); \
} while(0)

#define PERM_4(d,a) /* XOR 5 */ \
do { \
    d##l = shufxor( a##h, 1 ); \
    d##h = shufxor( a##l, 1 ); \
} while(0)

#define PERM_5(d,a) /* XOR 7 */ \
do { \
    d##l = shufxor( a##h, 3 ); \
    d##h = shufxor( a##l, 3 ); \
} while(0)

#define PERM_6(d,a) /* XOR 4 */ \
do { \
    d##l = a##h; \
    d##h = a##l; \
} while(0)
#endif

#define STEP_1_(a,b,c,d,w,fun,r,s,z) \
do { \
    TTl  = Fl( a,b,c,fun ); \
    TTh  = Fh( a,b,c,fun ); \
    a##l = mm256_rol_32( a##l, r ); \
    a##h = mm256_rol_32( a##h, r ); \
    w##l = _mm256_add_epi32( w##l, d##l ); \
    w##h = _mm256_add_epi32( w##h, d##h ); \
    TTl  = _mm256_add_epi32( TTl, w##l ); \
    TTh  = _mm256_add_epi32( TTh, w##h ); \
    TTl  = mm256_rol_32( TTl, s ); \
    TTh  = mm256_rol_32( TTh, s ); \
    PERM( z,d,a, shufxor2w ); \
} while(0)

#define STEP_1( a,b,c,d,w,fun,r,s,z )   STEP_1_( a,b,c,d,w,fun,r,s,z )

#define STEP_2_( a,b,c,d,w,fun,r,s ) \
do { \
    d##l = _mm256_add_epi32( d##l, TTl ); \
    d##h = _mm256_add_epi32( d##h, TTh ); \
} while(0)

#define STEP_2( a,b,c,d,w,fun,r,s )  STEP_2_( a,b,c,d,w,fun,r,s )

#define STEP( a,b,c,d,w1,w2,fun,r,s,z ) \
do { \
    register __m256i TTl, TTh, Wl=w1, Wh=w2; \
    STEP_1( a,b,c,d,W,fun,r,s,z ); \
    STEP_2( a,b,c,d,W,fun,r,s ); \
} while(0);

#define MSG_l(x) (2*(x))
#define MSG_h(x) (2*(x)+1)

#define MSG( w,hh,ll,u,z ) \
do { \
    int a = MSG_##u(hh); \
    int b = MSG_##u(ll); \
    w##l = _mm256_unpacklo_epi16( W[a], W[b] ); \
    w##l = _mm256_mullo_epi16( w##l, code[z].v256 ); \
    w##h = _mm256_unpackhi_epi16( W[a], W[b]) ; \
    w##h = _mm256_mullo_epi16( w##h, code[z].v256 ); \
} while(0)

#define ROUND( h0,l0,u0,h1,l1,u1,h2,l2,u2,h3,l3,u3,fun,r,s,t,u,z ) \
do { \
    register __m256i W0l, W1l, W2l, W3l, TTl; \
    register __m256i W0h, W1h, W2h, W3h, TTh; \
    MSG( W0, h0, l0, u0, z ); \
    STEP_1( S(0), S(1), S(2), S(3), W0, fun, r, s, 0 ); \
    MSG( W1, h1, l1, u1, z ); \
    STEP_2( S(0), S(1), S(2), S(3), W0, fun, r, s ); \
    STEP_1( S(3), S(0), S(1), S(2), W1, fun, s, t, 1 ); \
    MSG( W2,h2,l2,u2,z ); \
    STEP_2( S(3), S(0), S(1), S(2), W1, fun, s, t ); \
    STEP_1( S(2), S(3), S(0), S(1), W2, fun, t, u, 2 ); \
    MSG( W3,h3,l3,u3,z ); \
    STEP_2( S(2), S(3), S(0), S(1), W2, fun, t, u ); \
    STEP_1( S(1), S(2), S(3), S(0), W3, fun, u, r, 3 ); \
    STEP_2( S(1), S(2), S(3), S(0), W3, fun, u, r ); \
} while(0)

   // 4 rounds with code 185
#define PERM_START 0
   ROUND(  2, 10, l,  3, 11, l,  0,  8, l,  1,  9, l, 0, 3,  23, 17, 27, 0);
#undef PERM_START
#define PERM_START 4
   ROUND(  3, 11, h,  2, 10, h,  1,  9, h,  0,  8, h, 1, 3,  23, 17, 27, 0);
#undef PERM_START
#define PERM_START 1
   ROUND(  7, 15, h,  5, 13, h,  6, 14, l,  4, 12, l, 0, 28, 19, 22, 7,  0);
#undef PERM_START
#define PERM_START 5
   ROUND(  4, 12, h,  6, 14, h,  5, 13, l,  7, 15, l, 1, 28, 19, 22, 7,  0);
#undef PERM_START

   // 4 rounds with code 233
#define PERM_START 2
   ROUND(  0,  4, h,  1,  5, l,  3,  7, h,  2,  6, l, 0, 29,  9, 15,  5, 1);
#undef PERM_START
#define PERM_START 6
   ROUND(  3,  7, l,  2,  6, h,  0,  4, l,  1,  5, h, 1, 29,  9, 15,  5, 1);
#undef PERM_START
#define PERM_START 3
   ROUND( 11, 15, l,  8, 12, l,  8, 12, h, 11, 15, h, 0,  4, 13, 10, 25, 1);
#undef PERM_START
#define PERM_START 0
   ROUND(  9, 13, h, 10, 14, h, 10, 14, l,  9, 13, l, 1,  4, 13, 10, 25, 1);
#undef PERM_START

   // 1 round as feed-forward
#define PERM_START 4
   STEP( S(0), S(1), S(2), S(3), S[0], S[1], 0,  4, 13, 0 );
   STEP( S(3), S(0), S(1), S(2), S[2], S[3], 0, 13, 10, 1 );
   STEP( S(2), S(3), S(0), S(1), S[4], S[5], 0, 10, 25, 2 );
   STEP( S(1), S(2), S(3), S(0), S[6], S[7], 0, 25,  4, 3 );

   S[0] = S0l;  S[1] = S0h;  S[2] = S1l;  S[3] = S1h;
   S[4] = S2l;  S[5] = S2h;  S[6] = S3l;  S[7] = S3h;

#undef PERM_START
#undef STEP_1
#undef STEP_1_
#undef STEP_2
#undef STEP_2_
#undef STEP
#undef ROUND
#undef S
#undef F_0
#undef F_1
#undef Fl
#undef Fh
#undef MSG_l
#undef MSG_h
#undef MSG
}

void SIMD_2way_Compress( simd_2way_context *state, const void *m, int final )
{
   m256_v16 Y[32];
   uint16_t *y = (uint16_t*) Y[0].u16;

   fft256_2way_msg( y, m, final );

   rounds512_2way( state->A, m, y );
}

// imported from nist.c

int simd_2way_init( simd_2way_context *state, int hashbitlen )
{
  __m256i *A = (__m256i*)state->A;
  int n = 8;

  state->hashbitlen = hashbitlen;
  state->n_feistels = n;
  state->blocksize = 128*8;
  state->count = 0;

  for ( int i = 0; i < 8; i++ )
       A[i] = _mm256_set_epi32( SIMD_IV_512[4*i+3], SIMD_IV_512[4*i+2],
                                SIMD_IV_512[4*i+1], SIMD_IV_512[4*i+0],
                                SIMD_IV_512[4*i+3], SIMD_IV_512[4*i+2],
                                SIMD_IV_512[4*i+1], SIMD_IV_512[4*i+0] );
  return 0;
}

int simd_2way_update( simd_2way_context *state, const void *data,
                             int databitlen )
{
  int bs      = state->blocksize;
  int current = state->count & (bs - 1);

  while ( databitlen > 0 )
  {
    if ( current == 0 && databitlen >= bs )
    {
       // We can hash the data directly from the input buffer.
      SIMD_2way_Compress( state, data, 0 );
      databitlen -= bs;
      data += 2*(bs/8);
      state->count += bs;
    }
    else
    {
       // Copy a chunk of data to the buffer
      int len = bs - current;
      if ( databitlen < len )
      {
        memcpy( state->buffer + 2*(current/8), data, 2*((databitlen+7)/8) );
        state->count += databitlen;
        return 0;
      }
      else
      {
        memcpy( state->buffer + 2*(current/8), data, 2*(len/8) );
        state->count += len;
        databitlen -= len;
        data += 2*(len/8);
        current = 0;
        SIMD_2way_Compress( state, state->buffer, 0 );
      }
    }
  }
  return 0;
}

int simd_2way_close( simd_2way_context *state, void *hashval )
{
  uint64_t l;
  int current = state->count & (state->blocksize - 1);
  int i;
  int isshort = 1;

  // If there is still some data in the buffer, hash it
  if ( current )
  {
    current = ( current+7 ) / 8;
    memset( state->buffer + 2*current, 0, 2*( state->blocksize/8 - current ) );
    SIMD_2way_Compress( state, state->buffer, 0 );
  }

  //* Input the message length as the last block
  memset( state->buffer, 0, 2*(state->blocksize / 8) );
  l = state->count;
  for ( i = 0; i < 8; i++ )
  {
    state->buffer[ i     ] = l & 0xff;
    state->buffer[ i+16 ] = l & 0xff;
    l >>= 8;
  }
  if ( state->count < 16384 )
    isshort = 2;

  SIMD_2way_Compress( state, state->buffer, isshort );
  memcpy( hashval, state->A, 2*(state->hashbitlen / 8) );

  return 0;
}

int simd_2way_update_close( simd_2way_context *state, void *hashval,
                            const void *data, int databitlen )
{
  int current, i;
  int bs = state->blocksize;  // bits in one lane
  int isshort = 1;
  uint64_t l;

  current = state->count & (bs - 1);

  while ( databitlen > 0 )
  {
    if ( current == 0 && databitlen >= bs )
    {
      // We can hash the data directly from the input buffer.
      SIMD_2way_Compress( state, data, 0 );

      databitlen -= bs;
      data += 2*( bs/8 );
      state->count += bs;
    }
    else
    {
      // Copy a chunk of data to the buffer
      int len = bs - current;
      if ( databitlen < len )
      {

         memcpy( state->buffer + 2*( current/8 ), data, 2*( (databitlen+7)/8 ) );
        state->count += databitlen;
        break;
      }
      else
      {
        memcpy( state->buffer + 2*(current/8), data, 2*(len/8) );
        state->count += len;
        databitlen -= len;
        data += 2*( len/8 );
        current = 0;
        SIMD_2way_Compress( state, state->buffer, 0 );
      }
    }
  }

  current = state->count & (state->blocksize - 1);

  // If there is still some data in the buffer, hash it
  if ( current )
  {
    current = ( current+7 ) / 8;
    memset( state->buffer + 2*current, 0, 2*( state->blocksize/8 - current) );
    SIMD_2way_Compress( state, state->buffer, 0 );
  }

  //* Input the message length as the last block
  memset( state->buffer, 0, 2*( state->blocksize/8 ) );
  l = state->count;
  for ( i = 0; i < 8; i++ )
  {
    state->buffer[ i    ] = l & 0xff;
    state->buffer[ i+16 ] = l & 0xff;
    l >>= 8;
  }
  if ( state->count < 16384 )
    isshort = 2;

  SIMD_2way_Compress( state, state->buffer, isshort );
  memcpy( hashval, state->A, 2*( state->hashbitlen / 8 ) );
  return 0;
}

int simd512_2way_full( simd_2way_context *state, void *hashval,
                    const void *data, int datalen )
{
  __m256i *A = (__m256i*)state->A;

  state->hashbitlen = 512;
  state->n_feistels = 8;
  state->blocksize = 128*8;
  state->count = 0;

  for ( int i = 0; i < 8; i++ )
       A[i] = _mm256_set_epi32( SIMD_IV_512[4*i+3], SIMD_IV_512[4*i+2],
                                SIMD_IV_512[4*i+1], SIMD_IV_512[4*i+0],
                                SIMD_IV_512[4*i+3], SIMD_IV_512[4*i+2],
                                SIMD_IV_512[4*i+1], SIMD_IV_512[4*i+0] );

  int current, i;
  int bs = state->blocksize;  // bits in one lane
  int isshort = 1;
  uint64_t l;
  int databitlen = datalen * 8;

  current = state->count & (bs - 1);

  while ( databitlen > 0 )
  {
    if ( current == 0 && databitlen >= bs )
    {
      // We can hash the data directly from the input buffer.
      SIMD_2way_Compress( state, data, 0 );

      databitlen -= bs;
      data += 2*( bs/8 );
      state->count += bs;
    }
    else
    {
      // Copy a chunk of data to the buffer
      int len = bs - current;
      if ( databitlen < len )
      {

         memcpy( state->buffer + 2*( current/8 ), data, 2*( (databitlen+7)/8 ) );
        state->count += databitlen;
        break;
      }
      else
      {
        memcpy( state->buffer + 2*(current/8), data, 2*(len/8) );
        state->count += len;
        databitlen -= len;
        data += 2*( len/8 );
        current = 0;
        SIMD_2way_Compress( state, state->buffer, 0 );
      }
    }
  }

  current = state->count & (state->blocksize - 1);

  // If there is still some data in the buffer, hash it
  if ( current )
  {
    current = ( current+7 ) / 8;
    memset( state->buffer + 2*current, 0, 2*( state->blocksize/8 - current) );
    SIMD_2way_Compress( state, state->buffer, 0 );
  }

  //* Input the message length as the last block
  memset( state->buffer, 0, 2*( state->blocksize/8 ) );
  l = state->count;
  for ( i = 0; i < 8; i++ )
  {
    state->buffer[ i    ] = l & 0xff;
    state->buffer[ i+16 ] = l & 0xff;
    l >>= 8;
  }
  if ( state->count < 16384 )
    isshort = 2;

  SIMD_2way_Compress( state, state->buffer, isshort );
  memcpy( hashval, state->A, 2*( state->hashbitlen / 8 ) );
  return 0;
}


#endif
