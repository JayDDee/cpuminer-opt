#ifndef __VECTOR_H__
#define __VECTOR_H__

#include "compat.h"
#include "simd-utils.h"

/******************************* 
 * Using GCC vector extensions * 
 *******************************/

//typedef unsigned char v16qi __attribute__ ((vector_size (16)));
typedef char          v16qi __attribute__ ((vector_size (16)));
typedef short          v8hi __attribute__ ((vector_size (16)));
typedef int            v4si __attribute__ ((vector_size (16)));
typedef float          v4sf __attribute__ ((vector_size (16)));
typedef long long int  v2di __attribute__ ((vector_size (16)));

typedef short          v4hi __attribute__ ((vector_size (8)));
typedef unsigned char  v8qi __attribute__ ((vector_size (8)));

typedef v16qi v8;
typedef v8hi v16;
typedef v4si v32;
#define V16_SIZE 8

union cv {
  unsigned short u16[8];
  v16 v16;
};

union cv8 {
  unsigned char u8[16];
  v8 v8;
};

union u32 {
  u32 u[4];
  v32 v;
};

#define V3216(x) ((v16) (x))
#define V1632(x) ((v32) (x))
#define  V168(x) ( (v8) (x))
#define  V816(x) ((v16) (x))

#if 0
/* These instruction are shorter than the PAND/POR/... that GCC uses */

#define vec_and(x,y)  ({v16 a = (v16) x; v16 b = (v16) y;  __builtin_ia32_andps ((v4sf) a, (v4sf) b);})
#define vec_or(x,y)   ({v16 a = (v16) x; v16 b = (v16) y;  __builtin_ia32_orps ((v4sf) a, (v4sf) b);})
#define vec_xor(x,y)  ({v16 a = (v16) x; v16 b = (v16) y;  __builtin_ia32_xorps ((v4sf) a, (v4sf) b);})
#define vec_andn(x,y) ({v16 a = (v16) x; v16 b = (v16) y;  __builtin_ia32_andnps ((v4sf) a, (v4sf) b);})

#define v16_and(x,y)  ((v16) vec_and ((x), (y)))
#define v16_or(x,y)   ((v16) vec_or  ((x), (y)))
#define v16_xor(x,y)  ((v16) vec_xor ((x), (y)))
#define v16_andn(x,y) ((v16) vec_andn((x), (y)))

#define v32_and(x,y)  ((v32) vec_and ((x), (y)))
#define v32_or(x,y)   ((v32) vec_or  ((x), (y)))
#define v32_xor(x,y)  ((v32) vec_xor ((x), (y)))
#define v32_andn(x,y) ((v32) vec_andn((x), (y)))
#endif

//TODO  aarch support for widening multiply

#if defined(__SSE2__)

#define vec_and(x,y) ((x)&(y))
#define vec_or(x,y)  ((x)|(y))
#define vec_xor(x,y) ((x)^(y))

#define v16_and vec_and
#define v16_or  vec_or
#define v16_xor vec_xor

#define v32_and vec_and
#define v32_or  vec_or
#define v32_xor vec_xor

#define vec_andn(x,y) __builtin_ia32_pandn128 ((v2di) x, (v2di) y)
#define v16_andn(x,y) ((v16) vec_andn(x,y))
#define v32_andn(x,y) ((v32) vec_andn(x,y))

#define v32_add(x,y) ((x)+(y))

#define v16_add(x,y) ((x)+(y))
#define v16_sub(x,y) ((x)-(y))
#define v16_mul(x,y) ((x)*(y))
#define v16_neg(x)   (-(x))
#define v16_shift_l  __builtin_ia32_psllwi128
#define v16_shift_r  __builtin_ia32_psrawi128
#define v16_cmp      __builtin_ia32_pcmpgtw128

#define v16_interleavel   __builtin_ia32_punpcklwd128
#define v16_interleaveh   __builtin_ia32_punpckhwd128

#define v16_mergel(a,b)   V1632(__builtin_ia32_punpcklwd128(a,b))
#define v16_mergeh(a,b)   V1632(__builtin_ia32_punpckhwd128(a,b))

#define v8_mergel(a,b) V816(__builtin_ia32_punpcklbw128(a,b))
#define v8_mergeh(a,b) V816(__builtin_ia32_punpckhbw128(a,b))

#define v32_shift_l  __builtin_ia32_pslldi128
#define v32_shift_r  __builtin_ia32_psrldi128

#define v32_rotate(x,n)                                 \
  v32_or(v32_shift_l(x,n), v32_shift_r(x,32-(n)))

#define v32_shuf __builtin_ia32_pshufd

#define SHUFXOR_1 0xb1          /* 0b10110001 */
#define SHUFXOR_2 0x4e          /* 0b01001110 */
#define SHUFXOR_3 0x1b          /* 0b00011011 */

#define CAT(x, y) x##y
#define XCAT(x,y) CAT(x,y)

#define v32_shufxor(x,s) v32_shuf(x,XCAT(SHUFXOR_,s))

#define v32_bswap(x) (x)

#define v16_broadcast(x) ({                     \
      union u32 u;                              \
      u32 xx = x;                               \
      u.u[0] = xx | (xx << 16);                 \
      V3216(v32_shuf(u.v,0)); })

#define CV(x) {{x, x, x, x, x, x, x, x}}

#elif defined(__aarch64__) && defined(__ARM_NEON)

#define vec_and( x, y )    v128_and( x, y )
#define vec_or(x,y)        v128_or( x, y )
#define vec_xor(x,y)       v128_xor( x, y )

#define v16_and v128_and
#define v16_or  v128_or
#define v16_xor v128_xor

#define v32_and v128_and
#define v32_or  v128_or
#define v32_xor v128_xor

#define vec_andn( x,y )   v128_andnot( x, y )
#define v16_andn          vec_andn 
#define v32_andn          vec_andn

#define v32_add( x, y )   v128_add32( x, y )

#define v16_add( x, y )        v128_add16( x, y )
#define v16_sub( x, y )        v128_sub16( x, y )
#define v16_mul( x, y )        v128_mul16( x, y )
#define v16_neg(x)             v128_negate16( x )
#define v16_shift_l( x, c )    v128_sl16
#define v16_shift_r            v128_sr16
#define v16_cmp                v128_cmpgt16

#define v16_interleavel        v128_unpacklo16
#define v16_interleaveh        v128_unpackhi16 

#define v16_mergel(a,b)   V1632(__builtin_ia32_punpcklwd128(a,b))
#define v16_mergeh(a,b)   V1632(__builtin_ia32_punpckhwd128(a,b))

#define v8_mergel(a,b) V816(__builtin_ia32_punpcklbw128(a,b))
#define v8_mergeh(a,b) V816(__builtin_ia32_punpckhbw128(a,b))

#define v32_shift_l            v128_sl32
#define v32_shift_r            v128_sr32

#define v32_rotate(x,n)        v128_rol32

#define v32_shuf __builtin_ia32_pshufd

#define SHUFXOR_1 0xb1          /* 0b10110001 */
#define SHUFXOR_2 0x4e          /* 0b01001110 */
#define SHUFXOR_3 0x1b          /* 0b00011011 */

#define CAT(x, y) x##y
#define XCAT(x,y) CAT(x,y)

#define v32_shufxor(x,s) v32_shuf(x,XCAT(SHUFXOR_,s))

#define v32_bswap(x) (x)

#define v16_broadcast(x) ({                     \
      union u32 u;                              \
      u32 xx = x;                               \
      u.u[0] = xx | (xx << 16);                 \
      V3216(v32_shuf(u.v,0)); })

#define CV(x) {{x, x, x, x, x, x, x, x}}

#else

#error "I don't know how to vectorize on this architecture."

#endif


/* Twiddle tables */

  static const union cv FFT64_Twiddle[] = {
    {{1,    2,    4,    8,   16,   32,   64,  128}},
    {{1,   60,    2,  120,    4,  -17,    8,  -34}},
    {{1,  120,    8,  -68,   64,  -30,   -2,   17}},
    {{1,   46,   60,  -67,    2,   92,  120,  123}},
    {{1,   92,  -17,  -22,   32,  117,  -30,   67}},
    {{1,  -67,  120,  -73,    8,  -22,  -68,  -70}},
    {{1,  123,  -34,  -70,  128,   67,   17,   35}},
  };


  static const union cv FFT128_Twiddle[] =  {
    {{  1, -118,   46,  -31,   60,  116,  -67,  -61}},
    {{  2,   21,   92,  -62,  120,  -25,  123, -122}},
    {{  4,   42,  -73, -124,  -17,  -50,  -11,   13}},
    {{  8,   84,  111,    9,  -34, -100,  -22,   26}},
    {{ 16,  -89,  -35,   18,  -68,   57,  -44,   52}},
    {{ 32,   79,  -70,   36,  121,  114,  -88,  104}},
    {{ 64,  -99,  117,   72,  -15,  -29,   81,  -49}},
    {{128,   59,  -23, -113,  -30,  -58,  -95,  -98}},
  };


  static const union cv FFT256_Twiddle[] =  {
    {{   1,   41, -118,   45,   46,   87,  -31,   14}}, 
    {{  60, -110,  116, -127,  -67,   80,  -61,   69}}, 
    {{   2,   82,   21,   90,   92,  -83,  -62,   28}}, 
    {{ 120,   37,  -25,    3,  123,  -97, -122, -119}}, 
    {{   4,  -93,   42,  -77,  -73,   91, -124,   56}}, 
    {{ -17,   74,  -50,    6,  -11,   63,   13,   19}}, 
    {{   8,   71,   84,  103,  111,  -75,    9,  112}}, 
    {{ -34, -109, -100,   12,  -22,  126,   26,   38}}, 
    {{  16, -115,  -89,  -51,  -35,  107,   18,  -33}}, 
    {{ -68,   39,   57,   24,  -44,   -5,   52,   76}}, 
    {{  32,   27,   79, -102,  -70,  -43,   36,  -66}}, 
    {{ 121,   78,  114,   48,  -88,  -10,  104, -105}}, 
    {{  64,   54,  -99,   53,  117,  -86,   72,  125}}, 
    {{ -15, -101,  -29,   96,   81,  -20,  -49,   47}}, 
    {{ 128,  108,   59,  106,  -23,   85, -113,   -7}}, 
    {{ -30,   55,  -58,  -65,  -95,  -40,  -98,   94}}
  };




#endif
