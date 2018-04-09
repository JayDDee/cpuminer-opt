#ifndef AVXDEFS_H__
#define AVXDEFS_H__ 1

// Some tools to help using SIMD vectors.
//
// The baseline requirements for these utilities is SSE2 for 128 bit vectors
// and AVX2 for 256 bit vectors.
// 
// Some 128 bit functions have SSSE3 or SSE4.2 implementations that are
// more efficient on capable CPUs.
//
// AVX512F has more powerful 256 bit instructions but with 512 bit vectors
// available there is little reason to use the 256 bit enhancements.
// Proper alignment of data is required, 16 bytes for 128 bit vectors and
// 32 bytes for 256 bit vectors. 64 byte alignment is recommended for
// best cache alignment.
//
// Windows has problems with 256 bit vectors as function arguments passed by 
// value. Stack alignment is only guaranteed to 16 bytes and 32 is required.
// Always use pointers for 256 bit arguments.
//
// There exist duplicates of some functions. In general the first defined
// is preferred as it is more efficient but also more restrictive and may
// not be applicable. The less efficient versions are more flexible.
//
// Naming convention:
//
// [prefix]_[operation]_[size]
//
// prefix: 
//    m128:  128 bit variable vector data
//    c128:  128 bit constant vector data
//    mm:    128 bit intrinsic function
//    m256:  256 bit variable vector data
//    c256:  256 bit constant vector data
//    mm256: 256 bit intrinsic function
//
// operation;
//    data:     identifier name
//    function: description of operation
//
// size: size of element if applicable, ommitted otherwise.
// 
// Macros vs inline functions.
//
// Macros are used for statement functions.
// Macros are used when updating multiple arguments.
// Inline functions are used when multiple statements or local variables are
// needed.

#include <inttypes.h>
#include <immintrin.h>
#include <memory.h>
#include <stdbool.h>

// 128 bit utilities and shortcuts

//
// Experimental code to implement compile time vector initialization
// and support for constant vectors. Useful for arrays, simple constant
// vectors should use _mm_set at run time. The supporting constant and
// function macro definitions are used only for initializing global or
// local, constant or variable vectors.
// Element size is only used for intialization, all run time references should
// use the vector overlay with any element size.
//
// Long form initialization with union member specifier:
//
//   __m128i foo()
//   {
//      const m128_v64[] = { {{ 0, 0 }}, {{ 0, 0 }}, ... };
//      return x.m128i;
//   }
//
// Short form macros with union member abstracted:
//
//   __m128i foo()
//   {
//      const m128i_v64 x_[] = { c128_zero, c128_zero, ... };
//      #define x ((__m128i*)x_);
//      return x;
//      #undef x
//   }
//

union m128_v64 {
  uint64_t u64[2];
  __m128i m128i;
};
typedef union m128_v64 m128_v64; 

union m128_v32 {
  uint32_t u32[4];
  __m128i m128i;
};
typedef union m128_v32 m128_v32;

union m128_v16 {
  uint16_t u16[8];
  __m128i m128i;
};
typedef union m128_v16 m128_v16;

union m128_v8 {
  uint8_t u8[16];
  __m128i m128i;
};
typedef union m128_v8 m128_v8;

// Compile time definition macros, for compile time initializing only.
// x must be a scalar constant.
#define mm_setc_64( x1, x0 ) {{ x1, x0 }}
#define mm_setc1_64( x )     {{  x,  x }}

#define mm_setc_32( x3, x2, x1, x0 ) {{ x3, x2, x1, x0 }}
#define mm_setc1_32( x ) {{ x,x,x,x }}

#define mm_setc_16( x7, x6, x5, x4, x3, x2, x1, x0 ) \
                 {{ x7, x6, x5, x4, x3, x2, x1, x0 }}
#define mm_setc1_16( x ) {{ x,x,x,x, x,x,x,x }}

#define mm_setc_8( x15, x14, x13, x12, x11, x10, x09, x08, \
                   x07, x06, x05, x04, x03, x02, x01, x00 ) \
                {{ x15, x14, x13, x12, x11, x10, x09, x08, \
                   x07, x06, x05, x04, x03, x02, x01, x00 }}
#define mm_setc1_8( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

// Compile time constants, use only for compile time initializing.
#define c128_zero      mm_setc1_64( 0ULL )
#define c128_neg1      mm_setc1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c128_one_128   mm_setc_64(  0ULL, 1ULL )  
#define c128_one_64    mm_setc1_64( 1ULL )
#define c128_one_32    mm_setc1_32( 1UL )
#define c128_one_16    mm_setc1_16( 1U )
#define c128_one_8     mm_setc1_8(  1U )


// compile test
static const m128_v8 yyy_ = mm_setc1_8( 3 );
#define yyy yyy_.m128i

static const m128_v64 zzz_[] = { c128_zero, c128_zero };
#define zzz ((const __m128i*)zzz_)
static inline __m128i foo()
{
 m128_v64 x = mm_setc_64( 1, 2 );
 return  _mm_add_epi32( _mm_add_epi32( zzz[0], x.m128i ), yyy );
}

//
// Pseudo constants.
// These can't be used for compile time initialization.
// These should be used for all simple vectors. Use above for
// vector array initializing.
//
// _mm_setzero_si128 uses pxor instruction, it's unclear what _mm_set_epi does.
// If a pseudo constant is used repeatedly in a function it may be worthwhile
// to define a register variable to represent that constant.
// register __m128i zero = mm_zero;

// Constant zero
#define m128_zero      _mm_setzero_si128()

// Constant 1
#define m128_one_128   _mm_set_epi64x(  0ULL, 1ULL )
#define m128_one_64    _mm_set1_epi64x( 1ULL )
#define m128_one_32    _mm_set1_epi32(  1UL )
#define m128_one_16    _mm_set1_epi16(  1U )
#define m128_one_8     _mm_set1_epi8(   1U )

// Constant minus 1
#define m128_neg1      _mm_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )

//
// Basic operations without equivalent SIMD intrinsic

// Bitwise not (~v)
#define mm_not( v )  _mm_xor_si128( (v), m128_neg1 ) 

// Unary negation (-v)
#define mm_negate_64( v ) _mm_sub_epi64( m128_zero, v )
#define mm_negate_32( v ) _mm_sub_epi32( m128_zero, v )  
#define mm_negate_16( v ) _mm_sub_epi16( m128_zero, v )  

//
// Vector pointer cast

// p = any aligned pointer
// returns p as pointer to vector type
#define castp_m128i(p) ((__m128i*)(p))

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_m128i(p) (*((__m128i*)(p)))

// p = any aligned pointer, i = scaled array index
// returns value p[i]
#define casti_m128i(p,i) (((__m128i*)(p))[(i)])

// p = any aligned pointer, o = scaled offset
// returns pointer p+o
#define casto_m128i(p,o) (((__m128i*)(p))+(o))

//
// Memory functions
// n = number of __m128i, bytes/16

static inline void memset_zero_128( __m128i *dst,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m128_zero; }

static inline void memset_128( __m128i *dst, const __m128i a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_128( __m128i *dst, const __m128i *src, int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }

// A couple of 64 bit scalar functions
// n = bytes/8

static inline void memcpy_64( uint64_t *dst, const uint64_t *src, int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = src[i]; }

static inline void memset_zero_64( uint64_t *src, int n )
{   for ( int i = 0; i < n; i++ ) src[i] = 0; }

static inline void memset_64( uint64_t *dst, uint64_t a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }


//
// Bit operations

// Bitfield extraction/insertion.
// Return a vector with n bits extracted and right justified from each
// element of v starting at bit i, v[ i+n..i ] >> i
#define mm_bfextract_64( v, i, n ) \
   _mm_srli_epi64( _mm_slli_epi64( v, 64 - ((i)+(n)) ), 64 - (n) ) 

#define mm_bfextract_32( v, i, n ) \
   _mm_srli_epi32( _mm_slli_epi32( v, 32 - ((i)+(n)) ), 32 - (n) )

#define mm_bfextract_16( v, i, n ) \
   _mm_srli_epi16( _mm_slli_epi16( v, 16 - ((i)+(n)) ), 16 - (n) )

// Return v with n bits from a inserted starting at bit i.
#define mm_bfinsert_64( v, a, i, n ) \
   _mm_or_si128( _mm_and_si128( v, _mm_srli_epi64( _mm_slli_epi64( \
                    m128_neg1, 64-(n) ), 64-(i) ) ), _mm_slli_epi64( a, i ) )

#define mm_bfinsert_32( v, a, i, n ) \
   _mm_or_si128( _mm_and_si128( v, _mm_srli_epi32( _mm_slli_epi32( \
                    m128_neg1, 32-(n) ), 32-(i) ) ), _mm_slli_epi32( a, i ) )

#define mm_bfinsert_16( v, a, i, n ) \
   _mm_or_si128( _mm_and_si128( v, _mm_srli_epi16( _mm_slli_epi16( \
                    m128_neg1, 16-(n) ), 16-(i) ) ), _mm_slli_epi16( a, i) )

// Return vector with bit i of each element in v set/cleared
#define mm_bitset_64( v, i ) \
   _mm_or_si128( _mm_slli_epi64( m128_one_64, i ), v )

#define mm_bitclr_64( v, i ) \
   _mm_andnot_si128( _mm_slli_epi64( m128_one_64, i ), v )

#define mm_bitset_32( v, i ) \
   _mm_or_si128( _mm_slli_epi32( m128_one_32, i ), v )

#define mm_bitclr_32( v, i ) \
   _mm_andnot_si128( _mm_slli_epi32( m128_one_32, i ), v )

#define mm_bitset_16( v, i ) \
   _mm_or_si128( _mm_slli_epi16( m128_one_16, i ), v )

#define mm_bitclr_16( v, i ) \
   _mm_andnot_si128( _mm_slli_epi16( m128_one_16, i ), v )

// Return vector with bit i in each element toggled
#define mm_bitflip_64( v, i ) \
   _mm_xor_si128( _mm_slli_epi64( m128_one_64, i ), v )

#define mm_bitflip_32( v, i ) \
   _mm_xor_si128( _mm_slli_epi32( m128_one_32, i ), v )

#define mm_bitflip_16( v, i ) \
   _mm_xor_si128( _mm_slli_epi16( m128_one_16, i ), v )


//
// Bit rotations

// XOP is an obsolete AMD feature that has native rotation. 
//    _mm_roti_epi64( v, c)
// Never implemented by Intel and since removed from Zen by AMD.

// Rotate bits in vector elements
#define mm_ror_64( v, c ) \
   _mm_or_si128( _mm_srli_epi64( v, c ), _mm_slli_epi64( v, 64-(c) ) )

#define mm_rol_64( v, c ) \
   _mm_or_si128( _mm_slli_epi64( v, c ), _mm_srli_epi64( v, 64-(c) ) )

#define mm_ror_32( v, c ) \
   _mm_or_si128( _mm_srli_epi32( v, c ), _mm_slli_epi32( v, 32-(c) ) )

#define mm_rol_32( v, c ) \
   _mm_or_si128( _mm_slli_epi32( v, c ), _mm_srli_epi32( v, 32-(c) ) )

#define mm_ror_16( v, c ) \
   _mm_or_si128( _mm_srli_epi16( v, c ), _mm_slli_epi16( v, 16-(c) ) )

#define mm_rol_16( v, c ) \
   _mm_or_si128( _mm_slli_epi16( v, c ), _mm_srli_epi16( v, 16-(c) ) )

//
// Rotate elements in vector

#define mm_swap_64( v )    _mm_shuffle_epi32( v, 0x4e )

#define mm_ror_1x32( v )   _mm_shuffle_epi32( v, 0x39 )
#define mm_rol_1x32( v )   _mm_shuffle_epi32( v, 0x93 )

#define mm_ror_1x16( v, c ) \
   _mm_shuffle_epi8( v, _mm_set_epi8(  1, 0,15,14,13,12,11,10 \
                                       9, 8, 7, 6, 5, 4, 3, 2 ) )
#define mm_rol_1x16( v, c ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 13,12,11,10, 9, 8, 7, 6, \
                                       5, 4, 3, 2, 1, 0,15,14 ) )
#define mm_ror_1x8( v, c ) \
   _mm_shuffle_epi8( v, _mm_set_epi8(  0,15,14,13,12,11,10, 9, \
                                       8, 7, 6, 5, 4, 3, 2, 1 ) )
#define mm_rol_1x8( v, c ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 14,13,12,11,10, 9, 8, 7, \
                                       6, 5, 4, 3, 2, 1, 0,15 ) )

// Less efficient shift but more versatile. Use only for odd number rotations.
// Use shuffle above when possible.

// Rotate 16 byte (128 bit) vector by n bytes.
#define mm_bror( v, c ) \
   _mm_or_si128( _mm_srli_si128( v, c ), _mm_slli_si128( v, 16-(c) ) )

#define mm_brol( v, c ) \
   _mm_or_si128( _mm_slli_si128( v, c ), _mm_srli_si128( v, 16-(c) ) )

// Swap 32 bit elements in each 64 bit lane.
#define mm_swap64_32( v )  _mm_shuffle_epi32( v, 0xb1 )

//
// Rotate elements across two 128 bit vectors as one 256 bit vector

// Swap 128 bit source vectors in place, aka rotate 256 bits by 128 bits.
// void mm128_swap128( __m128i, __m128i )
#define mm_swap_128(v1, v2) \
{ \
   v1 = _mm_xor_si128(v1, v2); \
   v2 = _mm_xor_si128(v1, v2); \
   v1 = _mm_xor_si128(v1, v2); \
}

// Rotate two 128 bit vectors in place as one 256 vector by 1 element
// blend_epi16 is more efficient but requires SSE4.1

#if defined(__SSE4_1__)

// No comparable rol.
#define mm_ror256_1x64( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 8 ); \
   v1 = _mm_alignr_epi8( v2, v1, 8 ); \
   v2 = t; \
} while(0)

/*
#define mm_ror256_1x64( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blend_epi16( v1, v2, 0xF0 ); \
 v2 = _mm_blend_epi16( v1, v2, 0x0F ); \
 v1 = t; \
} while(0)
*/

#define mm_rol256_1x64( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blend_epi16( v1, v2, 0x0F ); \
 v2 = _mm_blend_epi16( v1, v2, 0xF0 ); \
 v1 = t; \
} while(0)


// No comparable rol.
#define mm_ror256_1x32( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 4 ); \
   v1 = _mm_alignr_epi8( v2, v1, 4 ); \
   v2 = t; \
} while(0)

/*
#define mm_ror256_1x32( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_ror_1x32( v1 ); \
 v2 = mm_ror_1x32( v2 ); \
 t  = _mm_blend_epi16( v1, v2, 0xFC ); \
 v2 = _mm_blend_epi16( v1, v2, 0x03 ); \
 v1 = t; \
} while(0)
*/

#define mm_rol256_1x32( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_rol_1x32( v1 ); \
 v2 = mm_rol_1x32( v2 ); \
 t  = _mm_blend_epi16( v1, v2, 0x03 ); \
 v2 = _mm_blend_epi16( v1, v2, 0xFC ); \
 v1 = t; \
} while(0)


// No comparable rol.
#define mm_ror256_1x16( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 2 ); \
   v1 = _mm_alignr_epi8( v2, v1, 2 ); \
   v2 = t; \
} while(0)

/*
#define mm_ror256_1x16( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_ror_1x16( v1 ); \
 v2 = mm_ror_1x16( v2 ); \
 t  = _mm_blend_epi16( v1, v2, 0xFE ); \
 v2 = _mm_blend_epi16( v1, v2, 0x01 ); \
 v1 = t; \
} while(0)
*/

#define mm_rol256_1x16( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_rol_1x16( v1 ); \
 v2 = mm_rol_1x16( v2 ); \
 t  = _mm_blend_epi16( v1, v2, 0x01 ); \
 v2 = _mm_blend_epi16( v1, v2, 0xFE ); \
 v1 = t; \
} while(0)

#else    // SSE2

#define mm_ror256_1x64( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0xffffffffffffffffull, 0ull)); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0ull, 0xffffffffffffffffull)); \
 v1 = t; \
} while(0)

#define mm_rol256_1x64( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0ull, 0xffffffffffffffffull)); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0xffffffffffffffffull, 0ull)); \
 v1 = t; \
} while(0)

#define mm_ror256_1x32( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_ror_1x32( v1 ); \
 v2 = mm_ror_1x32( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                                           0ul, 0ul, 0ul, 0xfffffffful )); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                         0xfffffffful, 0xfffffffful, 0xfffffffful, 0ul )); \
 v1 = t; \
} while(0)

#define mm_rol256_1x32( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_rol_1x32( v1 ); \
 v2 = mm_rol_1x32( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                         0xfffffffful, 0xfffffffful, 0xfffffffful, 0ul )); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                                           0ul, 0ul, 0ul, 0xfffffffful )); \
 v1 = t; \
} while(0)

#define mm_ror256_1x16( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_ror_1x16( v1 ); \
 v2 = mm_ror_1x16( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi16( 0, 0, 0, 0, 0, 0, 0, 0xffff )); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi16( 0xffff, 0xffff, 0xffff, 0xffff,\
                                              0xffff, 0xffff, 0xffff, 0 )); \
 v1 = t; \
} while(0)

#define mm_rol256_1x16( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_rol_1x16( v1 ); \
 v2 = mm_rol_1x16( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi16( 0xffff, 0xffff, 0xffff, 0xffff, \
                                              0xffff, 0xffff, 0xffff, 0 )); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi16( 0, 0, 0, 0, 0, 0, 0, 0xffff )); \
 v1 = t; \
} while(0)

#endif  // SSE4.1 else SSE2

//
// Swap bytes in vector elements

#if defined(__SSSE3__)

#define mm_bswap_64( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 8, 9,10,11,12,13,14,15, \
                                      0, 1, 2, 3, 4, 5, 6, 7 ) )

#define mm_bswap_32( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 12,13,14,15,   8, 9,10,11, \
                                       4, 5, 6, 7,   0, 1, 2, 3 ) )

#define mm_bswap_16( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 14,15,  12,13,  10,11,   8, 9, \
                                       6, 7,   4, 5,   2, 3,   0, 1 ) )

#else  // SSE2

static inline __m128i mm_bswap_64( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
}

static inline __m128i mm_bswap_32( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
}

static inline __m128i mm_bswap_16( __m128i v )
{
  return _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
}

#endif  // SSSE3 else SSE2

/////////////////////////////////////////////////////////////////////

#if defined (__AVX2__)

//
// 256 bit utilities and Shortcuts

// Vector overlays used by compile time vector constants.
// Vector operands of these types require union member .v be
// appended to the symbol name.

// can this be used with aes
union m256_v128 {
  uint64_t v64[4];
  __m128i  v128[2];
  __m256i  m256i;
};
typedef union m256_v128 m256_v128;

union m256_v64 {
  uint64_t u64[4];
  __m256i m256i;
};
typedef union m256_v64 m256_v64;

union m256_v32 {
  uint32_t u32[8];
  __m256i m256i;
};
typedef union m256_v32 m256_v32;

union m256_v16 {
  uint16_t u16[16];
  __m256i m256i;
};
typedef union m256_v16 m256_v16;

union m256_v8 {
  uint8_t u8[32];
  __m256i m256i;
};
typedef union m256_v8 m256_v8;

// The following macro constants and fucntions may only be used
// for compile time intialization of constant and variable vectors
// and should only be used for arrays. Use _mm256_set at run time for
// simple constant vectors.
 
#define mm256_setc_64( x3, x2, x1, x0 ) {{ x3, x2, x1, x0 }}
#define mm256_setc1_64( x ) {{ x,x,x,x }}

#define mm256_setc_32( x7, x6, x5, x4, x3, x2, x1, x0 ) \
                    {{ x7, x6, x5, x4, x3, x2, x1, x0 }}
#define mm256_setc1_32( x ) {{ x,x,x,x, x,x,x,x }}

#define mm256_setc_16( x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 ) \
                     {{ x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 }}
#define mm256_setc1_16( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

#define mm256_setc_8( x31, x30, x29, x28, x27, x26, x25, x24, \
                      x23, x22, x21, x20, x19, x18, x17, x16, \
                      x15, x14, x13, x12, x11, x10, x09, x08, \
                      x07, x06, x05, x04, x03, x02, x01, x00 ) \
                   {{ x31, x30, x29, x28, x27, x26, x25, x24, \
                      x23, x22, x21, x20, x19, x18, x17, x16, \
                      x15, x14, x13, x12, x11, x10, x09, x08, \
                      x07, x06, x05, x04, x03, x02, x01, x00 }}
#define mm256_setc1_8( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                              x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

// Predefined compile time constant vectors.
// Use Pseudo constants at run time for all simple constant vectors.
#define c256_zero      mm256_setc1_64( 0ULL )
#define c256_neg1      mm256_setc1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c256_one_256   mm256_setc_64(  0ULL, 0ULL, 0ULL, 1ULL )  
#define c256_one_128   mm256_setc_64(  0ULL, 1ULL, 0ULL, 1ULL )  
#define c256_one_64    mm256_setc1_64( 1ULL )
#define c256_one_32    mm256_setc1_32( 1UL )
#define c256_one_16    mm256_setc1_16( 1U )
#define c256_one_8     mm256_setc1_8(  1U )

//
// Pseudo constants.
// These can't be used for compile time initialization but are preferable
// for simple constant vectors at run time.

// Constant zero
#define m256_zero _mm256_setzero_si256()

// Constant 1
#define m256_one_256        _mm256_set_epi64x(  0ULL, 0ULL, 0ULL, 1ULL )
#define m256_one_128        _mm256_set_epi64x(  0ULL, 1ULL, 0ULL, 1ULL )
#define m256_one_64         _mm256_set1_epi64x( 1ULL )
#define m256_one_32         _mm256_set1_epi32(  1UL )
#define m256_one_16         _mm256_set1_epi16(  1U )
#define m256_one_8          _mm256_set1_epi16(  1U )

// Constant minus 1
#define m256_neg1            _mm256_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )

//
// Basic operations without SIMD equivalent

// Bitwise not ( ~x )
#define mm256_not( x )       _mm256_xor_si256( (x), m256_neg1 ) \

// Unary negation ( -a )
#define mm256_negate_64( a ) _mm256_sub_epi64( m256_zero, a )
#define mm256_negate_32( a ) _mm256_sub_epi32( m256_zero, a )  
#define mm256_negate_16( a ) _mm256_sub_epi16( m256_zero, a )  

//
// Pointer casting

// p = any aligned pointer
// returns p as pointer to vector type, not very useful
#define castp_m256i(p) ((__m256i*)(p))

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_m256i(p) (*((__m256i*)(p)))

// p = any aligned pointer, i = scaled array index
// returns value p[i]
#define casti_m256i(p,i) (((__m256i*)(p))[(i)])

// p = any aligned pointer, o = scaled offset
// returns pointer p+o
#define casto_m256i(p,o) (((__m256i*)(p))+(o))

//
// Memory functions
// n = number of 256 bit (32 byte) vectors

static inline void memset_zero_256( __m256i *dst, int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m256_zero; }

static inline void memset_256( __m256i *dst, const __m256i a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_256( __m256i *dst, const __m256i *src, int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }


//
// Bit operations

// Bit field extraction/insertion.
// Return a vector with bits [i..i+n] extracted and right justified from each
// element of v.
#define mm256_bfextract_64( v, i, n ) \
   _mm256_srli_epi64( _mm256_slli_epi64( v, 64 - i - n ), 64 - n )

#define mm256_bfextract_32( v, i, n ) \
   _mm256_srli_epi32( _mm256_slli_epi32( v, 32 - i - n ), 32 - n )

#define mm256_bfextract_16( v, i, n ) \
   _mm256_srli_epi16( _mm256_slli_epi16( v, 16 - i - n ), 16 - n )

// Return v with bits [i..i+n] of each element replaced with the corresponding
// bits from a.
#define mm256_bfinsert_64( v, a, i, n ) \
   _mm256_or_si256( _mm256_and_si256( v, _mm256_srli_epi64( \
                        _mm256_slli_epi64( m256_neg1, 64-(n) ), 64-(i) ) ), \
                    _mm256_slli_epi64( a, i) )

#define mm256_bfinsert_32( v,  a, i, n ) \
   _mm256_or_si256( _mm256_and_si256( v, _mm256_srli_epi32( \
                        _mm256_slli_epi32( m256_neg1, 32-(n) ), 32-(i) ) ), \
                    _mm256_slli_epi32( a, i) )

#define mm256_bfinsert_16( v, a, i, n ) \
   _mm256_or_si256( _mm256_and_si256( v, _mm256_srli_epi16( \
                        _mm256_slli_epi16( m256_neg1, 16-(n) ), 16-(i) ) ), \
                    _mm256_slli_epi16( a, i) )

// return bit n in position, all other bits cleared
#define mm256_bitextract_64 ( x, n ) \
   _mm256_and_si256( _mm256_slli_epi64( m256_one_64, n ), x )
#define mm256_bitextract_32 ( x, n ) \
   _mm256_and_si256( _mm256_slli_epi32( m256_one_32, n ), x )
#define mm256_bitextract_16 ( x, n ) \
   _mm256_and_si256( _mm256_slli_epi16( m256_one_16, n ), x )

// Return bit n as bool (bit 0)
#define mm_bittest_64( v, i ) mm_bfextract_64( v, i, 1 )
#define mm_bittest_32( v, i ) mm_bfextract_32( v, i, 1 )
#define mm_bittest_16( v, i ) mm_bfextract_16( v, i, 1 )

// Return x with bit n set/cleared in all elements
#define mm256_bitset_64( x, n ) \
    _mm256_or_si256( _mm256_slli_epi64( m256_one_64, n ), x )
#define mm256_bitclr_64( x, n ) \
    _mm256_andnot_si256( _mm256_slli_epi64( m256_one_64, n ), x )
#define mm256_bitset_32( x, n ) \
    _mm256_or_si256( _mm256_slli_epi32( m256_one_32, n ), x )
#define mm256_bitclr_32( x, n ) \
    _mm256_andnot_si256( _mm256_slli_epi32( m256_one_32, n ), x )
#define mm256_bitset_16( x, n ) \
    _mm256_or_si256( _mm256_slli_epi16( m256_one_16, n ), x )
#define mm256_bitclr_16( x, n ) \
    _mm256_andnot_si256( _mm256_slli_epi16( m256_one_16, n ), x )

// Return x with bit n toggled
#define mm256_bitflip_64( x, n ) \
   _mm256_xor_si256( _mm256_slli_epi64( m256_one_64, n ), x )
#define mm256_bitflip_32( x, n ) \
   _mm256_xor_si256( _mm256_slli_epi32( m256_one_32, n ), x )
#define mm256_bitflip_16( x, n ) \
   _mm256_xor_si256( _mm256_slli_epi16( m256_one_16, n ), x )

//
// Bit rotations.
// AVX2 as no bit shift for elements greater than 64 bit.

//
// Rotate each element of v by c bits
#define mm256_ror_64( v, c ) \
   _mm256_or_si256( _mm256_srli_epi64( v, c ), \
                    _mm256_slli_epi64( v, 64-(c) ) )

#define mm256_rol_64( v, c ) \
   _mm256_or_si256( _mm256_slli_epi64( v, c ), \
                    _mm256_srli_epi64( v, 64-(c) ) )

#define mm256_ror_32( v, c ) \
   _mm256_or_si256( _mm256_srli_epi32( v, c ), \
                    _mm256_slli_epi32( v, 32-(c) ) )

#define mm256_rol_32( v, c ) \
   _mm256_or_si256( _mm256_slli_epi32( v, c ), \
                           _mm256_srli_epi32( v, 32-(c) ) )

#define  mm256_ror_16( v, c ) \
   _mm256_or_si256( _mm256_srli_epi16( v, c ), \
                    _mm256_slli_epi16( v, 16-(c) )

#define mm256_rol_16( v, c ) \
   _mm256_or_si256( _mm256_slli_epi16( v, c ), \
                    _mm256_srli_epi16( v, 16-(c) )

// Rotate bits in each element of v by amount in corresponding element of
// index vector c
#define mm256_rorv_64( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi64( v, c ), \
         _mm256_sllv_epi64( v, \
                            _mm256_sub_epi64( _mm256_set1_epi64x(64), c ) ) )

#define mm256_rolv_64( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi64( v, c ), \
         _mm256_srlv_epi64( v, \
                            _mm256_sub_epi64( _mm256_set1_epi64x(64), c ) ) )

#define mm256_rorv_32( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi32( v, c ), \
         _mm256_sllv_epi32( v, \
                            _mm256_sub_epi32( _mm256_set1_epi32(32), c ) ) )

#define mm256_rolv_32( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi32( v, c ), \
         _mm256_srlv_epi32( v, \
                            _mm256_sub_epi32( _mm256_set1_epi32(32), c ) ) )


//
// Rotate elements in vector
// AVX2 has no full vector permute for elements less than 32 bits.

// Swap 128 bit elements in 256 bit vector.
#define mm256_swap_128( v )     _mm256_permute4x64_epi64( v, 0x4e )

// Rotate 256 bit vector by one 64 bit element
#define mm256_ror256_1x64( v )  _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_rol256_1x64( v )  _mm256_permute4x64_epi64( v, 0x93 )

// Rotate 256 bit vector by one 32 bit element.
#define mm256_ror256_1x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 0,7,6,5,4,3,2,1 );
#define mm256_rol256_1x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 6,5,4,3,2,1,0,7 );

// Rotate 256 bit vector by three 32 bit elements (96 bits).
#define mm256_ror256_3x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 2,1,0,7,6,5,4,3 );
#define mm256_rol256_3x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 4,3,2,1,0,7,6,5 );


//
// Rotate elements within lanes of 256 bit vector.

// Swap 64 bit elements in each 128 bit lane.
#define mm256_swap128_64( v )   _mm256_shuffle_epi32( v, 0x4e )

// Rotate each 128 bit lane by one 32 bit element.
#define mm256_ror128_1x32( v )  _mm256_shuffle_epi32( v, 0x39 )
#define mm256_rol128_1x32( v )  _mm256_shuffle_epi32( v, 0x93 )

// Rotate each 128 bit lane by c bytes.
#define mm256_ror128_x8( v, c ) \
  _mm256_or_si256( _mm256_bsrli_epi128( v, c ), \
                   _mm256_bslli_epi128( v, 16-(c) ) )
#define mm256_rol128_x8( v, c ) \
  _mm256_or_si256( _mm256_bslli_epi128( v, c ), \
                   _mm256_bsrli_epi128( v, 16-(c) ) )

// Swap 32 bit elements in each 64 bit lane
#define mm256_swap64_32( v )    _mm256_shuffle_epi32( v, 0xb1 )


//
// Rotate two 256 bit vectors as one circular 512 bit vector.

#define mm256_swap512_256(v1, v2)   _mm256_permute2x128_si256( v1, v2, 0x4e )
#define mm256_ror512_1x128(v1, v2)  _mm256_permute2x128_si256( v1, v2, 0x39 )
#define mm256_rol512_1x128(v1, v2)  _mm256_permute2x128_si256( v1, v2, 0x93 )

// No comparable rol.
#define mm256_ror512_1x64( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 8 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 8 ); \
   v2 = t; \
} while(0)

#define mm256_rol512_1x64( v1, v2 ) \
do { \
 __m256i t; \
 v1 = mm256_rol_1x64( v1 ); \
 v2 = mm256_rol_1x64( v2 ); \
 t  = _mm256_blend_epi32( v1, v2, 0x03 ); \
 v2 = _mm256_blend_epi32( v1, v2, 0xFC ); \
 v1 = t; \
} while(0)

#define mm256_ror512_1x32( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 4 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 4 ); \
   v2 = t; \
} while(0)

#define mm256_rol512_1x32( v1, v2 ) \
do { \
 __m256i t; \
 v1 = mm256_rol_1x32( v1 ); \
 v2 = mm256_rol_1x32( v2 ); \
 t  = _mm256_blend_epi32( v1, v2, 0x01 ); \
 v2 = _mm256_blend_epi32( v1, v2, 0xFE ); \
 v1 = t; \
} while(0)


//
// Swap bytes in vector elements
#define mm256_bswap_64( v ) \
   _mm256_shuffle_epi8( v, _mm256_set_epi8( 8, 9,10,11,12,13,14,15, \
                                            0, 1, 2, 3, 4, 5, 6, 7, \
                                            8, 9,10,11,12,13,14,15, \
                                            0, 1, 2, 3, 4, 5, 6, 7 ) )

#define mm256_bswap_32( v ) \
   _mm256_shuffle_epi8( v, _mm256_set_epi8( 12,13,14,15,   8, 9,10,11, \
                                             4, 5, 6, 7,   0, 1, 2, 3, \
                                            12,13,14,15,   8, 9,10,11, \
                                             4, 5, 6, 7,   0, 1, 2, 3 ) )

#define mm256_bswap_16( v ) \
   _mm256_shuffle_epi8( v, _mm256_set_epi8(  14,15,  12,13,  10,11,   8, 9, \
                                              6, 7,   4, 5,   2, 3,   0, 1, \
                                             14,15,  12,13,  10,11,   8, 9, \
                                              6, 7,   4, 5,   2, 3,   0, 1 ) )


// Pack/Unpack two 128 bit vectors into/from one 256 bit vector
// usefulness tbd
// __m128i hi, __m128i lo, returns __m256i
#define mm256_pack_2x128( hi, lo ) \
   _mm256_inserti128_si256( _mm256_castsi128_si256( lo ), hi, 1 ) \

// __m128i hi, __m128i lo, __m256i src 
#define mm256_unpack_2x128( hi, lo, src ) \
   lo = _mm256_castsi256_si128( src ); \
   hi = _mm256_castsi256_si128( mm256_swap_128( src ) );
//   hi = _mm256_extracti128_si256( src, 1 ); 

// Pseudo parallel AES
// Probably noticeably slower than using pure 128 bit vectors
// Windows has problems with __m256i args passed by value.
// Use pointers to facilitate __m256i to __m128i conversion.
// When key is used switching keys may reduce performance.
inline __m256i mm256_aesenc_2x128( void *msg, void *key )
{
   ((__m128i*)msg)[0] = _mm_aesenc_si128( ((__m128i*)msg)[0],
                                          ((__m128i*)key)[0] );
   ((__m128i*)msg)[1] = _mm_aesenc_si128( ((__m128i*)msg)[1],
                                          ((__m128i*)key)[1] );
}

inline __m256i mm256_aesenc_nokey_2x128( void *msg )
{
   ((__m128i*)msg)[0] = _mm_aesenc_si128( ((__m128i*)msg)[0], m128_zero );
   ((__m128i*)msg)[1] = _mm_aesenc_si128( ((__m128i*)msg)[1], m128_zero );
}

// source msg preserved
/*
inline __m256i mm256_aesenc_2x128( void *out, void *msg, void *key )
{
   ((__m128i*)out)[0] = _mm_aesenc_si128( ((__m128i*)msg)[0],
                                          ((__m128i*)key)[0] );
   ((__m128i*)out)[1] = _mm_aesenc_si128( ((__m128i*)msg)[1],
                                          ((__m128i*)key)[1] );
}

inline __m256i mm256_aesenc_nokey_2x128( void *out, void *msg )
{
   ((__m128i*)out)[0] = _mm_aesenc_si128( ((__m128i*)msg)[0], m128_zero );
   ((__m128i*)out)[1] = _mm_aesenc_si128( ((__m128i*)msg)[1], m128_zero );
}
*/

inline __m256i mm256_aesenc_2x128_obs( __m256i x, __m256i k )
{
    __m128i hi, lo, khi, klo;

    mm256_unpack_2x128( hi, lo, x );
    mm256_unpack_2x128( khi, klo, k );
    lo = _mm_aesenc_si128( lo, klo );
    hi = _mm_aesenc_si128( hi, khi );
    return mm256_pack_2x128( hi, lo );
}

inline __m256i mm256_aesenc_nokey_2x128_obs( __m256i x )
{
    __m128i hi, lo;

    mm256_unpack_2x128( hi, lo, x );
    lo = _mm_aesenc_si128( lo, m128_zero );
    hi = _mm_aesenc_si128( hi, m128_zero );
    return mm256_pack_2x128( hi, lo );
}


#endif  // AVX2

//////////////////////////////////////////////////////////////

#if defined(__AVX512F__) && defined(__AVX512DQ__) && defined(__AVX512BW__) && defined(__AVX512VBMI__)

// Experimental, not tested.


//
// Vector overlays


//
// Compile time constants


//
// Pseudo constants.

// _mm512_setzero_si512 uses xor instruction. If needed frequently
// in a function it's better to define a register variable (const?)
// initialized to zero.
// It isn't clear to me yet how set or set1 work.

#define m512_zero           _mm512_setzero_si512()
#define m512_one_512        _mm512_set_epi64x(  0ULL, 0ULL, 0ULL, 0ULL, \
                                                0ULL, 0ULL, 0ULL, 1ULL )
#define m512_one_256        _mm512_set4_epi64x( 0ULL, 0ULL, 0ULL, 1ULL )
#define m512_one_128        _mm512_set4_epi64x( 0ULL, 1ULL, 0ULL, 1ULL )
#define m512_one_64         _mm512_set1_epi64x( 1ULL )
#define m512_one_32         _mm512_set1_epi32(  1UL )
#define m512_one_16         _mm512_set1_epi16(  1U )
#define m512_one_8          _mm512_set1_epi8(   1U )
#define m512_neg1           _mm512_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )


//
// Basic operations without SIMD equivalent

#define mm512_not( x )       _mm512_xor_si512( x, m512_neg1 )
#define mm512_negate_64( x ) _mm512_sub_epi64( m512_zero, x )
#define mm512_negate_32( x ) _mm512_sub_epi32( m512_zero, x )  
#define mm512_negate_16( x ) _mm512_sub_epi16( m512_zero, x )  


//
// Pointer casting

// p = any aligned pointer
// i = scaled array index
// o = scaled address offset

// returns p as pointer to vector
#define castp_m512i(p) ((__m512i*)(p))

// returns *p as vector value
#define cast_m512i(p) (*((__m512i*)(p)))

// returns p[i] as vector value
#define casti_m512i(p,i) (((__m512i*)(p))[(i)])

// returns p+o as pointer to vector
#define casto_m512i(p,o) (((__m512i*)(p))+(o))

//
// Memory functions


//
// Bit operations


//
// Bit rotations.

// AVX512F has built-in bit fixed and variable rotation for 64 & 32 bit
// elements. There is no bit rotation or shift for larger elements.
//
// _mm512_rol_epi64,  _mm512_ror_epi64,  _mm512_rol_epi32,  _mm512_ror_epi32
// _mm512_rolv_epi64, _mm512_rorv_epi64, _mm512_rolv_epi32, _mm512_rorv_epi32

#define mm512_ror_16( v, c ) \
    _mm512_or_si512( _mm512_srli_epi16( v, c ), \
                     _mm512_slli_epi16( v, 32-(c) )
#define mm512_rol_16( v, c ) \
    _mm512_or_si512( _mm512_slli_epi16( v, c ), \
                     _mm512_srli_epi16( v, 32-(c) )


//
// Rotate elements in 512 bit vector.

#define mm512_swap_256( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64x( 3,2,1,0,  7,6,5,4 )

#define mm512_ror_1x128( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64x( 1,0,  7,6,  5,4,  3,2 )
#define mm512_rol_1x128( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64x( 5,4,  3,2,  1,0,  7,6 )

#define mm512_ror_1x64( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64x( 0,7,6,5,4,3,2,1 )
#define mm512_rol_1x64( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64x( 6,5,4,3,2,1,0,7 )

#define mm512_ror_1x32( v ) \
  _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
              0,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol_1x32( v ) \
  _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
             14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15 )

#define mm512_ror_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
              0,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17, \
             16,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
             30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15, \
             14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,31 )

#define mm512_ror_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
              0,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49, \
             48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33, \
             32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17, \
             16,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
             62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47, \
             46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,31, \
             30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15, \
             14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,63 )


//
// Rotate elements within 256 bit lanes of 512 bit vector.

#define mm512_swap256_128( v )   _mm512_permutex_epi64( v, 0x4e )

#define mm512_ror256_1x64( v )   _mm512_permutex_epi64( v, 0x39 )
#define mm512_rol256_1x64( v )   _mm512_permutex_epi64( v, 0x93 )

#define mm512_ror256_1x32( v ) \
   _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
             8,15,14,13,12,11,10, 9,   0, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol256_1x32( v ) \
   _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
            14,13,12,11,10, 9, 8,15,   6, 5, 4, 3, 2, 1, 0, 7 )

#define mm512_ror256_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
            16,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17, \
             0,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol256_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
            30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,31, \
            14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,15 )

#define mm512_ror256_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
            32,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49, \
            48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33, \
             0,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17, \
            16,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol256_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
            62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47, \
            46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,63, \
            30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15, \
            14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,31 )


//
// Rotate elements within 128 bit lanes of 512 bit vector.

#define mm512_swap128_64( v )    _mm512_permutex_epi64( v, 0xb1 )

#define mm512_ror128_1x32( v )   _mm512_shuffle_epi32( v, 0x39 )
#define mm512_rol128_1x32( v )   _mm512_shuffle_epi32( v, 0x93 )

#define mm512_ror128_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
            24,31,30,29,28,27,26,25,  16,23,22,21,20,19,18,17, \
             8,15,14,13,12,11,10, 9,   0, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol128_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
            30,29,28,27,26,25,24,31,  22,21,20,19,18,17,16,23, \
            14,13,12,11,10, 9, 8,15,   6, 5, 4, 3, 2, 1, 0, 7 )

#define mm512_ror128_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
            48,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49, \
            32,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33, \
            16,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17, \
             0,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 )
#define mm512_rol128_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
            62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,63, \
            46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,47, \
            30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,31, \
            14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,15 )

// Rotate 128 bit lanes by c bytes.  
#define mm512_ror128_x8( v, c ) \
   _mm512_or_si512( _mm512_bsrli_epi128( v, c ), \
                    _mm512_bslli_epi128( v, 16-(c) ) )
#define mm512_rol128_x8( v, c ) \
   _mm512_or_si512( _mm512_bslli_epi128( v, c ), \
                    _mm512_bsrli_epi128( v, 16-(c) ) )

// Swap 32 bit elements in each 64 bit lane
#define mm512_swap64_32( v )      _mm512_shuffle_epi32( v, 0xb1 )


//
// Swap bytes in vector elements.

#define mm512_bswap_64( v ) \
  _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
            56,57,58,59,60,61,62,63,   48,49,50,51,52,53,54,55, \
            40,41,42,43,44,45,46,47,   32,33,34,35,36,37,38,39, \
            24,25,26,27,28,29,30,31,   16,17,18,19,20,21,22,23, \
             8, 9,10,11,12,13,14,15,    0, 1, 2, 3, 4, 5, 6, 7, )

#define mm512_bswap_32( v ) \
  _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
            60,61,62,63,  56,57,58,59,  52,53,54,55,  48,49,50,51, \
            44,45,46,47,  40,41,42,43,  36,37,38,39,  32,33,34,35, \
            28,29,30,31,  24,25,26,27,  20,21,22,23,  16,17,18,19, \
            12,13,14,15,   8, 9,10,11,   4, 5, 6, 7,   0, 1, 2, 3 )

#define mm512_bswap_16( v ) \
  _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
            62,63,  60,61,  58,59,  56,57,  54,55,  52,53,  50,51,  48,49, \
            46,47,  44,45,  42,43,  40,41,  38,39,  36,37,  34,35,  32,33, \
            30,31,  28,29,  26,27,  24,25,  22,23,  20,21,  18,19,  16,17, \
            14,15,  12,13,  10,11,   8, 9,   6, 7,   4, 5,   2, 3,   0, 1 )


#endif   // AVX512F

#endif   // AVXDEFS_H__
