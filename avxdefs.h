#ifndef AVXDEFS_H__
#define AVXDEFS_H__

// Some tools to help using AVX and AVX2.
// SSE2 is required for most 128 vector operations with the exception of
// _mm_shuffle_epi8, used by bswap, which needs SSSE3.
// AVX2 is required for all 256 bit vector operations.
// AVX512 has more powerful 256 bit instructions but with AVX512 available
// there is little reason to use them.
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
//    data:     variable/constant name
//    function: deription of operation
//
// size: size of element if applicable
// 

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

#define mm_setc_32(  x3, x2, x1, x0 ) {{ x3, x2, x1, x0 }}
#define mm_setc1_32(  x ) {{ x,x,x,x }}

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
 return  _mm_add_epi32( zzz[0], x.m128i );
}

//
// Pseudo constants.
// These can't be used for compile time initialization.
// These should be used for all simple vectors. Use above for
// vector array initializing.

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
// returns p[i]
#define casti_m128i(p,i) (((__m128i*)(p))[(i)])

// p = any aligned pointer, o = scaled offset
// returns p+o
#define casto_m128i(p,i) (((__m128i*)(p))+(i))

//
// Memory functions
// n = number of __m128i, bytes/16

static inline void memset_zero_128( __m128i *dst,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m128_zero; }

static inline void memset_128( __m128i *dst, const __m128i a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_128( __m128i *dst, const __m128i *src, int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }

// Compare data in memory, return true if different
static inline bool memcmp_128( __m128i src1, __m128i src2, int n )
{   for ( int i = 0; i < n; i++ )
      if ( src1[i] != src2[i] ) return true;
    return false;
}

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
// element of v starting at bit i.
static inline __m128i mm_bfextract_64( __m128i v, int i, int n )
{   return _mm_srli_epi64( _mm_slli_epi64( v, 64 - i - n ), 64 - n ); } 

static inline __m128i mm_bfextract_32( __m128i v, int i, int n )
{   return _mm_srli_epi32( _mm_slli_epi32( v, 32 - i - n ), 32 - n ); }

static inline __m128i mm_bfextract_16( __m128i v, int i, int n )
{   return _mm_srli_epi16( _mm_slli_epi16( v, 16 - i - n ), 16 - n ); }

// Return v with n bits from a inserted starting at bit i.
static inline __m128i mm_bfinsert_64( __m128i v, __m128i a, int i, int n )
{   return _mm_or_si128(
               _mm_and_si128( v,
                  _mm_srli_epi64( _mm_slli_epi64( m128_neg1, 64-n ), 64-i ) ),
           _mm_slli_epi64( a, i) );
}

static inline __m128i mm_bfinsert_32( __m128i v, __m128i a, int i, int n )
{   return _mm_or_si128( 
               _mm_and_si128( v,
                  _mm_srli_epi32( _mm_slli_epi32( m128_neg1, 32-n ), 32-i ) ),
           _mm_slli_epi32( a, i) );
}

static inline __m128i mm_bfinsert_16( __m128i v, __m128i a, int i, int n )
{   return _mm_or_si128( 
               _mm_and_si128( v,
                  _mm_srli_epi16( _mm_slli_epi16( m128_neg1, 16-n ), 16-i ) ),
           _mm_slli_epi16( a, i) );
}

// not very useful, just use a mask.
// Return vector with bit i of each element in v in position,
// all other bits zeroed.
static inline __m128i  mm_bitextract_64( __m128i v, int i )
{   return _mm_and_si128( v, _mm_slli_epi64( m128_one_64, i ) ); }

static inline __m128i mm_bitextract_32( __m128i v, int i )
{   return _mm_and_si128( v, _mm_slli_epi32( m128_one_32, i ) ); }

static inline __m128i mm_bitextract_16( __m128i v, int i )
{   return _mm_and_si128( v, _mm_slli_epi16( m128_one_16, i ) ); }

// obsolete, use bfextract with n = 1
// Return vector with bit i of each element of v as a bool
// (shifted to position 0)
#define mm_bittest_64( v, i ) mm_bfextract_64( v, i, 1 )
#define mm_bittest_32( v, i ) mm_bfextract_32( v, i, 1 )
#define mm_bittest_16( v, i ) mm_bfextract_16( v, i, 1 )
/*
static inline __m128i mm_bittest_64( __m128i v, int i )
{   return _mm_and_si128( _mm_srli_epi64( v, i ), m128_one_64 ); }

static inline __m128i mm_bittest_32( __m128i v, int i )
{   return _mm_and_si128( _mm_srli_epi32( v, i ), m128_one_64 ); }

static inline __m128i mm_bittest_16( __m128i v, int i )
{   return _mm_and_si128( _mm_srli_epi16( v, i ), m128_one_64 ); }
*/

// Return vector with bit i of each element in v set/cleared
static inline __m128i mm_bitset_64( __m128i v, int i )
{   return _mm_or_si128( _mm_slli_epi64( m128_one_64, i ), v ); }

static inline __m128i mm_bitclr_64( __m128i v, int i )
{   return _mm_andnot_si128( _mm_slli_epi64( m128_one_64, i ), v ); }

static inline __m128i mm_bitset_32( __m128i v, int i )
{   return _mm_or_si128( _mm_slli_epi32( m128_one_32, i ), v ); }

static inline __m128i mm_bitclr_32( __m128i v, int i )
{   return _mm_andnot_si128( _mm_slli_epi32( m128_one_32, i ), v ); }

static inline __m128i mm_bitset_16( __m128i v, int i )
{   return _mm_or_si128( _mm_slli_epi16( m128_one_16, i ), v ); }

static inline __m128i mm_bitclr_16( __m128i v, int i )
{   return _mm_andnot_si128( _mm_slli_epi16( m128_one_16, i ), v ); }

// Return vector with bit i in each element toggled
static inline __m128i mm_bitflip_64( __m128i v, int i )
{   return _mm_xor_si128( _mm_slli_epi64( m128_one_64, i ), v ); }

static inline __m128i mm_bitflip_32( __m128i v, int i )
{   return _mm_xor_si128( _mm_slli_epi32( m128_one_32, i ), v ); }

static inline __m128i mm_bitflip_16( __m128i v, int i )
{   return _mm_xor_si128( _mm_slli_epi16( m128_one_16, i ), v ); }


// converting bitmask to vector mask
// return vector with each element set to -1 if the corresponding
// bit in the bitmask is set and zero if the corresponding bit is clear.
// Can be used by blend
static inline __m128i mm_mask_to_vmask_64( uint8_t m )
{  return _mm_set_epi64x( -( (m>>1) & 1 ), -( m & 1 ) ); }

static inline __m128i mm_mask_to_vmask_32( uint8_t m )
{  return _mm_set_epi32( -( (m>>3) & 1 ), -( (m>>2) & 1 ),
                         -( (m>>1) & 1 ), -(  m     & 1 ) );
}

static inline __m128i mm_mask_to_vmask_16( uint8_t m )
{  return _mm_set_epi16( -( (m>>7) & 1 ), -( (m>>6) & 1 ),
                         -( (m>>5) & 1 ), -(  m>>4  & 1 ),
                         -( (m>>3) & 1 ), -( (m>>2) & 1 ),
                         -( (m>>1) & 1 ), -(  m     & 1 ) );
}

// converting immediate index to vector index, used by permute, shuffle, shift
// Return vector with each element set from the corresponding n bits in imm8
// index i.
static inline __m128i mm_index_to_vindex_64( uint8_t i, uint8_t n )
{  uint8_t mask = ( 2 << n ) - 1;
   return _mm_set_epi64x( (i >> n) & mask, i & mask );
}

static inline __m128i mm_index_to_vindex_32( uint8_t i, uint8_t n )
{  uint8_t mask = ( 2 << n ) - 1;
   return _mm_set_epi32( ( (i >> 3*n) & mask ), ( (i >> 2*n) & mask ),
                         ( (i >>   n) & mask ), (  i         & mask ) ) ;
}

static inline __m128i mm_index_to_vindex_16( uint8_t i, uint8_t n )
{  uint8_t mask = ( 2 << n ) - 1;
   return _mm_set_epi16( ( (i >> 7*n) & mask ), ( (i >> 6*n) & mask ),
                         ( (i >> 5*n) & mask ), ( (i >> 4*n) & mask ),
                         ( (i >> 3*n) & mask ), ( (i >> 2*n) & mask ),
                         ( (i >>   n) & mask ), (  i         & mask ) ) ;
}

static inline uint8_t mm_vindex_to_imm8_64( __m128i v, uint8_t n )
{  m128_v64 s = (m128_v64)v;
   return ( s.u64[1] << n ) | ( s.u64[0] );
} 

static inline uint8_t mm_vindex_to_imm8_32( __m128i v, uint8_t n )
{  m128_v32 s = (m128_v32)v;
   return ( s.u32[3] << 3*n ) | ( s.u32[2] << 2*n )
        | ( s.u32[1] <<   n ) | ( s.u32[0]        );
}

static inline uint8_t mm_vindex_to_imm8_16( __m128i v, uint8_t n )
{  m128_v16 s = (m128_v16)v;
   return ( s.u16[7] << 7*n ) | ( s.u16[6] << 6*n )
        | ( s.u16[5] << 5*n ) | ( s.u16[4] << 4*n )
        | ( s.u16[3] << 3*n ) | ( s.u16[2] << 2*n )
        | ( s.u16[1] <<   n ) | ( s.u16[0]        );
}


//
// Bit rotations

// XOP is an obsolete AMD feature that has native rotation. 
//    _mm_roti_epi64( v, c)
// Never implemented by Intel and since removed from Zen by AMD.

// Rotate bits in vector elements

static inline __m128i mm_rotr_64( __m128i v, int c )
{ return _mm_or_si128( _mm_srli_epi64( v, c ), _mm_slli_epi64( v, 64-(c) ) ); }

static inline __m128i mm_rotl_64( __m128i v, int c )
{ return _mm_or_si128( _mm_slli_epi64( v, c ), _mm_srli_epi64( v, 64-(c) ) ); }

static inline __m128i mm_rotr_32( __m128i v, int c )
{ return _mm_or_si128( _mm_srli_epi32( v, c ), _mm_slli_epi32( v, 32-(c) ) ); }

static inline __m128i mm_rotl_32( __m128i v, int c ) 
{ return _mm_or_si128( _mm_slli_epi32( v, c ), _mm_srli_epi32( v, 32-(c) ) ); }

static inline __m128i mm_rotr_16( __m128i v, int c )
{ return _mm_or_si128( _mm_srli_epi16( v, c ), _mm_slli_epi16( v, 16-(c) ) ); }

static inline __m128i mm_rotl_16( __m128i v, int c )
{ return _mm_or_si128( _mm_slli_epi16( v, c ), _mm_srli_epi16( v, 16-(c) ) ); }

// Rotate bits in each element by amount in corresponding element of
// index vector
/* Needs AVX2
static inline __m128i mm_rotrv_64( __m128i v, __m128i c )
{
   return _mm_or_si128(
              _mm_srlv_epi64( v, c ),
              _mm_sllv_epi64( v, _mm_sub_epi64( _mm_set1_epi64x(64), c ) ) );
}

static inline __m128i mm_rotlv_64( __m128i v, __m128i c )
{
   return _mm_or_si128(
              _mm_sllv_epi64( v, c ),
              _mm_srlv_epi64( v, _mm_sub_epi64( _mm_set1_epi64x(64), c ) ) );
}

static inline __m128i mm_rotrv_32( __m128i v, __m128i c )
{
   return _mm_or_si128(
              _mm_srlv_epi32( v, c ),
              _mm_sllv_epi32( v, _mm_sub_epi32( _mm_set1_epi32(32), c ) ) );
}

static inline __m128i mm_rotlv_32( __m128i v, __m128i c )
{
   return _mm_or_si128(
              _mm_sllv_epi32( v, c ),
              _mm_srlv_epi32( v, _mm_sub_epi32( _mm_set1_epi32(32), c ) ) );
}
*/

//
// Rotate elements in vector

// Optimized shuffle

// Swap hi/lo 64 bits in 128 bit vector
#define mm_swap_64( v )    _mm_shuffle_epi32( v, 0x4e )

// Rotate 128 bit vector by 32 bits
#define mm_rotr_1x32( v )  _mm_shuffle_epi32( v, 0x39 )
#define mm_rotl_1x32( v )  _mm_shuffle_epi32( v, 0x93 )

// Swap hi/lo 32 bits in each 64 bit element
#define mm_swap64_32( v )  _mm_shuffle_epi32( v, 0xb1 )

// Less efficient but more versatile. Use only for odd number rotations.
// Use shuffle above when possible.

// Rotate vector by n bytes.
static inline __m128i mm_brotr_128( __m128i v, int c )
{
  return _mm_or_si128( _mm_bsrli_si128( v, c ), _mm_bslli_si128( v, 16-(c) ) );}

static inline __m128i mm_brotl_128( __m128i v, int c )
{
  return _mm_or_si128( _mm_bslli_si128( v, c ), _mm_bsrli_si128( v, 16-(c) ) );
}

// Rotate vector by c elements, use only for odd number rotations
#define mm_rotr128_x32( v, c ) mm_brotr_128( v, (c)>>2 ) 
#define mm_rotl128_x32( v, c ) mm_brotl_128( v, (c)>>2 )
#define mm_rotr128_x16( v, c ) mm_brotr_128( v, (c)>>1 ) 
#define mm_rotl128_x16( v, c ) mm_brotl_128( v, (c)>>1 )

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
#define mm_rotl256_1x64( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0xffffffffffffffffull, 0ull)); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0ull, 0xffffffffffffffffull)); \
 v1 = t; \
} while(0)

#define mm_rotr256_1x64( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0ull, 0xffffffffffffffffull)); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi64x(0xffffffffffffffffull, 0ull)); \
 v1 = t; \
} while(0)

#define mm_rotl256_1x32( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                         0xfffffffful, 0xfffffffful, 0xfffffffful, 0ul )); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                                           0ul, 0ul, 0ul, 0xfffffffful )); \
 v1 = t; \
} while(0)

#define mm_rotr256_1x32( v1, v2 ) \
do { \
 __m128i t; \
 v1 = mm_swap_64( v1 ); \
 v2 = mm_swap_64( v2 ); \
 t  = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                                           0ul, 0ul, 0ul, 0xfffffffful )); \
 v2 = _mm_blendv_epi8( v1, v2, _mm_set_epi32( \
                         0xfffffffful, 0xfffffffful, 0xfffffffful, 0ul )); \
 v1 = t; \
} while(0)

//
// Swap bytes in vector elements
static inline __m128i mm_bswap_64( __m128i v )
{
#ifdef __SSSE3__
    return _mm_shuffle_epi8( v, _mm_set_epi8(
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ) );
#else
    __m128i a = _mm_or_si128(
        _mm_slli_epi16(v, 8),
        _mm_srli_epi16(v, 8));

    a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(0, 1, 2, 3));
    a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(0, 1, 2, 3));

    return a;
#endif
}

static inline __m128i mm_bswap_32( __m128i v )
{
#ifdef __SSSE3__
    return _mm_shuffle_epi8( v, _mm_set_epi8(
                           0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x09, 0x0a, 0x0b,
                           0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03 ) );
#else
    __m128i a = _mm_or_si128(
        _mm_slli_epi16(v, 8),
        _mm_srli_epi16(v, 8));

    a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(2, 3, 0, 1));
    a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(2, 3, 0, 1));

    return a;
#endif
}

static inline __m128i mm_bswap_16( __m128i v )
{
#ifdef __SSSE3__
    return _mm_shuffle_epi8( v, _mm_set_epi8(
                           0x0e, 0x0f, 0x0c, 0x0d, 0x0a, 0x0b, 0x08, 0x09,
                           0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01 ) );
#else	   
    return _mm_or_si128(
        _mm_slli_epi16(v, 8),
        _mm_srli_epi16(v, 8));
#endif
}

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
// returns p[i]
#define casti_m256i(p,i) (((__m256i*)(p))[(i)])

// p = any aligned pointer, o = scaled offset
// returns p+o
#define casto_m256i(p,i) (((__m256i*)(p))+(i))

//
// Memory functions
// n = number of 256 bit (32 byte) vectors

static inline void memset_zero_256( __m256i *dst, int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m256_zero; }

static inline void memset_256( __m256i *dst, const __m256i a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_256( __m256i *dst, const __m256i *src, int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }

// Compare data in memory, return true if different
static inline bool memcmp_256( __m256i src1, __m256i src2, int n )
{
   for ( int i = 0; i < n; i++ )
      if ( src1[i] != src2[i] ) return true;
   return false;
}

//
// Mask conversion

// converting bitmask to vector mask
// return vector with each element set to -1 if the corresponding
// bit in the bitmask is set and zero if the corresponding bit is clear.
// Can be used by blend
static inline __m256i mm256_mask_to_vmask_64( uint8_t m )
{  return _mm256_set_epi64x(  -( (m>>3) & 1 ), -( (m>>2) & 1 ),
                              -( (m>>1) & 1 ), -( m & 1 ) ); }

static inline __m256i mm256_mask_to_vmask_32( uint8_t m )
{  return _mm256_set_epi32( -( (m>>7) & 1 ), -( (m>>6) & 1 ),
                            -( (m>>5) & 1 ), -( (m>>4) & 1 ),
                            -( (m>>3) & 1 ), -( (m>>2) & 1 ),
                            -( (m>>1) & 1 ), -(  m     & 1 ) );
}

static inline __m256i mm256_mask_to_vmask_16( uint8_t m )
{  return _mm256_set_epi16( -( (m>>15) & 1 ), -( (m>>14) & 1 ),
                            -( (m>>13) & 1 ), -( (m>>12) & 1 ),
                            -( (m>>11) & 1 ), -( (m>>10) & 1 ),
                            -( (m>> 9) & 1 ), -( (m>> 8) & 1 ),
                            -( (m>> 7) & 1 ), -( (m>> 6) & 1 ),
                            -( (m>> 5) & 1 ), -( (m>> 4) & 1 ),
                            -( (m>> 3) & 1 ), -( (m>> 2) & 1 ),
                            -( (m>> 1) & 1 ), -(  m      & 1 ) );
}

// converting immediate index to vector index, used by permute, shuffle, shift
// Return vector with each element set from the corresponding n bits in imm8
// index i.
static inline __m256i mm256_index_to_vindex_64( uint8_t i, uint8_t n )
{  uint8_t mask = ( 2 << n ) - 1;
   return _mm256_set_epi64x( ( (i >> 3*n) & mask ), ( (i >> 2*n) & mask ),
                             ( (i >>   n) & mask ), (  i         & mask ) );
}

static inline __m256i mm256_index_to_vindex_32( uint8_t i, uint8_t n )
{  uint8_t mask = ( 2 << n ) - 1;
   return _mm256_set_epi32( ( (i >> 7*n) & mask ), ( (i >> 6*n) & mask ),
                            ( (i >> 5*n) & mask ), ( (i >> 4*n) & mask ),
                            ( (i >> 3*n) & mask ), ( (i >> 2*n) & mask ),
                            ( (i >>   n) & mask ), (  i         & mask ) );
}

static inline __m256i mm256_index_to_vindex_16( uint8_t i, uint8_t n )
{  uint8_t mask = ( 2 << n ) - 1;
   return _mm256_set_epi16( ( (i >> 15*n) & mask ), ( (i >> 14*n) & mask ),
                            ( (i >> 13*n) & mask ), ( (i >> 12*n) & mask ),
                            ( (i >> 11*n) & mask ), ( (i >> 10*n) & mask ),
                            ( (i >>  9*n) & mask ), ( (i >>  8*n) & mask ),
                            ( (i >>  7*n) & mask ), ( (i >>  6*n) & mask ),
                            ( (i >>  5*n) & mask ), ( (i >>  4*n) & mask ),
                            ( (i >>  3*n) & mask ), ( (i >>  2*n) & mask ),
                            ( (i >>    n) & mask ), (  i          & mask ) );
}

static inline uint8_t m256_vindex_to_imm8_64( __m256i v, uint8_t n )
{  m256_v64 s = (m256_v64)v;
   return ( s.u64[3] << 3*n ) | ( s.u64[2] << 2*n )
        | ( s.u64[1] <<   n ) | ( s.u64[0]        );
}

static inline uint8_t mm256_vindex_to_imm8_32( __m256i v, uint8_t n )
{  m256_v32 s = (m256_v32)v;
   return ( s.u32[7] << 7*n ) | ( s.u32[6] << 6*n )
        | ( s.u32[5] << 5*n ) | ( s.u32[4] << 4*n )
        | ( s.u32[3] << 3*n ) | ( s.u32[2] << 2*n )
        | ( s.u32[1] <<   n ) | ( s.u32[0]        );
}

static inline uint8_t mm256_vindex_to_imm8_16( __m256i v, uint8_t n )
{  m256_v16 s = (m256_v16)v;
   return ( s.u16[15] << 15*n ) | ( s.u16[14] << 14*n )
        | ( s.u16[13] << 13*n ) | ( s.u16[12] << 12*n )
        | ( s.u16[11] << 11*n ) | ( s.u16[10] << 10*n )
        | ( s.u16[ 9] <<  9*n ) | ( s.u16[ 8] <<  8*n )
        | ( s.u16[ 7] <<  7*n ) | ( s.u16[ 6] <<  6*n )
        | ( s.u16[ 5] <<  5*n ) | ( s.u16[ 4] <<  4*n )
        | ( s.u16[ 3] <<  3*n ) | ( s.u16[ 2] <<  2*n )
        | ( s.u16[ 1] <<    n ) | ( s.u16[ 0]         );
}


//
// Bit operations

// Bit field extraction/insertion.
// Return a vector with bits [i..i+n] extracted and right justified from each
// element of v.
static inline __m256i mm256_bfextract_64( __m256i v, int i, int n )
{   return _mm256_srli_epi64( _mm256_slli_epi64( v, 64 - i - n ), 64 - n ); }

static inline __m256i mm256_bfextract_32( __m256i v, int i, int n )
{   return _mm256_srli_epi32( _mm256_slli_epi32( v, 32 - i - n ), 32 - n ); }

static inline __m256i mm256_bfextract_16( __m256i v, int i, int n )
{   return _mm256_srli_epi16( _mm256_slli_epi16( v, 16 - i - n ), 16 - n ); }

// Return v1 with bits [i..i+n] of each element replaced with the corresponding
// bits from a from v2.
static inline __m256i mm256_bfinsert_64( __m256i v, __m256i a, int i, int n )
{
 return _mm256_or_si256(
           _mm256_and_si256( v,
                             _mm256_srli_epi64(
                                _mm256_slli_epi64( m256_neg1, 64-n ), 64-i ) ),
        _mm256_slli_epi64( a, i) );
}

static inline __m256i mm256_bfinsert_32( __m256i v, __m256i a, int i, int n )
{
 return _mm256_or_si256(
           _mm256_and_si256( v,
                             _mm256_srli_epi32(
                                _mm256_slli_epi32( m256_neg1, 32-n ), 32-i ) ),
        _mm256_slli_epi32( a, i) );
}

static inline __m256i mm256_bfinsert_16( __m256i v, __m256i a, int i, int n )
{
 return _mm256_or_si256(
           _mm256_and_si256( v,
                             _mm256_srli_epi16(
                                _mm256_slli_epi16( m256_neg1, 16-n ), 16-i ) ),
        _mm256_slli_epi16( a, i) );
}

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

/*
#define mm256_bittest_64( x, n ) \
   _mm256_and_si256( m256_one_64, _mm256_srli_epi64( x, n ) )
#define mm256_bittest_32( x, n ) \
   _mm256_and_si256( m256_one_32, _mm256_srli_epi32( x, n ) )
#define mm256_bittest_16( x, n ) \
   _mm256_and_si256( m256_one_16, _mm256_srli_epi16( x, n ) )
*/

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
// Bit rotations

//
// Rotate each element of v by c bits
static inline __m256i mm256_rotr_64( __m256i v, int c )
{
   return _mm256_or_si256( _mm256_srli_epi64( v, c ),
                           _mm256_slli_epi64( v, 64-(c) ) );
}

static inline __m256i mm256_rotl_64( __m256i v, int c )
{
   return _mm256_or_si256( _mm256_slli_epi64( v, c ),
                           _mm256_srli_epi64( v, 64-(c) ) );
}

static inline __m256i mm256_rotr_32( __m256i v, int c )
{
   return _mm256_or_si256( _mm256_srli_epi32( v, c ),
                           _mm256_slli_epi32( v, 32-(c) ) );
}

static inline __m256i mm256_rotl_32( __m256i v, int c )
{
   return _mm256_or_si256( _mm256_slli_epi32( v, c ),
                           _mm256_srli_epi32( v, 32-(c) ) );
}

static inline __m256i  mm256_rotr_16( __m256i v, int c )
{ 
  return _mm256_or_si256( _mm256_srli_epi16(v, c),
                          _mm256_slli_epi16(v, 32-(c)) );
}

static inline __m256i mm256_rotl_16( __m256i v, int c )
{
  return _mm256_or_si256( _mm256_slli_epi16(v, c),
                          _mm256_srli_epi16(v, 32-(c)) );
}

// Rotate bits in each element of v by amount in corresponding element of
// index vector c
static inline __m256i mm256_rotrv_64( __m256i v, __m256i c )
{
  return _mm256_or_si256(
            _mm256_srlv_epi64( v, c ),
            _mm256_sllv_epi64( v,
                              _mm256_sub_epi64( _mm256_set1_epi64x(64), c ) ) );
}

static inline __m256i mm256_rotlv_64( __m256i v, __m256i c )
{
  return _mm256_or_si256(
            _mm256_sllv_epi64( v, c ),
            _mm256_srlv_epi64( v,
                              _mm256_sub_epi64( _mm256_set1_epi64x(64), c ) ) );
}

static inline __m256i mm256_rotrv_32( __m256i v, __m256i c )
{
  return _mm256_or_si256(
            _mm256_srlv_epi32( v, c ),
            _mm256_sllv_epi32( v,
                              _mm256_sub_epi32( _mm256_set1_epi32(32), c ) ) );
}

static inline __m256i mm256_rotlv_32( __m256i v, __m256i c )
{
  return _mm256_or_si256(
            _mm256_sllv_epi32( v, c ),
            _mm256_srlv_epi32( v,
                              _mm256_sub_epi32( _mm256_set1_epi32(32), c ) ) );
}

//
// Rotate elements in vector
// There is no full vector permute for elements less than 64 bits or 256 bit
// shift, a little more work is needed.

// Optimized 64 bit permutations
// Swap 128 bit elements in v
#define mm256_swap_128( v )      _mm256_permute4x64_epi64( v, 0x4e )

// Rotate v by one 64 bit element
#define mm256_rotl256_1x64( v )  _mm256_permute4x64_epi64( v, 0x93 )
#define mm256_rotr256_1x64( v )  _mm256_permute4x64_epi64( v, 0x39 )

// Swap 64 bit elements in each 128 bit lane of v
#define mm256_swap128_64( v )    _mm256_shuffle_epi32( v, 0x4e )

// Rotate each 128 bit lane in v by one 32 bit element
#define mm256_rotr128_1x32( v )  _mm256_shuffle_epi32( v, 0x39 )
#define mm256_rotl128_1x32( v )  _mm256_shuffle_epi32( v, 0x93 )

// Swap 32 bit elements in each 64 bit lane of v
#define mm256_swap64_32( v )     _mm256_shuffle_epi32( v, 0xb1 )

// Less efficient but more versatile. Use only for rotations that are not 
// integrals of 64 bits. Use permutations above when possible.

// Rotate 256 bit vector v by c bytes.
static inline __m256i mm256_brotr_256( __m256i v, int c )
{ return _mm256_or_si256( _mm256_bsrli_epi128( v, c ),
                          mm256_swap_128( _mm256_bslli_epi128( v, 16-(c) ) ) );
}

static inline __m256i mm256_brotl_256( __m256i v, int c )
{ return _mm256_or_si256( _mm256_bslli_epi128( v, c ),
                          mm256_swap_128( _mm256_bsrli_epi128( v, 16-(c) ) ) );
}

// Rotate each 128 bit lane in v by c bytes
static inline __m256i mm256_brotr_128( __m256i v, int c )
{ return _mm256_or_si256( _mm256_bsrli_epi128( v, c ),
                          _mm256_bslli_epi128( v, 16 - (c) ) );
}

static inline __m256i mm256_brotl_128( __m256i v, int c )
{ return _mm256_or_si256( _mm256_bslli_epi128( v, c ),
                          _mm256_bsrli_epi128( v, 16 - (c) ) );
}

// Rotate 256 bit vector v by c elements, use only for odd value rotations
#define mm256_rotr256_x32( v, c )   mm256_rotr256_x8( v, (c)>>2 ) 
#define mm256_rotl256_x32( v, c )   mm256_rotl256_x8( v, (c)>>2 )
#define mm256_rotr256_x16( v, c )   mm256_rotr256_x8( v, (c)>>1 ) 
#define mm256_rotl256_x16( v, c )   mm256_rotl256_x8( v, (c)>>1 )

//
// Rotate two 256 bit vectors as one 512 bit vector

// Fast but limited to 128 bit granularity
#define mm256_swap512_256(v1, v2)    _mm256_permute2x128_si256( v1, v2, 0x4e )
#define mm256_rotr512_1x128(v1, v2)  _mm256_permute2x128_si256( v1, v2, 0x39 )
#define mm256_rotl512_1x128(v1, v2)  _mm256_permute2x128_si256( v1, v2, 0x93 )

// Much slower, for 64 and 32 bit granularity
#define mm256_rotr512_1x64(v1, v2) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_srli_si256(v1,8), _mm256_slli_si256(v2,24) ); \
  v2 = _mm256_or_si256( _mm256_srli_si256(v2,8), _mm256_slli_si256(v1,24) ); \
  v1 = t; \
while (0);              

#define mm256_rotl512_1x64(v1, v2) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_slli_si256(v1,8), _mm256_srli_si256(v2,24) ); \
  v2 = _mm256_or_si256( _mm256_slli_si256(v2,8), _mm256_srli_si256(v1,24) ); \
  v1 = t; \
while (0);              

#define mm256_rotr512_1x32(v1, v2) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_srli_si256(v1,4), _mm256_slli_si256(v2,28) ); \
  v2 = _mm256_or_si256( _mm256_srli_si256(v2,4), _mm256_slli_si256(v1,28) ); \
  v1 = t; \
while (0);              

#define mm256_rotl512_1x32(v1, v2) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_slli_si256(v1,4), _mm256_srli_si256(v2,28) ); \
  v2 = _mm256_or_si256( _mm256_slli_si256(v2,4), _mm256_srli_si256(v1,28) ); \
  v1 = t; \
while (0);              

// Byte granularity but even a bit slower
#define mm256_rotr512_x8( v1, v2, c ) \
do { \
   __m256i t; \
    t = _mm256_or_si256( _mm256_srli_epi64( v1, c ), \
                         _mm256_slli_epi64( v2, ( 32 - (c) ) ) ); \
   v2 = _mm256_or_si256( _mm256_srli_epi64( v2, c ), \
                         _mm256_slli_epi64( v1, ( 32 - (c) ) ) ); \
   v1 = t; \
while (0);              

#define mm256_rotl512_x8( v1, v2, c ) \
do { \
   __m256i t; \
    t = _mm256_or_si256( _mm256_slli_epi64( v1, c ), \
                         _mm256_srli_epi64( v2, ( 32 - (c) ) ) ); \
   v2 = _mm256_or_si256( _mm256_slli_epi64( v2, c ), \
                         _mm256_srli_epi64( v1, ( 32 - (c) ) ) ); \
   v2 = t; \
while (0);              

//
// Swap bytes in vector elements
static inline __m256i mm256_bswap_64( __m256i v )
{
  return _mm256_shuffle_epi8( v, _mm256_set_epi8(
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ) );
}

static inline __m256i  mm256_bswap_32( __m256i v )
{
   return _mm256_shuffle_epi8( v, _mm256_set_epi8(
                           0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x09, 0x0a, 0x0b,
                           0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03,
                           0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x09, 0x0a, 0x0b,
                           0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03 ) );
}

static inline __m256i mm256_bswap_16( __m256i v )
{
  return _mm256_shuffle_epi8( v, _mm256_set_epi8(
                           0x0e, 0x0f, 0x0c, 0x0d, 0x0a, 0x0b, 0x08, 0x09,
                           0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01,
                           0x0e, 0x0f, 0x0c, 0x0d, 0x0a, 0x0b, 0x08, 0x09,
                           0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01 ) );
}


// Pack/Unpack two 128 bit vectors into/from one 256 bit vector
// usefulness tbd
// __m128i hi, __m128i lo, returns __m256i
#define mm256_pack_2x128( hi, lo ) \
   _mm256_inserti128_si256( _mm256_castsi128_si256( hi ), lo, 0 ) \

// __m128i hi, __m128i lo, __m256i src 
#define mm256_unpack_2x128( hi, lo, src ) \
   lo = _mm256_castsi256_si128( src ); \
   hi = _mm256_castsi256_si128( mm256_swap_128( src ) );
//   hi = _mm256_extracti128_si256( src, 1 ); 

// Pseudo parallel AES
// Probably noticeably slower than using pure 128 bit vectors
// Windows has problems with __m256i args paddes by value.
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

// Paired functions for interleaving and deinterleaving data for vector
// processing. 
// Size is specfied in bits regardless of vector size to avoid pointer
// arithmetic confusion with different size vectors and be consistent with
// the function's name. 
//
// Each function has 2 implementations, an optimized version that uses
// vector indexing and a slower version that uses pointers. The optimized
// version can only be used with 64 bit elements and only supports sizes
// of 256, 512 or 640 bits, 32, 64, and 80 bytes respectively.
//
// NOTE: Contrary to GCC documentation accessing vector elements using array
// indexes only works with 64 bit elements. 
// Interleaving and deinterleaving of vectors of 32 bit elements
// must use the slower implementations that don't use vector indexing. 
// 
// All data must be aligned to 256 bits for AVX2, or 128 bits for AVX.
// Interleave source args and deinterleave destination args are not required
// to be contiguous in memory but it's more efficient if they are.
// Interleave source agrs may be the same actual arg repeated.
// 640 bit deinterleaving 4x64 using 256 bit AVX2 requires the
// destination buffers be defined with padding up to 768 bits for overrun
// space. Although overrun space use is non destructive it should not overlay
// useful data and should be ignored by the caller.

// SSE2 AVX

// interleave 4 arrays of 32 bit elements for 128 bit processing
// bit_len must be 256, 512 or 640 bits.
static inline void mm_interleave_4x32( void *dst, const void *src0,
           const void *src1, const void *src2, const void *src3, int bit_len )
{
   uint32_t *s0 = (uint32_t*)src0;
   uint32_t *s1 = (uint32_t*)src1;
   uint32_t *s2 = (uint32_t*)src2;
   uint32_t *s3 = (uint32_t*)src3;
   __m128i* d = (__m128i*)dst;

   d[0] = _mm_set_epi32( s3[ 0], s2[ 0], s1[ 0], s0[ 0] );
   d[1] = _mm_set_epi32( s3[ 1], s2[ 1], s1[ 1], s0[ 1] );
   d[2] = _mm_set_epi32( s3[ 2], s2[ 2], s1[ 2], s0[ 2] );
   d[3] = _mm_set_epi32( s3[ 3], s2[ 3], s1[ 3], s0[ 3] );
   d[4] = _mm_set_epi32( s3[ 4], s2[ 4], s1[ 4], s0[ 4] );
   d[5] = _mm_set_epi32( s3[ 5], s2[ 5], s1[ 5], s0[ 5] );
   d[6] = _mm_set_epi32( s3[ 6], s2[ 6], s1[ 6], s0[ 6] );
   d[7] = _mm_set_epi32( s3[ 7], s2[ 7], s1[ 7], s0[ 7] );

   if ( bit_len <= 256 ) return;

   d[ 8] = _mm_set_epi32( s3[ 8], s2[ 8], s1[ 8], s0[ 8] );
   d[ 9] = _mm_set_epi32( s3[ 9], s2[ 9], s1[ 9], s0[ 9] );
   d[10] = _mm_set_epi32( s3[10], s2[10], s1[10], s0[10] );
   d[11] = _mm_set_epi32( s3[11], s2[11], s1[11], s0[11] );
   d[12] = _mm_set_epi32( s3[12], s2[12], s1[12], s0[12] );
   d[13] = _mm_set_epi32( s3[13], s2[13], s1[13], s0[13] );
   d[14] = _mm_set_epi32( s3[14], s2[14], s1[14], s0[14] );
   d[15] = _mm_set_epi32( s3[15], s2[15], s1[15], s0[15] );

   if ( bit_len <= 512 ) return;

   d[16] = _mm_set_epi32( s3[16], s2[16], s1[16], s0[16] );
   d[17] = _mm_set_epi32( s3[17], s2[17], s1[17], s0[17] );
   d[18] = _mm_set_epi32( s3[18], s2[18], s1[18], s0[18] );
   d[19] = _mm_set_epi32( s3[19], s2[19], s1[19], s0[19] );

   if ( bit_len <= 640 ) return;

   d[20] = _mm_set_epi32( s3[20], s2[20], s1[20], s0[20] );
   d[21] = _mm_set_epi32( s3[21], s2[21], s1[21], s0[21] );
   d[22] = _mm_set_epi32( s3[22], s2[22], s1[22], s0[22] );
   d[23] = _mm_set_epi32( s3[23], s2[23], s1[23], s0[23] );

   d[24] = _mm_set_epi32( s3[24], s2[24], s1[24], s0[24] );
   d[25] = _mm_set_epi32( s3[25], s2[25], s1[25], s0[25] );
   d[26] = _mm_set_epi32( s3[26], s2[26], s1[26], s0[26] );
   d[27] = _mm_set_epi32( s3[27], s2[27], s1[27], s0[27] );
   d[28] = _mm_set_epi32( s3[28], s2[28], s1[28], s0[28] );
   d[29] = _mm_set_epi32( s3[29], s2[29], s1[29], s0[29] );
   d[30] = _mm_set_epi32( s3[30], s2[30], s1[30], s0[30] );
   d[31] = _mm_set_epi32( s3[31], s2[31], s1[31], s0[31] );
   // bit_len == 1024
}

// bit_len must be multiple of 32
static inline void mm_interleave_4x32x( void *dst, void *src0, void  *src1,
                                        void *src2, void *src3, int bit_len )
{
   uint32_t *d  = (uint32_t*)dst;
   uint32_t *s0 = (uint32_t*)src0;
   uint32_t *s1 = (uint32_t*)src1;
   uint32_t *s2 = (uint32_t*)src2;
   uint32_t *s3 = (uint32_t*)src3;

   for ( int i = 0; i < bit_len >> 5; i++, d += 4 )
   {
      *d     = *(s0+i);
      *(d+1) = *(s1+i);
      *(d+2) = *(s2+i);
      *(d+3) = *(s3+i);
   }
}

static inline void mm_deinterleave_4x32( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src, int bit_len )
{
   uint32_t *s = (uint32_t*)src;
   __m128i* d0 = (__m128i*)dst0;
   __m128i* d1 = (__m128i*)dst1;
   __m128i* d2 = (__m128i*)dst2;
   __m128i* d3 = (__m128i*)dst3;

   d0[0] = _mm_set_epi32( s[12], s[ 8], s[ 4], s[ 0] );
   d1[0] = _mm_set_epi32( s[13], s[ 9], s[ 5], s[ 1] );
   d2[0] = _mm_set_epi32( s[14], s[10], s[ 6], s[ 2] );
   d3[0] = _mm_set_epi32( s[15], s[11], s[ 7], s[ 3] );

   d0[1] = _mm_set_epi32( s[28], s[24], s[20], s[16] );
   d1[1] = _mm_set_epi32( s[29], s[25], s[21], s[17] );
   d2[1] = _mm_set_epi32( s[30], s[26], s[22], s[18] );
   d3[1] = _mm_set_epi32( s[31], s[27], s[23], s[19] );

   if ( bit_len <= 256 ) return;

   d0[2] = _mm_set_epi32( s[44], s[40], s[36], s[32] );
   d1[2] = _mm_set_epi32( s[45], s[41], s[37], s[33] );
   d2[2] = _mm_set_epi32( s[46], s[42], s[38], s[34] );
   d3[2] = _mm_set_epi32( s[47], s[43], s[39], s[35] );

   d0[3] = _mm_set_epi32( s[60], s[56], s[52], s[48] );
   d1[3] = _mm_set_epi32( s[61], s[57], s[53], s[49] );
   d2[3] = _mm_set_epi32( s[62], s[58], s[54], s[50] );
   d3[3] = _mm_set_epi32( s[63], s[59], s[55], s[51] );

   if ( bit_len <= 512 ) return;

   d0[4] = _mm_set_epi32( s[76], s[72], s[68], s[64] );
   d1[4] = _mm_set_epi32( s[77], s[73], s[69], s[65] );
   d2[4] = _mm_set_epi32( s[78], s[74], s[70], s[66] );
   d3[4] = _mm_set_epi32( s[79], s[75], s[71], s[67] );

   if ( bit_len <= 640 ) return;

   d0[5] = _mm_set_epi32( s[92], s[88], s[84], s[80] );
   d1[5] = _mm_set_epi32( s[93], s[89], s[85], s[81] );
   d2[5] = _mm_set_epi32( s[94], s[90], s[86], s[82] );
   d3[5] = _mm_set_epi32( s[95], s[91], s[87], s[83] );

   d0[6] = _mm_set_epi32( s[108], s[104], s[100], s[ 96] );
   d1[6] = _mm_set_epi32( s[109], s[105], s[101], s[ 97] );
   d2[6] = _mm_set_epi32( s[110], s[106], s[102], s[ 98] );
   d3[6] = _mm_set_epi32( s[111], s[107], s[103], s[ 99] );

   d0[7] = _mm_set_epi32( s[124], s[120], s[116], s[112] );
   d1[7] = _mm_set_epi32( s[125], s[121], s[117], s[113] );
   d2[7] = _mm_set_epi32( s[126], s[122], s[118], s[114] );
   d3[7] = _mm_set_epi32( s[127], s[123], s[119], s[115] );
   // bit_len == 1024
}

// deinterleave 4 arrays into individual buffers for scalarm processing
// bit_len must be multiple of 32
static inline void mm_deinterleave_4x32x( void *dst0, void *dst1, void *dst2,
                                    void *dst3, const void *src, int bit_len )
{
  uint32_t *s  = (uint32_t*)src;
  uint32_t *d0 = (uint32_t*)dst0;
  uint32_t *d1 = (uint32_t*)dst1;
  uint32_t *d2 = (uint32_t*)dst2;
  uint32_t *d3 = (uint32_t*)dst3;

  for ( int i = 0; i < bit_len >> 5; i++, s += 4 )
  {
     *(d0+i) = *s;
     *(d1+i) = *(s+1);
     *(d2+i) = *(s+2);
     *(d3+i) = *(s+3);
  }
}

#if defined (__AVX2__)

// Interleave 4 source buffers containing 64 bit data into the destination
// buffer. Only bit_len 256, 512, 640 & 1024 are supported.
static inline void mm256_interleave_4x64( void *dst, const void *src0,
            const void *src1, const void *src2, const void *src3, int bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;
   uint64_t *s2 = (uint64_t*)src2;
   uint64_t *s3 = (uint64_t*)src3;

   d[0] = _mm256_set_epi64x( s3[0], s2[0], s1[0], s0[0] );
   d[1] = _mm256_set_epi64x( s3[1], s2[1], s1[1], s0[1] );
   d[2] = _mm256_set_epi64x( s3[2], s2[2], s1[2], s0[2] );
   d[3] = _mm256_set_epi64x( s3[3], s2[3], s1[3], s0[3] );

   if ( bit_len <= 256 ) return;

   d[4] = _mm256_set_epi64x( s3[4], s2[4], s1[4], s0[4] );
   d[5] = _mm256_set_epi64x( s3[5], s2[5], s1[5], s0[5] );
   d[6] = _mm256_set_epi64x( s3[6], s2[6], s1[6], s0[6] );
   d[7] = _mm256_set_epi64x( s3[7], s2[7], s1[7], s0[7] );

   if ( bit_len <= 512 ) return;

   d[8] = _mm256_set_epi64x( s3[8], s2[8], s1[8], s0[8] );
   d[9] = _mm256_set_epi64x( s3[9], s2[9], s1[9], s0[9] );

   if ( bit_len <= 640 ) return;

   d[10] = _mm256_set_epi64x( s3[10], s2[10], s1[10], s0[10] );
   d[11] = _mm256_set_epi64x( s3[11], s2[11], s1[11], s0[11] );

   d[12] = _mm256_set_epi64x( s3[12], s2[12], s1[12], s0[12] );
   d[13] = _mm256_set_epi64x( s3[13], s2[13], s1[13], s0[13] );
   d[14] = _mm256_set_epi64x( s3[14], s2[14], s1[14], s0[14] );
   d[15] = _mm256_set_epi64x( s3[15], s2[15], s1[15], s0[15] );
   // bit_len == 1024
}

// Slower version
// bit_len must be multiple of 64
static inline void mm256_interleave_4x64x( void *dst, void *src0, void *src1,
                                    void *src2, void *src3, int bit_len )
{
   uint64_t *d = (uint64_t*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;
   uint64_t *s2 = (uint64_t*)src2;
   uint64_t *s3 = (uint64_t*)src3;

   for ( int i = 0; i < bit_len>>6; i++, d += 4 )
   {
      *d     = *(s0+i);
      *(d+1) = *(s1+i);
      *(d+2) = *(s2+i);
      *(d+3) = *(s3+i);
  }
}

// Deinterleave 4 buffers of 64 bit data from the source buffer.
// bit_len must be 256, 512, 640 or 1024 bits.
// Requires overrun padding for 640 bit len.
static inline void mm256_deinterleave_4x64( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src, int bit_len )
{
   __m256i* d0 = (__m256i*)dst0;
   __m256i* d1 = (__m256i*)dst1;
   __m256i* d2 = (__m256i*)dst2;
   __m256i* d3 = (__m256i*)dst3;
   uint64_t* s = (uint64_t*)src;

   d0[0] = _mm256_set_epi64x( s[12], s[ 8], s[ 4], s[ 0] );
   d1[0] = _mm256_set_epi64x( s[13], s[ 9], s[ 5], s[ 1] );
   d2[0] = _mm256_set_epi64x( s[14], s[10], s[ 6], s[ 2] );
   d3[0] = _mm256_set_epi64x( s[15], s[11], s[ 7], s[ 3] );

   if ( bit_len <= 256 ) return;

   d0[1] = _mm256_set_epi64x( s[28], s[24], s[20], s[16] );
   d1[1] = _mm256_set_epi64x( s[29], s[25], s[21], s[17] );
   d2[1] = _mm256_set_epi64x( s[30], s[26], s[22], s[18] );
   d3[1] = _mm256_set_epi64x( s[31], s[27], s[23], s[19] );

   if ( bit_len <= 512 ) return;

   if ( bit_len <= 640 )
   {
      // null change to overrun area
      d0[2] = _mm256_set_epi64x( d0[2][3], d0[2][2], s[36], s[32] );
      d1[2] = _mm256_set_epi64x( d1[2][3], d1[2][2], s[37], s[33] );
      d2[2] = _mm256_set_epi64x( d2[2][3], d2[2][2], s[38], s[34] );
      d3[2] = _mm256_set_epi64x( d3[2][3], d3[2][2], s[39], s[35] );
      return;
   }

   d0[2] = _mm256_set_epi64x( s[44], s[40], s[36], s[32] );
   d1[2] = _mm256_set_epi64x( s[45], s[41], s[37], s[33] );
   d2[2] = _mm256_set_epi64x( s[46], s[42], s[38], s[34] );
   d3[2] = _mm256_set_epi64x( s[47], s[43], s[39], s[35] );

   d0[3] = _mm256_set_epi64x( s[60], s[56], s[52], s[48] );
   d1[3] = _mm256_set_epi64x( s[61], s[57], s[53], s[49] );
   d2[3] = _mm256_set_epi64x( s[62], s[58], s[54], s[50] );
   d3[3] = _mm256_set_epi64x( s[63], s[59], s[55], s[51] );
   // bit_len == 1024
}

// Slower version
// bit_len must be multiple 0f 64
static inline void mm256_deinterleave_4x64x( void *dst0, void *dst1,
                             void *dst2, void *dst3, void *src, int bit_len )
{
  uint64_t *s = (uint64_t*)src;
  uint64_t *d0 = (uint64_t*)dst0;
  uint64_t *d1 = (uint64_t*)dst1;
  uint64_t *d2 = (uint64_t*)dst2;
  uint64_t *d3 = (uint64_t*)dst3;

  for ( int i = 0; i < bit_len>>6; i++, s += 4 )
  {
     *(d0+i) = *s;
     *(d1+i) = *(s+1);
     *(d2+i) = *(s+2);
     *(d3+i) = *(s+3);
  }
}

// Interleave 8 source buffers containing 32 bit data into the destination
// vector
static inline void mm256_interleave_8x32( void *dst, const void *src0,
        const void *src1, const void *src2, const void *src3, const void *src4,
        const void *src5, const void *src6, const void *src7, int bit_len )
{
   uint32_t *s0 = (uint32_t*)src0;
   uint32_t *s1 = (uint32_t*)src1;
   uint32_t *s2 = (uint32_t*)src2;
   uint32_t *s3 = (uint32_t*)src3;
   uint32_t *s4 = (uint32_t*)src4;
   uint32_t *s5 = (uint32_t*)src5;
   uint32_t *s6 = (uint32_t*)src6;
   uint32_t *s7 = (uint32_t*)src7;
   __m256i *d = (__m256i*)dst;

   d[ 0] = _mm256_set_epi32( s7[0], s6[0], s5[0], s4[0],
                             s3[0], s2[0], s1[0], s0[0] );
   d[ 1] = _mm256_set_epi32( s7[1], s6[1], s5[1], s4[1],
                             s3[1], s2[1], s1[1], s0[1] );
   d[ 2] = _mm256_set_epi32( s7[2], s6[2], s5[2], s4[2],
                             s3[2], s2[2], s1[2], s0[2] );
   d[ 3] = _mm256_set_epi32( s7[3], s6[3], s5[3], s4[3],
                             s3[3], s2[3], s1[3], s0[3] );
   d[ 4] = _mm256_set_epi32( s7[4], s6[4], s5[4], s4[4],
                             s3[4], s2[4], s1[4], s0[4] );
   d[ 5] = _mm256_set_epi32( s7[5], s6[5], s5[5], s4[5],
                             s3[5], s2[5], s1[5], s0[5] );
   d[ 6] = _mm256_set_epi32( s7[6], s6[6], s5[6], s4[6],
                             s3[6], s2[6], s1[6], s0[6] );
   d[ 7] = _mm256_set_epi32( s7[7], s6[7], s5[7], s4[7],
                             s3[7], s2[7], s1[7], s0[7] );

   if ( bit_len <= 256 ) return;

   d[ 8] = _mm256_set_epi32( s7[ 8], s6[ 8], s5[ 8], s4[ 8],
                             s3[ 8], s2[ 8], s1[ 8], s0[ 8] );
   d[ 9] = _mm256_set_epi32( s7[ 9], s6[ 9], s5[ 9], s4[ 9],
                             s3[ 9], s2[ 9], s1[ 9], s0[ 9] );
   d[10] = _mm256_set_epi32( s7[10], s6[10], s5[10], s4[10],
                             s3[10], s2[10], s1[10], s0[10] );
   d[11] = _mm256_set_epi32( s7[11], s6[11], s5[11], s4[11],
                             s3[11], s2[11], s1[11], s0[11] );
   d[12] = _mm256_set_epi32( s7[12], s6[12], s5[12], s4[12],
                             s3[12], s2[12], s1[12], s0[12] );
   d[13] = _mm256_set_epi32( s7[13], s6[13], s5[13], s4[13],
                             s3[13], s2[13], s1[13], s0[13] );
   d[14] = _mm256_set_epi32( s7[14], s6[14], s5[14], s4[14],
                             s3[14], s2[14], s1[14], s0[14] );
   d[15] = _mm256_set_epi32( s7[15], s6[15], s5[15], s4[15],
                             s3[15], s2[15], s1[15], s0[15] );

   if ( bit_len <= 512 ) return;

   d[16] = _mm256_set_epi32( s7[16], s6[16], s5[16], s4[16],
                             s3[16], s2[16], s1[16], s0[16] );
   d[17] = _mm256_set_epi32( s7[17], s6[17], s5[17], s4[17],
                             s3[17], s2[17], s1[17], s0[17] );
   d[18] = _mm256_set_epi32( s7[18], s6[18], s5[18], s4[18],
                             s3[18], s2[18], s1[18], s0[18] );
   d[19] = _mm256_set_epi32( s7[19], s6[19], s5[19], s4[19],
                             s3[19], s2[19], s1[19], s0[19] );

   if ( bit_len <= 640 ) return;

   d[20] = _mm256_set_epi32( s7[20], s6[20], s5[20], s4[20],
                             s3[20], s2[20], s1[20], s0[20] );
   d[21] = _mm256_set_epi32( s7[21], s6[21], s5[21], s4[21],
                             s3[21], s2[21], s1[21], s0[21] );
   d[22] = _mm256_set_epi32( s7[22], s6[22], s5[22], s4[22],
                             s3[22], s2[22], s1[22], s0[22] );
   d[23] = _mm256_set_epi32( s7[23], s6[23], s5[23], s4[23],
                             s3[23], s2[23], s1[23], s0[23] );

   if ( bit_len <= 768 ) return;

   d[24] = _mm256_set_epi32( s7[24], s6[24], s5[24], s4[24],
                             s3[24], s2[24], s1[24], s0[24] );
   d[25] = _mm256_set_epi32( s7[25], s6[25], s5[25], s4[25],
                             s3[25], s2[25], s1[25], s0[25] );
   d[26] = _mm256_set_epi32( s7[26], s6[26], s5[26], s4[26],
                             s3[26], s2[26], s1[26], s0[26] );
   d[27] = _mm256_set_epi32( s7[27], s6[27], s5[27], s4[27],
                             s3[27], s2[27], s1[27], s0[27] );
   d[28] = _mm256_set_epi32( s7[28], s6[28], s5[28], s4[28],
                             s3[28], s2[28], s1[28], s0[28] );
   d[29] = _mm256_set_epi32( s7[29], s6[29], s5[29], s4[29],
                             s3[29], s2[29], s1[29], s0[29] );
   d[30] = _mm256_set_epi32( s7[30], s6[30], s5[30], s4[30],
                             s3[30], s2[30], s1[30], s0[30] );
   d[31] = _mm256_set_epi32( s7[31], s6[31], s5[31], s4[31],
                             s3[31], s2[31], s1[31], s0[31] );

   // bit_len == 1024
}

// probably obsolete with double pack 2x32->64, 4x64->256.
// Slower but it works with 32 bit data
// bit_len must be multiple of 32
static inline void mm256_interleave_8x32x( uint32_t *dst, uint32_t *src0,
          uint32_t *src1, uint32_t *src2, uint32_t *src3, uint32_t *src4,
          uint32_t *src5, uint32_t *src6, uint32_t *src7, int bit_len )
{
   uint32_t *d = dst;;
   for ( int i = 0; i < bit_len>>5; i++, d += 8 )
   {
      *d     = *(src0+i);
      *(d+1) = *(src1+i);
      *(d+2) = *(src2+i);
      *(d+3) = *(src3+i);
      *(d+4) = *(src4+i);
      *(d+5) = *(src5+i);
      *(d+6) = *(src6+i);
      *(d+7) = *(src7+i);
  }
}

// Deinterleave 8 buffers of 32 bit data from the source buffer.
static inline void mm256_deinterleave_8x32( void *dst0, void *dst1, void *dst2,
              void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
              const void *src, int bit_len )
{
   uint32_t *s = (uint32_t*)src;
   __m256i* d0 = (__m256i*)dst0;
   __m256i* d1 = (__m256i*)dst1;
   __m256i* d2 = (__m256i*)dst2;
   __m256i* d3 = (__m256i*)dst3;
   __m256i* d4 = (__m256i*)dst4;
   __m256i* d5 = (__m256i*)dst5;
   __m256i* d6 = (__m256i*)dst6;
   __m256i* d7 = (__m256i*)dst7;

   d0[0] = _mm256_set_epi32( s[ 56], s[ 48], s[ 40], s[ 32],
                             s[ 24], s[ 16], s[  8], s[  0] );
   d1[0] = _mm256_set_epi32( s[ 57], s[ 49], s[ 41], s[ 33],
                             s[ 25], s[ 17], s[  9], s[  1] );
   d2[0] = _mm256_set_epi32( s[ 58], s[ 50], s[ 42], s[ 34],
                             s[ 26], s[ 18], s[ 10], s[  2] );
   d3[0] = _mm256_set_epi32( s[ 59], s[ 51], s[ 43], s[ 35],
                             s[ 27], s[ 19], s[ 11], s[  3] );
   d4[0] = _mm256_set_epi32( s[ 60], s[ 52], s[ 44], s[ 36],
                             s[ 28], s[ 20], s[ 12], s[  4] );
   d5[0] = _mm256_set_epi32( s[ 61], s[ 53], s[ 45], s[ 37],
                             s[ 29], s[ 21], s[ 13], s[  5] );
   d6[0] = _mm256_set_epi32( s[ 62], s[ 54], s[ 46], s[ 38],
                             s[ 30], s[ 22], s[ 14], s[  6] );
   d7[0] = _mm256_set_epi32( s[ 63], s[ 55], s[ 47], s[ 39],
                             s[ 31], s[ 23], s[ 15], s[  7] );

   if ( bit_len <= 256 ) return;

   d0[1] = _mm256_set_epi32( s[120], s[112], s[104], s[ 96],
                             s[ 88], s[ 80], s[ 72], s[ 64] );
   d1[1] = _mm256_set_epi32( s[121], s[113], s[105], s[ 97],
                             s[ 89], s[ 81], s[ 73], s[ 65] );
   d2[1] = _mm256_set_epi32( s[122], s[114], s[106], s[ 98],
                             s[ 90], s[ 82], s[ 74], s[ 66]);
   d3[1] = _mm256_set_epi32( s[123], s[115], s[107], s[ 99],
                             s[ 91], s[ 83], s[ 75], s[ 67] );
   d4[1] = _mm256_set_epi32( s[124], s[116], s[108], s[100],
                             s[ 92], s[ 84], s[ 76], s[ 68] );
   d5[1] = _mm256_set_epi32( s[125], s[117], s[109], s[101],
                             s[ 93], s[ 85], s[ 77], s[ 69] );
   d6[1] = _mm256_set_epi32( s[126], s[118], s[110], s[102],
                             s[ 94], s[ 86], s[ 78], s[ 70] );
   d7[1] = _mm256_set_epi32( s[127], s[119], s[111], s[103],
                             s[ 95], s[ 87], s[ 79], s[ 71] );

   if ( bit_len <= 512 ) return;

   // null change for overrun space, vector indexing doesn't work for
   // 32 bit data
   if ( bit_len <= 640 )
   {
      uint32_t *d = ((uint32_t*)d0) + 8;
      d0[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[152], s[144], s[136], s[128] );
      d = ((uint32_t*)d1) + 8;
      d1[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[153], s[145], s[137], s[129] );
      d = ((uint32_t*)d2) + 8;
      d2[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[154], s[146], s[138], s[130]);
      d = ((uint32_t*)d3) + 8;
      d3[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[155], s[147], s[139], s[131] );
      d = ((uint32_t*)d4) + 8;
      d4[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[156], s[148], s[140], s[132] );
      d = ((uint32_t*)d5) + 8;
      d5[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[157], s[149], s[141], s[133] );
      d = ((uint32_t*)d6) + 8;
      d6[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[158], s[150], s[142], s[134] );
      d = ((uint32_t*)d7) + 8;
      d7[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[159], s[151], s[143], s[135] );
      return;
   }

   d0[2] = _mm256_set_epi32( s[184], s[176], s[168], s[160],
                             s[152], s[144], s[136], s[128] );
   d1[2] = _mm256_set_epi32( s[185], s[177], s[169], s[161],
                             s[153], s[145], s[137], s[129] );
   d2[2] = _mm256_set_epi32( s[186], s[178], s[170], s[162],
                             s[154], s[146], s[138], s[130] );
   d3[2] = _mm256_set_epi32( s[187], s[179], s[171], s[163],
                             s[155], s[147], s[139], s[131] );
   d4[2] = _mm256_set_epi32( s[188], s[180], s[172], s[164],
                             s[156], s[148], s[140], s[132] );
   d5[2] = _mm256_set_epi32( s[189], s[181], s[173], s[165],
                             s[157], s[149], s[141], s[133] );
   d6[2] = _mm256_set_epi32( s[190], s[182], s[174], s[166],
                             s[158], s[150], s[142], s[134] );
   d7[2] = _mm256_set_epi32( s[191], s[183], s[175], s[167],
                             s[159], s[151], s[143], s[135] );

   if ( bit_len <= 768 ) return;

   d0[3] = _mm256_set_epi32( s[248], s[240], s[232], s[224],
                             s[216], s[208], s[200], s[192] );
   d1[3] = _mm256_set_epi32( s[249], s[241], s[233], s[225],
                             s[217], s[209], s[201], s[193] );
   d2[3] = _mm256_set_epi32( s[250], s[242], s[234], s[226],
                             s[218], s[210], s[202], s[194] );
   d3[3] = _mm256_set_epi32( s[251], s[243], s[235], s[227],
                             s[219], s[211], s[203], s[195] );
   d4[3] = _mm256_set_epi32( s[252], s[244], s[236], s[228],
                             s[220], s[212], s[204], s[196] );
   d5[3] = _mm256_set_epi32( s[253], s[245], s[237], s[229],
                             s[221], s[213], s[205], s[197] );
   d6[3] = _mm256_set_epi32( s[254], s[246], s[238], s[230],
                             s[222], s[214], s[206], s[198] );
   d7[3] = _mm256_set_epi32( s[255], s[247], s[239], s[231],
                             s[223], s[215], s[207], s[199] );
// bit_len == 1024
}

// Deinterleave 8 arrays into indivdual buffers for scalar processing
// bit_len must be multiple of 32
static inline void mm256_deinterleave_8x32x( uint32_t *dst0, uint32_t *dst1,
                uint32_t *dst2,uint32_t *dst3, uint32_t *dst4, uint32_t *dst5,
                uint32_t *dst6,uint32_t *dst7,uint32_t *src, int bit_len )
{
  uint32_t *s = src;
  for ( int i = 0; i < bit_len>>5; i++, s += 8 )
  {
     *(dst0+i) = *( s     );
     *(dst1+i) = *( s + 1 );
     *(dst2+i) = *( s + 2 );
     *(dst3+i) = *( s + 3 );
     *(dst4+i) = *( s + 4 );
     *(dst5+i) = *( s + 5 );
     *(dst6+i) = *( s + 6 );
     *(dst7+i) = *( s + 7 );
  }
}

// Can't do it in place
static inline void mm256_reinterleave_4x64( void *dst, void *src, int  bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint32_t *s = (uint32_t*)src;

   d[0] = _mm256_set_epi32( s[7], s[3], s[6], s[2], s[5], s[1], s[4], s[0] );
   d[1] = _mm256_set_epi32( s[15],s[11],s[14],s[10],s[13],s[9],s[12], s[8] );
   d[2] = _mm256_set_epi32( s[23],s[19],s[22],s[18],s[21],s[17],s[20],s[16] );
   d[3] = _mm256_set_epi32( s[31],s[27],s[30],s[26],s[29],s[25],s[28],s[24] );

   if ( bit_len <= 256 ) return;

   d[4] = _mm256_set_epi32( s[39],s[35],s[38],s[34],s[37],s[33],s[36],s[32] );
   d[5] = _mm256_set_epi32( s[47],s[43],s[46],s[42],s[45],s[41],s[44],s[40] );
   d[6] = _mm256_set_epi32( s[55],s[51],s[54],s[50],s[53],s[49],s[52],s[48] );
   d[7] = _mm256_set_epi32( s[63],s[59],s[62],s[58],s[61],s[57],s[60],s[56] );

   if ( bit_len <= 512 ) return;

   d[8] = _mm256_set_epi32( s[71],s[67],s[70],s[66],s[69],s[65],s[68],s[64] );
   d[9] = _mm256_set_epi32( s[79],s[75],s[78],s[74],s[77],s[73],s[76],s[72] );

   if ( bit_len <= 640 ) return;

  d[10] = _mm256_set_epi32(s[87],s[83],s[86],s[82],s[85],s[81],s[84],s[80]);
  d[11] = _mm256_set_epi32(s[95],s[91],s[94],s[90],s[93],s[89],s[92],s[88]);

  d[12] = _mm256_set_epi32(s[103],s[99],s[102],s[98],s[101],s[97],s[100],s[96]);
  d[13] = _mm256_set_epi32(s[111],s[107],s[110],s[106],s[109],s[105],s[108],s[104]);
  d[14] = _mm256_set_epi32(s[119],s[115],s[118],s[114],s[117],s[113],s[116],s[112]);
  d[15] = _mm256_set_epi32(s[127],s[123],s[126],s[122],s[125],s[121],s[124],s[120]);
   // bit_len == 1024
}

// likely of no use.
// convert 4x32 byte (128 bit) vectors to 4x64 (256 bit) vectors for AVX2
// bit_len must be multiple of 64
// broken
static inline void mm256_reinterleave_4x64x( uint64_t *dst, uint32_t *src,
                                             int  bit_len )
{
   uint32_t *d = (uint32_t*)dst;
   uint32_t *s = (uint32_t*)src;
   for ( int i = 0; i < bit_len >> 5; i += 8 )
   {
      *( d + i     ) = *( s + i     );      // 0 <- 0    8 <- 8
      *( d + i + 1 ) = *( s + i + 4 );      // 1 <- 4    9 <- 12
      *( d + i + 2 ) = *( s + i + 1 );      // 2 <- 1    10 <- 9
      *( d + i + 3 ) = *( s + i + 5 );      // 3 <- 5    11 <- 13
      *( d + i + 4 ) = *( s + i + 2 );      // 4 <- 2    12 <- 10
      *( d + i + 5 ) = *( s + i + 6 );      // 5 <- 6    13 <- 14
      *( d + i + 6 ) = *( s + i + 3 );      // 6 <- 3    14 <- 11
      *( d + i + 7 ) = *( s + i + 7 );      // 7 <- 7    15 <- 15
     }
}

// convert 4x64 byte (256 bit) vectors to 4x32 (128 bit) vectors for AVX
// bit_len must be multiple of 64
static inline void mm256_reinterleave_4x32( void *dst, void *src, int  bit_len )
{
   __m256i  *d = (__m256i*)dst;
   uint32_t *s = (uint32_t*)src;

   d[0] = _mm256_set_epi32( s[ 7],s[ 5],s[ 3],s[ 1],s[ 6],s[ 4],s[ 2],s[ 0] );
   d[1] = _mm256_set_epi32( s[15],s[13],s[11],s[ 9],s[14],s[12],s[10],s[ 8] );
   d[2] = _mm256_set_epi32( s[23],s[21],s[19],s[17],s[22],s[20],s[18],s[16] );
   d[3] = _mm256_set_epi32( s[31],s[29],s[27],s[25],s[30],s[28],s[26],s[24] );

   if ( bit_len <= 256 ) return;

   d[4] = _mm256_set_epi32( s[39],s[37],s[35],s[33],s[38],s[36],s[34],s[32] );
   d[5] = _mm256_set_epi32( s[47],s[45],s[43],s[41],s[46],s[44],s[42],s[40] );
   d[6] = _mm256_set_epi32( s[55],s[53],s[51],s[49],s[54],s[52],s[50],s[48] );
   d[7] = _mm256_set_epi32( s[63],s[61],s[59],s[57],s[62],s[60],s[58],s[56] );

   if ( bit_len <= 512 ) return;

   d[8] = _mm256_set_epi32( s[71],s[69],s[67],s[65],s[70],s[68],s[66],s[64] );
   d[9] = _mm256_set_epi32( s[79],s[77],s[75],s[73],s[78],s[76],s[74],s[72] );

   if ( bit_len <= 640 ) return;

   d[10] = _mm256_set_epi32( s[87],s[85],s[83],s[81],s[86],s[84],s[82],s[80] );
   d[11] = _mm256_set_epi32( s[95],s[93],s[91],s[89],s[94],s[92],s[90],s[88] );

   d[12] = _mm256_set_epi32( s[103],s[101],s[99],s[97],s[102],s[100],s[98],s[96] );
   d[13] = _mm256_set_epi32( s[111],s[109],s[107],s[105],s[110],s[108],s[106],s[104] );
   d[14] = _mm256_set_epi32( s[119],s[117],s[115],s[113],s[118],s[116],s[114],s[112] );
   d[15] = _mm256_set_epi32( s[127],s[125],s[123],s[121],s[126],s[124],s[122],s[120] );
   // bit_len == 1024
}

static inline void mm256_interleave_2x128( void *dst, void *src0, void *src1,
                                           int bit_len )
{
   __m256i  *d = (__m256i*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;   

   d[0] = _mm256_set_epi64x( s1[ 1], s1[ 0], s0[ 1], s0[ 0] );
   d[1] = _mm256_set_epi64x( s1[ 3], s1[ 2], s0[ 3], s0[ 2] );

   if ( bit_len <= 256 ) return;

   d[2] = _mm256_set_epi64x( s1[ 5], s1[ 4], s0[ 5], s0[ 4] );
   d[3] = _mm256_set_epi64x( s1[ 7], s1[ 6], s0[ 7], s0[ 6] );

   if ( bit_len <= 512 ) return;

   d[4] = _mm256_set_epi64x( s1[ 9], s1[ 8], s0[ 9], s0[ 8] );
   
   if ( bit_len <= 640 ) return;

   d[5] = _mm256_set_epi64x( s1[11], s1[10], s0[11], s0[10] );

   d[6] = _mm256_set_epi64x( s1[13], s1[12], s0[13], s0[12] );
   d[7] = _mm256_set_epi64x( s1[15], s1[14], s0[15], s0[14] );

   // bit_len == 1024
}

static inline void mm256_deinterleave_2x128( void *dst0, void *dst1, void *src,
                                             int bit_len )
{
   uint64_t *s = (uint64_t*)src;
   __m256i  *d0 = (__m256i*)dst0;
   __m256i  *d1 = (__m256i*)dst1;

   d0[0] = _mm256_set_epi64x( s[ 5], s[4], s[ 1], s[ 0] );
   d1[0] = _mm256_set_epi64x( s[ 7], s[6], s[ 3], s[ 2] );

   if ( bit_len <= 256 ) return;

   d0[1] = _mm256_set_epi64x( s[13], s[12], s[ 9], s[ 8] );
   d1[1] = _mm256_set_epi64x( s[15], s[14], s[11], s[10] );

   if ( bit_len <= 512 ) return;

   if ( bit_len <= 640 )
   {
      d0[2] = _mm256_set_epi64x( d0[2][3], d0[2][2], s[17], s[16] );
      d1[2] = _mm256_set_epi64x( d1[2][3], d1[2][2], s[19], s[18] );
      return;
   }

   d0[2] = _mm256_set_epi64x( s[21], s[20], s[17], s[16] );
   d1[2] = _mm256_set_epi64x( s[23], s[22], s[19], s[18] );

   d0[3] = _mm256_set_epi64x( s[29], s[28], s[25], s[24] );
   d1[3] = _mm256_set_epi64x( s[31], s[30], s[27], s[26] );

   // bit_len == 1024
}

// not used
static inline void mm_reinterleave_4x32( void *dst, void *src, int  bit_len )
{
   uint32_t *d = (uint32_t*)dst;
   uint32_t *s = (uint32_t*)src;
   for ( int i = 0; i < bit_len >> 5; i +=8 )
   {
      *( d + i     ) = *( s + i     );
      *( d + i + 1 ) = *( s + i + 2 );
      *( d + i + 2 ) = *( s + i + 4 );
      *( d + i + 3 ) = *( s + i + 6 );
      *( d + i + 4 ) = *( s + i + 1 );
      *( d + i + 5 ) = *( s + i + 3 );
      *( d + i + 6 ) = *( s + i + 5 );
      *( d + i + 7 ) = *( s + i + 7 );
   }
}

#endif // __AVX2__
#endif // AVXDEFS_H__
