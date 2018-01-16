#ifndef AVXDEFS_H__
#define AVXDEFS_H__

// Some tools to help using AVX and AVX2.
// At this time SSE2 is sufficient for all 128 bit code in this file
// but could change without notice.
// 256 bit requires AVX2.
// AVX512 has more powerful 256 bit instructions but with AVX512 available
// there is little reason to use them.
// Proper alignment of data is required, 16 bytes for 128 bit vectors and
// 32 bytes for 256 bit vectors. 64 byte alignment is recommended for
// best cache alignment.
//
// There exist dupplicates of some functions. In general the first defined
// is preferred as it is more efficient but also more restrictive and may
// not be applicable. The less efficient versions are more flexible.

#include <inttypes.h>
#include <immintrin.h>
#include <memory.h>
#include <stdbool.h>

//
// 128 bit utilities and shortcuts

//
// Pseudo constants, there are no real vector constants.
// These can't be used for compile time initialization.

// Constant zero
#define mm_zero      _mm_setzero_si128()

// Constant 1
#define mm_one_128   _mm_set_epi64x(  0ULL, 1ULL )
#define mm_one_64    _mm_set1_epi64x( 1ULL )
#define mm_one_32    _mm_set1_epi32(  1UL )
#define mm_one_16    _mm_set1_epi16(  1U )
#define mm_one_8     _mm_set1_epi8(   1U )

// Constant minus 1
#define mm_neg1      _mm_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )

// Lane index, useful for byte rotate using shuffle
#define mm_lanex_64 _mm_set_epi64( 1ULL, 0ULL );
#define mm_lanex_32 _mm_set_epi32( 3UL, 2UL, 1UL, 0UL );
#define mm_lanex_16 _mm_set_epi16( 7U, 6U, 5U, 4U, 3U, 2U, 1U, 0U );
#define mm_lanex_8 _mm_set_epi8( 15U, 14U, 13U, 12U, 11U, 10U , 9U,  8U, \
                                  7U,  6U,  5U,  4U,  3U,  2U,  1U,  0U );

//
// Basic operations without equivalent SIMD intrinsic

// Bitwise not (~x)
#define mm_not( x )  _mm_xor_si128( (x), mm_neg1 ) 

// Unary negation (-a)
#define mm_negate_64( a ) _mm_sub_epi64( mm_zero, a )
#define mm_negate_32( a ) _mm_sub_epi32( mm_zero, a )  
#define mm_negate_16( a ) _mm_sub_epi16( mm_zero, a )  

//
// Bit operations

// Return bit n in position, all other bits zeroed.
#define mm_bitextract_64 ( x, n ) \
   _mm_and_si128( _mm_slli_epi64( mm_one_64, n ), x )
#define mm_bitextract_32 ( x, n ) \
   _mm_and_si128( _mm_slli_epi32( mm_one_32, n ), x )
#define mm_bitextract_16 ( x, n ) \
   _mm_and_si128( _mm_slli_epi16( mm_one_16, n ), x )

// Return bit n as bool
#define mm_bittest_64( x, n ) \
   _mm_and_si256( mm_one_64, _mm_srli_epi64( x, n ) ) 
#define mm_bittest_32( x, n ) \
   _mm_and_si256( mm_one_32, _mm_srli_epi32( x, n ) ) 
#define mm_bittest_16( x, n ) \
   _mm_and_si256( mm_one_16, _mm_srli_epi16( x, n ) ) 

// Return x with bit n set/cleared in all elements
#define mm_bitset_64( x, n ) \
   _mm_or_si128( _mm_slli_epi64( mm_one_64, n ), x )
#define mm_bitclr_64( x, n ) \
   _mm_andnot_si128( _mm_slli_epi64( mm_one_64, n ), x )
#define mm_bitset_32( x, n ) \
   _mm_or_si128( _mm_slli_epi32( mm_one_32, n ), x )
#define mm_bitclr_32( x, n ) \
   _mm_andnot_si128( _mm_slli_epi32( mm_one_32, n ), x )
#define mm_bitset_16( x, n ) \
   _mm_or_si128( _mm_slli_epi16( mm_one_16, n ), x )
#define mm_bitclr_16( x, n ) \
   _mm_andnot_si128( _mm_slli_epi16( mm_one_16, n ), x )

// Return x with bit n toggled
#define mm_bitflip_64( x, n ) \
   _mm_xor_si128( _mm_slli_epi64( mm_one_64, n ), x )
#define mm_bitflip_32( x, n ) \
   _mm_xor_si128( _mm_slli_epi32( mm_one_32, n ), x )
#define mm_bitflip_16( x, n ) \
   _mm_xor_si128( _mm_slli_epi16( mm_one_16, n ), x )


//
// Memory functions
// n = number of __m128i, bytes/16

inline void memset_zero_128( __m128i *dst,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = mm_zero;
}

inline void memset_128( __m128i *dst, const __m128i a,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = a;
}

inline void memcpy_128( __m128i *dst, const __m128i *src, int n )
{
   for ( int i = 0; i < n; i ++ ) dst[i] = src[i];
}

// Compare data in memory, return true if different
inline bool memcmp_128( __m128i src1, __m128i src2, int n )
{
   for ( int i = 0; i < n; i++ )
     if ( src1[i] != src2[i] ) return true;
   return false;
}

// A couple of 64 bit scalar functions
// n = bytes/8

inline void memcpy_64( uint64_t *dst, const uint64_t *src, int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = src[i];
}

inline void memset_zero_64( uint64_t *src, int n )
{
   for ( int i = 0; i < n; i++ ) src[i] = 0;
}

inline void memset_64( uint64_t *dst, uint64_t a,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = a;
}


//
// Pointer cast

// p = any aligned pointer
// returns p as pointer to vector type
#define castp_m128i(p) ((__m128i*)(p))

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_m128i(p) (*((__m128i*)(p)))

// p = any aligned pointer, i = scaled array index
// returns p[i]
#define casti_m128i(p,i) (((__m128i*)(p))[(i)])

//
// Bit rotations

// XOP is an obsolete AMD feature that has native rotation. 
//    _mm_roti_epi64( w, c)
// Never implemented by Intel and since removed from Zen by AMD.

// Rotate bits in vector elements
#define mm_rotr_64( w, c ) _mm_or_si128( _mm_srli_epi64( w, c ), \
                                         _mm_slli_epi64( w, 64-(c) ) )
#define mm_rotl_64( w, c ) _mm_or_si128( _mm_slli_epi64( w, c ), \
                                         _mm_srli_epi64( w, 64-(c) ) )
#define mm_rotr_32( w, c ) _mm_or_si128( _mm_srli_epi32( w, c ), \
                                         _mm_slli_epi32( w, 32-(c) ) )
#define mm_rotl_32( w, c ) _mm_or_si128( _mm_slli_epi32( w, c ), \
                                         _mm_srli_epi32( w, 32-(c) ) )
#define mm_rotr_16( w, c ) _mm_or_si128( _mm_srli_epi16( w, c ), \
                                         _mm_slli_epi16( w, 16-(c) ) )
#define mm_rotl_16( w, c ) _mm_or_si128( _mm_slli_epi16( w, c ), \
                                         _mm_srli_epi16( w, 16-(c) ) )

//
// Rotate elements in vector

// Optimized shuffle

// Swap hi/lo 64 bits in 128 bit vector
#define mm_swap_64( w )    _mm_shuffle_epi32( w, 0x4e )

// rotate 128 bit vector by 32 bits
#define mm_rotr_1x32( w )  _mm_shuffle_epi32( w, 0x39 )
#define mm_rotl_1x32( w )  _mm_shuffle_epi32( w, 0x93 )

// Swap hi/lo 32 bits in each 64 bit element
#define mm_swap64_32( x )  _mm_shuffle_epi32( x, 0xb1 )

// Less efficient but more versatile. Use only for odd number rotations.
// Use shuffle above when possible.

// Rotate vector by n bytes.
#define mm_rotr128_x8( w, n ) \
     _mm_or_si128( _mm_srli_si128( w, n ), _mm_slli_si128( w, 16-(n) ) )
#define mm_rotl128_x8( w, n ) \
     _mm_or_si128( _mm_slli_si128( w, n ), _mm_srli_si128( w, 16-(n) ) )

// Rotate vector by c elements, use only for odd number rotations
#define mm_rotr128_x32( w, c ) mm_rotr128_x8( w, (c)>>2 ) 
#define mm_rotl128_x32( w, c ) mm_rotl128_x8( w, (c)>>2 )
#define mm_rotr128_x16( w, c ) mm_rotr128_x8( w, (c)>>1 ) 
#define mm_rotl128_x16( w, c ) mm_rotl128_x8( w, (c)>>1 )

//
// Rotate elements across two 128 bit vectors as one 256 bit vector {hi,lo}

// Swap 128 bit source vectors in place, aka rotate 256 bits by 128 bits.
// void mm128_swap128( __m128i, __m128i )
#define mm_swap_128(hi, lo) \
{ \
   hi = _mm_xor_si128(hi, lo); \
   lo = _mm_xor_si128(hi, lo); \
   hi = _mm_xor_si128(hi, lo); \
}

// Rotate two 128 bit vectors in place as one 256 vector by 1 element
#define mm_rotl256_1x64( hi, lo ) \
do { \
 __m128i t; \
 hi = mm_swap_64( hi ); \
 lo = mm_swap_64( lo ); \
 t  = _mm_blendv_epi8( hi, lo, _mm_set_epi64x( 0xffffffffffffffffull, 0ull )); \
 lo = _mm_blendv_epi8( hi, lo, _mm_set_epi64x( 0ull, 0xffffffffffffffffull )); \
 hi = t; \
} while(0)

#define mm_rotr256_1x64( hi, lo ) \
do { \
 __m128i t; \
 hi = mm_swap_64( hi ); \
 lo = mm_swap_64( lo ); \
 t  = _mm_blendv_epi8( hi, lo, _mm_set_epi64x( 0ull, 0xffffffffffffffffull )); \
 lo = _mm_blendv_epi8( hi, lo, _mm_set_epi64x( 0xffffffffffffffffull, 0ull )); \
 hi = t; \
} while(0)

#define mm_rotl256_1x32( hi, lo ) \
do { \
 __m128i t; \
 hi = mm_swap_64( hi ); \
 lo = mm_swap_64( lo ); \
 t  = _mm_blendv_epi8( hi, lo, _mm_set_epi32( \
                 0xfffffffful, 0xfffffffful, 0xfffffffful,          0ul )); \
 lo = _mm_blendv_epi8( hi, lo, _mm_set_epi32( \
                          0ul,          0ul,          0ul, 0xfffffffful )); \
 hi = t; \
} while(0)

#define mm_rotr256_1x32( hi, lo ) \
do { \
 __m128i t; \
 hi = mm_swap_64( hi ); \
 lo = mm_swap_64( lo ); \
 t  = _mm_blendv_epi8( hi, lo, _mm_set_epi32( \
                          0ul,          0ul,          0ul, 0xfffffffful )); \
 lo = _mm_blendv_epi8( hi, lo, _mm_set_epi32( \
                 0xfffffffful, 0xfffffffful, 0xfffffffful,          0ul )); \
 hi = t; \
} while(0)

// Return hi 128 bits with elements shifted one lane with vacated lane filled
// with data rotated from lo.
// Partially rotate elements in two 128 bit vectors as one 256 bit vector
// and return the rotated high 128 bits.
// Similar to mm_rotr256_1x32 but only a partial rotation as lo is not
// completed. It's faster than a full rotation.

inline __m128i mm_rotr256hi_1x32( __m128i hi, __m128i lo, int n )
{
   return _mm_or_si128( _mm_srli_si128( hi, n<<2 ),
                        _mm_slli_si128( lo, 16 - (n<<2) ) );
}

inline __m128i mm_rotl256hi_1x32( __m128i hi, __m128i lo, int n )
{
   return _mm_or_si128( _mm_slli_si128( hi, n<<2 ), 
                        _mm_srli_si128( lo, 16 - (n<<2) ) );
}

//
// Swap bytes in vector elements

inline __m128i mm_byteswap_64( __m128i x )
{
  return _mm_shuffle_epi8( x, _mm_set_epi8(
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ) );
}

inline __m128i mm_byteswap_32( __m128i x )
{
  return _mm_shuffle_epi8( x, _mm_set_epi8(
                           0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x09, 0x0a, 0x0b,
                           0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03 ) );
}

inline __m128i mm_byteswap_16( __m128i x )
{
  return _mm_shuffle_epi8( x, _mm_set_epi8(
                           0x0e, 0x0f, 0x0c, 0x0d, 0x0a, 0x0b, 0x08, 0x09,
                           0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01 ) );
}

/////////////////////////////////////////////////////////////////////

#if defined (__AVX2__)

//
// 256 bit utilities and Shortcuts

//
// Pseudo constants, there are no real vector constants.
// These can't be used for compile time initialization

// Constant zero
#define mm256_zero _mm256_setzero_si256()

// Constant 1
#define mm256_one_128        _mm256_set_epi64x(  0ULL, 1ULL, 0ULL, 1ULL )
#define mm256_one_64         _mm256_set1_epi64x( 1ULL )
#define mm256_one_32         _mm256_set1_epi32(  1UL )
#define mm256_one_16         _mm256_set1_epi16(  1U )

// Constant minus 1
#define mm256_neg1           _mm256_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )

// Lane index, useful for rotate using permutevar
#define mm256_lane_64 _mm_set_epi64x( 3ULL, 2ULL, 1ULL, 0ULL );
#define mm256_lane_32 _mm_set_epi32( 7UL, 6UL, 5UL, 4UL, 3UL, 2UL, 1UL, 0UL );
#define mm256_lane_16 _mm_set_epi16( 15U, 14U, 13U, 12U, 11U, 10U , 9U,  8U, \
                                      7U,  6U,  5U,  4U,  3U,  2U,  1U,  0U );
#define mm256_lane_8 _mm_set_epi8( 31U, 30U, 29U, 28U, 27U, 26U, 25U, 24U, \
                                   23U, 22U, 21U, 20U, 19U, 18U, 17U, 16U, \
                                   15U, 14U, 13U, 12U, 11U, 10U , 9U,  8U, \
                                    7U,  6U,  5U,  4U,  3U,  2U,  1U,  0U );

//
// Basic operations without SIMD equivalent

// Bitwise not ( ~x )
#define mm256_not( x )       _mm256_xor_si256( (x), mm256_neg1 ) \

// Unary negation ( -a )
#define mm256_negate_64( a ) _mm256_sub_epi64( mm256_zero, a )
#define mm256_negate_32( a ) _mm256_sub_epi32( mm256_zero, a )  
#define mm256_negate_16( a ) _mm256_sub_epi16( mm256_zero, a )  

//
// Bit operations

// return bit n in position, all othr bits cleared
#define mm256_bitextract_64 ( x, n ) \
   _mm256_and_si128( _mm256_slli_epi64( mm256_one_64, n ), x )
#define mm256_bitextract_32 ( x, n ) \
   _mm256_and_si128( _mm256_slli_epi32( mm256_one_32, n ), x )
#define mm256_bitextract_16 ( x, n ) \
   _mm256_and_si128( _mm256_slli_epi16( mm256_one_16, n ), x )

// Return bit n as bool (bit 0)
#define mm256_bittest_64( x, n ) \
   _mm256_and_si256( mm256_one_64, _mm256_srli_epi64( x, n ) )
#define mm256_bittest_32( x, n ) \
   _mm256_and_si256( mm256_one_32, _mm256_srli_epi32( x, n ) )
#define mm256_bittest_16( x, n ) \
   _mm256_and_si256( mm256_one_16, _mm256_srli_epi16( x, n ) )

// Return x with bit n set/cleared in all elements
#define mm256_bitset_64( x, n ) \
    _mm256_or_si256( _mm256_slli_epi64( mm256_one_64, n ), x )
#define mm256_bitclr_64( x, n ) \
    _mm256_andnot_si256( _mm256_slli_epi64( mm256_one_64, n ), x )
#define mm256_bitset_32( x, n ) \
    _mm256_or_si256( _mm256_slli_epi32( mm256_one_32, n ), x )
#define mm256_bitclr_32( x, n ) \
    _mm256_andnot_si256( _mm256_slli_epi32( mm256_one_32, n ), x )
#define mm256_bitset_16( x, n ) \
    _mm256_or_si256( _mm256_slli_epi16( mm256_one_16, n ), x )
#define mm256_bitclr_16( x, n ) \
    _mm256_andnot_si256( _mm256_slli_epi16( mm256_one_16, n ), x )

// Return x with bit n toggled
#define mm256_bitflip_64( x, n ) \
   _mm256_xor_si128( _mm256_slli_epi64( mm256_one_64, n ), x )
#define mm256_bitflip_32( x, n ) \
   _mm256_xor_si128( _mm256_slli_epi32( mm256_one_32, n ), x )
#define mm256_bitflip_16( x, n ) \
   _mm256_xor_si128( _mm256_slli_epi16( mm256_one_16, n ), x )


//
// Memory functions
// n = number of 256 bit (32 byte) vectors

inline void memset_zero_256( __m256i *dst, int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = mm256_zero;
}

inline void memset_256( __m256i *dst, const __m256i a,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = a;
}

inline void memcpy_256( __m256i *dst, const __m256i *src, int n )
{
   for ( int i = 0; i < n; i ++ ) dst[i] = src[i];
}

// Compare data in memory, return true if different
inline bool memcmp_256( __m256i src1, __m256i src2, int n )
{
   for ( int i = 0; i < n; i++ )
     if ( src1[i] != src2[i] ) return true;
   return false;
}

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

//
// Bit rotations

//
// Rotate bits in vector elements
// w = packed data, c = number of bits to rotate

#define  mm256_rotr_64( w, c ) \
    _mm256_or_si256( _mm256_srli_epi64(w, c), _mm256_slli_epi64(w, 64-(c)) )
#define  mm256_rotl_64( w, c ) \
    _mm256_or_si256( _mm256_slli_epi64(w, c), _mm256_srli_epi64(w, 64-(c)) )
#define  mm256_rotr_32( w, c ) \
    _mm256_or_si256( _mm256_srli_epi32(w, c), _mm256_slli_epi32(w, 32-(c)) )
#define  mm256_rotl_32( w, c ) \
    _mm256_or_si256( _mm256_slli_epi32(w, c), _mm256_srli_epi32(w, 32-(c)) )
#define  mm256_rotr_16( w, c ) \
    _mm256_or_si256( _mm256_srli_epi16(w, c), _mm256_slli_epi16(w, 32-(c)) )
#define  mm256_rotl_16( w, c ) \
    _mm256_or_si256( _mm256_slli_epi16(w, c), _mm256_srli_epi16(w, 32-(c)) )

//
// Rotate elements in vector
// There is no full vector permute for elements less than 64 bits or 256 bit
// shift, a little more work is needed.

// Optimized 64 bit permutations
// Swap 128 bit elements in 256 bit vector
#define mm256_swap_128( w )      _mm256_permute4x64_epi64( w, 0x4e )

// Rotate 256 bit vector by one 64 bit element
#define mm256_rotl256_1x64( w )  _mm256_permute4x64_epi64( w, 0x93 )
#define mm256_rotr256_1x64( w )  _mm256_permute4x64_epi64( w, 0x39 )

// Swap 64 bits in each 128 bit element of 256 bit vector
#define mm256_swap128_64( x )    _mm256_shuffle_epi32( x, 0x4e )

// Rotate 128 bit elements in 256 bit vector by 32 bits
#define mm256_rotr128_1x32( x )  _mm256_shuffle_epi32( x, 0x39 )
#define mm256_rotl128_1x32( x )  _mm256_shuffle_epi32( x, 0x93 )

// Swap 32 bits in each 64 bit element olf 256 bit vector
#define mm256_swap64_32( x )     _mm256_shuffle_epi32( x, 0xb1 )

// Less efficient but more versatile. Use only for rotations that are not 
// integrals of 64 bits. Use permutations above when possible.

// Rotate 256 bit vector by c bytes.
#define mm256_rotr256_x8( w, c ) \
   _mm256_or_si256( _mm256_srli_si256( w, c ), \
                     mm256_swap_128( _mm256i_slli_si256( w, 32-(c) ) ) )
#define mm256_rotl256_x8( w, c ) \
   _mm256_or_si256( _mm256_slli_si256( w, c ), \
                     mm256_swap_128( _mm256i_srli_si256( w, 32-(c) ) ) )

// Rotate 256 bit vector by c elements, use only for odd value rotations
#define mm256_rotr256_x32( w, c )   mm256_rotr256_x8( w, (c)>>2 ) 
#define mm256_rotl256_x32( w, c )   mm256_rotl256_x8( w, (c)>>2 )
#define mm256_rotr256_x16( w, c )   mm256_rotr256_x8( w, (c)>>1 ) 
#define mm256_rotl256_x16( w, c )   mm256_rotl256_x8( w, (c)>>1 )

//
// Rotate two 256 bit vectors as one 512 bit vector

// Fast but limited to 128 bit granularity
#define mm256_swap512_256(a, b)    _mm256_permute2x128_si256( a, b, 0x4e )
#define mm256_rotr512_1x128(a, b)  _mm256_permute2x128_si256( a, b, 0x39 )
#define mm256_rotl512_1x128(a, b)  _mm256_permute2x128_si256( a, b, 0x93 )

// Much slower, for 64 and 32 bit granularity
#define mm256_rotr512_1x64(a, b) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_srli_si256(a,8), _mm256_slli_si256(b,24) ); \
   b = _mm256_or_si256( _mm256_srli_si256(b,8), _mm256_slli_si256(a,24) ); \
   a = t; \
while (0);              

#define mm256_rotl512_1x64(a, b) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_slli_si256(a,8), _mm256_srli_si256(b,24) ); \
   b = _mm256_or_si256( _mm256_slli_si256(b,8), _mm256_srli_si256(a,24) ); \
   a = t; \
while (0);              

#define mm256_rotr512_1x32(a, b) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_srli_si256(a,4), _mm256_slli_si256(b,28) ); \
   b = _mm256_or_si256( _mm256_srli_si256(b,4), _mm256_slli_si256(a,28) ); \
   a = t; \
while (0);              

#define mm256_rotl512_1x32(a, b) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_slli_si256(a,4), _mm256_srli_si256(b,28) ); \
   b = _mm256_or_si256( _mm256_slli_si256(b,4), _mm256_srli_si256(a,28) ); \
   a = t; \
while (0);              

// Byte granularity but even a bit slower
#define mm256_rotr512_x8( a, b, n ) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_srli_epi64( a, n ), \
                        _mm256_slli_epi64( b, ( 32 - (n) ) ) ); \
   b = _mm256_or_si256( _mm256_srli_epi64( b, n ), \
                        _mm256_slli_epi64( a, ( 32 - (n) ) ) ); \
   a = t; \
while (0);              

#define mm256_rotl512_x8( a, b, n ) \
do { \
   __m256i t; \
   t = _mm256_or_si256( _mm256_slli_epi64( a, n ), \
                        _mm256_srli_epi64( b, ( 32 - (n) ) ) ); \
   b = _mm256_or_si256( _mm256_slli_epi64( b, n ), \
                        _mm256_srli_epi64( a, ( 32 - (n) ) ) ); \
   a = t; \
while (0);              

//
// Swap bytes in vector elements

inline __m256i mm256_byteswap_64( __m256i x )
{
  return _mm256_shuffle_epi8( x, _mm256_set_epi8(
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ) );
}

inline __m256i  mm256_byteswap_32( __m256i x )
{
   return _mm256_shuffle_epi8( x, _mm256_set_epi8(
                           0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x09, 0x0a, 0x0b,
                           0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03,
                           0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x09, 0x0a, 0x0b,
                           0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03 ) );
}

inline __m256i mm256_byteswap_16( __m256i x )
{
  return _mm256_shuffle_epi8( x, _mm256_set_epi8(
                           0x0e, 0x0f, 0x0c, 0x0d, 0x0a, 0x0b, 0x08, 0x09,
                           0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01,
                           0x0e, 0x0f, 0x0c, 0x0d, 0x0a, 0x0b, 0x08, 0x09,
                           0x06, 0x07, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01 ) );
}


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
inline __m256i mm256_aesenc_2x128( __m256i x, __m256i k )
{
    __m128i hi, lo, khi, klo;

    mm256_unpack_2x128( hi, lo, x );
    mm256_unpack_2x128( khi, klo, k );
    lo = _mm_aesenc_si128( lo, klo );
    hi = _mm_aesenc_si128( hi, khi );
    return mm256_pack_2x128( hi, lo );
}

inline __m256i mm256_aesenc_nokey_2x128( __m256i x )
{
    __m128i hi, lo;

    mm256_unpack_2x128( hi, lo, x );
    lo = _mm_aesenc_si128( lo, mm_zero );
    hi = _mm_aesenc_si128( hi, mm_zero );
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
inline void mm_interleave_4x32( void *dst, const void *src0, const void *src1,
                             const void *src2, const void *src3, int bit_len )
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
inline void mm_interleave_4x32x( void *dst, void *src0, void  *src1,
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

inline void mm_deinterleave_4x32( void *dst0, void *dst1, void *dst2,
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
inline void mm_deinterleave_4x32x( void *dst0, void *dst1, void *dst2,
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
inline void mm256_interleave_4x64( void *dst, const void *src0,
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
inline void mm256_interleave_4x64x( void *dst, void *src0, void *src1,
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
inline void mm256_deinterleave_4x64( void *dst0, void *dst1, void *dst2,
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
inline void mm256_deinterleave_4x64x( void *dst0, void *dst1, void *dst2,
                                      void *dst3, void *src, int bit_len )
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
inline void mm256_interleave_8x32( void *dst, const void *src0,
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
}

// probably obsolete with double pack 2x32->64, 4x64->256.
// Slower but it works with 32 bit data
// bit_len must be multiple of 32
inline void mm256_interleave_8x32x( uint32_t *dst, uint32_t *src0,
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
inline void mm256_deinterleave_8x32( void *dst0, void *dst1, void *dst2,
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
}

// Deinterleave 8 arrays into indivdual buffers for scalar processing
// bit_len must be multiple of 32
inline void mm256_deinterleave_8x32x( uint32_t *dst0, uint32_t *dst1,
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
inline void mm256_reinterleave_4x64( void *dst, void *src, int  bit_len )
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
inline void mm256_reinterleave_4x64x( uint64_t *dst, uint32_t *src,
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
inline void mm256_reinterleave_4x32( void *dst, void *src, int  bit_len )
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

// not used
inline void mm_reinterleave_4x32( void *dst, void *src, int  bit_len )
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
