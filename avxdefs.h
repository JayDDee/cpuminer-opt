#ifndef AVXDEFS_H__
#define AVXDEFS_H__ 1

// Some tools to help using integer SIMD vectors.
//
// The baseline requirements for these utilities is SSE2 for 128 bit vectors,
// however, some functions defined here require SSSE3 or SSE4.1. 
// AVX2 is needed for 256 bit vectors and AVX512F for 512 bit vectors.
// 
// Strict alignment of data is required: 16 bytes for 128 bit vectors,
// 32 bytes for 256 bit vectors and 64 bytes for 512 bit vectors. 64 byte
// alignment is recommended in all cases for best cache alignment.
//
// Windows has problems with function vector arguments larger than 128 bits.
// Stack alignment is only guaranteed to 16 bytes. Always use pointers for
// larger vectors in function arguments. Macros can be used for larger value
// arguments.
//
// There exists duplication in some functions. In general the first defined
// is preferred as it is more efficient but also more restrictive.
// The less efficient versions are more flexible.
//
// Naming convention:
//
// The naming convention attempts to be similar to Intel intrinsics to
// be easilly recognizable. There are some differences to avoid conflicts and
// eliminate some extraneous characters. The main ones are:
//   - the leading underscore(s) "_" and the "i" are dropped from the prefix,
//   - "mm64" and "mm128" used for 64 and 128 bit prefix respectively to avoid
//     the ambiguity of mm,
//   - the element size does not include additional type specifiers like "epi",
//   - some macros contain value args that are updated,
//   - specialized shift and rotate functions that move elements around
//     use the notation "1x32" to indicate the distance moved as units of
//     the element size.
//     
// [prefix]_[op][op_size]_[lane_size]
//
// prefix: indicates the vector type of the returned value of a function,
//         the type of the vector args of a function or the type of a data
//         identifier.
//     m64:   64 bit variable vector data
//    mm64:   64 bit vector intrinsic function
//    m128:  128 bit variable vector data
//    c128:  128 bit constant vector data
//    mm:    128 bit vector intrinsic function
//    mm128: 128 bit vectorintrinsic function disambiguated
//    m256:  256 bit variable vector data
//    c256:  256 bit constant vector data
//    mm256: 256 bit vector intrinsic function
//    m512:  512 bit variable vector data
//    c512:  512 bit constant vector data
//    mm512: 512 bit vector intrinsic function
//
// op: describes the operation of the function or names the constant
// identifier.
// 
// op_size: optional, used if the size of the operation is different than the
// size specified in the prefix.
//
// lane_size: optional, used when a function operates on lanes of packed
// elements within a vector.
//
// Macros vs inline functions:
//
// Macros are very convenient and efficient for statement functions.
// Macro args are passed by value and modifications are seen by the caller.
// Macros should not generally call regular functions unless it is for a
// special purpose such overloading a function name.
// Statement function macros that return a value should not end in ";"
// Statement function macros that return a value and don't modify input args
// may be used in function arguments and expressions.
// Macro args used in expressions should be protected ex: (x)+1
// Macros force inlining, function inlining can be overridden by the compiler.
// Inline functions are preferred when multiple statements or local variables
// are needed.
// The compiler can't do any syntax checking or type checking of args making
// macros difficult to debug.
// Although it is technically posssible to access the callers data without
// they being passed as arguments it is good practice to always define
// arguments even if they have the same name. 
// 
// General tips for inline functions:
//
// Inline functions should not have loops, it defeats the purpose of inlining.
// Inline functions should be short, the benefit is lost and the memory cost
// increases if the function is referenced often.
// Inline functions may call other functions, inlined or not. It is convenient
// for wrapper functions whether or not the wrapped function is itself inlined. 
// Care should be taken when unrolling loops that contain calls to inlined
// functions that may be large.
// Large code blocks used only once may use function inlining to
// improve high level code readability without the penalty of function
// overhead.

#include <inttypes.h>
#include <x86intrin.h>
#include <memory.h>
#include <stdbool.h>

////////////////////////////////////////////////////////////////
//
//         64 bit MMX vectors.
//
// There are rumours MMX wil be removed.

// Universal 64 bit overlay
union _m64v
{
  uint8_t  u8[8];
  uint16_t u16[4];
  uint32_t u32[2];
  uint64_t u64;
  __m64    v64;
};
typedef union _m64v m64v;

// Use one of these for initialization
union _m64_v64
{
  uint64_t u64;
  __m64    v64;
};
typedef union _m64_v64 m64_v64;
union _m64_v32
{
  uint32_t u32[2];
  __m64    v64;
};
typedef union _m64_v32 m64_v32;
union _m64_v16
{
  uint16_t u16[4];
  __m64    v64;
};
typedef union _m64_v16 m64_v16;

// Pseudo constants
#define m64_zero   _mm_setzero_si64()
#define m64_one_64 _mm_set_pi32(  0UL, 1UL )
#define m64_one_32 _mm_set1_pi32( 1UL )
#define m64_one_16 _mm_set1_pi16( 1U )
#define m64_one_8  _mm_set1_pi8(  1U );
#define m64_neg1   _mm_set1_pi32( 0xFFFFFFFFUL )
/* cast also works, which is better?
#define m64_zero   ( (__m64)0ULL )
#define m64_one_64 ( (__m64)1ULL )
#define m64_one_32 ( (__m64)0x0000000100000001ULL )
#define m64_one_16 ( (__m64)0x0001000100010001ULL )
#define m64_one_8  ( (__m64)0x0101010101010101ULL )
#define m64_neg1   ( (__m64)0xFFFFFFFFFFFFFFFFULL )
*/

// Bitwise not: ~(a)
#define mm64_not( a ) _mm_xor_si64( a, m64_neg1 )

// Unary negate elements
#define mm64_negate_32( v ) _mm_sub_pi32( m64_zero, v )
#define mm64_negate_16( v ) _mm_sub_pi16( m64_zero, v )

// Rotate bits in packed elements of 64 bit vector
#define mm64_rotl_32( a, n ) \
   _mm_or_si64( _mm_slli_pi32( a, n ), _mm_srli_pi32( a, 32-(n) ) )

#define mm64_rotr_32( a, n ) \
   _mm_or_si64( _mm_srli_pi32( a, n ), _mm_slli_pi32( a, 32-(n) ) )

#define mm64_rotl_16( a, n ) \
   _mm_or_si64( _mm_slli_pi16( a, n ), _mm_srli_pi16( a, 16-(n) ) )

#define mm64_rotr_16( a, n ) \
   _mm_or_si64( _mm_srli_pi16( a, n ), _mm_slli_pi16( a, 16-(n) ) )


// Rotate packed elements accross lanes

// Swap hi & lo 32 bits.
#define mm64_swap_32( a )    _mm_shuffle_pi16( a, 0x4e )

// Swap hi & lo 16 bits of each 32 bit element
#define mm64_swap32_16( a )  _mm_shuffle_pi16( a, 0xb1 )

#define mm64_ror_1x16( v )   _mm_shuffle_pi16( v, 0x39 )
#define mm64_rol_1x16( v )   _mm_shuffle_pi16( v, 0x93 )

// Endian byte swap packed elements
#define mm64_bswap_32( v ) \
    _mm_shuffle_pi8( v, _mm_set_pi8( 4,5,6,7,  0,1,2,3 ) )

#define mm64_bswap_16( v ) \
    _mm_shuffle_pi8( v, _mm_set_pi8( 6,7,  4,5,  2,3,  0,1 ) );

// Invert vector: {3,2,1,0} -> {0,1,2,3}
#define mm64_invert_16( v ) _mm_shuffle_pi16( a, 0x1b )
	
#define mm64_invert_8(  v ) \
    _mm_shuffle_pi8( v, _mm_set_pi8( 0,1,2,3,4,5,6,7 ) );


// A couple of 64 bit scalar functions. restrictive, data must be aligned and
// integral. The compiler can probably do just as well with memset.
// n = bytes/8

static inline void memcpy_64( __m64 *dst, const __m64 *src, int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = src[i]; }

static inline void memset_zero_64( __m64 *src, int n )
{   for ( int i = 0; i < n; i++ ) src[i] = _mm_setzero_si64(); }

static inline void memset_64( __m64 *dst, const __m64 a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }


//////////////////////////////////////////////////////////////////
//
//                 128 bit SSE vectors
//
// SSE2 is generally required for full 128 bit support. Some functions
// are also optimized with SSSE3 or SSE4.1.

// Vector type overlays. Handy for intializing vector constants at compile
// time using scalar values of the first size listed in the union definition.
// The universal overlay should not be used for compile time initialzing,
// use a specificaly sized union instead.

// Universal 128 bit overlay
union _m128v
{
  uint8_t  u8[16];
  uint16_t u16[8];
  uint32_t u32[4];
  uint64_t u64[2];
  __m64    v64[2];
#if ( __GNUC__ > 4 ) || ( ( __GNUC__ == 4 ) && ( __GNUC_MINOR__ >= 8 ) )
  __int128 u128;
#endif
  __m128i  v128;
};
typedef union _m128v m128v;

union _m128_v64
{
  uint64_t u64[2];
  __m128i v128;
};
typedef union _m128_v64 m128_v64; 

union _m128_v32
{
  uint32_t u32[4];
  __m128i v128;
};
typedef union _m128_v32 m128_v32;

union _m128_v16
{
  uint16_t u16[8];
  __m128i v128;
};
typedef union _m128_v16 m128_v16;

union _m128_v8
{
  uint8_t u8[16];
  __m128i v128;
};
typedef union _m128_v8 m128_v8;

// Compile time constant initializers are type agnostic and can have
// a pointer handle of almost any type. All arguments must be scalar constants.
// These iniitializers should only be used at compile time to initialize
// vector arrays. All data reside in memory.

#define mm128_const_64( x1, x0 ) {{ x1, x0 }}
#define mm128_const1_64( x )     {{  x,  x }}

#define mm128_const_32( x3, x2, x1, x0 ) {{ x3, x2, x1, x0 }}
#define mm128_const1_32( x ) {{ x,x,x,x }}

#define mm128_const_16( x7, x6, x5, x4, x3, x2, x1, x0 ) \
                     {{ x7, x6, x5, x4, x3, x2, x1, x0 }}
#define mm128_const1_16( x ) {{ x,x,x,x, x,x,x,x }}

#define mm128_const_8( x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 ) \
                    {{ x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 }}
#define mm128_const1_8( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

// Compile time constants, use only for compile time initializing.
#define c128_zero      mm128_const1_64( 0ULL )
#define c128_one_128   mm128_const_64(  0ULL, 1ULL )  
#define c128_one_64    mm128_const1_64( 1ULL )
#define c128_one_32    mm128_const1_32( 1UL )
#define c128_one_16    mm128_const1_16( 1U )
#define c128_one_8     mm128_const1_8(  1U )
#define c128_neg1      mm128_const1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c128_neg1_64   mm128_const1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c128_neg1_32   mm128_const1_32( 0xFFFFFFFFUL )
#define c128_neg1_16   mm128_const1_32( 0xFFFFU )
#define c128_neg1_8    mm128_const1_32( 0xFFU )

//
// Pseudo constants.
//
// These can't be used for compile time initialization.
// These should be used for all simple vectors.
//
// _mm_setzero_si128 uses pxor instruction, it's unclear what _mm_set_epi does.
// Clearly it's faster than reading a memory resident constant. Assume set
// is also faster.
// If a pseudo constant is used often in a function it may be preferable
// to define a register variable to represent that constant.
// register __m128i zero = mm_setzero_si128().
// This reduces any references to a move instruction.

#define m128_zero      _mm_setzero_si128()

#define m128_one_128   _mm_set_epi64x(  0ULL, 1ULL )
#define m128_one_64    _mm_set1_epi64x( 1ULL )
#define m128_one_32    _mm_set1_epi32(  1UL )
#define m128_one_16    _mm_set1_epi16(  1U )
#define m128_one_8     _mm_set1_epi8(   1U )

#define m128_neg1      _mm_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )

//
// Basic operations without equivalent SIMD intrinsic

// Bitwise not (~v)  
#define mm128_not( v )          _mm_xor_si128( (v), m128_neg1 ) 

// Unary negation of elements
#define mm128_negate_64( v )    _mm_sub_epi64( m128_zero, v )
#define mm128_negate_32( v )    _mm_sub_epi32( m128_zero, v )  
#define mm128_negate_16( v )    _mm_sub_epi16( m128_zero, v )  

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

// Gather and scatter data.
// Surprise, they don't use vector instructions. Several reasons why.
// Since scalar data elements are being manipulated scalar instructions
// are most appropriate and can bypass vector registers. They are faster
// and more efficient on a per instruction basis due to the higher clock
// speed and greater avaiability of execution resources. It's good for
// interleaving data buffers for parallel processing.
// May suffer overhead if data is already in a vector register. This can
// usually be easilly avoided by the coder. Sometimes _mm_set is simply better.
// These macros are likely to be used when transposing matrices rather than
// conversions of a single vector.

// Gather data elements into contiguous memory for vector use.
// Source args are appropriately sized value integers, destination arg  is a
// type agnostic pointer.
// Vector alignment is not required, though likely. Appropriate integer
// alignment satisfies these macros.

#define mm128_gather_64( d, s0, s1 ) \
    ((uint64_t*)d)[0] = (uint64_t)s0; \
    ((uint64_t*)d)[1] = (uint64_t)s1;

#define mm128_gather_32( d, s0, s1, s2, s3 ) \
    ((uint32_t*)d)[0] = (uint32_t)s0; \
    ((uint32_t*)d)[1] = (uint32_t)s1; \
    ((uint32_t*)d)[2] = (uint32_t)s2; \
    ((uint32_t*)d)[3] = (uint32_t)s3;

// Scatter data from contiguous memory.
// All arguments are pointers
#define mm128_scatter_64( d0, d1, s ) \
   *( (uint64_t*)d0) = ((uint64_t*)s)[0]; \
   *( (uint64_t*)d1) = ((uint64_t*)s)[1]; 

#define mm128_scatter_32( d0, d1, d2, d3, s ) \
   *( (uint32_t*)d0) = ((uint32_t*)s)[0]; \
   *( (uint32_t*)d1) = ((uint32_t*)s)[1]; \
   *( (uint32_t*)d2) = ((uint32_t*)s)[2]; \
   *( (uint32_t*)d3) = ((uint32_t*)s)[3];

// Memory functions
// Mostly for convenience, avoids calculating bytes.
// Assumes data is alinged and integral.
// n = number of __m128i, bytes/16

static inline void memset_zero_128( __m128i *dst,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m128_zero; }

static inline void memset_128( __m128i *dst, const __m128i a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_128( __m128i *dst, const __m128i *src, int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }


//
// Bit rotations

// AVX512 has implemented bit rotation for 128 bit vectors with
// 64 and 32 bit elements. Not really useful.

//
// Rotate each element of v by c bits

/*
#if defined(__AVX512F__) && defined(__AVX512VL__)

#define mm128_ror_64( v, c ) _mm_ror_epi64( v, c )
#define mm128_rol_64( v, c ) _mm_rol_epi64( v, c )
#define mm128_ror_32( v, c ) _mm_ror_epi32( v, c )
#define mm128_rol_32( v, c ) _mm_rol_epi32( v, c )

#else
*/

#define mm128_ror_64( v, c ) \
   _mm_or_si128( _mm_srli_epi64( v, c ), _mm_slli_epi64( v, 64-(c) ) )

#define mm128_rol_64( v, c ) \
   _mm_or_si128( _mm_slli_epi64( v, c ), _mm_srli_epi64( v, 64-(c) ) )

#define mm128_ror_32( v, c ) \
   _mm_or_si128( _mm_srli_epi32( v, c ), _mm_slli_epi32( v, 32-(c) ) )

#define mm128_rol_32( v, c ) \
   _mm_or_si128( _mm_slli_epi32( v, c ), _mm_srli_epi32( v, 32-(c) ) )

//#endif

#define mm128_ror_16( v, c ) \
   _mm_or_si128( _mm_srli_epi16( v, c ), _mm_slli_epi16( v, 16-(c) ) )

#define mm128_rol_16( v, c ) \
   _mm_or_si128( _mm_slli_epi16( v, c ), _mm_srli_epi16( v, 16-(c) ) )

//
// Rotate elements accross all lanes

#define mm128_swap_64( v )    _mm_shuffle_epi32( v, 0x4e )

#define mm128_ror_1x32( v )   _mm_shuffle_epi32( v, 0x39 )
#define mm128_rol_1x32( v )   _mm_shuffle_epi32( v, 0x93 )

#define mm128_swap32_16( v )  _mm_shuffle_epi8( v, \
                  _mm_set_epi8( 13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2 )

#define mm128_ror_1x16( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8(  1, 0,15,14,13,12,11,10 \
                                       9, 8, 7, 6, 5, 4, 3, 2 ) )
#define mm128_rol_1x16( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 13,12,11,10, 9, 8, 7, 6, \
                                       5, 4, 3, 2, 1, 0,15,14 ) )
#define mm128_ror_1x8( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8(  0,15,14,13,12,11,10, 9, \
                                       8, 7, 6, 5, 4, 3, 2, 1 ) )
#define mm128_rol_1x8( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 14,13,12,11,10, 9, 8, 7, \
                                       6, 5, 4, 3, 2, 1, 0,15 ) )

// Rotate 16 byte (128 bit) vector by c bytes.
// Less efficient using shift but more versatile. Use only for odd number
// byte rotations. Use shuffle above whenever possible.
#define mm128_bror( v, c ) \
   _mm_or_si128( _mm_srli_si128( v, c ), _mm_slli_si128( v, 16-(c) ) )

#define mm128_brol( v, c ) \
   _mm_or_si128( _mm_slli_si128( v, c ), _mm_srli_si128( v, 16-(c) ) )

// Invert vector: {3,2,1,0} -> {0,1,2,3}
#define mm128_invert_32( v ) _mm_shuffle_epi32( a, 0x1b )

#define mm128_invert_16( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 1, 0,   3, 2,   5, 4,   7, 6, \
                                      9, 8,  11,10,  13,12,  15,14 ) )

#define mm128_invert_8( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 0, 1, 2, 3, 4, 5, 6, 7, \
                                      8, 9,10,11,12,13,14,15 ) )

//
// Rotate elements within lanes.

#define mm128_swap64_32( v )  _mm_shuffle_epi32( v, 0xb1 )

#define mm128_swap32_16( v )  _mm_shuffle_epi8( v, \
                      _mm_set_epi8( 13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2 )

//
// Endian byte swap.

#if defined(__SSSE3__)

#define mm128_bswap_64( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 8, 9,10,11,12,13,14,15, \
                                      0, 1, 2, 3, 4, 5, 6, 7 ) )

#define mm128_bswap_32( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 12,13,14,15,   8, 9,10,11, \
                                       4, 5, 6, 7,   0, 1, 2, 3 ) )

#define mm128_bswap_16( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi8( 14,15,  12,13,  10,11,   8, 9, \
                                       6, 7,   4, 5,   2, 3,   0, 1 ) )

#else  // SSE2

// Use inline function instead of macro due to multiple statements.
static inline __m128i mm128_bswap_64( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
}

static inline __m128i mm128_bswap_32( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
}

static inline __m128i mm128_bswap_16( __m128i v )
{
  return _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
}

#endif // SSSE3 else SSE2

//
// Concatenate 128 bit vectors v1 & v2 to form a 256 bit vector then rotate it
// in place. Source arguments are overwritten.

#define mm128_swap256_128(v1, v2) \
   v1 = _mm_xor_si128(v1, v2); \
   v2 = _mm_xor_si128(v1, v2); \
   v1 = _mm_xor_si128(v1, v2);

#if defined(__SSE4_1__)

// There are no SSE2 compatible versions of these functions.

#define mm128_ror256_1x64( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 8 ); \
   v1 = _mm_alignr_epi8( v2, v1, 8 ); \
   v2 = t; \
} while(0)

#define mm128_rol256_1x64( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 8 ); \
   v2 = _mm_alignr_epi8( v2, v1, 8 ); \
   v1 = t; \
} while(0)

#define mm128_ror256_1x32( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 4 ); \
   v1 = _mm_alignr_epi8( v2, v1, 4 ); \
   v2 = t; \
} while(0)

#define mm128_rol256_1x32( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 12 ); \
   v2 = _mm_alignr_epi8( v2, v1, 12 ); \
   v1 = t; \
} while(0)

#define mm128_ror256_1x16( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 2 ); \
   v1 = _mm_alignr_epi8( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm128_rol256_1x16( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 14 ); \
   v2 = _mm_alignr_epi8( v2, v1, 14 ); \
   v1 = t; \
} while(0)

#define mm128_ror256_1x8( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 1 ); \
   v1 = _mm_alignr_epi8( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm128_rol256_1x8( v1, v2 ) \
do { \
   __m128i t = _mm_alignr_epi8( v1, v2, 15 ); \
   v2 = _mm_alignr_epi8( v2, v1, 15 ); \
   v1 = t; \
} while(0)

#endif  // SSE4.1

#if defined (__AVX2__)

/////////////////////////////////////////////////////////////////////
//
//             AVX2 256 bit vectors
//
// AVX2 is required for integer support of 256 bit vectors.
// Some 256 bit vector utilities require AVX512 or have more efficient
// AVX512 implementations. They will be selected automatically but their use
// is limited because 256 bit vectors are less likely to be used when 512
// is available.

// Vector type overlays used by compile time vector constants.
// Constants of these types reside in memory.

union _m256v
{
  uint8_t  u8 [32];
  uint16_t u16[16];
  uint32_t u32[ 8];
  uint64_t u64[ 4];
  __m64    v64[ 4];
#if ( __GNUC__ > 4 ) || ( ( __GNUC__ == 4 ) && ( __GNUC_MINOR__ >= 8 ) )
  __int128 u128[2];
#endif
  __m128i  v128[2];
  __m256i  v256;
};
typedef union _m256v m256v;

// Use these for initialization to avoid element size ambiguity.
union _m256_v128 {
  __m128i  v128[2];
  __m256i  v256;
};
typedef union _m256_v128 m256_v128;

union _m256_v64 {
  uint64_t u64[4];
  __m256i v256;
};
typedef union _m256_v64 m256_v64;

union _m256_v32 {
  uint32_t u32[8];
  __m256i v256;
};
typedef union _m256_v32 m256_v32;

union _m256_v16 {
  uint16_t u16[16];
  __m256i v256;
};
typedef union _m256_v16 m256_v16;

union _m256_v8
{
  uint8_t u8[32];
  __m256i v256;
};
typedef union _m256_v8 m256_v8;

// Compile time vector constants and initializers.
//
// The following macro constants and functions should only be used
// for compile time initialization of constant and variable vector
// arrays. These constants use memory, use _mm256_set at run time to
// avoid using memory.
 
#define mm256_const_64( x3, x2, x1, x0 ) {{ x3, x2, x1, x0 }}
#define mm256_const1_64( x ) {{ x,x,x,x }}

#define mm256_const_32( x7, x6, x5, x4, x3, x2, x1, x0 ) \
                     {{ x7, x6, x5, x4, x3, x2, x1, x0 }}
#define mm256_const1_32( x ) {{ x,x,x,x, x,x,x,x }}

#define mm256_const_16( x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 ) \
                     {{ x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 }}
#define mm256_const1_16( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

#define mm256_const_8( x31, x30, x29, x28, x27, x26, x25, x24, \
                       x23, x22, x21, x20, x19, x18, x17, x16, \
                       x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 ) \
                    {{ x31, x30, x29, x28, x27, x26, x25, x24, \
                       x23, x22, x21, x20, x19, x18, x17, x16, \
                       x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 }}
#define mm256_const1_8( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                               x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

// Predefined compile time constant vectors.
// Use Pseudo constants at run time for all simple constant vectors.
#define c256_zero         mm256_const1_64( 0ULL )
#define c256_one_256      mm256_const_64(  0ULL, 0ULL, 0ULL, 1ULL )  
#define c256_one_128      mm256_const_64(  0ULL, 1ULL, 0ULL, 1ULL )  
#define c256_one_64       mm256_const1_64( 1ULL )
#define c256_one_32       mm256_const1_32( 1UL )
#define c256_one_16       mm256_const1_16( 1U )
#define c256_one_8        mm256_const1_8(  1U )
#define c256_neg1         mm256_const1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c256_neg1_64      mm256_const1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c256_neg1_32      mm256_const1_32( 0xFFFFFFFFUL )
#define c256_neg1_16      mm256_const1_16( 0xFFFFU )
#define c256_neg1_8       mm256_const1_8(  0xFFU )

//
// Pseudo constants.
// These can't be used for compile time initialization but are preferable
// for simple constant vectors at run time.

#define m256_zero            _mm256_setzero_si256()
#define m256_one_256         _mm256_set_epi64x(  0ULL, 0ULL, 0ULL, 1ULL )
#define m256_one_128         _mm256_set_epi64x(  0ULL, 1ULL, 0ULL, 1ULL )
#define m256_one_64          _mm256_set1_epi64x( 1ULL )
#define m256_one_32          _mm256_set1_epi32(  1UL )
#define m256_one_16          _mm256_set1_epi16(  1U )
#define m256_one_8           _mm256_set1_epi8(   1U )
#define m256_neg1            _mm256_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )

//
// Basic operations without SIMD equivalent

// Bitwise not ( ~x )
#define mm256_not( x )       _mm256_xor_si256( (x), m256_neg1 ) \

// Unary negation of each element ( -a )
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


// Gather scatter

#define mm256_gather_64( d, s0, s1, s2, s3 ) \
    ((uint64_t*)(d))[0] = (uint64_t)(s0); \
    ((uint64_t*)(d))[1] = (uint64_t)(s1); \
    ((uint64_t*)(d))[2] = (uint64_t)(s2); \
    ((uint64_t*)(d))[3] = (uint64_t)(s3);

#define mm256_gather_32( d, s0, s1, s2, s3, s4, s5, s6, s7 ) \
    ((uint32_t*)(d))[0] = (uint32_t)(s0); \
    ((uint32_t*)(d))[1] = (uint32_t)(s1); \
    ((uint32_t*)(d))[2] = (uint32_t)(s2); \
    ((uint32_t*)(d))[3] = (uint32_t)(s3); \
    ((uint32_t*)(d))[4] = (uint32_t)(s4); \
    ((uint32_t*)(d))[5] = (uint32_t)(s5); \
    ((uint32_t*)(d))[6] = (uint32_t)(s6); \
    ((uint32_t*)(d))[7] = (uint32_t)(s7);


// Scatter data from contiguous memory.
// All arguments are pointers
#define mm256_scatter_64( d0, d1, d2, d3, s ) \
   *((uint64_t*)(d0)) = ((uint64_t*)(s))[0]; \
   *((uint64_t*)(d1)) = ((uint64_t*)(s))[1]; \
   *((uint64_t*)(d2)) = ((uint64_t*)(s))[2]; \
   *((uint64_t*)(d3)) = ((uint64_t*)(s))[3];

#define mm256_scatter_32( d0, d1, d2, d3, d4, d5, d6, d7, s ) \
   *((uint32_t*)(d0)) = ((uint32_t*)(s))[0]; \
   *((uint32_t*)(d1)) = ((uint32_t*)(s))[1]; \
   *((uint32_t*)(d2)) = ((uint32_t*)(s))[2]; \
   *((uint32_t*)(d3)) = ((uint32_t*)(s))[3]; \
   *((uint32_t*)(d4)) = ((uint32_t*)(s))[4]; \
   *((uint32_t*)(d5)) = ((uint32_t*)(s))[5]; \
   *((uint32_t*)(d6)) = ((uint32_t*)(s))[6]; \
   *((uint32_t*)(d7)) = ((uint32_t*)(s))[7];


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
// Bit rotations.
// AVX2 as no bit shift for elements greater than 64 bit.
// AVX512 has bit rotate for 256 bit vectors with 64 or 32 bit elements
// but has not yet been tested.

//
// Rotate each element of v by c bits
/*
#if defined(__AVX512F__) && defined(__AVX512VL__)

#define mm256_ror_64( v, c ) _mm256_ror_epi64( v, c )
#define mm256_rol_64( v, c ) _mm256_rol_epi64( v, c )
#define mm256_ror_32( v, c ) _mm256_ror_epi32( v, c )
#define mm256_rol_32( v, c ) _mm256_rol_epi32( v, c )

#else
*/
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

//#endif // AVX512 else

#define  mm256_ror_16( v, c ) \
   _mm256_or_si256( _mm256_srli_epi16( v, c ), \
                    _mm256_slli_epi16( v, 16-(c) ) )

#define mm256_rol_16( v, c ) \
   _mm256_or_si256( _mm256_slli_epi16( v, c ), \
                    _mm256_srli_epi16( v, 16-(c) ) )

// Rotate bits in each element of v by the amount in corresponding element of
// index vector c
#define mm256_rorv_64( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi64( v, _mm256_set1_epi64x( c ) ), \
         _mm256_sllv_epi64( v, _mm256_set1_epi64x( 64-(c) ) ) )

#define mm256_rolv_64( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi64( v, _mm256_set1_epi64x( c ) ), \
         _mm256_srlv_epi64( v, _mm256_set1_epi64x( 64-(c) ) ) )


#define mm256_rorv_32( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi32( v, _mm256_set1_epi32( c ) ), \
         _mm256_sllv_epi32( v, _mm256_set1_epi32( 32-(c) ) ) )

#define mm256_rolv_32( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi32( v, _mm256_set1_epi32( c ) ), \
         _mm256_srlv_epi32( v, _mm256_set1_epi32( 32-(c) ) ) )

// AVX512 can do 16 bit elements.
#if defined(__AVX512VL__) && defined(__AVX512BW__)

#define mm256_rorv_16( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi16( v, _mm256_set1_epi16( c ) ), \
         _mm256_sllv_epi16( v, _mm256_set1_epi16( 16-(c) ) ) )

#define mm256_rolv_16( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi16( v, _mm256_set1_epi16( c ) ), \
         _mm256_srlv_epi16( v, _mm256_set1_epi16( 16-(c) ) ) )

#endif // AVX512

//
// Rotate elements accross all lanes.
//
// AVX2 has no full vector permute for elements less than 32 bits.
// AVX512 has finer granularity full vector permutes.

// Swap 128 bit elements in 256 bit vector.
#define mm256_swap_128( v )     _mm256_permute4x64_epi64( v, 0x4e )

// Rotate 256 bit vector by one 64 bit element
#define mm256_ror_1x64( v )  _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_rol_1x64( v )  _mm256_permute4x64_epi64( v, 0x93 )

// Rotate 256 bit vector by one 32 bit element.
#define mm256_ror_1x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 0,7,6,5, 4,3,2,1 ) )
#define mm256_rol_1x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 6,5,4,3, 2,1,0,7 ) )

// Rotate 256 bit vector by three 32 bit elements (96 bits).
#define mm256_ror_3x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 2,1,0,7, 6,5,4,3 ) )
#define mm256_rol_3x32( v ) \
    _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 4,3,2,1, 0,7,6,5 ) )

// AVX512 can do 16 & 8 bit elements.
#if defined(__AVX512VL__)

// Rotate 256 bit vector by one 16 bit element.	    
#define mm256_ror_1x16( v ) \
   _mm256_permutexvar_epi16( _mm256_set_epi16( \
	 0,15,14,13,12,11,10, 9,   8, 7, 6, 5, 4, 3, 2, 1 ), v )

#define mm256_rol_1x16( v ) \
   _mm256_permutexvar_epi16( _mm256_set_epi16( \
        14,13,12,11,10, 9, 8, 7,   6, 5, 4, 3, 2, 1, 0,15 ), v )

// Rotate 256 bit vector by one byte.
#define mm256_ror_1x8( v ) \
   _mm256_permutexvar_epi8( _mm256_set_epi8( \
         0,31,30,29,28,27,26,25,  24,23,22,21,20,19,18,17, \
	16,15,14,13,12,11,10, 9,   8, 7, 6, 5, 4, 3, 2, 1 ), v )

#define mm256_rol_1x8( v ) \
   _mm256_permutexvar_epi8( _mm256_set_epi8( \
        30,29,28,27,26,25,24,23,  22,21,20,19,18,17,16,15, \
        14,13,12,11,10, 9, 8, 7,   6, 5, 4, 3, 2, 1, 0,31 ), v )

#endif  // AVX512

// Invert vector: {3,2,1,0} -> {0,1,2,3}
#define mm256_invert_64( v ) _mm256_permute4x64_epi64( a, 0x1b )

#define mm256_invert_32( v ) \
     _mm256_permutevar8x32_epi32( v, _mm256_set_epi32( 0,1,2,3,4,5,6,7 ) )

// AVX512 can do 16 & 8 bit elements.
#if defined(__AVX512BW__) && defined(__AVX512VL__)

#define mm256_invert_16 ( v ) \
     _mm256_permutex_epi16( v, _mm256_set_epi16( 0, 1, 2, 3, 4, 5, 6, 7, \
			                         8, 9,10,11,12,13,14,15 ) )

#define mm256_invert_8( v ) \
     _mm256_permutex_epi8( v, _mm256_set_epi8( 0, 1, 2, 3, 4, 5, 6, 7, \
                                               8, 9,10,11,12,13,14,15, \
					      16,17,18,19,20,21,22,23, \
					      24,25,26,27,28,29,30,31 ) )
#endif // AVX512

//
// Rotate elements within lanes of 256 bit vector.

// Swap 64 bit elements in each 128 bit lane.
#define mm256_swap128_64( v )   _mm256_shuffle_epi32( v, 0x4e )

// Rotate each 128 bit lane by one 32 bit element.
#define mm256_ror128_1x32( v )  _mm256_shuffle_epi32( v, 0x39 )
#define mm256_rol128_1x32( v )  _mm256_shuffle_epi32( v, 0x93 )

// Rotate each 128 bit lane by one 16 bit element.
#define mm256_rol128_1x16( v ) \
       	_mm256_shuffle_epi8( 13,12,11,10, 9,8,7,6, 5,4,3,2, 1,0,15,14 )
#define mm256_ror128_1x16( v ) \
        _mm256_shuffle_epi8( 1,0,15,14, 13,12,11,10, 9,8,7,6, 5,4,3,2 )

// Rotate each 128 bit lane by one byte
#define mm256_rol128_1x8( v ) \
        _mm256_shuffle_epi8( 14, 13,12,11, 10,9,8,7, 6,5,4,3, 2,1,0,15 )
#define mm256_ror128_1x8( v ) \
        _mm256_shuffle_epi8( 0,15,14,13, 12,11,10,9, 8,7,6,5, 4,3,2,1 )

// Rotate each 128 bit lane by c bytes.
#define mm256_ror128_x8( v, c ) \
  _mm256_or_si256( _mm256_bsrli_epi128( v, c ), \
                   _mm256_bslli_epi128( v, 16-(c) ) )
#define mm256_rol128_x8( v, c ) \
  _mm256_or_si256( _mm256_bslli_epi128( v, c ), \
                   _mm256_bsrli_epi128( v, 16-(c) ) )

// Swap 32 bit elements in each 64 bit lane
#define mm256_swap64_32( v )    _mm256_shuffle_epi32( v, 0xb1 )

// Swap 16 bit elements in each 32 bit lane
#define mm256_swap32_16( v )  _mm256_shuffle_epi8( v, \
        _mm_set_epi8( 13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2 )

//
// Swap bytes in vector elements, endian bswap.
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


//
// Rotate two concatenated 256 bit vectors as one 512 bit vector by specified
// number of elements. Rotate is done in place, source arguments are
// overwritten.
// Some of these can use permute but appears to be slower. Maybe a Ryzen
// issue

#define mm256_swap512_256 (v1, v2) \
   v1 = _mm256_xor_si256(v1, v2); \
   v2 = _mm256_xor_si256(v1, v2); \
   v1 = _mm256_xor_si256(v1, v2);

#define mm256_ror512_1x128( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 16 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 16 ); \
   v2 = t; \
} while(0)

#define mm256_rol512_1x128( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 16 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 16 ); \
   v1 = t; \
} while(0)

#define mm256_ror512_1x64( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 8 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 8 ); \
   v2 = t; \
} while(0)

#define mm256_rol512_1x64( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 24 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 24 ); \
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
   __m256i t = _mm256_alignr_epi8( v1, v2, 28 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 28 ); \
   v1 = t; \
} while(0)

#define mm256_ror512_1x16( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 2 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm256_rol512_1x16( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 30 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 30 ); \
   v1 = t; \
} while(0)

#define mm256_ror512_1x8( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 1 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm256_rol512_1x8( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 31 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 31 ); \
   v1 = t; \
} while(0)

#endif  // AVX2

//////////////////////////////////////////////////////////////
//
//   AVX512 512 bit vectors
//

#if defined(__AVX512F__)
//#if defined(__AVX512F__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
// && defined(__AVX512VBMI__) && defined(__AVX512VL__)
// && defined(__AVX512VAES__)

// Experimental, not fully tested.


// Universal 512 bit vector overlay
union _m512v
{
  uint8_t   u8[64];
  uint16_t u16[32];
  uint32_t u32[16];
  uint64_t u64[ 8];
  __m64    v64[ 8];
#if ( __GNUC__ > 4 ) || ( ( __GNUC__ == 4 ) && ( __GNUC_MINOR__ >= 8 ) )
  __int128 u128[4];
#endif
  __m128i  v128[4];
  __m256i  v256[2];
  __m512i  v512;
};
typedef union _m512v m512v;

// Use these for compile time definition to avoid element size ambiguity.
union _m512_v256
{
  __m256i  v256[2];
  __m512i  v512;
};
typedef union _m512_v256 m512_v256;
union _m512_v128
{
  __m128i  v128[4];
  __m512i  v512;
};
typedef union _m512_v128 m512_v128;
union _m512_v64
{
  uint64_t  u64[8];
  __m512i  v512;
};
typedef union _m512_v64 m512_v64;
union _m512_v32
{
  uint32_t  u32[16];
  __m512i  v512;
};
typedef union _m512_v32 m512_v32;
union _m512_v16
{
  uint16_t  u16[32];
  __m512i  v512;
};
typedef union _m512_v16 m512_v16;
union _m512_v8
{
  uint8_t  u8[64];
  __m512i  v512;
};
typedef union _m512_v8 m512_v8;


//
// Compile time vector constants and initializers.
//
// The following macro constants and functions should only be used
// for compile time initialization of constant and variable vector
// arrays. These constants use memory, use set instruction or pseudo
// constants at run time to avoid using memory.

// Constant initializers
#define mm512_const_64( x7, x6, x5, x4, x3, x2, x1, x0 ) \
                     {{ x7, x6, x5, x4, x3, x2, x1, x0 }}

#define mm512_const1_64( x ) {{ x,x,x,x,x,x,x }}

#define mm512_const_32( x15, x14, x13, x12, x11, x10, x09, x08, \
	                x07, x06, x05, x04, x03, x02, x01, x00 ) \
                     {{ x07, x06, x05, x04, x03, x02, x01, x00, \
	                x15, x14, x13, x12, x11, x10, x09, x08 }}

#define mm512_const1_32( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

#define mm512_const_16( x31, x30, x29, x28, x27, x26, x25, x24, \
                        x23, x22, x21, x20, x19, x18, x17, x16, \
                        x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 ) \
                     {{ x31, x30, x29, x28, x27, x26, x25, x24, \
                        x23, x22, x21, x20, x19, x18, x17, x16, \
                        x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 }}

#define mm512_const1_16( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                                x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

#define mm512_const_8( x63, x62, x61, x60, x59, x58, x57, x56, \
		       x55, x54, x53, x52, x51, x50, x49, x48, \
	 	       x47, x46, x45, x44, x43, x42, x41, x40, \
	 	       x39, x38, x37, x36, x35, x34, x33, x32, \
	               x31, x30, x29, x28, x27, x26, x25, x24, \
                       x23, x22, x21, x20, x19, x18, x17, x16, \
                       x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 ) \
                    {{ x63, x62, x61, x60, x59, x58, x57, x56, \
                       x55, x54, x53, x52, x51, x50, x49, x48, \
                       x47, x46, x45, x44, x43, x42, x41, x40, \
                       x39, x38, x37, x36, x35, x34, x33, x32, \
                       x31, x30, x29, x28, x27, x26, x25, x24, \
                       x23, x22, x21, x20, x19, x18, x17, x16, \
                       x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 }}

#define mm512_const1_8( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                               x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                               x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
	                       x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

// Predefined compile time constant vectors.
#define c512_zero      mm512_const1_64(   0ULL )
#define c512_neg1      mm512_const1_64(   0xFFFFFFFFFFFFFFFFULL )
#define c512_one_512   mm512_const_epi64( 0ULL, 0ULL, 0ULL, 0ULL, \
		                          0ULL, 0ULL, 0ULL, 1ULL )
#define c512_one_256   mm512_const_64(    0ULL, 0ULL, 0ULL, 1ULL, \
	                                  0ULL, 0ULL, 0ULL, 1ULL )
#define c512_one_128   mm512_const_64(    0ULL, 1ULL, 0ULL, 1ULL, \
	                                  0ULL, 1ULL, 0ULL, 1ULL	)
#define c512_one_64    mm512_const1_64(   1ULL )
#define c512_one_32    mm512_const1_32(   1UL )
#define c512_one_16    mm512_const1_16(   1U )
#define c512_one_8     mm512_const1_8(    1U )
#define c512_neg1_64   mm512_const1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c512_neg1_32   mm512_const1_32( 0xFFFFFFFFUL )
#define c512_neg1_16   mm512_const1_32( 0xFFFFU )
#define c512_neg1_8    mm512_const1_32( 0xFFU )

//
// Pseudo constants.

// _mm512_setzero_si512 uses xor instruction. If needed frequently
// in a function is it better to define a register variable (const?)
// initialized to zero.
// It isn't clear to me yet how set or set1 actually work.

#define m512_zero           _mm512_setzero_si512()
#define m512_one_512        _mm512_set_epi64(  0ULL, 0ULL, 0ULL, 0ULL, \
                                               0ULL, 0ULL, 0ULL, 1ULL )
#define m512_one_256        _mm512_set4_epi64( 0ULL, 0ULL, 0ULL, 1ULL )
#define m512_one_128        _mm512_set4_epi64( 0ULL, 1ULL, 0ULL, 1ULL )
#define m512_one_64         _mm512_set1_epi64( 1ULL )
#define m512_one_32         _mm512_set1_epi32( 1UL )
#define m512_one_16         _mm512_set1_epi16( 1U )
#define m512_one_8          _mm512_set1_epi8(  1U )
#define m512_neg1           _mm512_set1_epi64( 0xFFFFFFFFFFFFFFFFULL )


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

// Gather scatter

#define mm512_gather_64( d, s0, s1, s2, s3, s4, s5, s6, s7 ) \
    ((uint64_t*)(d))[0] = (uint64_t)(s0); \
    ((uint64_t*)(d))[1] = (uint64_t)(s1); \
    ((uint64_t*)(d))[2] = (uint64_t)(s2); \
    ((uint64_t*)(d))[3] = (uint64_t)(s3); \
    ((uint64_t*)(d))[4] = (uint64_t)(s4); \
    ((uint64_t*)(d))[5] = (uint64_t)(s5); \
    ((uint64_t*)(d))[6] = (uint64_t)(s6); \
    ((uint64_t*)(d))[7] = (uint64_t)(s7); 


#define mm512_gather_32( d, s00, s01, s02, s03, s04, s05, s06, s07, \
		             s08, s09, s10, s11, s12, s13, s14, s15 ) \
    ((uint32_t*)(d))[ 0] = (uint32_t)(s00); \
    ((uint32_t*)(d))[ 1] = (uint32_t)(s01); \
    ((uint32_t*)(d))[ 2] = (uint32_t)(s02); \
    ((uint32_t*)(d))[ 3] = (uint32_t)(s03); \
    ((uint32_t*)(d))[ 4] = (uint32_t)(s04); \
    ((uint32_t*)(d))[ 5] = (uint32_t)(s05); \
    ((uint32_t*)(d))[ 6] = (uint32_t)(s06); \
    ((uint32_t*)(d))[ 7] = (uint32_t)(s07); \
    ((uint32_t*)(d))[ 8] = (uint32_t)(s08); \
    ((uint32_t*)(d))[ 9] = (uint32_t)(s09); \
    ((uint32_t*)(d))[10] = (uint32_t)(s10); \
    ((uint32_t*)(d))[11] = (uint32_t)(s11); \
    ((uint32_t*)(d))[12] = (uint32_t)(s12); \
    ((uint32_t*)(d))[13] = (uint32_t)(s13); \
    ((uint32_t*)(d))[13] = (uint32_t)(s14); \
    ((uint32_t*)(d))[15] = (uint32_t)(s15);



// Scatter data from contiguous memory.
// All arguments are pointers
#define mm512_scatter_64( d0, d1, d2, d3, d4, d5, d6, d7, s ) \
   *((uint64_t*)(d0)) = ((uint64_t*)(s))[0]; \
   *((uint64_t*)(d1)) = ((uint64_t*)(s))[1]; \
   *((uint64_t*)(d2)) = ((uint64_t*)(s))[2]; \
   *((uint64_t*)(d3)) = ((uint64_t*)(s))[3]; \
   *((uint64_t*)(d4)) = ((uint64_t*)(s))[4]; \
   *((uint64_t*)(d5)) = ((uint64_t*)(s))[5]; \
   *((uint64_t*)(d6)) = ((uint64_t*)(s))[6]; \
   *((uint64_t*)(d7)) = ((uint64_t*)(s))[7];


#define mm512_scatter_32( d00, d01, d02, d03, d04, d05, d06, d07, \
	                  d08, d09, d10, d11, d12, d13, d14, d15, s ) \
   *((uint32_t*)(d00)) = ((uint32_t*)(s))[ 0]; \
   *((uint32_t*)(d01)) = ((uint32_t*)(s))[ 1]; \
   *((uint32_t*)(d02)) = ((uint32_t*)(s))[ 2]; \
   *((uint32_t*)(d03)) = ((uint32_t*)(s))[ 3]; \
   *((uint32_t*)(d04)) = ((uint32_t*)(s))[ 4]; \
   *((uint32_t*)(d05)) = ((uint32_t*)(s))[ 5]; \
   *((uint32_t*)(d06)) = ((uint32_t*)(s))[ 6]; \
   *((uint32_t*)(d07)) = ((uint32_t*)(s))[ 7]; \
   *((uint32_t*)(d00)) = ((uint32_t*)(s))[ 8]; \
   *((uint32_t*)(d01)) = ((uint32_t*)(s))[ 9]; \
   *((uint32_t*)(d02)) = ((uint32_t*)(s))[10]; \
   *((uint32_t*)(d03)) = ((uint32_t*)(s))[11]; \
   *((uint32_t*)(d04)) = ((uint32_t*)(s))[12]; \
   *((uint32_t*)(d05)) = ((uint32_t*)(s))[13]; \
   *((uint32_t*)(d06)) = ((uint32_t*)(s))[14]; \
   *((uint32_t*)(d07)) = ((uint32_t*)(s))[15];


//
// Bit rotations.

// AVX512F has built-in bit fixed and variable rotation for 64 & 32 bit
// elements. There is no bit rotation or shift for larger elements.
//
// _mm512_rol_epi64,  _mm512_ror_epi64,  _mm512_rol_epi32,  _mm512_ror_epi32
// _mm512_rolv_epi64, _mm512_rorv_epi64, _mm512_rolv_epi32, _mm512_rorv_epi32
//
// Here is a bit rotate for 16 bit elements:
#define mm512_ror_16( v, c ) \
    _mm512_or_si512( _mm512_srli_epi16( v, c ), \
                     _mm512_slli_epi16( v, 16-(c) )
#define mm512_rol_16( v, c ) \
    _mm512_or_si512( _mm512_slli_epi16( v, c ), \
                     _mm512_srli_epi16( v, 16-(c) )


//
// Rotate elements in 512 bit vector.

#define mm512_swap_256( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 3,2,1,0,  7,6,5,4 ) )

#define mm512_ror_1x128( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 1,0,  7,6,  5,4,  3,2 ) )

#define mm512_rol_1x128( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 5,4,  3,2,  1,0,  7,6 ) )

#define mm512_ror_1x64( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 0,7,6,5,4,3,2,1 ) )

#define mm512_rol_1x64( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 6,5,4,3,2,1,0,7 ) )

#define mm512_ror_1x32( v ) \
  _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                      0,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 ) )

#define mm512_rol_1x32( v ) \
  _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                     14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15 ) )

//  Although documented to exist in AVX512F the _mm512_set_epi8 &
//  _mm512_set_epi16 intrinsics fail to compile. Seems usefull to have
//  for endian byte swapping. Workaround by using _mm512_set_epi32.
//  Ugly but it works.

#define mm512_ror_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                       0x0000001F, 0x001E001D, 0x001C001B, 0x001A0019, \
                       0X00180017, 0X00160015, 0X00140013, 0X00120011, \
                       0X0010000F, 0X000E000D, 0X000C000B, 0X000A0009, \
		       0X00080007, 0X00060005, 0X00040003, 0X00020001 ) )

#define mm512_rol_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
                       0x001E001D, 0x001C001B, 0x001A0019, 0x00180017, \
                       0X00160015, 0X00140013, 0X00120011, 0x0010000F, \
                       0X000E000D, 0X000C000B, 0X000A0009, 0X00080007, \
		       0X00060005, 0X00040003, 0X00020001, 0x0000001F ) )


#define mm512_ror_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
                       0x003F3E3D, 0x3C3B3A39, 0x38373635, 0x34333231, \
                       0x302F2E2D, 0x2C2B2A29, 0x28272625, 0x24232221, \
		       0x201F1E1D, 0x1C1B1A19. 0x18171615, 0x14131211, \
		       0x100F0E0D, 0x0C0B0A09, 0x08070605, 0x04030201 ) )

#define mm512_rol_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
                       0x3E3D3C3B, 0x3A393837, 0x36353433, 0x3231302F. \
		       0x2E2D2C2B, 0x2A292827, 0x26252423, 0x2221201F, \
		       0x1E1D1C1B, 0x1A191817, 0x16151413, 0x1211100F, \
		       0x0E0D0C0B, 0x0A090807, 0x06050403, 0x0201003F ) )

// Invert vector: {3,2,1,0} -> {0,1,2,3}
#define mm512_invert_128( v ) _mm512_permute4f128_epi32( a, 0x1b )

#define mm512_invert_64( v ) \
     _mm512_permutex_epi64( v, _mm512_set_epi64( 0,1,2,3,4,5,6,7 ) )

#define mm512_invert_32( v ) \
     _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                     0, 1, 2, 3, 4, 5, 6, 7,   8, 9,10,11,12,13,14,15 ) )


#define mm512_invert_16( v ) \
     _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                      0x00000001, 0x00020003, 0x00040005, 0x00060007, \
                      0x00080009, 0x000A000B, 0x000C000D, 0x000E000F, \
                      0x00100011, 0x00120013, 0x00140015, 0x00160017, \
                      0x00180019, 0x001A001B, 0x001C001D, 0x001E001F ) )

#define mm512_invert_8(  v ) \
     _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                      0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, \
                      0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F, \
                      0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, \
                      0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F ) )

//
// Rotate elements within 256 bit lanes of 512 bit vector.

// Swap hi & lo 128 bits in each 256 bit lane
#define mm512_swap256_128( v )   _mm512_permutex_epi64( v, 0x4e )

// Rotate 256 bit lanes by one 64 bit element
#define mm512_ror256_1x64( v )   _mm512_permutex_epi64( v, 0x39 )
#define mm512_rol256_1x64( v )   _mm512_permutex_epi64( v, 0x93 )

// Rotate 256 bit lanes by one 32 bit element
#define mm512_ror256_1x32( v ) \
           _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                    8,15,14,13,12,11,10, 9,   0, 7, 6, 5, 4, 3, 2, 1 ) )
#define mm512_rol256_1x32( v ) \
           _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                   14,13,12,11,10, 9, 8,15,   6, 5, 4, 3, 2, 1, 0, 7 ) )

#define mm512_ror256_1x16( v ) \
           _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                   0x0010001F, 0x001E001D, 0x001C001B, 0x001A0019, \
                   0x00180017, 0x00160015, 0x00140013, 0x00120011, \
                   0x0000000F, 0x000E000D, 0x000C000B, 0x000A0009, \
                   0x00080007, 0x00060005, 0x00040003, 0x00020001 ) )

#define mm512_rol256_1x16( v ) \
           _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                   0x001E001D, 0x001C001B, 0x001A0019, 0x00180017, \
	           0x00160015, 0x00140013, 0x00120011, 0x0000000F, \
	           0x000E000D, 0x000C000B, 0x000A0009, 0x00080007, \
                   0x00060005, 0x00040003, 0x00020001, 0x0000001F ) )

#define mm512_ror256_1x8( v ) \
            _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                   0x203F3E3D, 0x3C3B3A39, 0x38373635, 0x34333231, \
                   0x302F2E2D, 0x2C2B2A29, 0x28272625, 0x24232221, \
                   0x001F1E1D, 0x1C1B1A19, 0x18171615, 0x14131211, \
                   0x100F0E0D, 0x0C0B0A09, 0x08070605, 0x04030201 ) )
 
#define mm512_rol256_1x8( v ) \
            _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                   0x3E3D3C3B, 0x3A393837, 0x36353433, 0x3231302F, \
	           0x2E2D2C2B, 0x2A292827, 0x26252423, 0x2221203F, \
                   0x1E1D1C1B, 0x1A191817, 0x16151413, 0x1211100F, \
	           0x0E0D0C0B, 0x0A090807, 0x06050403, 0x0201001F ) )

//
// Rotate elements within 128 bit lanes of 512 bit vector.

// Swap hi & lo 64 bits in each 128 bit lane
#define mm512_swap128_64( v )    _mm512_permutex_epi64( v, 0xb1 )

// Rotate 128 bit lanes by one 32 bit element
#define mm512_ror128_1x32( v )   _mm512_shuffle_epi32( v, 0x39 )
#define mm512_rol128_1x32( v )   _mm512_shuffle_epi32( v, 0x93 )

#define mm512_ror128_1x16( v ) \
            _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                   0x0018001F, 0x001E001D, 0x001C001B, 0x001A0019, \
	           0x00100017, 0x00160015, 0x00140013, 0x00120011, \
                   0x0008000F, 0x000E000D, 0x000C000B, 0x000A0009, \
                   0x00000007, 0x00060005, 0x00040003, 0x00020001 ) )

#define mm512_rol128_1x16( v ) \
            _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                   0x001E001D, 0x001C001B, 0x001A0019, 0x0018001F, \
	           0x00160015, 0x00140013, 0x00120011, 0x00100017, \
	           0x000E000D, 0x000C000B, 0x000A0009, 0x0008000F, \
	           0x00060005, 0x00040003, 0x00020001, 0x00000007 ) )


#define mm512_ror128_1x8( v ) \
            _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                   0x303F3E3D, 0x3C3B3A39, 0x38373635, 0x34333231, \
                   0x202F2E2D, 0x2C2B2A29, 0x28272625, 0x24232221, \
                   0x101F1E1D, 0x1C1B1A19, 0x18171615, 0x14131211, \
                   0x000F0E0D, 0x0C0B0A09, 0x08070605, 0x04030201 ) )

#define mm512_rol128_1x8( v ) \
            _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                   0x3E3D3C3B, 0x3A393837, 0x36353433. 0x3231303F, \
                   0x2E2D2C2B, 0x2A292827, 0x26252423, 0x2221202F, \
                   0x1E1D1C1B, 0x1A191817, 0x16151413, 0x1211101F, \
                   0x0E0D0C0B, 0x0A090807, 0x06050403, 0x0201000F ) )

// Rotate 128 bit lanes by c bytes.  
#define mm512_ror128_x8( v, c ) \
   _mm512_or_si512( _mm512_bsrli_epi128( v, c ), \
                    _mm512_bslli_epi128( v, 16-(c) ) )
#define mm512_rol128_x8( v, c ) \
   _mm512_or_si512( _mm512_bslli_epi128( v, c ), \
                    _mm512_bsrli_epi128( v, 16-(c) ) )


//
// Rotate elements within 64 bit lanes.

// Swap 32 bit elements in each 64 bit lane
#define mm512_swap64_32( v )      _mm512_shuffle_epi32( v, 0xb1 )

// _mm512_set_epi8 doesn't seem to work
 
// Rotate each 64 bit lane by one 16 bit element.
#define mm512_ror64_1x16( v ) \
            _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                   0x39383F3E, 0x3D3C3B3A,   0x31303736, 0x35343332, \
                   0x29282F2E, 0x2D2C2B2A,   0x21202726, 0x25242322, \
                   0x19181F1E, 0x1D1C1B1A,   0x11101716, 0x15141312, \
                   0x09080F0E, 0x0D0C0B0A,   0x01000706, 0x05040302 ) )

#define mm512_rol64_1x16( v ) \
            _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                   0x3D3C3B3A, 0x39383F3E,   0x35343332, 0x31303736 \
                   0x2D2C2B2A, 0x29282F2E,   0x25242322, 0x21202726 \
                   0x1D1C1B1A, 0x19181F1E,   0x15141312, 0x11101716 \
                   0x0D0C0B0A, 0x09080F0E,   0x05040302, 0x01000706 ) ) 

// Rotate each 64 bit lane by one byte.
#define mm512_ror64_1x8( v ) \
            _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                   0x383F3E3D, 0x3C3B3A39,   0x30373635, 0x34333231, \
                   0x282F2E2D, 0x2C2B2A29,   0x20272625, 0x24232221, \
                   0x181F1E1D, 0x1C1B1A19,   0x10171615, 0x14131211, \
                   0x080F0E0D, 0x0C0B0A09,   0x00070605, 0x0403020 )

#define mm512_rol64_1x8( v ) \
             _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                    0x3E3D3C3B, 0x3A39383F,   0x36353433, 0x32313037, \
                    0x2E2D2C2B, 0x2A29282F,   0x26252423, 0x22212027, \
                    0x1E1D1C1B, 0x1A19181F,   0x16151413, 0x12111017, \
                    0x0E0D0C0B, 0x0A09080F,   0x06050403, 0x02010007 )

//
// Rotate elements within 32 bit lanes.

#define mm512_swap32_16( v ) \
              _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                     0x001D001C, 0x001F001E, 0x00190018, 0x001B001A, \
                     0x00150014, 0x00170016, 0x00110010, 0x00130012, \
                     0x000D000C, 0x000F000E, 0x00190008, 0x000B000A, \
                     0x00050004, 0x00070006, 0x00110000, 0x00030002 )
  
#define mm512_ror32_8( v ) \
              _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                     0x3C3F3E3D, 0x383B3A39, 0x34373635, 0x30333231, \
                     0x2C2F2E2D, 0x282B2A29, 0x24272625, 0x20232221, \
                     0x1C1F1E1D, 0x181B1A19, 0x14171615, 0x10131211, \
                     0x0C0F0E0D, 0x080B0A09, 0x04070605, 0x00030201 ) )

#define mm512_rol32_8( v ) \
               _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                      0x3E3D3C3F, 0x3A39383B, 0x36353437, 0x32313033, \
                      0x2E2D2C2F, 0x2A29282B, 0x26252427, 0x22212023, \
                      0x1E1D1C1F, 0x1A19181B, 0x16151417, 0x12111013, \
                      0x0E0D0C0F, 0x0A09080B, 0x06050407, 0x02010003 ) )

//
// Swap bytes in vector elements, vectorized bswap.

#define mm512_bswap_64( v ) \
                _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x38393A3B, 0x3C3D3E3F,   0x20313233, 0x34353637, \
                       0x28292A2B, 0x2C2D2E2F,   0x20212223, 0x34353637, \
                       0x18191A1B, 0x1C1D1E1F,   0x10111213, 0x14151617, \
                       0x08090A0B, 0x0C0D0E0F,   0x00010203, 0x04050607 ) )

#define mm512_bswap_32( v ) \
                _mm512_permutexvar_epi8( v, _mm512_set_epi832( \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233, \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233, \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233, \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233 ) )

#define mm512_bswap_16( v ) \
                _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x3E3F3C3D, 0x3A3B3839, 0x36373435, 0x32333031, \
                       0x2E2F2C2D, 0x2A2B2829, 0x26272425, 0x22232021, \
                       0x1E1F1C1D, 0x1A1B1819, 0x16171415, 0x12131011, \
                       0x0E0F0C0D, 0x0A0B0809, 0x06070405, 0x02030001 ) )

//
//  Rotate elements from 2 512 bit vectors in place, source arguments
//  are overwritten.
//  These can all be done with 2 permutex2var instructions but they are
//  slower than either xor or alignr.

#define mm512_swap1024_512(v1, v2) \
   v1 = _mm512_xor_si512(v1, v2); \
   v2 = _mm512_xor_si512(v1, v2); \
   v1 = _mm512_xor_si512(v1, v2);

#define mm512_ror1024_1x256( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 4 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 4 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_1x256( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 4 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 4 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_1x128( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 2 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_1x128i( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 6 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 6 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_1x64( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_1x64( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 7 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 7 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_1x32( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi32( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi32( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_1x32( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi32( v1, v2, 15 ); \
   v2 = _mm512_alignr_epi32( v2, v1, 15 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_1x16( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 2 ); \
   v1 = _mm512_alignr_epi8( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_1x16( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 62 ); \
   v2 = _mm512_alignr_epi8( v2, v1, 62 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_1x8( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi8( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_1x8( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 63 ); \
   v2 = _mm512_alignr_epi8( v2, v1, 63 ); \
   v1 = t; \
} while(0)

#endif   // AVX512F

//////////////////////////////////////////////////
//
//   Compile test.
//
//   Code to test that macros compile.

// Don't use universal overlay for initialized globals
static const m128_v64 m128_v64_ex[4] = { mm128_const1_64( 3), c128_zero,
                               c128_neg1,           c128_one_64 };

static inline __m128i sse2_compile_test( __m128i *a )
{
  m128v x;
  __m128i w = _mm_set_epi64x( 1, 2 );
  casti_m128i( a, 2 ) = mm128_not( w );
  w = mm128_negate_32( casti_m128i( m128_v64_ex, 1 ) );
  w = m128_v64_ex[0].v128;
  w = mm128_bror( w, 3 );
  w = mm128_invert_8( w );
  w = mm128_bswap_64( *a );           // sse2 vs ssse3
  w = mm128_ror_1x32( x.v128 );
#if defined(__SSE4_1__)
  mm128_ror256_1x64( w, x.v128 );     // sse4.1 only
#endif
  return w;
}

#if defined(__AVX2__)

// Don't use universal overlay for initialized globals
// Inilialize like vectors...
static const m256_v32 m256_v32_ex[4] = { mm256_const1_32( 3), c256_zero,
                                         c256_neg1_32,        c256_one_32 };
// ...or like scalars.
static const m256_v64 m256_v64_ex[2] = { {{ 0, 1, 2, 3 }},
	                                 {{ 4, 5, 6, 7 }} };

static inline __m256i avx2_compile_test( __m256i *a )
{
  m256v x;
  __m256i w = m256_v64_ex[1].v256;
  casti_m256i( a, 2 ) = mm256_not( w );
  w = mm256_negate_32( casti_m256i( m256_v32_ex, 1 ) );
  w = m256_v32_ex[0].v256;
  w = mm256_invert_32( w );
  w = mm256_bswap_64( *a );
  w = mm256_ror_1x32( w );  
  mm256_ror512_1x64( w, x.v256 );
  w = mm256_rolv_64( w, 2 );
  w = mm256_ror128_x8( w, 5 );
  return w;
}

#endif // AVX2

#if defined(__AVX512F__)

// Don't use universal overlay for initialized globals
static const m512_v64 m512_v64_ex[4] = { mm512_const1_64( 3), c512_zero,
                                         c512_neg1_64,           c512_one_64 };

static inline __m512i avx512_compile_test( __m512i *a )
{
  m512v x;
  __m512i w =   _mm512_set_epi32(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16);
  casti_m512i( a, 2 ) = mm512_not( w );
  w = mm512_negate_32( casti_m512i( m512_v64_ex, 1 ) );
  w = m512_v64_ex[0].v512;
  w = mm512_invert_32( w );
  w = mm512_bswap_64( *a );
  w = mm512_ror_1x32( w );
  mm512_ror1024_1x64( w, x.v512 );
  w = mm512_ror128_x8( w, 5 );

  __m256i y = m256_zero;
  y = mm256_rorv_16( y, 3 );
  y = mm256_ror_1x16( y );
  return w;
}

#endif  // AVX512

#endif   // AVXDEFS_H__

