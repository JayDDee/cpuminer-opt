#if !defined(SIMD_SSE2_H__)
#define SIMD_SSE2_H__ 1

#if defined(__SSE2__)

//////////////////////////////////////////////////////////////////
//
//                 128 bit SSE vectors
//
// SSE2 is generally required for full 128 bit support. Some functions
// are also optimized with SSSE3 or SSE4.1.
//
// Do not call _mm_extract directly, it isn't supported in SSE2.
// Use mm128_extr instead, it will select the appropriate implementation.
//
// 128 bit operations are enhanced with uint128 which adds 128 bit integer
// support for arithmetic and other operations. Casting to uint128_t is not
// free, it requires a move from mmx to gpr but is often the only way or
// the more efficient way for certain operations.

// Compile time constant initializers are type agnostic and can have
// a pointer handle of almost any type. All arguments must be scalar constants.
// up to 64 bits. These iniitializers should only be used at compile time
// to initialize vector arrays. All data reside in memory.
//
// These are of limited use, it is often simpler to use uint64_t arrays
// and cast as required.

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

// Use uint128_t for most arithmetic, bit shift, comparison operations
// spanning all 128 bits. Some extractions are also more efficient 
// casting __m128i as uint128_t and usingstandard operators.

// This isn't cheap, not suitable for bulk usage.
#define mm128_extr_4x32( a0, a1, a2, a3, src ) \
do { \
  a0 = _mm_extract_epi32( src, 0 ); \
  a1 = _mm_extract_epi32( src, 1 ); \
  a1 = _mm_extract_epi32( src, 2 ); \
  a3 = _mm_extract_epi32( src, 3 ); \
} while(0)

// Horizontal vector testing

// Bit-wise test of entire vector, useful to test results of cmp.
#define mm128_anybits0( a ) (uint128_t)(a)
#define mm128_anybits1( a ) (((uint128_t)(a))+1)

#define mm128_allbits0( a ) ( !mm128_anybits1(a) )
#define mm128_allbits1( a ) ( !mm128_anybits0(a) )

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

// SSE2 doesn't implement extract
#if defined(__SSE4_1)

#define mm128_extr_64(a,n)   _mm_extract_epi64( a, n )
#define mm128_extr_32(a,n)   _mm_extract_epi32( a, n )

#else

#define mm128_extr_64(a,n)   (((uint64_t*)&a)[n])
#define mm128_extr_32(a,n)   (((uint32_t*)&a)[n])

#endif


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

// rewrite using insert
#define mm128_gather_64( d, s0, s1 ) \
    ((uint64_t*)d)[0] = (uint64_t)s0; \
    ((uint64_t*)d)[1] = (uint64_t)s1;

#define mm128_gather_32( d, s0, s1, s2, s3 ) \
    ((uint32_t*)d)[0] = (uint32_t)s0; \
    ((uint32_t*)d)[1] = (uint32_t)s1; \
    ((uint32_t*)d)[2] = (uint32_t)s2; \
    ((uint32_t*)d)[3] = (uint32_t)s3;

// Scatter data from contiguous memory.
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

#define mm128_ror_64( v, c ) \
   _mm_or_si128( _mm_srli_epi64( v, c ), _mm_slli_epi64( v, 64-(c) ) )

#define mm128_rol_64( v, c ) \
   _mm_or_si128( _mm_slli_epi64( v, c ), _mm_srli_epi64( v, 64-(c) ) )

#define mm128_ror_32( v, c ) \
   _mm_or_si128( _mm_srli_epi32( v, c ), _mm_slli_epi32( v, 32-(c) ) )

#define mm128_rol_32( v, c ) \
   _mm_or_si128( _mm_slli_epi32( v, c ), _mm_srli_epi32( v, 32-(c) ) )

#define mm128_ror_16( v, c ) \
   _mm_or_si128( _mm_srli_epi16( v, c ), _mm_slli_epi16( v, 16-(c) ) )

#define mm128_rol_16( v, c ) \
   _mm_or_si128( _mm_slli_epi16( v, c ), _mm_srli_epi16( v, 16-(c) ) )

//
// Rotate elements accross all lanes

#define mm128_swap_64( v )    _mm_shuffle_epi32( v, 0x4e )

#define mm128_ror_1x32( v )   _mm_shuffle_epi32( v, 0x39 )
#define mm128_rol_1x32( v )   _mm_shuffle_epi32( v, 0x93 )

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

#define mm128_swap32_64( v )  _mm_shuffle_epi32( v, 0xb1 )

#define mm128_ror16_64( v )   _mm_shuffle_epi8( v, \
         _mm_set_epi8(  9, 8,15,14,13,12,11,10,  1, 0, 7, 6, 5, 4, 3, 2 )
#define mm128_rol16_64( v )   _mm_shuffle_epi8( v, \
              _mm_set_epi8( 13,12,11,10, 9, 8,15,14,  5, 4, 3, 2, 1, 0, 7, 6 )


#define mm128_swap16_32( v )  _mm_shuffle_epi8( v, \
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
// Rotate in place concatenated 128 bit vectors as one 256 bit vector.

// Swap 128 bit vectorse.

#define mm128_swap128_256(v1, v2) \
   v1 = _mm_xor_si128(v1, v2); \
   v2 = _mm_xor_si128(v1, v2); \
   v1 = _mm_xor_si128(v1, v2);

// Concatenate v1 & v2 and rotate as one 256 bit vector.
#if defined(__SSE4_1__)

#define mm128_ror1x64_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 8 ); \
           v1 = _mm_alignr_epi8( v2, v1, 8 ); \
           v2 = t; \
} while(0)

#define mm128_rol1x64_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 8 ); \
           v2 = _mm_alignr_epi8( v2, v1, 8 ); \
           v1 = t; \
} while(0)

#define mm128_ror1x32_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 4 ); \
           v1 = _mm_alignr_epi8( v2, v1, 4 ); \
           v2 = t; \
} while(0)

#define mm128_rol1x32_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 12 ); \
           v2 = _mm_alignr_epi8( v2, v1, 12 ); \
           v1 = t; \
} while(0)

#define mm128_ror1x16_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 2 ); \
           v1 = _mm_alignr_epi8( v2, v1, 2 ); \
           v2 = t; \
} while(0)

#define mm128_rol1x16_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 14 ); \
           v2 = _mm_alignr_epi8( v2, v1, 14 ); \
           v1 = t; \
} while(0)

#define mm128_ror1x8_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 1 ); \
           v1 = _mm_alignr_epi8( v2, v1, 1 ); \
           v2 = t; \
} while(0)

#define mm128_rol1x8_256( v1, v2 ) \
do { \
   __m128i t  = _mm_alignr_epi8( v1, v2, 15 ); \
           v2 = _mm_alignr_epi8( v2, v1, 15 ); \
           v1 = t; \
} while(0)

#else  // SSE2

#define mm128_ror1x64_256( v1, v2 ) \
do { \
   __m128i t  = _mm_srli_si128( v1, 8 ) | _mm_slli_si128( v2, 8 ); \
           v2 = _mm_srli_si128( v2, 8 ) | _mm_slli_si128( v1, 8 ); \
           v1 = t; \
} while(0)

#define mm128_rol1x64_256( v1, v2 ) \
do { \
   __m128i t  = _mm_slli_si128( v1, 8 ) | _mm_srli_si128( v2, 8 ); \
           v2 = _mm_slli_si128( v2, 8 ) | _mm_srli_si128( v1, 8 ); \
           v1 = t; \
} while(0)

#define mm128_ror1x32_256( v1, v2 ) \
do { \
   __m128i t  = _mm_srli_si128( v1, 4 ) | _mm_slli_si128( v2, 12 ); \
           v2 = _mm_srli_si128( v2, 4 ) | _mm_slli_si128( v1, 12 ); \
           v1 = t; \
} while(0)

#define mm128_rol1x32_256( v1, v2 ) \
do { \
   __m128i t  = _mm_slli_si128( v1, 4 ) | _mm_srli_si128( v2, 12 ); \
           v2 = _mm_slli_si128( v2, 4 ) | _mm_srli_si128( v1, 12 ); \
           v1 = t; \
} while(0)

#define mm128_ror1x16_256( v1, v2 ) \
do { \
   __m128i t  = _mm_srli_si128( v1, 2 ) | _mm_slli_si128( v2, 14 ); \
           v2 = _mm_srli_si128( v2, 2 ) | _mm_slli_si128( v1, 14 ); \
           v1 = t; \
} while(0)

#define mm128_rol1x16_256( v1, v2 ) \
do { \
   __m128i t  = _mm_slli_si128( v1, 2 ) | _mm_srli_si128( v2, 14 ); \
           v2 = _mm_slli_si128( v2, 2 ) | _mm_srli_si128( v1, 14 ); \
           v1 = t; \
} while(0)

#define mm128_ror1x8_256( v1, v2 ) \
do { \
   __m128i t  = _mm_srli_si128( v1, 1 ) | _mm_slli_si128( v2, 15 ); \
           v2 = _mm_srli_si128( v2, 1 ) | _mm_slli_si128( v1, 15 ); \
           v1 = t; \
} while(0)

#define mm128_rol1x8_256( v1, v2 ) \
do { \
   __m128i t  = _mm_slli_si128( v1, 1 ) | _mm_srli_si128( v2, 15 ); \
           v2 = _mm_slli_si128( v2, 1 ) | _mm_srli_si128( v1, 15 ); \
           v1 = t; \
} while(0)

#endif  // SSE4.1 else SSE2

#endif // __SSE2__
#endif // SIMD_SSE2_H__
