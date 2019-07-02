#if !defined(SIMD_AVX_H__)
#define SIMD_AVX_H__ 1

#if defined(__AVX__)

/////////////////////////////////////////////////////////////////////
//
//             AVX 256 bit vectors
//
//   Basic support for 256 bit vectors. Most of the good stuff needs AVX2.

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
// Vector size conversion.
//
// Allows operations on either or both halves of a 256 bit vector serially.
// Handy for parallel AES.
// Caveats:
//      _mm256_castsi256_si128 is free and without side effects.
//      _mm256_castsi128_si256 is also free but leaves the high half
//      undefined. That's ok if the hi half will be subseqnently assigned.
//      If assigning both, do lo first, If assigning only 1, use
//      _mm256_inserti128_si256.
//
// What to do about extractf128 (AVX) and extracti128 (AVX2)?
#define mm128_extr_lo128_256( a ) _mm256_castsi256_si128( a )
#define mm128_extr_hi128_256( a ) _mm256_extractf128_si256( a, 1 )

// Extract 4 u64 from 256 bit vector.
#define mm256_extr_4x64( a0, a1, a2, a3, src ) \
do { \
  __m128i hi = _mm256_extractf128_si256( src, 1 ); \
  a0 = _mm_extract_epi64( _mm256_castsi256_si128( src ), 0 ); \
  a1 = _mm_extract_epi64( _mm256_castsi256_si128( src ), 1 ); \
  a2 = _mm_extract_epi64( hi, 0 ); \
  a3 = _mm_extract_epi64( hi, 1 ); \
} while(0)

#define mm256_extr_8x32( a0, a1, a2, a3, a4, a5, a6, a7, src ) \
do { \
  __m128i hi = _mm256_extractf128_si256( src, 1 ); \
  a0 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 0 ); \
  a1 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 1 ); \
  a2 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 2 ); \
  a3 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 3 ); \
  a4 = _mm_extract_epi32( hi, 0 ); \
  a5 = _mm_extract_epi32( hi, 1 ); \
  a6 = _mm_extract_epi32( hi, 2 ); \
  a7 = _mm_extract_epi32( hi, 3 ); \
} while(0)

// input __m128i, returns __m256i
// To build a 256 bit vector from 2 128 bit vectors lo must be done first.
// lo alone leaves hi undefined, hi alone leaves lo unchanged.
// Both cost one clock while preserving the other half..
// Insert b into specified half of a leaving other half of a unchanged.
#define mm256_ins_lo128_256( a, b )  _mm256_insertf128_si256( a, b, 0 )
#define mm256_ins_hi128_256( a, b )  _mm256_insertf128_si256( a, b, 1 )

// concatenate two 128 bit vectors into one 256 bit vector: { hi, lo }
#define mm256_concat_128( hi, lo ) \
   mm256_ins_hi128_256( _mm256_castsi128_si256( lo ), hi )

// Horizontal vector testing

// Needs int128 support
// Bit-wise test of entire vector, useful to test results of cmp.
#define mm256_anybits0( a ) \
         ( (uint128_t)mm128_extr_hi128_256( a ) \
         | (uint128_t)mm128_extr_lo128_256( a ) )

#define mm256_anybits1( a ) \
         ( ( (uint128_t)mm128_extr_hi128_256( a ) + 1 ) \
         | ( (uint128_t)mm128_extr_lo128_256( a ) + 1 ) )

#define mm256_allbits0_256( a ) ( !mm256_anybits1(a) )
#define mm256_allbits1_256( a ) ( !mm256_anybits0(a) )

// Parallel AES, for when x is expected to be in a 256 bit register.
#define mm256_aesenc_2x128( x ) \
     mm256_concat_128( \
     _mm_aesenc_si128( mm128_extr_hi128_256( x ), m128_zero ), \
          _mm_aesenc_si128( mm128_extr_lo128_256( x ), m128_zero ) )

#define mm256_aesenckey_2x128( x, k ) \
     mm256_concat_128( \
     _mm_aesenc_si128( mm128_extr_hi128_256( x ), \
                       mm128_extr_lo128_256( k ) ), \
     _mm_aesenc_si128( mm128_extr_hi128_256( x ), \
                       mm128_extr_lo128_256( k ) ) )

#define mm256_paesenc_2x128( y, x ) do \
{ \
  __m256i *X = (__m256i*)x; \
  __m256i *Y = (__m256i*)y; \
  y[0] = _mm_aesenc_si128( x[0], m128_zero ); \
  y[1] = _mm_aesenc_si128( x[1], m128_zero ); \
} while(0);

// With pointers.
#define mm256_paesenckey_2x128( y, x, k ) do \
{ \
  __m256i *X = (__m256i*)x; \
  __m256i *Y = (__m256i*)y; \
  __m256i *K = (__m256i*)ky; \
  y[0] = _mm_aesenc_si128( x[0], K[0] ); \
  y[1] = _mm_aesenc_si128( x[1], K[1] ); \
} while(0);

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


#endif // __AVX__
#endif // SIMD_AVX_H__

