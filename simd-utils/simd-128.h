#if !defined(SIMD_128_H__)
#define SIMD_128_H__ 1

#if defined(__SSE2__)

//////////////////////////////////////////////////////////////////
//
//                 128 bit SSE vectors
//
// SSE2 is generally required for full 128 bit support. Some functions
// are also optimized with SSSE3 or SSE4.1.
//
// Do not call intrinsic _mm_extract directly, it isn't supported in SSE2.
// Use mm128_extr macro instead, it will select the appropriate implementation.
//
// 128 bit operations are enhanced with uint128 which adds 128 bit integer
// support for arithmetic and other operations. Casting to uint128_t is not
// free but is sometimes the only way for certain operations.
//
// Constants are an issue with simd. Simply put, immediate constants don't
// exist. All simd constants either reside in memory or a register and
// must be loaded from memory or generated using instructions at run time.
//
// Due to the cost of generating constants it is often more efficient to
// define a local const for repeated references to the same constant.
//
// Some constant values can be generated using shortcuts. Zero for example
// is as simple as XORing any register with itself, and is implemented
// iby the setzero instrinsic. These shortcuts must be implemented using ASM
// due to doing things the compiler would complain about. Another single
// instruction constant is -1, defined below. Others may be added as the need
// arises. Even single instruction constants are less efficient than local
// register variables so the advice above stands. These pseudo-constants
// do not perform any memory accesses
//
// One common use for simd constants is as a control index for some simd
// instructions like blend and shuffle. The utilities below do not take this
// into account. Those that generate a simd constant should not be used
// repeatedly. It may be better for the application to reimplement the
// utility to better suit its usage.

#define m128_zero      _mm_setzero_si128()

static inline __m128i mm128_one_128_fn()
{
  __m128i a;
   const uint64_t one = 1;
   asm( "movq %1, %0\n\t"
        : "=x"(a)
        : "r" (one) );
   return a;
}
#define m128_one_128    mm128_one_128_fn()

static inline __m128i mm128_one_64_fn()
{
  __m128i a;
  const uint64_t one = 1;
  asm( "movq %1, %0\n\t"
       : "=x" (a)
       : "r"  (one) );
  return _mm_shuffle_epi32( a, 0x44 );
}
#define m128_one_64    mm128_one_64_fn()

static inline __m128i mm128_one_32_fn()
{
  __m128i a;
  const uint32_t one = 1;
  asm( "movd %1, %0\n\t"
       : "=x" (a)
       : "r"  (one) );
  return _mm_shuffle_epi32( a, 0x00 );
}
#define m128_one_32    mm128_one_32_fn()

static inline __m128i mm128_one_16_fn()
{
  __m128i a;
  const uint32_t one = 0x00010001;
  asm( "movd %1, %0\n\t"
       : "=x" (a)
       : "r"  (one) );
  return _mm_shuffle_epi32( a, 0x00 );
}
#define m128_one_16    mm128_one_16_fn()

static inline __m128i mm128_one_8_fn()
{
  __m128i a;
  const uint32_t one = 0x01010101;
  asm( "movd %1, %0\n\t"
       : "=x" (a)
       : "r"  (one) );
  return _mm_shuffle_epi32( a, 0x00 );
}
#define m128_one_8    mm128_one_8_fn()

static inline __m128i mm128_neg1_fn()
{
   __m128i a;
   asm( "pcmpeqd %0, %0\n\t"
        : "=x" (a) );
   return a;
}
#define m128_neg1    mm128_neg1_fn()

// move uint64_t to low bits of __m128i, zeros the rest
static inline __m128i mm128_mov64_128( uint64_t n )
{
  __m128i a;
  asm( "movq %1, %0\n\t"
       : "=x" (a)
       : "r"  (n) );
  return  a;
}

static inline __m128i mm128_mov32_128( uint32_t n )
{
  __m128i a;
  asm( "movd %1, %0\n\t"
       : "=x" (a)
       : "r"  (n) );
  return  a;
}

static inline uint64_t mm128_mov128_64( __m128i a )
{
  uint64_t n;
  asm( "movq %1, %0\n\t"
       : "=x" (n)
       : "r"  (a) );
  return  n;
}

static inline uint32_t mm128_mov128_32( __m128i a )
{
  uint32_t n;
  asm( "movd %1, %0\n\t"
       : "=x" (n)
       : "r"  (a) );
  return  n;
}

static inline __m128i m128_const1_64( const uint64_t n )
{
  __m128i a;
  asm( "movq %1, %0\n\t"
       : "=x" (a)
       : "r"  (n) );
  return _mm_shuffle_epi32( a, 0x44 );
}

static inline __m128i m128_const1_32( const uint32_t n )
{
  __m128i a;
  asm( "movd %1, %0\n\t"
       : "=x" (a)
       : "r"  (n) );
  return _mm_shuffle_epi32( a, 0x00 );
}

#if defined(__SSE41__)

// alternative to _mm_set_epi64x, doesn't use mem,

static inline __m128i m128_const_64( const uint64_t hi, const uint64_t lo )
{
   __m128i a;
   asm( "movq %2, %0\n\t"
        "pinsrq $1, %1, %0\n\t"
        : "=x" (a)
        : "r"  (hi), "r" (lo) );
   return a;
}

#else

#define m128_const_64  _mm_set_epi64x

#endif

//
// Basic operations without equivalent SIMD intrinsic

// Bitwise not (~v)  
#define mm128_not( v )          _mm_xor_si128( (v), m128_neg1 ) 

// Unary negation of elements
#define mm128_negate_64( v )    _mm_sub_epi64( m128_zero, v )
#define mm128_negate_32( v )    _mm_sub_epi32( m128_zero, v )  
#define mm128_negate_16( v )    _mm_sub_epi16( m128_zero, v )  

// Add 4 values, fewer dependencies than sequential addition.
#define mm128_add4_64( a, b, c, d ) \
   _mm_add_epi64( _mm_add_epi64( a, b ), _mm_add_epi64( c, d ) )

#define mm128_add4_32( a, b, c, d ) \
   _mm_add_epi32( _mm_add_epi32( a, b ), _mm_add_epi32( c, d ) )

#define mm128_add4_16( a, b, c, d ) \
   _mm_add_epi16( _mm_add_epi16( a, b ), _mm_add_epi16( c, d ) )

#define mm128_add4_8( a, b, c, d ) \
   _mm_add_epi8( _mm_add_epi8( a, b ), _mm_add_epi8( c, d ) )

#define mm128_xor4( a, b, c, d ) \
   _mm_xor_si128( _mm_xor_si128( a, b ), _mm_xor_si128( c, d ) )

// This isn't cheap, not suitable for bulk usage.
#define mm128_extr_4x32( a0, a1, a2, a3, src ) \
do { \
  a0 = _mm_extract_epi32( src, 0 ); \
  a1 = _mm_extract_epi32( src, 1 ); \
  a1 = _mm_extract_epi32( src, 2 ); \
  a3 = _mm_extract_epi32( src, 3 ); \
} while(0)

// Horizontal vector testing

#if defined(__SSE41__)

#define mm128_allbits0( a )    _mm_testz_si128(   a, a )
#define mm128_allbits1( a )    _mm_testc_si128(   a, m128_neg1 )
#define mm128_allbitsne( a )   _mm_testnzc_si128( a, m128_neg1 )
#define mm128_anybits0         mm128_allbitsne
#define mm128_anybits1         mm128_allbitsne

#else   // SSE2

// Bit-wise test of entire vector, useful to test results of cmp.
#define mm128_anybits0( a ) (uint128_t)(a)
#define mm128_anybits1( a ) (((uint128_t)(a))+1)

#define mm128_allbits0( a ) ( !mm128_anybits1(a) )
#define mm128_allbits1( a ) ( !mm128_anybits0(a) )

#endif // SSE41 else SSE2

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

// Doesn't work with register variables.
#define mm128_extr_64(a,n)   (((uint64_t*)&a)[n])
#define mm128_extr_32(a,n)   (((uint32_t*)&a)[n])

#endif


// Memory functions
// Mostly for convenience, avoids calculating bytes.
// Assumes data is alinged and integral.
// n = number of __m128i, bytes/16

// Memory functions
// Mostly for convenience, avoids calculating bytes.
// Assumes data is alinged and integral.
// n = number of __m128i, bytes/16

static inline void memset_zero_128( __m128i *dst,  const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m128_zero; }

static inline void memset_128( __m128i *dst, const __m128i a, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_128( __m128i *dst, const __m128i *src, const int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }


//
// Bit rotations

// AVX512 has implemented bit rotation for 128 bit vectors with
// 64 and 32 bit elements.

// compiler doesn't like when a variable is used for the last arg of
// _mm_rol_epi32, must be "8 bit immediate".
// sm3-hash-4way.c fails to compile.
/*
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define mm128_ror_64( v, c )    _mm_ror_epi64( v, c )
#define mm128_rol_64( v, c )    _mm_rol_epi64( v, c )
#define mm128_ror_32( v, c )    _mm_ror_epi32( v, c )
#define mm128_rol_32( v, c )    _mm_rol_epi32( v, c )

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

//#endif   // AVX512 else

#define mm128_ror_16( v, c ) \
   _mm_or_si128( _mm_srli_epi16( v, c ), _mm_slli_epi16( v, 16-(c) ) )

#define mm128_rol_16( v, c ) \
   _mm_or_si128( _mm_slli_epi16( v, c ), _mm_srli_epi16( v, 16-(c) ) )

//
// Rotate vector elements accross all lanes

#define mm128_swap_64( v )    _mm_shuffle_epi32( v, 0x4e )

#define mm128_ror_1x32( v )   _mm_shuffle_epi32( v, 0x39 )
#define mm128_rol_1x32( v )   _mm_shuffle_epi32( v, 0x93 )

#if defined (__SSE3__)
// no SSE2 implementation, no current users

#define mm128_ror_1x16( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x01000f0e0d0c0b0a, \
                                       0x0908070605040302 ) )
#define mm128_rol_1x16( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x0d0c0b0a09080706, \
                                       0x0504030201000f0e ) )
#define mm128_ror_1x8( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x000f0e0d0c0b0a09, \
                                       0x0807060504030201 ) )
#define mm128_rol_1x8( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x0e0d0c0b0a090807, \
                                       0x060504030201000f ) )
#endif  // SSE3

// Rotate 16 byte (128 bit) vector by c bytes.
// Less efficient using shift but more versatile. Use only for odd number
// byte rotations. Use shuffle above whenever possible.
#define mm128_bror( v, c ) \
   _mm_or_si128( _mm_srli_si128( v, c ), _mm_slli_si128( v, 16-(c) ) )

#define mm128_brol( v, c ) \
   _mm_or_si128( _mm_slli_si128( v, c ), _mm_srli_si128( v, 16-(c) ) )


// Invert vector: {3,2,1,0} -> {0,1,2,3}
#define mm128_invert_32( v ) _mm_shuffle_epi32( v, 0x1b )

#if defined(__SSSE3__)

#define mm128_invert_16( v ) \
   _mm_shuffle_epi8( v, mm128_const_64( 0x0100030205040706, \
                                        0x09080b0a0d0c0f0e )
#define mm128_invert_8( v ) \
   _mm_shuffle_epi8( v, mm128_const_64( 0x0001020304050607, \
                                        0x08090a0b0c0d0e0f )

#endif   // SSSE3


//
// Rotate elements within lanes.

// Equivalent to mm128_ror_64( v, 32 )
#define mm128_swap32_64( v )  _mm_shuffle_epi32( v, 0xb1 )

// Equivalent to mm128_ror_64( v, 16 )
#define mm128_ror16_64( v )   _mm_shuffle_epi8( v, \
                   m128_const_64( 0x09080f0e0d0c0b0a, 0x0100070605040302 )
#define mm128_rol16_64( v )   _mm_shuffle_epi8( v, \
                   m128_const_64( 0x0dc0b0a09080f0e, 0x0504030201000706 )

// Equivalent to mm128_ror_32( v, 16 )
#define mm128_swap16_32( v )  _mm_shuffle_epi8( v, \
                   m128_const_64( 0x0d0c0f0e09080b0a, 0x0504070601000302 )

//
// Endian byte swap.

#if defined(__SSSE3__)

#define mm128_bswap_64( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x08090a0b0c0d0e0f, \
                                       0x0001020304050607 ) )

#define mm128_bswap_32( v ) \
   _mm_shuffle_epi8( v, m128_const_64( 0x0c0d0e0f08090a0b, \
                                       0x0405060700010203 ) )

#define mm128_bswap_16( v ) _mm_shuffle_epi8( \
                   m128_const_64( 0x0e0f0c0d0a0b0809, 0x0607040502030001 )

// 8 byte qword * 8 qwords * 2 lanes = 128 bytes
#define mm128_block_bswap_64( d, s ) do \
{ \
   __m128i ctl = m128_const_64(  0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  casti_m128i( d, 0 ) = _mm_shuffle_epi8( casti_m128i( s, 0 ), ctl ); \
  casti_m128i( d, 1 ) = _mm_shuffle_epi8( casti_m128i( s, 1 ), ctl ); \
  casti_m128i( d, 2 ) = _mm_shuffle_epi8( casti_m128i( s, 2 ), ctl ); \
  casti_m128i( d, 3 ) = _mm_shuffle_epi8( casti_m128i( s, 3 ), ctl ); \
  casti_m128i( d, 4 ) = _mm_shuffle_epi8( casti_m128i( s, 4 ), ctl ); \
  casti_m128i( d, 5 ) = _mm_shuffle_epi8( casti_m128i( s, 5 ), ctl ); \
  casti_m128i( d, 6 ) = _mm_shuffle_epi8( casti_m128i( s, 6 ), ctl ); \
  casti_m128i( d, 7 ) = _mm_shuffle_epi8( casti_m128i( s, 7 ), ctl ); \
} while(0)

// 4 byte dword * 8 dwords * 4 lanes = 128 bytes
#define mm128_block_bswap_32( d, s ) do \
{ \
   __m128i ctl = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_m128i( d, 0 ) = _mm_shuffle_epi8( casti_m128i( s, 0 ), ctl ); \
  casti_m128i( d, 1 ) = _mm_shuffle_epi8( casti_m128i( s, 1 ), ctl ); \
  casti_m128i( d, 2 ) = _mm_shuffle_epi8( casti_m128i( s, 2 ), ctl ); \
  casti_m128i( d, 3 ) = _mm_shuffle_epi8( casti_m128i( s, 3 ), ctl ); \
  casti_m128i( d, 4 ) = _mm_shuffle_epi8( casti_m128i( s, 4 ), ctl ); \
  casti_m128i( d, 5 ) = _mm_shuffle_epi8( casti_m128i( s, 5 ), ctl ); \
  casti_m128i( d, 6 ) = _mm_shuffle_epi8( casti_m128i( s, 6 ), ctl ); \
  casti_m128i( d, 7 ) = _mm_shuffle_epi8( casti_m128i( s, 7 ), ctl ); \
} while(0)

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

static inline void mm128_block_bswap_64( __m128i *d, const __m128i *s )
{
   d[0] = mm128_bswap_64( s[0] );
   d[1] = mm128_bswap_64( s[1] );
   d[2] = mm128_bswap_64( s[2] );
   d[3] = mm128_bswap_64( s[3] );
   d[4] = mm128_bswap_64( s[4] );
   d[5] = mm128_bswap_64( s[5] );
   d[6] = mm128_bswap_64( s[6] );
   d[7] = mm128_bswap_64( s[7] );
}

static inline void mm128_block_bswap_32( __m128i *d, const __m128i *s )
{
   d[0] = mm128_bswap_32( s[0] );
   d[1] = mm128_bswap_32( s[1] );
   d[2] = mm128_bswap_32( s[2] );
   d[3] = mm128_bswap_32( s[3] );
   d[4] = mm128_bswap_32( s[4] );
   d[5] = mm128_bswap_32( s[5] );
   d[6] = mm128_bswap_32( s[6] );
   d[7] = mm128_bswap_32( s[7] );
}

#endif // SSSE3 else SSE2

//
// Rotate in place concatenated 128 bit vectors as one 256 bit vector.

// Swap 128 bit vectorse.

#define mm128_swap128_256( v1, v2 ) \
   v1 = _mm_xor_si128( v1, v2 ); \
   v2 = _mm_xor_si128( v1, v2 ); \
   v1 = _mm_xor_si128( v1, v2 );

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
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 8 ), \
                              _mm_slli_si128( v2, 8 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 8 ), \
                              _mm_slli_si128( v1, 8 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol1x64_256( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 8 ), \
                              _mm_srli_si128( v2, 8 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 8 ), \
                              _mm_srli_si128( v1, 8 ) ); \
           v1 = t; \
} while(0)

#define mm128_ror1x32_256( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 4 ), \
                              _mm_slli_si128( v2, 12 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 4 ), \
                              _mm_slli_si128( v1, 12 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol1x32_256( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 4 ), \
                              _mm_srli_si128( v2, 12 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 4 ), \
                              _mm_srli_si128( v1, 12 ) ); \
           v1 = t; \
} while(0)

#define mm128_ror1x16_256( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 2 ), \
                              _mm_slli_si128( v2, 14 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 2 ), \
                              _mm_slli_si128( v1, 14 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol1x16_256( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 2 ), \
                              _mm_srli_si128( v2, 14 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 2 ), \
                              _mm_srli_si128( v1, 14 ) ); \
           v1 = t; \
} while(0)

#define mm128_ror1x8_256( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_srli_si128( v1, 1 ), \
                              _mm_slli_si128( v2, 15 ) ); \
           v2 = _mm_or_si128( _mm_srli_si128( v2, 1 ), \
                              _mm_slli_si128( v1, 15 ) ); \
           v1 = t; \
} while(0)

#define mm128_rol1x8_256( v1, v2 ) \
do { \
   __m128i t  = _mm_or_si128( _mm_slli_si128( v1, 1 ), \
                              _mm_srli_si128( v2, 15 ) ); \
           v2 = _mm_or_si128( _mm_slli_si128( v2, 1 ), \
                              _mm_srli_si128( v1, 15 ) ); \
           v1 = t; \
} while(0)

#endif  // SSE4.1 else SSE2

#endif // __SSE2__
#endif // SIMD_128_H__
