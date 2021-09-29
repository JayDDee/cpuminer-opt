#if !defined(SIMD_INT_H__)
#define SIMD_INT_H__ 1

// Endian byte swap
#define bswap_64( a ) __builtin_bswap64( a )
#define bswap_32( a ) __builtin_bswap32( a )

// Safe division, integer or floating point. For floating point it's as  
// safe as 0. is precisely zero.
// Returns safe_result if division by zero.
#define safe_div( dividend, divisor, safe_result ) \
   ( (divisor) == 0 ? safe_result : ( (dividend) / (divisor) )  )

// Aliases with familiar names for built in bit rotate instructions
#define rol64( a, n )   _lrotl( a, n )  
#define ror64( a, n )   _lrotr( a, n )
#define rol32( a, n )   _rotl( a, n )
#define ror32( a, n )   _rotr( a, n )
#define rol16( a, n )   _rotwl( a, n )
#define ror16( a, n )   _rotwr( a, n )

///////////////////////////////////////
// 
//      128 bit integers
//
// 128 bit integers are inneficient and not a shortcut for __m128i.
// Native type __int128 supported starting with GCC-4.8.
//
// __int128 uses two 64 bit GPRs to hold the data. The main benefits are
// for 128 bit arithmetic. Vectors are preferred when 128 bit arith
// is not required. int128 also works better with other integer sizes.
// Vectors benefit from wider registers.
//
// For safety use typecasting on all numeric arguments.
//
// Use typecasting for conversion to/from 128 bit vector:
// __m128i v128 = (__m128i)my_int128l
// __m256i v256 = _mm256_set_m128i( (__m128i)my_int128, (__m128i)my_int128 );
// my_int128 = (uint128_t)_mm256_extracti128_si256( v256, 1 );

// obsolete test
// Compiler check for __int128 support
// Configure also has a test for int128.
#if ( __GNUC__ > 4 ) || ( ( __GNUC__ == 4 ) && ( __GNUC_MINOR__ >= 8 ) )
  #define GCC_INT128 1
#endif

// obsolte test
#if !defined(GCC_INT128)
  #warning "__int128 not supported, requires GCC-4.8 or newer."
#endif

#if defined(GCC_INT128)

// Familiar looking type names
typedef          __int128  int128_t;
typedef unsigned __int128 uint128_t;

// Extracting the low bits is a trivial cast.
// These specialized functions are optimized while providing a
// consistent interface.
#define u128_hi64( x )    ( (uint64_t)( (uint128_t)(x) >> 64 ) )
#define u128_lo64( x )    ( (uint64_t)(x) )

#endif  // GCC_INT128

#endif // SIMD_INT_H__


