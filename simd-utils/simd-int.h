#if !defined(SIMD_INT_H__)
#define SIMD_INT_H__ 1

///////////////////////////////////
//
//    Integers up to 128 bits.
//
//   These utilities enhance support for integers up to 128 bits.
//   All standard operations are supported on 128 bit integers except
//   numeric constant representation and IO. 128 bit integers must be built
//   and displayed as 2 64 bit halves, just like the old times.
//
//   Some utilities are also provided for smaller integers, most notably
//   bit rotation.   



// MMX has no extract instruction for 32 bit elements so this:
// Lo is trivial, high is a simple shift. 
// Input may be uint64_t or __m64, returns uint32_t.
#define u64_extr_lo32(a)   ( (uint32_t)( (uint64_t)(a) ) )
#define u64_extr_hi32(a)   ( (uint32_t)( ((uint64_t)(a)) >> 32)  )

#define u64_extr_32( a, n )  ( (uint32_t)( (a) >> ( ( 2-(n)) <<5 ) ) )
#define u64_extr_16( a, n )  ( (uint16_t)( (a) >> ( ( 4-(n)) <<4 ) ) )
#define u64_extr_8(  a, n )  ( (uint8_t) ( (a) >> ( ( 8-(n)) <<3 ) ) )

// Rotate bits in various sized integers.
#define u64_ror_64( x, c ) \
      (uint64_t)( ( (uint64_t)(x) >> (c) ) | ( (uint64_t)(x) << (64-(c)) ) )
#define u64_rol_64( x, c ) \
      (uint64_t)( ( (uint64_t)(x) << (c) ) | ( (uint64_t)(x) >> (64-(c)) ) )
#define u32_ror_32( x, c ) \
      (uint32_t)( ( (uint32_t)(x) >> (c) ) | ( (uint32_t)(x) << (32-(c)) ) )
#define u32_rol_32( x, c ) \
      (uint32_t)( ( (uint32_t)(x) << (c) ) | ( (uint32_t)(x) >> (32-(c)) ) )
#define u16_ror_16( x, c ) \
      (uint16_t)( ( (uint16_t)(x) >> (c) ) | ( (uint16_t)(x) << (16-(c)) ) )
#define u16_rol_16( x, c ) \
      (uint16_t)( ( (uint16_t)(x) << (c) ) | ( (uint16_t)(x) >> (16-(c)) ) )
#define u8_ror_8( x, c ) \
      (uint8_t) ( ( (uint8_t) (x) >> (c) ) | ( (uint8_t) (x) << ( 8-(c)) ) )
#define u8_rol_8( x, c ) \
      (uint8_t) ( ( (uint8_t) (x) << (c) ) | ( (uint8_t) (x) >> ( 8-(c)) ) )

// Endian byte swap
#define bswap_64( a ) __builtin_bswap64( a )
#define bswap_32( a ) __builtin_bswap32( a )

// 64 bit mem functions use integral sizes instead of bytes, data must
// be aligned to 64 bits. Mostly for scaled indexing convenience.
static inline void memcpy_64( uint64_t *dst, const uint64_t *src, int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = src[i]; }

static inline void memset_zero_64( uint64_t *src, int n )
{   for ( int i = 0; i < n; i++ ) src[i] = 0ull; }

static inline void memset_64( uint64_t *dst, const uint64_t a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }


///////////////////////////////////////
// 
//      128 bit integers
//
//  128 bit integers are inneficient and not a shortcut for __m128i.
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

// Compiler check for __int128 support
// Configure also has a test for int128.
#if ( __GNUC__ > 4 ) || ( ( __GNUC__ == 4 ) && ( __GNUC_MINOR__ >= 8 ) )
  #define GCC_INT128 1
#endif

#if !defined(GCC_INT128)
  #warning "__int128 not supported, requires GCC-4.8 or newer."
#endif

#if defined(GCC_INT128)

// Familiar looking type names
typedef          __int128  int128_t;
typedef unsigned __int128 uint128_t;



// Maybe usefull for making constants.
#define mk_uint128( hi, lo ) \
   ( ( (uint128_t)(hi) << 64 ) | ( (uint128_t)(lo) ) )


// Extracting the low bits is a trivial cast.
// These specialized functions are optimized while providing a
// consistent interface.
#define u128_hi64( x )    ( (uint64_t)( (uint128_t)(x) >> 64 ) )
#define u128_lo64( x )    ( (uint64_t)(x) )

// Generic extract, don't use for extracting low bits, cast instead.
#define u128_extr_64( a, n )  ( (uint64_t)( (a) >> ( ( 2-(n)) <<6 ) ) )
#define u128_extr_32( a, n )  ( (uint32_t)( (a) >> ( ( 4-(n)) <<5 ) ) )
#define u128_extr_16( a, n )  ( (uint16_t)( (a) >> ( ( 8-(n)) <<4 ) ) )
#define u128_extr_8(  a, n )  ( (uint8_t) ( (a) >> ( (16-(n)) <<3 ) ) )

// Not much need for this but it fills a gap.
#define u128_ror_128( x, c ) \
       ( ( (uint128_t)(x) >> (c) ) | ( (uint128_t)(x) << (128-(c)) ) )
#define u128_rol_128( x, c ) \
       ( ( (uint128_t)(x) << (c) ) | ( (uint128_t)(x) >> (128-(c)) ) )

#endif  // GCC_INT128

#endif // SIMD_INT_H__


