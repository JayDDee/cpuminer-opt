#if !defined(SIMD_SCALAR_H__)
#define SIMD_SCALAR_H__ 1

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
#define u16rol_16( x, c ) \
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

#if defined (GCC_INT128)

///////////////////////////////////////
// 
//      128 bit integers
//

// No real need or use.
//#define u128_neg1        ((uint128_t)(-1))

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

#endif // SIMD_SCALAR_H__


