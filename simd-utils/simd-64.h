#if !defined(SIMD_64_H__)
#define SIMD_64_H__ 1

#if defined(__MMX__) && defined(__SSE__)

////////////////////////////////////////////////////////////////
//
//               64 bit MMX vectors.
//
// This code is not used anywhere annd likely never will. It's intent was
// to support 2 way parallel hashing using SSE2 for 64 bit, and MMX for 32
// bit hash functions, but was never implemented.

// Pseudo constants

/*
#define m64_zero   _mm_setzero_si64()
#define m64_one_64 _mm_set_pi32(  0UL, 1UL )
#define m64_one_32 _mm_set1_pi32( 1UL )
#define m64_one_16 _mm_set1_pi16( 1U )
#define m64_one_8  _mm_set1_pi8(  1U );
#define m64_neg1   _mm_set1_pi32( 0xFFFFFFFFUL )
*/
#define m64_zero   ( (__m64)0ULL )
#define m64_one_64 ( (__m64)1ULL )
#define m64_one_32 ( (__m64)0x0000000100000001ULL )
#define m64_one_16 ( (__m64)0x0001000100010001ULL )
#define m64_one_8  ( (__m64)0x0101010101010101ULL )
#define m64_neg1   ( (__m64)0xFFFFFFFFFFFFFFFFULL )

#define casti_m64(p,i) (((__m64*)(p))[(i)])

// Bitwise not: ~(a)
//#define mm64_not( a ) _mm_xor_si64( (__m64)a, m64_neg1 )
#define mm64_not( a ) ( (__m64)( ~( (uint64_t)(a) ) )

// Unary negate elements
#define mm64_negate_32( v ) _mm_sub_pi32( m64_zero, v )
#define mm64_negate_16( v ) _mm_sub_pi16( m64_zero, v )
#define mm64_negate_8(  v ) _mm_sub_pi8(  m64_zero, v )

// Rotate bits in packed elements of 64 bit vector
#define mm64_rol_64( a, n ) \
   _mm_or_si64( _mm_slli_si64( a, n ), \
                _mm_srli_si64( a, 64-(n) ) )

#define mm64_ror_64( a, n ) \
   _mm_or_si64( _mm_srli_si64( a, n ), \
                _mm_slli_si64( a, 64-(n) ) )

#define mm64_rol_32( a, n ) \
   _mm_or_si64( _mm_slli_pi32( a, n ), \
                _mm_srli_pi32( a, 32-(n) ) )

#define mm64_ror_32( a, n ) \
   _mm_or_si64( _mm_srli_pi32( a, n ), \
                _mm_slli_pi32( a, 32-(n) ) )

#define mm64_rol_16( a, n ) \
   _mm_or_si64( _mm_slli_pi16( a, n ), \
                _mm_srli_pi16( a, 16-(n) ) )

#define mm64_ror_16( a, n ) \
   _mm_or_si64( _mm_srli_pi16( a, n ), \
                _mm_slli_pi16( a, 16-(n) ) )

// Rotate packed elements accross lanes. Useful for byte swap and byte
// rotation.

// Swap hi & lo 32 bits.
#define mm64_swap_32( a )     _mm_shuffle_pi16( a, 0x4e )

#define mm64_ror64_1x16( a )  _mm_shuffle_pi16( a, 0x39 ) 
#define mm64_rol64_1x16( a )  _mm_shuffle_pi16( a, 0x93 ) 

// Swap hi & lo 16 bits of each 32 bit element
#define mm64_swap32_16( a )  _mm_shuffle_pi16( a, 0xb1 )

#if defined(__SSSE3__)

// Endian byte swap packed elements
#define mm64_bswap_32( v ) \
    _mm_shuffle_pi8( v, (__m64)0x0405060700010203 )

#define mm64_bswap_16( v ) \
    _mm_shuffle_pi8( v, (__m64)0x0607040502030001 );

// Rotate right by c bytes
static inline __m64 mm64_ror_x8( __m64 v, const int c )
{ return _mm_alignr_pi8( v, v, c ); }

#else

#define mm64_bswap_32( v ) \
   _mm_set_pi32( __builtin_bswap32( ((uint32_t*)&v)[1] ), \
                 __builtin_bswap32( ((uint32_t*)&v)[0] )  )

#define mm64_bswap_16( v ) \
   _mm_set_pi16( __builtin_bswap16( ((uint16_t*)&v)[3] ), \
                 __builtin_bswap16( ((uint16_t*)&v)[2] ), \
                 __builtin_bswap16( ((uint16_t*)&v)[1] ), \
                 __builtin_bswap16( ((uint16_t*)&v)[0] )  )

#endif

#endif // MMX

#endif // SIMD_64_H__

