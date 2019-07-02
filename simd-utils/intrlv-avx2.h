#if !defined(INTRLV_AVX2_H__)
#define INTRLV_AVX2_H__ 1

#if  defined(__AVX2__)

///////////////////////////////////////////////////////////
//
//          AVX2 256 Bit Vectors
//
//  A few functions that need AVX2 for 256 bit.


// Blend 2 vectors alternating hi & lo: { hi[n], lo[n-1], ... hi[1], lo[0] }
#define mm256_intrlv_blend_128( hi, lo ) \
                _mm256_blend_epi32( hi, lo, 0x0f )

#define mm256_intrlv_blend_64( hi, lo ) \
                _mm256_blend_epi32( hi, lo, 0x33 )

#define mm256_intrlv_blend_32( hi, lo ) \
           _mm256_blend_epi32( hi, lo, 0x55 )


#define mm256_bswap_intrlv_8x32_256( d, src ) \
do { \
  __m256i s0 = mm256_bswap_32( src ); \
  __m128i s1 = _mm256_extracti128_si256( s0, 1 ); \
  casti_m256i( d, 0 ) = _mm256_set1_epi32( _mm_extract_epi32( \
                                     _mm256_castsi256_si128( s0 ), 0 ) ); \
  casti_m256i( d, 1 ) = _mm256_set1_epi32( _mm_extract_epi32( \
                                     _mm256_castsi256_si128( s0 ), 1 ) ); \
  casti_m256i( d, 2 ) = _mm256_set1_epi32( _mm_extract_epi32( \
                                     _mm256_castsi256_si128( s0 ), 2 ) ); \
  casti_m256i( d, 3 ) = _mm256_set1_epi32( _mm_extract_epi32( \
                                     _mm256_castsi256_si128( s0 ), 3 ) ); \
  casti_m256i( d, 4 ) = _mm256_set1_epi32( _mm_extract_epi32( s1,   0 ) ); \
  casti_m256i( d, 5 ) = _mm256_set1_epi32( _mm_extract_epi32( s1,   1 ) ); \
  casti_m256i( d, 6 ) = _mm256_set1_epi32( _mm_extract_epi32( s1,   2 ) ); \
  casti_m256i( d, 7 ) = _mm256_set1_epi32( _mm_extract_epi32( s1,   3 ) ); \
} while(0)

#define mm256_bswap_intrlv_8x32_128( d, src ) \
do { \
  __m128i ss = mm128_bswap_32( src ); \
  casti_m256i( d, 0 ) = _mm256_set1_epi32( _mm_extract_epi32( ss, 0 ) ); \
  casti_m256i( d, 1 ) = _mm256_set1_epi32( _mm_extract_epi32( ss, 1 ) ); \
  casti_m256i( d, 2 ) = _mm256_set1_epi32( _mm_extract_epi32( ss, 2 ) ); \
  casti_m256i( d, 3 ) = _mm256_set1_epi32( _mm_extract_epi32( ss, 3 ) ); \
} while(0)

#define mm256_bswap_intrlv_4x64_256( d, src ) \
do { \
  __m256i s0 = mm256_bswap_32( src ); \
  __m128i s1 = _mm256_extracti128_si256( s0, 1 ); \
  casti_m256i( d,0 ) = _mm256_set1_epi64x( _mm_extract_epi64( \
                                        _mm256_castsi256_si128( s0 ), 0 ) ); \
  casti_m256i( d,1 ) = _mm256_set1_epi64x( _mm_extract_epi64( \
                                        _mm256_castsi256_si128( s0 ), 1 ) ); \
  casti_m256i( d,2 ) = _mm256_set1_epi64x(   _mm_extract_epi64( s1,   0 ) ); \
  casti_m256i( d,3 ) = _mm256_set1_epi64x(   _mm_extract_epi64( s1,   1 ) ); \
} while(0)

#define mm256_bswap_intrlv_4x64_128( d, src ) \
do { \
  __m128i ss = mm128_bswap_32( src ); \
  casti_m256i( d,0 ) = _mm256_set1_epi64x( _mm_extract_epi64( ss, 0 ) ); \
  casti_m256i( d,1 ) = _mm256_set1_epi64x( _mm_extract_epi64( ss, 1 ) ); \
} while(0)


// A couple of mining specifi functions.

// Interleave 80 bytes of 32 bit data for 8 lanes.
static inline void mm256_bswap_intrlv80_8x32( void *d, const void *s )
{
   mm256_bswap_intrlv_8x32_256( d    , casti_m256i( s, 0 ) );
   mm256_bswap_intrlv_8x32_256( d+256, casti_m256i( s, 1 ) );
   mm256_bswap_intrlv_8x32_128( d+512, casti_m128i( s, 4 ) );
}

// Interleave 80 bytes of 32 bit data for 8 lanes.
static inline void mm256_bswap_intrlv80_4x64( void *d, const void *s )
{
   mm256_bswap_intrlv_4x64_256( d    , casti_m256i( s, 0 ) );
   mm256_bswap_intrlv_4x64_256( d+128, casti_m256i( s, 1 ) );
   mm256_bswap_intrlv_4x64_128( d+256, casti_m128i( s, 4 ) );
}

// Blend 32 byte lanes of hash from 2 sources according to control mask.
// macro due to 256 bit value arg.
#define mm256_blend_hash_4x64( dst, a, b, mask ) \
do { \
    dst[0] = _mm256_blendv_epi8( a[0], b[0], mask ); \
    dst[1] = _mm256_blendv_epi8( a[1], b[1], mask ); \
    dst[2] = _mm256_blendv_epi8( a[2], b[2], mask ); \
    dst[3] = _mm256_blendv_epi8( a[3], b[3], mask ); \
    dst[4] = _mm256_blendv_epi8( a[4], b[4], mask ); \
    dst[5] = _mm256_blendv_epi8( a[5], b[5], mask ); \
    dst[6] = _mm256_blendv_epi8( a[6], b[6], mask ); \
    dst[7] = _mm256_blendv_epi8( a[7], b[7], mask ); \
} while(0)

#endif // AVX2
#endif // INTRLV_AVX2_H__
