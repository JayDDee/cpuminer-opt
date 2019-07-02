#if !defined(INTRLV_AVX_H__)
#define INTRLV_AVX_H__ 1

#if  defined(__AVX__)

// Convenient short cuts for local use only

// Extract 64 bits from the low 128 bits of 256 bit vector.
#define extr64_cast128_256( a, n ) \
   _mm_extract_epi64( _mm256_castsi256_si128( a ), n )

// Extract 32 bits from the low 128 bits of 256 bit vector.
#define extr32_cast128_256( a, n ) \
   _mm_extract_epi32( _mm256_castsi256_si128( a ), n )

///////////////////////////////////////////////////////////
//
//          AVX 256 Bit Vectors
//
//  256 bit interleaving can be done with AVX.

#define mm256_put_64( s0, s1, s2, s3) \
  _mm256_set_epi64x( *((const uint64_t*)(s3)), *((const uint64_t*)(s2)), \
                     *((const uint64_t*)(s1)), *((const uint64_t*)(s0)) )

#define mm256_put_32( s00, s01, s02, s03, s04, s05, s06, s07 ) \
  _mm256_set_epi32( *((const uint32_t*)(s07)), *((const uint32_t*)(s06)), \
                    *((const uint32_t*)(s05)), *((const uint32_t*)(s04)), \
                    *((const uint32_t*)(s03)), *((const uint32_t*)(s02)), \
                    *((const uint32_t*)(s01)), *((const uint32_t*)(s00)) )

#define mm256_get_64( s, i0, i1, i2, i3 ) \
  _mm256_set_epi64x( ((const uint64_t*)(s))[i3], ((const uint64_t*)(s))[i2], \
                     ((const uint64_t*)(s))[i1], ((const uint64_t*)(s))[i0] )

#define mm256_get_32( s, i0, i1, i2, i3, i4, i5, i6, i7 ) \
  _mm256_set_epi32( ((const uint32_t*)(s))[i7], ((const uint32_t*)(s))[i6], \
                    ((const uint32_t*)(s))[i5], ((const uint32_t*)(s))[i4], \
                    ((const uint32_t*)(s))[i3], ((const uint32_t*)(s))[i2], \
                    ((const uint32_t*)(s))[i1], ((const uint32_t*)(s))[i0] )

/*
// Blend 2 vectors alternating hi & lo: { hi[n], lo[n-1], ... hi[1], lo[0] }
#define mm256_intrlv_blend_128( hi, lo ) \
                _mm256_blend_epi32( hi, lo, 0x0f )

#define mm256_intrlv_blend_64( hi, lo ) \
                _mm256_blend_epi32( hi, lo, 0x33 )

#define mm256_intrlv_blend_32( hi, lo ) \
           _mm256_blend_epi32( hi, lo, 0x55 )
*/

// Interleave 8x32_256
#define mm256_intrlv_8x32_256( d, s0, s1, s2, s3, s4, s5, s6, s7 ) \
{ \
   __m128i s0hi = mm128_extr_hi128_256( s0 ); \
   __m128i s1hi = mm128_extr_hi128_256( s1 ); \
   __m128i s2hi = mm128_extr_hi128_256( s2 ); \
   __m128i s3hi = mm128_extr_hi128_256( s3 ); \
   __m128i s4hi = mm128_extr_hi128_256( s4 ); \
   __m128i s5hi = mm128_extr_hi128_256( s5 ); \
   __m128i s6hi = mm128_extr_hi128_256( s6 ); \
   __m128i s7hi = mm128_extr_hi128_256( s7 ); \
   casti_m256i( d,0 ) = _mm256_set_epi32( \
                        extr32_cast128_256(s7,0), extr32_cast128_256(s6,0), \
                        extr32_cast128_256(s5,0), extr32_cast128_256(s4,0), \
                        extr32_cast128_256(s3,0), extr32_cast128_256(s2,0), \
                        extr32_cast128_256(s1,0), extr32_cast128_256(s0,0) ); \
   casti_m256i( d,1 ) = _mm256_set_epi32( \
                        extr32_cast128_256(s7,1), extr32_cast128_256(s6,1), \
                        extr32_cast128_256(s5,1), extr32_cast128_256(s4,1), \
                        extr32_cast128_256(s3,1), extr32_cast128_256(s2,1), \
                        extr32_cast128_256(s1,1), extr32_cast128_256(s0,1) ); \
   casti_m256i( d,2 ) = _mm256_set_epi32( \
                        extr32_cast128_256(s7,2), extr32_cast128_256(s6,2), \
                        extr32_cast128_256(s5,2), extr32_cast128_256(s4,2), \
                        extr32_cast128_256(s3,2), extr32_cast128_256(s2,2), \
                        extr32_cast128_256(s1,2), extr32_cast128_256(s0,2) ); \
   casti_m256i( d,3 ) = _mm256_set_epi32( \
                        extr32_cast128_256(s7,3), extr32_cast128_256(s6,3), \
                        extr32_cast128_256(s5,3), extr32_cast128_256(s4,3), \
                        extr32_cast128_256(s3,3), extr32_cast128_256(s2,3), \
                        extr32_cast128_256(s1,3), extr32_cast128_256(s0,3) ); \
   casti_m256i( d,4 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7hi,0),    mm128_extr_32(s6hi,0), \
                           mm128_extr_32(s5hi,0),    mm128_extr_32(s4hi,0), \
                           mm128_extr_32(s3hi,0),    mm128_extr_32(s2hi,0), \
                           mm128_extr_32(s1hi,0),    mm128_extr_32(s0hi,0) ); \
   casti_m256i( d,5 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7hi,1),    mm128_extr_32(s6hi,1), \
                           mm128_extr_32(s5hi,1),    mm128_extr_32(s4hi,1), \
                           mm128_extr_32(s3hi,1),    mm128_extr_32(s2hi,1), \
                           mm128_extr_32(s1hi,1),    mm128_extr_32(s0hi,1) ); \
   casti_m256i( d,6 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7hi,2),    mm128_extr_32(s6hi,2), \
                           mm128_extr_32(s5hi,2),    mm128_extr_32(s4hi,2), \
                           mm128_extr_32(s3hi,2),    mm128_extr_32(s2hi,2), \
                           mm128_extr_32(s1hi,2),    mm128_extr_32(s0hi,2) ); \
   casti_m256i( d,7 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7hi,3),    mm128_extr_32(s6hi,3), \
                           mm128_extr_32(s5hi,3),    mm128_extr_32(s4hi,3), \
                           mm128_extr_32(s3hi,3),    mm128_extr_32(s2hi,3), \
                           mm128_extr_32(s1hi,3),    mm128_extr_32(s0hi,3) ); \
} while(0)

#define mm256_intrlv_8x32_128( d, s0, s1, s2, s3, s4, s5, s6, s7 ) \
{ \
   casti_m256i( d,0 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7,0), mm128_extr_32(s6,0), \
                           mm128_extr_32(s5,0), mm128_extr_32(s4,0), \
                           mm128_extr_32(s3,0), mm128_extr_32(s2,0), \
                           mm128_extr_32(s1,0), mm128_extr_32(s0,0) ); \
   casti_m256i( d,1 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7,1), mm128_extr_32(s6,1), \
                           mm128_extr_32(s5,1), mm128_extr_32(s4,1), \
                           mm128_extr_32(s3,1), mm128_extr_32(s2,1), \
                           mm128_extr_32(s1,1), mm128_extr_32(s0,1) ); \
   casti_m256i( d,2 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7,2), mm128_extr_32(s6,2), \
                           mm128_extr_32(s5,2), mm128_extr_32(s4,2), \
                           mm128_extr_32(s3,2), mm128_extr_32(s2,2), \
                           mm128_extr_32(s1,2), mm128_extr_32(s0,2) ); \
   casti_m256i( d,3 ) = _mm256_set_epi32( \
                           mm128_extr_32(s7,3), mm128_extr_32(s6,3), \
                           mm128_extr_32(s5,3), mm128_extr_32(s4,3), \
                           mm128_extr_32(s3,3), mm128_extr_32(s2,3), \
                           mm128_extr_32(s1,3), mm128_extr_32(s0,3) ); \
} while(0)

/*
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
*/

#define mm256_dintrlv_8x32_256( d0, d1, d2, d3, d4, d5, d6, d7, s ) \
do { \
  __m256i s0 = casti_m256i(s,0); \
  __m256i s1 = casti_m256i(s,1); \
  __m256i s2 = casti_m256i(s,2); \
  __m256i s3 = casti_m256i(s,3); \
  __m256i s4 = casti_m256i(s,4); \
  __m256i s5 = casti_m256i(s,5); \
  __m256i s6 = casti_m256i(s,6); \
  __m256i s7 = casti_m256i(s,7); \
  __m128i s0hi = _mm256_extracti128_si256( s0, 1 ); \
  __m128i s1hi = _mm256_extracti128_si256( s1, 1 ); \
  __m128i s2hi = _mm256_extracti128_si256( s2, 1 ); \
  __m128i s3hi = _mm256_extracti128_si256( s3, 1 ); \
  __m128i s4hi = _mm256_extracti128_si256( s4, 1 ); \
  __m128i s5hi = _mm256_extracti128_si256( s5, 1 ); \
  __m128i s6hi = _mm256_extracti128_si256( s6, 1 ); \
  __m128i s7hi = _mm256_extracti128_si256( s7, 1 ); \
   d0 = _mm256_set_epi32( \
              extr32_cast128_256( s7, 0 ), extr32_cast128_256( s6, 0 ), \
              extr32_cast128_256( s5, 0 ), extr32_cast128_256( s4, 0 ), \
              extr32_cast128_256( s3, 0 ), extr32_cast128_256( s2, 0 ), \
              extr32_cast128_256( s1, 0 ), extr32_cast128_256( s0, 0 ) );\
   d1 = _mm256_set_epi32( \
              extr32_cast128_256( s7, 1 ), extr32_cast128_256( s6, 1 ), \
              extr32_cast128_256( s5, 1 ), extr32_cast128_256( s4, 1 ), \
              extr32_cast128_256( s3, 1 ), extr32_cast128_256( s2, 1 ), \
              extr32_cast128_256( s1, 1 ), extr32_cast128_256( s0, 1 ) );\
   d2 = _mm256_set_epi32( \
              extr32_cast128_256( s7, 2 ), extr32_cast128_256( s6, 2 ), \
              extr32_cast128_256( s5, 2 ), extr32_cast128_256( s4, 2 ), \
              extr32_cast128_256( s3, 2 ), extr32_cast128_256( s2, 2 ), \
              extr32_cast128_256( s1, 2 ), extr32_cast128_256( s0, 2 ) );\
   d3 = _mm256_set_epi32( \
              extr32_cast128_256( s7, 3 ), extr32_cast128_256( s6, 3 ), \
              extr32_cast128_256( s5, 3 ), extr32_cast128_256( s4, 3 ), \
              extr32_cast128_256( s3, 3 ), extr32_cast128_256( s2, 3 ), \
              extr32_cast128_256( s1, 3 ), extr32_cast128_256( s0, 3 ) );\
   d4 = _mm256_set_epi32( \
              _mm_extract_epi32( s7hi, 0 ), _mm_extract_epi32( s6hi, 0 ), \
              _mm_extract_epi32( s5hi, 0 ), _mm_extract_epi32( s4hi, 0 ), \
              _mm_extract_epi32( s3hi, 0 ), _mm_extract_epi32( s2hi, 0 ), \
              _mm_extract_epi32( s1hi, 0 ), _mm_extract_epi32( s0hi, 0 ) ); \
   d5 = _mm256_set_epi32( \
              _mm_extract_epi32( s7hi, 1 ), _mm_extract_epi32( s6hi, 1 ), \
              _mm_extract_epi32( s5hi, 1 ), _mm_extract_epi32( s4hi, 1 ), \
              _mm_extract_epi32( s3hi, 1 ), _mm_extract_epi32( s2hi, 1 ), \
              _mm_extract_epi32( s1hi, 1 ), _mm_extract_epi32( s0hi, 1 ) ); \
   d6 = _mm256_set_epi32( \
              _mm_extract_epi32( s7hi, 2 ), _mm_extract_epi32( s6hi, 2 ), \
              _mm_extract_epi32( s5hi, 2 ), _mm_extract_epi32( s4hi, 2 ), \
              _mm_extract_epi32( s3hi, 2 ), _mm_extract_epi32( s2hi, 2 ), \
              _mm_extract_epi32( s1hi, 2 ), _mm_extract_epi32( s0hi, 2 ) ); \
   d7 = _mm256_set_epi32( \
              _mm_extract_epi32( s7hi, 3 ), _mm_extract_epi32( s6hi, 3 ), \
              _mm_extract_epi32( s5hi, 3 ), _mm_extract_epi32( s4hi, 3 ), \
              _mm_extract_epi32( s3hi, 3 ), _mm_extract_epi32( s2hi, 3 ), \
              _mm_extract_epi32( s1hi, 3 ), _mm_extract_epi32( s0hi, 3 ) ); \
} while(0)

#define mm128_dintrlv_8x32_128( d0, d1, d2, d3, d4, d5, d6, d7, s ) \
do { \
   __m128i s0 = casti_m128i(s,0); \
   __m128i s1 = casti_m128i(s,1); \
   __m128i s2 = casti_m128i(s,2); \
   __m128i s3 = casti_m128i(s,3); \
   d0 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 0 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 0 ), _mm_extract_epi32( s0, 0 ) ); \
   d1 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 1 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 1 ), _mm_extract_epi32( s0, 0 ) ); \
   d2 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 0 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 0 ), _mm_extract_epi32( s0, 0 ) ); \
   d3 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 0 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 0 ), _mm_extract_epi32( s0, 0 ) ); \
   d4 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 0 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 0 ), _mm_extract_epi32( s0, 0 ) ); \
   d5 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 0 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 0 ), _mm_extract_epi32( s0, 0 ) ); \
   d6 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 0 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 0 ), _mm_extract_epi32( s0, 0 ) ); \
   d7 = _mm_set_epi32( \
              _mm_extract_epi32( s3, 0 ), _mm_extract_epi32( s2, 0 ), \
              _mm_extract_epi32( s1, 0 ), _mm_extract_epi32( s0, 0 ) ); \
} while(0)

#define mm256_intrlv_4x64_256( d, s0, s1, s2, s3 ) \
do { \
  __m128i s0hi = _mm256_extracti128_si256( s0, 1 ); \
  __m128i s1hi = _mm256_extracti128_si256( s1, 1 ); \
  __m128i s2hi = _mm256_extracti128_si256( s2, 1 ); \
  __m128i s3hi = _mm256_extracti128_si256( s3, 1 ); \
  casti_m256i( d,0 ) = _mm256_set_epi64x( \
                extr64_cast128_256( s3, 0 ), extr64_cast128_256( s2, 0 ), \
                extr64_cast128_256( s1, 0 ), extr64_cast128_256( s0, 0 ) ); \
  casti_m256i( d,1 ) = _mm256_set_epi64x( \
                extr64_cast128_256( s3, 1 ), extr64_cast128_256( s2, 1 ), \
                extr64_cast128_256( s1, 1 ), extr64_cast128_256( s0, 1 ) ); \
  casti_m256i( d,2 ) = _mm256_set_epi64x( \
                  _mm_extract_epi64( s3hi,0 ), _mm_extract_epi64( s2hi,0 ), \
                  _mm_extract_epi64( s1hi,0 ), _mm_extract_epi64( s0hi,0 ) ); \
  casti_m256i( d,3 ) = _mm256_set_epi64x( \
                  _mm_extract_epi64( s3hi,1 ), _mm_extract_epi64( s2hi,1 ), \
                  _mm_extract_epi64( s1hi,1 ), _mm_extract_epi64( s0hi,1 ) ); \
} while(0)

#define mm256_intrlv_4x64_128( d, s0, s1, s2, s3 ) \
do { \
  casti_m256i( d,0 ) = _mm256_set_epi64x( \
                  _mm_extract_epi64( s3, 0 ), _mm_extract_epi64( s2, 0 ), \
                  _mm_extract_epi64( s1, 0 ), _mm_extract_epi64( s0, 0 ) ); \
  casti_m256i( d,1 ) = _mm256_set_epi64x( \
                  _mm_extract_epi64( s3, 1 ), _mm_extract_epi64( s2, 1 ), \
                  _mm_extract_epi64( s1, 1 ), _mm_extract_epi64( s0, 1 ) ); \
} while(0)

/*
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
*/

// 4 lanes of 256 bits using 64 bit interleaving (standard final hash size)
static inline void mm256_dintrlv_4x64_256( void *d0, void *d1, void *d2,
                            void *d3, const int n, const void *src )
{
   __m256i s0   = *( (__m256i*) src     );            // s[0][1:0]
   __m256i s1   = *( (__m256i*)(src+32) );            // s[1][1:0]
   __m256i s2   = *( (__m256i*)(src+64) );            // s[2][1:0]
   __m256i s3   = *( (__m256i*)(src+96) );            // s[3][2:0]
   __m128i s0hi = _mm256_extracti128_si256( s0, 1 );  // s[0][3:2]
   __m128i s1hi = _mm256_extracti128_si256( s1, 1 );  // s[1][3:2]
   __m128i s2hi = _mm256_extracti128_si256( s2, 1 );  // s[2][3:2]
   __m128i s3hi = _mm256_extracti128_si256( s3, 1 );  // s[3][3:2]

   casti_m256i( d0,n ) = _mm256_set_epi64x(
              extr64_cast128_256( s3, 0 ), extr64_cast128_256( s2, 0 ),
              extr64_cast128_256( s1, 0 ), extr64_cast128_256( s0, 0 ) );
   casti_m256i( d1,n ) = _mm256_set_epi64x(
              extr64_cast128_256( s3, 1 ), extr64_cast128_256( s2, 1 ),
              extr64_cast128_256( s1, 1 ), extr64_cast128_256( s0, 1 ) );
   casti_m256i( d2,n ) = _mm256_set_epi64x(
              _mm_extract_epi64( s3hi, 0 ), _mm_extract_epi64( s2hi, 0 ),
              _mm_extract_epi64( s1hi, 0 ), _mm_extract_epi64( s0hi, 0 ) );
   casti_m256i( d3,n ) = _mm256_set_epi64x(
              _mm_extract_epi64( s3hi, 1 ), _mm_extract_epi64( s2hi, 1 ),
              _mm_extract_epi64( s1hi, 1 ), _mm_extract_epi64( s0hi, 1 ) );
}


// quarter avx2 block, 16 bytes * 4 lanes
// 4 lanes of 128 bits using 64 bit interleaving
// Used for last 16 bytes of 80 byte input, only used for testing.
static inline void mm128_dintrlv_4x64_128( void *d0, void *d1, void *d2,
                                  void *d3, const int n, const void *src )
{
  __m256i s0 = *( (__m256i*) src     );
  __m256i s1 = *( (__m256i*)(src+32) );
  __m128i s0hi = _mm256_extracti128_si256( s0, 1 );
  __m128i s1hi = _mm256_extracti128_si256( s1, 1 );

  casti_m128i( d0,n ) = _mm_set_epi64x( extr64_cast128_256( s1  , 0 ),
                                        extr64_cast128_256( s0  , 0 ) );
  casti_m128i( d1,n ) = _mm_set_epi64x( extr64_cast128_256( s1  , 1 ),
                                        extr64_cast128_256( s0  , 1 ) );
  casti_m128i( d2,n ) = _mm_set_epi64x( _mm_extract_epi64(    s1hi, 0 ),
                                        _mm_extract_epi64(    s0hi, 0 ) );
  casti_m128i( d3,n ) = _mm_set_epi64x( _mm_extract_epi64(    s1hi, 1 ),
                                        _mm_extract_epi64(    s0hi, 1 ) );
}

/*
static inline void mm256_dintrlv_2x128x256( void *d0, void *d1,
                                                 const int n, const void *s )
{
   casti_m256i( d0,n ) = mm256_get_64( s, 0, 1, 4, 5 );
   casti_m256i( d1,n ) = mm256_get_64( s, 2, 3, 6, 7 );
}
*/
//

#define mm256_intrlv_4x32_256( d, s0, s1, s2, s3 ) \
do { \
   casti_m256i( d,0 ) = _mm256_set_epi32( \
                            mm128_extr_32( s3, 1 ), mm128_extr_32( s2, 1 ), \
                            mm128_extr_32( s1, 1 ), mm128_extr_32( s0, 1 ), \
                            mm128_extr_32( s3, 0 ), mm128_extr_32( s2, 0 ), \
                            mm128_extr_32( s1, 0 ), mm128_extr_32( s0, 0 ) ); \
   casti_m256i( d,1 ) = _mm256_set_epi32( \
                            mm128_extr_32( s3, 3 ), mm128_extr_32( s2, 3 ), \
                            mm128_extr_32( s1, 3 ), mm128_extr_32( s0, 3 ), \
                            mm128_extr_32( s3, 2 ), mm128_extr_32( s2, 2 ), \
                            mm128_extr_32( s1, 2 ), mm128_extr_32( s0, 2 ) ); \
   casti_m256i( d,2 ) = _mm256_set_epi32( \
                            mm128_extr_32( s3, 5 ), mm128_extr_32( s2, 5 ), \
                            mm128_extr_32( s1, 5 ), mm128_extr_32( s0, 5 ), \
                            mm128_extr_32( s3, 4 ), mm128_extr_32( s2, 4 ), \
                            mm128_extr_32( s1, 4 ), mm128_extr_32( s0, 4 ) ); \
   casti_m256i( d,3 ) = _mm256_set_epi32( \
                            mm128_extr_32( s3, 7 ), mm128_extr_32( s2, 7 ), \
                            mm128_extr_32( s1, 7 ), mm128_extr_32( s0, 7 ), \
                            mm128_extr_32( s3, 6 ), mm128_extr_32( s2, 6 ), \
                            mm128_extr_32( s1, 6 ), mm128_extr_32( s0, 6 ) ); \
} while(0)

// 256 bit versions of commmon 128 bit functions.
static inline void mm256_intrlv_4x32( void *d, const void *s0,
               const void *s1, const void *s2, const void *s3, int bit_len )
{
   mm256_intrlv_4x32_256( d     ,casti_m256i(s0,0), casti_m256i(s1,0),
                                 casti_m256i(s2,0), casti_m256i(s3,0) );
   if ( bit_len <= 256 ) return;
   mm256_intrlv_4x32_256( d+128 ,casti_m256i(s0,1), casti_m256i(s1,1),
                                 casti_m256i(s2,1), casti_m256i(s3,1) );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      mm128_intrlv_4x32_128( d+256, casti_m128i(s0,4), casti_m128i(s1,4),
                                    casti_m128i(s2,4), casti_m128i(s3,4) );
      return;
   }
   mm256_intrlv_4x32_256( d+256 ,casti_m256i(s0,2), casti_m256i(s1,2),
                                 casti_m256i(s2,2), casti_m256i(s3,2) );
   mm256_intrlv_4x32_256( d+384 ,casti_m256i(s0,3), casti_m256i(s1,3),
                                 casti_m256i(s2,3), casti_m256i(s3,3) );
}

static inline void mm256_dintrlv_4x32_256( void *d0, void *d1, void *d2,
                                           void *d3, const void *src )
{
   __m256i s0 = *(__m256i*) src;
   __m256i s1 = *(__m256i*)(src+32);
   __m256i s2 = *(__m256i*)(src+64);
   __m256i s3 = *(__m256i*)(src+96);
   *(__m256i*)d0 = _mm256_set_epi32(
                  _mm256_extract_epi32( s3,4 ), _mm256_extract_epi32( s3,0 ),
                  _mm256_extract_epi32( s2,4 ), _mm256_extract_epi32( s2,0 ),
                  _mm256_extract_epi32( s1,4 ), _mm256_extract_epi32( s1,0 ),
                  _mm256_extract_epi32( s0,4 ), _mm256_extract_epi32( s0,0 ) );
   *(__m256i*)d1 = _mm256_set_epi32(
                  _mm256_extract_epi32( s3,5 ), _mm256_extract_epi32( s3,1 ),
                  _mm256_extract_epi32( s2,5 ), _mm256_extract_epi32( s2,1 ),
                  _mm256_extract_epi32( s1,5 ), _mm256_extract_epi32( s1,1 ),
                  _mm256_extract_epi32( s0,5 ), _mm256_extract_epi32( s0,1 ) );
   *(__m256i*)d2 = _mm256_set_epi32(
                  _mm256_extract_epi32( s3,6 ), _mm256_extract_epi32( s3,2 ),
                  _mm256_extract_epi32( s2,6 ), _mm256_extract_epi32( s2,2 ),
                  _mm256_extract_epi32( s1,6 ), _mm256_extract_epi32( s1,2 ),
                  _mm256_extract_epi32( s0,6 ), _mm256_extract_epi32( s0,2 ) );
   *(__m256i*)d3 = _mm256_set_epi32(
                  _mm256_extract_epi32( s3,7 ), _mm256_extract_epi32( s3,3 ),
                  _mm256_extract_epi32( s2,7 ), _mm256_extract_epi32( s2,3 ),
                  _mm256_extract_epi32( s1,7 ), _mm256_extract_epi32( s1,3 ),
                  _mm256_extract_epi32( s0,7 ), _mm256_extract_epi32( s0,3 ) );
}

static inline void mm256_dintrlv_4x32( void *d0, void *d1, void *d2,
                                       void *d3, const void *s, int bit_len )
{
   mm256_dintrlv_4x32_256( d0    , d1    , d2    , d3    , s     );
   if ( bit_len <= 256 ) return;
   mm256_dintrlv_4x32_256( d0+ 32, d1+ 32, d2+ 32, d3+ 32, s+128 );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      mm128_dintrlv_4x32_128( d0+ 64, d1+ 64, d2+ 64, d3+ 64, s+256 );
      return;
   }
   mm256_dintrlv_4x32_256( d0+ 64, d1+ 64, d2+ 64, d3+ 64, s+256 );
   mm256_dintrlv_4x32_256( d0+ 96, d1+ 96, d2+ 96, d3+ 96, s+384 );
}

static inline void mm256_extr_lane_4x32( void *d, const void *s,
                                         const int lane, const int bit_len )
{
  casti_m256i( d, 0 ) = mm256_get_32( s, lane   , lane+ 4, lane+ 8, lane+12,
                                         lane+16, lane+20, lane+24, lane+28 );
  if ( bit_len <= 256 ) return;
  casti_m256i( d, 1 ) = mm256_get_32( s, lane+32, lane+36, lane+40, lane+44,
                                         lane+48, lane+52, lane+56, lane+60 );
}

// Interleave 8 source buffers containing 32 bit data into the destination
// vector
static inline void mm256_intrlv_8x32( void *d, const void *s0,
        const void *s1, const void *s2, const void *s3, const void *s4,
        const void *s5, const void *s6, const void *s7, int bit_len )
{
   mm256_intrlv_8x32_256( d    , casti_m256i( s0,0 ), casti_m256i( s1,0 ),
            casti_m256i( s2,0 ), casti_m256i( s3,0 ), casti_m256i( s4,0 ),
            casti_m256i( s5,0 ), casti_m256i( s6,0 ), casti_m256i( s7,0 ) );
   if ( bit_len <= 256 ) return;
   mm256_intrlv_8x32_256( d+256, casti_m256i( s0,1 ), casti_m256i( s1,1 ), 
            casti_m256i( s2,1 ), casti_m256i( s3,1 ), casti_m256i( s4,1 ),
            casti_m256i( s5,1 ), casti_m256i( s6,1 ), casti_m256i( s7,1 ) );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      mm256_intrlv_8x32_128( d+512, casti_m128i( s0,4 ), casti_m128i( s1,4 ),
               casti_m128i( s2,4 ), casti_m128i( s3,4 ), casti_m128i( s4,4 ),
               casti_m128i( s5,4 ), casti_m128i( s6,4 ), casti_m128i( s7,4 ) );
      return;
   }
   mm256_intrlv_8x32_256( d+512, casti_m256i( s0,2 ), casti_m256i( s1,2 ), 
            casti_m256i( s2,2 ), casti_m256i( s3,2 ), casti_m256i( s4,2 ),
            casti_m256i( s5,2 ), casti_m256i( s6,2 ), casti_m256i( s7,2 ) );
   mm256_intrlv_8x32_256( d+768, casti_m256i( s0,3 ), casti_m256i( s1,3 ), 
            casti_m256i( s2,3 ), casti_m256i( s3,3 ), casti_m256i( s4,3 ),
            casti_m256i( s5,3 ), casti_m256i( s6,3 ), casti_m256i( s7,3 ) );
   // bit_len == 1024
}

// A couple of mining specifi functions.
/*
// Interleave 80 bytes of 32 bit data for 8 lanes.
static inline void mm256_bswap_intrlv80_8x32( void *d, const void *s )
{
   mm256_bswap_intrlv_8x32_256( d    , casti_m256i( s, 0 ) );
   mm256_bswap_intrlv_8x32_256( d+256, casti_m256i( s, 1 ) );
   mm256_bswap_intrlv_8x32_128( d+512, casti_m128i( s, 4 ) );
}
*/

// Deinterleave 8 buffers of 32 bit data from the source buffer.
// Sub-function can be called directly for 32 byte final hash.
static inline void mm256_dintrlv_8x32( void *d0, void *d1, void *d2,
                        void *d3, void *d4, void *d5, void *d6, void *d7,
                        const void *s, int bit_len )
{
   mm256_dintrlv_8x32_256( casti_m256i(d0,0), casti_m256i(d1,0),
        casti_m256i(d2,0), casti_m256i(d3,0), casti_m256i(d4,0),
        casti_m256i(d5,0), casti_m256i(d6,0), casti_m256i(d7,0), s );
   if ( bit_len <= 256 ) return;
   mm256_dintrlv_8x32_256( casti_m256i(d0,1), casti_m256i(d1,1), 
        casti_m256i(d2,1), casti_m256i(d3,1), casti_m256i(d4,1),
        casti_m256i(d5,1), casti_m256i(d6,1), casti_m256i(d7,1), s+256 );
   if ( bit_len <= 512 ) return;
   // short block, final 16 bytes of input data
   if ( bit_len <= 640 )
   {
      mm128_dintrlv_8x32_128( casti_m128i(d0,2), casti_m128i(d1,2), 
           casti_m128i(d2,2), casti_m128i(d3,2), casti_m128i(d4,2),
           casti_m128i(d5,2), casti_m128i(d6,2), casti_m128i(d7,2), s+512 );
      return;
   }
   // bitlen == 1024
   mm256_dintrlv_8x32_256( casti_m256i(d0,2), casti_m256i(d1,2), 
        casti_m256i(d2,2), casti_m256i(d3,2), casti_m256i(d4,2),
        casti_m256i(d5,2), casti_m256i(d6,2), casti_m256i(d7,2), s+512 );
   mm256_dintrlv_8x32_256( casti_m256i(d0,3), casti_m256i(d1,3), 
        casti_m256i(d2,3), casti_m256i(d3,3), casti_m256i(d4,3),
        casti_m256i(d5,3), casti_m256i(d6,3), casti_m256i(d7,3), s+768 );
}

static inline void mm256_extr_lane_8x32( void *d, const void *s,
                                            const int lane, const int bit_len )
{
  casti_m256i( d,0 ) = mm256_get_32(s, lane   , lane+  8, lane+ 16, lane+ 24,
                                       lane+32, lane+ 40, lane+ 48, lane+ 56 );
  if ( bit_len <= 256 ) return;
  casti_m256i( d,1 ) = mm256_get_32(s, lane+64, lane+ 72, lane+ 80, lane+ 88,
                                       lane+96, lane+104, lane+112, lane+120 );
  // bit_len == 512
}

// Interleave 4 source buffers containing 64 bit data into the destination
// buffer. Only bit_len 256, 512, 640 & 1024 are supported.
static inline void mm256_intrlv_4x64( void *d, const void *s0,
            const void *s1, const void *s2, const void *s3, int bit_len )
{
  mm256_intrlv_4x64_256( d    , casti_m256i(s0,0), casti_m256i(s1,0),
                                casti_m256i(s2,0), casti_m256i(s3,0) );
  if ( bit_len <= 256 ) return;
  mm256_intrlv_4x64_256( d+128, casti_m256i(s0,1), casti_m256i(s1,1),
                                casti_m256i(s2,1), casti_m256i(s3,1) );
  if ( bit_len <= 512 ) return;
  if ( bit_len <= 640 )
  {
    mm256_intrlv_4x64_128( d+256, casti_m128i(s0,4), casti_m128i(s1,4),
                                  casti_m128i(s2,4), casti_m128i(s3,4) );
    return;
  }
  // bit_len == 1024
  mm256_intrlv_4x64_256( d+256, casti_m256i(s0,2), casti_m256i(s1,2),
                                casti_m256i(s2,2), casti_m256i(s3,2) );
  mm256_intrlv_4x64_256( d+384, casti_m256i(s0,3), casti_m256i(s1,3),
                                casti_m256i(s2,3), casti_m256i(s3,3) );
}
/*
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
*/

// Deinterleave 4 buffers of 64 bit data from the source buffer.
// bit_len must be 256, 512, 640 or 1024 bits.
// Requires overrun padding for 640 bit len.
static inline void mm256_dintrlv_4x64( void *d0, void *d1, void *d2,
                                    void *d3, const void *s, int bit_len )
{
   mm256_dintrlv_4x64_256( d0, d1, d2, d3, 0, s );
   if ( bit_len <= 256 ) return;
   mm256_dintrlv_4x64_256( d0, d1, d2, d3, 1, s+128 );
   if ( bit_len <= 512 ) return;
   // short block, final 16 bytes of input data
   if ( bit_len <= 640 )
   {
      mm128_dintrlv_4x64_128( d0, d1, d2, d3, 4, s+256 );
      return;
   }
   // bit_len == 1024
   mm256_dintrlv_4x64_256( d0, d1, d2, d3, 2, s+256 );
   mm256_dintrlv_4x64_256( d0, d1, d2, d3, 3, s+384 );
}

// extract and deinterleave specified lane.
#define mm256_extr_lane_4x64_256 \
      casti_m256i( d, 0 ) = mm256_get_64( s, lane, lane+4, lane+8, lane+12 )
static inline void mm256_extr_lane_4x64( void *d, const void *s,
                                            const int lane, const int bit_len )
{
  casti_m256i( d, 0 ) = mm256_get_64( s, lane, lane+4, lane+8, lane+12 );
  if ( bit_len <= 256 ) return;
  casti_m256i( d, 1 ) = mm256_get_64( s, lane+16, lane+20, lane+24, lane+28 );
  return;
}


// Convert from 4x32 SSE2 interleaving to 4x64 AVX2.
// Can't do it in place
static inline void mm256_rintrlv_4x32_4x64( void *dst, void *src,
                                            int  bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint32_t *s = (uint32_t*)src;

   d[0] = _mm256_set_epi32( s[ 7],s[ 3],s[ 6],s[ 2],s[ 5],s[ 1],s[ 4],s[ 0] );
   d[1] = _mm256_set_epi32( s[15],s[11],s[14],s[10],s[13],s[ 9],s[12],s[ 8] );
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

// Convert 4x64 byte (256 bit) vectors to 4x32 (128 bit) vectors for AVX
// bit_len must be multiple of 64
static inline void mm256_rintrlv_4x64_4x32( void *dst, void *src,
                                            int  bit_len )
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

static inline void mm256_rintrlv_4x64_2x128( void *dst0, void *dst1,
                                              const void *src, int  bit_len )
{
   __m256i* d0 = (__m256i*)dst0;
   __m256i* d1 = (__m256i*)dst1;
   uint64_t *s = (uint64_t*)src;

   d0[0] = _mm256_set_epi64x( s[ 5], s[ 1], s[ 4], s[ 0] );
   d1[0] = _mm256_set_epi64x( s[ 7], s[ 3], s[ 6], s[ 2] );

   d0[1] = _mm256_set_epi64x( s[13], s[ 9], s[12], s[ 8] );
   d1[1] = _mm256_set_epi64x( s[15], s[11], s[14], s[10] );

   if ( bit_len <= 256 ) return;

   d0[2] = _mm256_set_epi64x( s[21], s[17], s[20], s[16] );
   d1[2] = _mm256_set_epi64x( s[23], s[19], s[22], s[18] );

   d0[3] = _mm256_set_epi64x( s[29], s[25], s[28], s[24] );
   d1[3] = _mm256_set_epi64x( s[31], s[27], s[30], s[26] );

   if ( bit_len <= 512 ) return;

   d0[4] = _mm256_set_epi64x( s[37], s[33], s[36], s[32] );
   d1[4] = _mm256_set_epi64x( s[39], s[35], s[38], s[34] );

   d0[5] = _mm256_set_epi64x( s[45], s[41], s[44], s[40] );
   d1[5] = _mm256_set_epi64x( s[47], s[43], s[46], s[42] );

   d0[6] = _mm256_set_epi64x( s[53], s[49], s[52], s[48] );
   d1[6] = _mm256_set_epi64x( s[55], s[51], s[54], s[50] );

   d0[7] = _mm256_set_epi64x( s[61], s[57], s[60], s[56] );
   d1[7] = _mm256_set_epi64x( s[63], s[59], s[62], s[58] );
}

static inline void mm256_rintrlv_2x128_4x64( void *dst, const void *src0,
                                         const void *src1, int  bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;

   d[ 0] = _mm256_set_epi64x( s1[2], s1[0], s0[2], s0[0] );
   d[ 1] = _mm256_set_epi64x( s1[3], s1[1], s0[3], s0[1] );
   d[ 2] = _mm256_set_epi64x( s1[6], s1[4], s0[6], s0[4] );
   d[ 3] = _mm256_set_epi64x( s1[7], s1[5], s0[7], s0[5] );

   if ( bit_len <= 256 ) return;

   d[ 4] = _mm256_set_epi64x( s1[10], s1[ 8], s0[10], s0[ 8] );
   d[ 5] = _mm256_set_epi64x( s1[11], s1[ 9], s0[11], s0[ 9] );
   d[ 6] = _mm256_set_epi64x( s1[14], s1[12], s0[14], s0[12] );
   d[ 7] = _mm256_set_epi64x( s1[15], s1[13], s0[15], s0[13] );

   if ( bit_len <= 512 ) return;

   d[ 8] = _mm256_set_epi64x( s1[18], s1[16], s0[18], s0[16] );
   d[ 9] = _mm256_set_epi64x( s1[19], s1[17], s0[19], s0[17] );
   d[10] = _mm256_set_epi64x( s1[22], s1[20], s0[22], s0[20] );
   d[11] = _mm256_set_epi64x( s1[23], s1[21], s0[23], s0[21] );

   d[12] = _mm256_set_epi64x( s1[26], s1[24], s0[26], s0[24] );
   d[13] = _mm256_set_epi64x( s1[27], s1[25], s0[27], s0[25] );
   d[14] = _mm256_set_epi64x( s1[30], s1[28], s0[30], s0[28] );
   d[15] = _mm256_set_epi64x( s1[31], s1[29], s0[31], s0[29] );
}


static inline void mm256_intrlv_2x128( const void *d, const void *s0,
                                      void *s1, const int bit_len )
{
  __m128i s1hi = _mm256_extracti128_si256( casti_m256i( s1,0 ), 1 );
  __m128i s0hi = _mm256_extracti128_si256( casti_m256i( s0,0 ), 1 );
  casti_m256i( d,0 ) = mm256_concat_128(
                           _mm256_castsi256_si128( casti_m256i( s1,0 ) ),
                           _mm256_castsi256_si128( casti_m256i( s0,0 ) ) );
  casti_m256i( d,1 ) = mm256_concat_128( s1hi, s0hi );                  

  if ( bit_len <= 256 ) return;
  s0hi = _mm256_extracti128_si256( casti_m256i( s0,1 ), 1 );
  s1hi = _mm256_extracti128_si256( casti_m256i( s1,1 ), 1 );
  casti_m256i( d,2 ) = mm256_concat_128(
                           _mm256_castsi256_si128( casti_m256i( s1,1 ) ),
                           _mm256_castsi256_si128( casti_m256i( s0,1 ) ) );
  casti_m256i( d,3 ) = mm256_concat_128( s1hi, s0hi );        

  if ( bit_len <= 512 ) return;
  if ( bit_len <= 640 )
  {
     casti_m256i( d,4 ) = mm256_concat_128(
                           _mm256_castsi256_si128( casti_m256i( s1,2 ) ),
                           _mm256_castsi256_si128( casti_m256i( s0,2 ) ) );
     return;
  }

  s0hi = _mm256_extracti128_si256( casti_m256i( s0,2 ), 1 );
  s1hi = _mm256_extracti128_si256( casti_m256i( s1,2 ), 1 );
  casti_m256i( d,4 ) = mm256_concat_128(
                           _mm256_castsi256_si128( casti_m256i( s1,2 ) ),
                           _mm256_castsi256_si128( casti_m256i( s0,2 ) ) );
  casti_m256i( d,5 ) = mm256_concat_128( s1hi, s0hi );        

  s0hi = _mm256_extracti128_si256( casti_m256i( s0,3 ), 1 );
  s1hi = _mm256_extracti128_si256( casti_m256i( s1,3 ), 1 );
  casti_m256i( d,6 ) = mm256_concat_128(
                           _mm256_castsi256_si128( casti_m256i( s1,3 ) ),
                           _mm256_castsi256_si128( casti_m256i( s0,3 ) ) );
  casti_m256i( d,7 ) = mm256_concat_128( s1hi, s0hi );        
}

// 512 is the bit len used by most, eliminate the conditionals
static inline void mm256_dintrlv_2x128_512( void *dst0, void *dst1,
                                            const void *s )
{
   __m256i *d0 = (__m256i*)dst0;
   __m256i *d1 = (__m256i*)dst1;

   __m256i s0 = casti_m256i( s, 0 );
   __m256i s1 = casti_m256i( s, 1 );
   d0[0] = _mm256_permute2x128_si256( s0, s1, 0x20 );
   d1[0] = _mm256_permute2x128_si256( s0, s1, 0x31 );

   s0 = casti_m256i( s, 2 );
   s1 = casti_m256i( s, 3 );
   d0[1] = _mm256_permute2x128_si256( s0, s1, 0x20 );
   d1[1] = _mm256_permute2x128_si256( s0, s1, 0x31 );
}   

// Phase out usage for all 512 bit data lengths
static inline void mm256_dintrlv_2x128( void *dst0, void *dst1, const void *s,
                                             int bit_len )
{
   __m256i *d0 = (__m256i*)dst0;
   __m256i *d1 = (__m256i*)dst1;

   __m256i s0 = casti_m256i( s, 0 );
   __m256i s1 = casti_m256i( s, 1 );
   d0[0] = _mm256_permute2x128_si256( s0, s1, 0x20 );
   d1[0] = _mm256_permute2x128_si256( s0, s1, 0x31 );

   if ( bit_len <= 256 ) return;

   s0 = casti_m256i( s, 2 );
   s1 = casti_m256i( s, 3 );
   d0[1] = _mm256_permute2x128_si256( s0, s1, 0x20 );
   d1[1] = _mm256_permute2x128_si256( s0, s1, 0x31 );

   if ( bit_len <= 512 ) return;

   s0 = casti_m256i( s, 4 );
   s1 = casti_m256i( s, 5 );
   d0[2] = _mm256_permute2x128_si256( s0, s1, 0x20 );
   d1[2] = _mm256_permute2x128_si256( s0, s1, 0x31 );

   s0 = casti_m256i( s, 6 );
   s1 = casti_m256i( s, 7 );
   d0[3] = _mm256_permute2x128_si256( s0, s1, 0x20 );
   d1[3] = _mm256_permute2x128_si256( s0, s1, 0x31 );
}

#undef extr64_cast128_256
#undef extr32_cast128_256

#endif // AVX
#endif // INTRLV_AVX_H__
