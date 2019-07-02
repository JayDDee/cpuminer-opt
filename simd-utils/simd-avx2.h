#if !defined(SIMD_AVX2_H__)
#define SIMD_AVX2_H__ 1

#if defined(__AVX2__)

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


//
// Basic operations without SIMD equivalent

// Bitwise not ( ~x )
#define mm256_not( x )       _mm256_xor_si256( (x), m256_neg1 ) \

// Unary negation of each element ( -a )
#define mm256_negate_64( a ) _mm256_sub_epi64( m256_zero, a )
#define mm256_negate_32( a ) _mm256_sub_epi32( m256_zero, a )
#define mm256_negate_16( a ) _mm256_sub_epi16( m256_zero, a )

/***************************
 *
 * extracti128 (AVX2) vs extractf128 (AVX)???
 
 
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
#define mm128_extr_lo128_256( a ) _mm256_castsi256_si128( a )
#define mm128_extr_hi128_256( a ) _mm256_extracti128_si256( a, 1 )

// Extract 4 u64 from 256 bit vector.
#define mm256_extr_4x64( a0, a1, a2, a3, src ) \
do { \
  __m128i hi = _mm256_extracti128_si256( src, 1 ); \
  a0 = _mm_extract_epi64( _mm256_castsi256_si128( src ), 0 ); \
  a1 = _mm_extract_epi64( _mm256_castsi256_si128( src ), 1 ); \
  a2 = _mm_extract_epi64( hi, 0 ); \
  a3 = _mm_extract_epi64( hi, 1 ); \
} while(0)

#define mm256_extr_8x32( a0, a1, a2, a3, a4, a5, a6, a7, src ) \
do { \
  __m128i hi = _mm256_extracti128_si256( src, 1 ); \
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
#define mm256_ins_lo128_256( a, b )  _mm256_inserti128_si256( a, b, 0 )
#define mm256_ins_hi128_256( a, b )  _mm256_inserti128_si256( a, b, 1 )
*/

/*
// concatenate two 128 bit vectors into one 256 bit vector: { hi, lo }
#define mm256_concat_128( hi, lo ) \
   mm256_ins_hi128_256( _mm256_castsi128_si256( lo ), hi )

// Horizontal vector testing

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

*************************************/

//
//           Bit rotations.
//
// The only bit shift for more than 64 bits is with __int128.
//
// AVX512 has bit rotate for 256 bit vectors with 64 or 32 bit elements
// but is of little value

//
// Rotate each element of v by c bits
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

//
// Rotate elements accross all lanes.
//
// AVX2 has no full vector permute for elements less than 32 bits.
// AVX512 has finer granularity full vector permutes.

// Swap 128 bit elements in 256 bit vector.
#define mm256_swap_128( v )     _mm256_permute4x64_epi64( v, 0x4e )

// Rotate 256 bit vector by one 64 bit element
#define mm256_ror_1x64( v )     _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_rol_1x64( v )     _mm256_permute4x64_epi64( v, 0x93 )

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

//
// Rotate elements within lanes of 256 bit vector.

// Swap 64 bit elements in each 128 bit lane.
#define mm256_swap64_128( v )   _mm256_shuffle_epi32( v, 0x4e )

// Rotate each 128 bit lane by one 32 bit element.
#define mm256_ror1x32_128( v )  _mm256_shuffle_epi32( v, 0x39 )
#define mm256_rol1x32_128( v )  _mm256_shuffle_epi32( v, 0x93 )

// Rotate each 128 bit lane by one 16 bit element.
#define mm256_rol1x16_128( v ) \
         _mm256_shuffle_epi8( 13,12,11,10, 9,8,7,6, 5,4,3,2, 1,0,15,14 )
#define mm256_ror1x16_128( v ) \
        _mm256_shuffle_epi8( 1,0,15,14, 13,12,11,10, 9,8,7,6, 5,4,3,2 )

// Rotate each 128 bit lane by one byte
#define mm256_rol1x8_128( v ) \
        _mm256_shuffle_epi8( 14, 13,12,11, 10,9,8,7, 6,5,4,3, 2,1,0,15 )
#define mm256_ror1x8_128( v ) \
        _mm256_shuffle_epi8( 0,15,14,13, 12,11,10,9, 8,7,6,5, 4,3,2,1 )

// Rotate each 128 bit lane by c bytes.
#define mm256_bror_128( v, c ) \
  _mm256_or_si256( _mm256_bsrli_epi128( v, c ), \
                   _mm256_bslli_epi128( v, 16-(c) ) )
#define mm256_brol_128( v, c ) \
  _mm256_or_si256( _mm256_bslli_epi128( v, c ), \
                   _mm256_bsrli_epi128( v, 16-(c) ) )

// Swap 32 bit elements in each 64 bit lane
#define mm256_swap32_64( v )    _mm256_shuffle_epi32( v, 0xb1 )

#define mm256_ror16_64( v ) \
      _mm256_shuffle_epi8(  9, 8,15,14,13,12,11,10,  1, 0, 7, 6, 5, 4, 3, 2 );
#define mm256_rol16_64( v ) \
      _mm256_shuffle_epi8( 13,12,11,10, 9, 8,15,14,  5, 4, 3, 2, 1, 0, 7, 6 );


// Swap 16 bit elements in each 32 bit lane
#define mm256_swap16_32( v )  _mm256_shuffle_epi8( v, \
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

#define mm256_swap256_512 (v1, v2) \
   v1 = _mm256_xor_si256(v1, v2); \
   v2 = _mm256_xor_si256(v1, v2); \
   v1 = _mm256_xor_si256(v1, v2);

#define mm256_ror1x128_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 16 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 16 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x128_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 16 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 16 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x64_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 8 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 8 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x64_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 24 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 24 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x32_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 4 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 4 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x32_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 28 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 28 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x16_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 2 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x16_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 30 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 30 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x8_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 1 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x8_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 31 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 31 ); \
   v1 = t; \
} while(0)

#endif // __AVX2__
#endif // SIMD_AVX2_H__

