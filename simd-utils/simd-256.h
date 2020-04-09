#if !defined(SIMD_256_H__)
#define SIMD_256_H__ 1

#if defined(__AVX2__)

/////////////////////////////////////////////////////////////////////
//
//             AVX2 256 bit vectors
//
// Basic support for 256 bit vectors is available with AVX but integer
// support requires AVX2.
// Some 256 bit vector utilities require AVX512 or have more efficient
// AVX512 implementations. They will be selected automatically but their use
// is limited because 256 bit vectors are less likely to be used when 512
// is available.

// Move integer to low element of vector, other elements are set to zero.

#define mm256_mov64_256( n ) _mm256_castsi128_si256( mm128_mov64_128( n ) )
#define mm256_mov32_256( n ) _mm256_castsi128_si256( mm128_mov32_128( n ) )

#define mm256_mov256_64( a ) mm128_mov128_64( _mm256_castsi256_si128( a ) )
#define mm256_mov256_32( a ) mm128_mov128_32( _mm256_castsi256_si128( a ) )

// concatenate two 128 bit vectors into one 256 bit vector: { hi, lo }
#define mm256_concat_128( hi, lo ) \
   _mm256_inserti128_si256( _mm256_castsi128_si256( lo ), hi, 1 )

#define m256_const1_128( v ) \
         _mm256_broadcastsi128_si256( v )

// Equavalent of set, move 64 bit integer constants to respective 64 bit
// elements.
static inline __m256i m256_const_64( const uint64_t i3, const uint64_t i2,
                                     const uint64_t i1, const uint64_t i0 )
{
    __m128i hi, lo;
   lo = mm128_mov64_128( i0 );
   hi = mm128_mov64_128( i2 );
   lo = _mm_insert_epi64( lo, i1, 1 );
   hi = _mm_insert_epi64( hi, i3, 1 );
   return mm256_concat_128( hi, lo );
}

// Equivalent of set1, broadcast integer constant to all elements.
#define m256_const1_128( v ) _mm256_broadcastsi128_si256( v )
#define m256_const1_64( i )  _mm256_broadcastq_epi64( mm128_mov64_128( i ) )
#define m256_const1_32( i )  _mm256_broadcastd_epi32( mm128_mov32_128( i ) )
#define m256_const1_16( i )  _mm256_broadcastw_epi16( mm128_mov32_128( i ) )
#define m256_const1_8 ( i )  _mm256_broadcastb_epi8 ( mm128_mov32_128( i ) )

#define m256_const2_64( i1, i0 ) \
  m256_const1_128( m128_const_64( i1, i0 ) )

#define m126_const2_32( i1, i0 ) \
   m256_const1_64( ( (uint64_t)(i1) << 32 ) | ( (uint64_t)(i0) & 0xffffffff ) ) 


//
// All SIMD constant macros are actually functions containing executable
// code and therefore can't be used as compile time initializers.

#define m256_zero       _mm256_setzero_si256()
#define m256_one_256    mm256_mov64_256( 1 )
#define m256_one_128 \
    _mm256_permute4x64_epi64( _mm256_castsi128_si256( \
                               mm128_mov64_128( 1 ) ), 0x44 )
#define m256_one_64     _mm256_broadcastq_epi64( mm128_mov64_128( 1 ) )
#define m256_one_32     _mm256_broadcastd_epi32( mm128_mov64_128( 1 ) )
#define m256_one_16     _mm256_broadcastw_epi16( mm128_mov64_128( 1 ) )
#define m256_one_8      _mm256_broadcastb_epi8 ( mm128_mov64_128( 1 ) )

static inline __m256i mm256_neg1_fn()
{
   __m256i a;
   asm( "vpcmpeqq %0, %0, %0\n\t" : "=x"(a) );
   return a;
}
#define m256_neg1  mm256_neg1_fn()


//
// Vector size conversion.
//
// Allows operations on either or both halves of a 256 bit vector serially.
// Handy for parallel AES.
// Caveats when writing:
//      _mm256_castsi256_si128 is free and without side effects.
//      _mm256_castsi128_si256 is also free but leaves the high half
//      undefined. That's ok if the hi half will be subseqnently assigned.
//      If assigning both, do lo first, If assigning only 1, use
//      _mm256_inserti128_si256.
//
#define mm128_extr_lo128_256( a ) _mm256_castsi256_si128( a )
#define mm128_extr_hi128_256( a ) _mm256_extracti128_si256( a, 1 )

// Extract integers from 256 bit vector, ineficient, avoid if possible..
#define mm256_extr_4x64( a3, a2, a1, a0, src ) \
do { \
  __m128i hi = _mm256_extracti128_si256( src, 1 ); \
  a0 = mm128_mov128_64( _mm256_castsi256_si128( src) ); \
  a1 = _mm_extract_epi64( _mm256_castsi256_si128( src ), 1 ); \
  a2 = mm128_mov128_64( hi ); \
  a3 = _mm_extract_epi64( hi, 1 ); \
} while(0)

#define mm256_extr_8x32( a7, a6, a5, a4, a3, a2, a1, a0, src ) \
do { \
  uint64_t t = _mm_extract_epi64( _mm256_castsi256_si128( src ), 1 ); \
  __m128i hi = _mm256_extracti128_si256( src, 1 ); \
  a0 = mm256_mov256_32( src ); \
  a1 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 1 ); \
  a2 = (uint32_t)( t ); \
  a3 = (uint32_t)( t<<32 ); \
  t = _mm_extract_epi64(  hi, 1 ); \
  a4 = mm128_mov128_32( hi ); \
  a5 = _mm_extract_epi32( hi, 1 ); \
  a6 = (uint32_t)( t ); \
  a7 = (uint32_t)( t<<32 ); \
} while(0)


// Bytewise test of all 256 bits
#define mm256_all0_8( a ) \
     ( _mm256_movemask_epi8( a ) == 0 )

#define mm256_all1_8( a ) \
    ( _mm256_movemask_epi8( a ) == -1 )


#define mm256_anybits0( a ) \
   (  _mm256_movemask_epi8( a ) & 0xffffffff  )

#define mm256_anybits1( a ) \
   ( ( _mm256_movemask_epi8( a ) & 0xffffffff ) != 0xffffffff )


// Bitwise test of all 256 bits
#define mm256_allbits0( a )   _mm256_testc_si256( a, m256_neg1 )
#define mm256_allbits1( a )   _mm256_testc_si256( m256_zero, a )
//#define mm256_anybits0( a )   !mm256_allbits1( a )
//#define mm256_anybits1( a )   !mm256_allbits0( a )


// Parallel AES, for when x is expected to be in a 256 bit register.
// Use same 128 bit key.
#if defined(__VAES__) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define mm256_aesenc_2x128( x, k ) \
   _mm256_aesenc_epi128( x, m256_const1_128(k ) )

#else

#define mm256_aesenc_2x128( x, k ) \
   mm256_concat_128( _mm_aesenc_si128( mm128_extr_hi128_256( x ), k ), \
                     _mm_aesenc_si128( mm128_extr_lo128_256( x ), k ) )

#endif

#define mm256_paesenc_2x128( y, x, k ) do \
{ \
  __m128i *X = (__m128i*)x; \
  __m128i *Y = (__m128i*)y; \
  Y[0] = _mm_aesenc_si128( X[0], k ); \
  Y[1] = _mm_aesenc_si128( X[1], k ); \
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


//
// Memory functions
// n = number of 256 bit (32 byte) vectors

static inline void memset_zero_256( __m256i *dst, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m256_zero; }

static inline void memset_256( __m256i *dst, const __m256i a, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_256( __m256i *dst, const __m256i *src, const int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }


//
// Basic operations without SIMD equivalent

// Bitwise not ( ~x )
#define mm256_not( x )       _mm256_xor_si256( (x), m256_neg1 ) \

// Unary negation of each element ( -a )
#define mm256_negate_64( a ) _mm256_sub_epi64( m256_zero, a )
#define mm256_negate_32( a ) _mm256_sub_epi32( m256_zero, a )
#define mm256_negate_16( a ) _mm256_sub_epi16( m256_zero, a )


// Add 4 values, fewer dependencies than sequential addition.

#define mm256_add4_64( a, b, c, d ) \
   _mm256_add_epi64( _mm256_add_epi64( a, b ), _mm256_add_epi64( c, d ) )

#define mm256_add4_32( a, b, c, d ) \
   _mm256_add_epi32( _mm256_add_epi32( a, b ), _mm256_add_epi32( c, d ) )

#define mm256_add4_16( a, b, c, d ) \
   _mm256_add_epi16( _mm256_add_epi16( a, b ), _mm256_add_epi16( c, d ) )

#define mm256_add4_8( a, b, c, d ) \
   _mm256_add_epi8( _mm256_add_epi8( a, b ), _mm256_add_epi8( c, d ) )

#define mm256_xor4( a, b, c, d ) \
   _mm256_xor_si256( _mm256_xor_si256( a, b ), _mm256_xor_si256( c, d ) )

//
//           Bit rotations.
//
// The only bit shift for more than 64 bits is with __int128.
//
// AVX512 has bit rotate for 256 bit vectors with 64 or 32 bit elements


// compiler doesn't like when a variable is used for the last arg of
// _mm_rol_epi32, must be "8 bit immediate". Therefore use rol_var where
// necessary. 

#define mm256_ror_var_64( v, c ) \
   _mm256_or_si256( _mm256_srli_epi64( v, c ), \
                    _mm256_slli_epi64( v, 64-(c) ) )

#define mm256_rol_var_64( v, c ) \
   _mm256_or_si256( _mm256_slli_epi64( v, c ), \
                    _mm256_srli_epi64( v, 64-(c) ) )

#define mm256_ror_var_32( v, c ) \
   _mm256_or_si256( _mm256_srli_epi32( v, c ), \
                    _mm256_slli_epi32( v, 32-(c) ) )

#define mm256_rol_var_32( v, c ) \
   _mm256_or_si256( _mm256_slli_epi32( v, c ), \
                    _mm256_srli_epi32( v, 32-(c) ) )


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// AVX512, control must be 8 bit immediate.

#define mm256_ror_64    _mm256_ror_epi64
#define mm256_rol_64    _mm256_rol_epi64
#define mm256_ror_32    _mm256_ror_epi32
#define mm256_rol_32    _mm256_rol_epi32

#else


// No AVX512, use fallback.

#define mm256_ror_64    mm256_ror_var_64 
#define mm256_rol_64    mm256_rol_var_64
#define mm256_ror_32    mm256_ror_var_32
#define mm256_rol_32    mm256_rol_var_32

#endif     // AVX512 else

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
         _mm256_srlv_epi64( v, c ), \
         _mm256_sllv_epi64( v, _mm256_sub_epi64( \
                                   _mm256_set1_epi64x( 64 ), c ) ) )

#define mm256_rolv_64( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi64( v, c ), \
         _mm256_srlv_epi64( v, _mm256_sub_epi64( \
                                   _mm256_set1_epi64x( 64 ), c ) ) )

#define mm256_rorv_32( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi32( v, c ), \
         _mm256_sllv_epi32( v, _mm256_sub_epi32( \
                                  _mm256_set1_epi32( 32 ), c ) ) )

#define mm256_rolv_32( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi32( v, c ), \
         _mm256_srlv_epi32( v, _mm256_sub_epi32( \
                                     _mm256_set1_epi32( 32 ), c ) ) )

// AVX512 can do 16 bit elements.
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define mm256_rorv_16( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi16( v, _mm256_set1_epi16( c ) ), \
         _mm256_sllv_epi16( v, _mm256_set1_epi16( 16-(c) ) ) )

#define mm256_rolv_16( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi16( v, _mm256_set1_epi16( c ) ), \
         _mm256_srlv_epi16( v, _mm256_set1_epi16( 16-(c) ) ) )

#endif  // AVX512

//
// Rotate elements accross all lanes.
//
// AVX2 has no full vector permute for elements less than 32 bits.
// AVX512 has finer granularity full vector permutes.
// AVX512 has full vector alignr which might be faster, especially for 32 bit


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define mm256_swap_128( v )   _mm256_alignr_epi64( v, v, 2 )
#define mm256_ror_1x64( v )   _mm256_alignr_epi64( v, v, 1 )
#define mm256_rol_1x64( v )   _mm256_alignr_epi64( v, v, 3 )
#define mm256_ror_1x32( v )   _mm256_alignr_epi32( v, v, 1 )
#define mm256_rol_1x32( v )   _mm256_alignr_epi32( v, v, 7 )
#define mm256_ror_3x32( v )   _mm256_alignr_epi32( v, v, 3 )
#define mm256_rol_3x32( v )   _mm256_alignr_epi32( v, v, 5 )

#else   // AVX2

// Swap 128 bit elements in 256 bit vector.
#define mm256_swap_128( v )     _mm256_permute4x64_epi64( v, 0x4e )

// Rotate 256 bit vector by one 64 bit element
#define mm256_ror_1x64( v )     _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_rol_1x64( v )     _mm256_permute4x64_epi64( v, 0x93 )

// Rotate 256 bit vector by one 32 bit element.
#define mm256_ror_1x32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                     m256_const_64( 0x0000000000000007, 0x0000000600000005, \
                                    0x0000000400000003, 0x0000000200000001 )

#define mm256_rol_1x32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                     m256_const_64( 0x0000000600000005,  0x0000000400000003, \
                                    0x0000000200000001,  0x0000000000000007 )

// Rotate 256 bit vector by three 32 bit elements (96 bits).
#define mm256_ror_3x32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                     m256_const_64( 0x0000000200000001, 0x0000000000000007, \
                                    0x0000000600000005, 0x0000000400000003 ) 

#define mm256_rol_3x32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                     m256_const_64( 0x0000000400000003, 0x0000000200000001, \
                                    0x0000000000000007, 0x0000000600000005 )

#endif    // AVX512 else AVX2


// AVX512 can do 16 & 8 bit elements.
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// Rotate 256 bit vector by one 16 bit element.     
#define mm256_ror_1x16( v ) \
   _mm256_permutexvar_epi16( m256_const_64( \
                                 0x0000000f000e000d, 0x000c000b000a0009, \
                                 0x0008000700060005, 0x0004000300020001 ), v )

#define mm256_rol_1x16( v ) \
   _mm256_permutexvar_epi16( m256_const_64( \
                                 0x000e000d000c000b, 0x000a000900080007, \
                                 0x0006000500040003, 0x000200010000000f ), v )

#if defined (__AVX512VBMI__)

// Rotate 256 bit vector by one byte.
#define mm256_ror_1x8( v ) _mm256_permutexvar_epi8( m256_const_64( \
                                 0x001f1e1d1c1b1a19, 0x1817161514131211, \
                                 0x100f0e0d0c0b0a09, 0x0807060504030201 ), v )

#define mm256_rol_1x8( v ) _mm256_permutexvar_epi16( m256_const_64( \
                                 0x1e1d1c1b1a191817, 0x161514131211100f, \
                                 0x0e0d0c0b0a090807, 0x060504030201001f ), v )

#endif  // VBMI

#endif  // AVX512


// Invert vector: {3,2,1,0} -> {0,1,2,3}

#define mm256_invert_64 ( v ) _mm256_permute4x64_epi64( v, 0x1b )

#define mm256_invert_32 ( v ) _mm256_permutevar8x32_epi32( v, \
                     m256_const_64( 0x0000000000000001, 0x0000000200000003 \
                                    0x0000000400000005, 0x0000000600000007 )

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// Invert vector: {7,6,5,4,3,2,1,0} -> {0,1,2,3,4,5,6,7}
#define mm256_invert_16 ( v ) \
     _mm256_permutexvar_epi16( m256_const_64( \
                                  0x0000000100020003, 0x0004000500060007, \
                                  0x00080009000a000b, 0x000c000d000e000f ), v )

#if defined(__AVX512VBMI__)

#define mm256_invert_8( v ) \
     _mm256_permutexvar_epi8( m256_const_64( \
                                  0x0001020304050607, 0x08090a0b0c0d0e0f, \
                                  0x1011121314151617, 0x18191a1b1c1d1e1f ), v )
#endif  // VBMI
#endif  // AVX512


//
// Rotate elements within each 128 bit lane of 256 bit vector.

#define mm256_swap128_64( v )   _mm256_shuffle_epi32( v, 0x4e )

#define mm256_ror128_32( v )  _mm256_shuffle_epi32( v, 0x39 )

#define mm256_rol128_32( v )  _mm256_shuffle_epi32( v, 0x93 )

#define mm256_ror128_x8( v, c )  _mm256_alignr_epi8( v, v, c ) 

/*
// Rotate each 128 bit lane by c elements.
#define mm256_ror128_8( v, c ) \
  _mm256_or_si256( _mm256_bsrli_epi128( v, c ), \
                   _mm256_bslli_epi128( v, 16-(c) ) )
#define mm256_rol128_8( v, c ) \
  _mm256_or_si256( _mm256_bslli_epi128( v, c ), \
                   _mm256_bsrli_epi128( v, 16-(c) ) )
*/

// Rotate elements in each 64 bit lane

#define mm256_swap64_32( v )    _mm256_shuffle_epi32( v, 0xb1 )

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define mm256_rol64_8( v, c )   _mm256_rol_epi64( v, ((c)<<3) ) 
#define mm256_ror64_8( v, c )   _mm256_ror_epi64( v, ((c)<<3) ) 

#else

#define mm256_rol64_8( v, c ) \
     _mm256_or_si256( _mm256_slli_epi64( v, ( ( (c)<<3 ) ), \
                      _mm256_srli_epi64( v, ( ( 64 - ( (c)<<3 ) ) ) )

#define mm256_ror64_8( v, c ) \
     _mm256_or_si256( _mm256_srli_epi64( v, ( ( (c)<<3 ) ), \
                      _mm256_slli_epi64( v, ( ( 64 - ( (c)<<3 ) ) ) )

#endif


// Rotate elements in each 32 bit lane

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define mm256_swap32_16( v ) _mm256_rol_epi32( v, 16 )

#define mm256_rol32_8( v )   _mm256_rol_epi32( v, 8 )
#define mm256_ror32_8( v )   _mm256_ror_epi32( v, 8 )

#else

#define mm256_swap32_16( v ) \
     _mm256_or_si256( _mm256_slli_epi32( v, 16 ), \
                      _mm256_srli_epi32( v, 16 ) )

#define mm256_rol32_8( v ) \
     _mm256_or_si256( _mm256_slli_epi32( v, 8 ), \
                      _mm256_srli_epi32( v, 8 ) )

#define mm256_ror32_8( v, c ) \
     _mm256_or_si256( _mm256_srli_epi32( v, 8 ), \
                      _mm256_slli_epi32( v, 8 ) )

#endif


//
// Swap bytes in vector elements, endian bswap.
#define mm256_bswap_64( v ) \
   _mm256_shuffle_epi8( v, \
         m256_const_64( 0x18191a1b1c1d1e1f, 0x1011121314151617, \
                        0x08090a0b0c0d0e0f, 0x0001020304050607 ) )

#define mm256_bswap_32( v ) \
   _mm256_shuffle_epi8( v, \
         m256_const_64( 0x1c1d1e1f18191a1b, 0x1415161710111213, \
                        0x0c0d0e0f08090a0b, 0x0405060700010203 ) )

#define mm256_bswap_16( v ) \
   _mm256_shuffle_epi8( v, \
         m256_const_64( 0x1e1f1c1d1a1b1819, 0x1617141512131011, \
                        0x0e0f0c0d0a0b0809, 0x0607040502030001, ) )

// Source and destination are pointers, may point to same memory.
// 8 byte qword * 8 qwords * 4 lanes = 256 bytes
#define mm256_block_bswap_64( d, s ) do \
{ \
  __m256i ctl = m256_const_64( 0x18191a1b1c1d1e1f, 0x1011121314151617, \
                               0x08090a0b0c0d0e0f, 0x0001020304050607 ) ; \
  casti_m256i( d, 0 ) = _mm256_shuffle_epi8( casti_m256i( s, 0 ), ctl ); \
  casti_m256i( d, 1 ) = _mm256_shuffle_epi8( casti_m256i( s, 1 ), ctl ); \
  casti_m256i( d, 2 ) = _mm256_shuffle_epi8( casti_m256i( s, 2 ), ctl ); \
  casti_m256i( d, 3 ) = _mm256_shuffle_epi8( casti_m256i( s, 3 ), ctl ); \
  casti_m256i( d, 4 ) = _mm256_shuffle_epi8( casti_m256i( s, 4 ), ctl ); \
  casti_m256i( d, 5 ) = _mm256_shuffle_epi8( casti_m256i( s, 5 ), ctl ); \
  casti_m256i( d, 6 ) = _mm256_shuffle_epi8( casti_m256i( s, 6 ), ctl ); \
  casti_m256i( d, 7 ) = _mm256_shuffle_epi8( casti_m256i( s, 7 ), ctl ); \
} while(0)

// 4 byte dword * 8 dwords * 8 lanes = 256 bytes
#define mm256_block_bswap_32( d, s ) do \
{ \
  __m256i ctl = m256_const_64( 0x1c1d1e1f18191a1b, 0x1415161710111213, \
                               0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_m256i( d, 0 ) = _mm256_shuffle_epi8( casti_m256i( s, 0 ), ctl ); \
  casti_m256i( d, 1 ) = _mm256_shuffle_epi8( casti_m256i( s, 1 ), ctl ); \
  casti_m256i( d, 2 ) = _mm256_shuffle_epi8( casti_m256i( s, 2 ), ctl ); \
  casti_m256i( d, 3 ) = _mm256_shuffle_epi8( casti_m256i( s, 3 ), ctl ); \
  casti_m256i( d, 4 ) = _mm256_shuffle_epi8( casti_m256i( s, 4 ), ctl ); \
  casti_m256i( d, 5 ) = _mm256_shuffle_epi8( casti_m256i( s, 5 ), ctl ); \
  casti_m256i( d, 6 ) = _mm256_shuffle_epi8( casti_m256i( s, 6 ), ctl ); \
  casti_m256i( d, 7 ) = _mm256_shuffle_epi8( casti_m256i( s, 7 ), ctl ); \
} while(0)

//
// Rotate two concatenated 256 bit vectors as one 512 bit vector by specified
// number of elements. Rotate is done in place, source arguments are
// overwritten.
// Some of these can use permute but appears to be slower. Maybe a Ryzen
// issue

//  _mm256_alignr_epi 64/32 are only available with AVX512 but AVX512 also
//  makes these macros unnecessary.

#define mm256_swap512_256( v1, v2 ) \
   v1 = _mm256_xor_si256( v1, v2 ); \
   v2 = _mm256_xor_si256( v1, v2 ); \
   v1 = _mm256_xor_si256( v1, v2 );

#define mm256_ror512_128( v1, v2 ) \
do { \
   __m256i t = _mm256_permute2x128( v1, v2, 0x03 ); \
   v1 = _mm256_permute2x128( v2, v1, 0x21 ); \
   v2 = t; \
} while(0)

#define mm256_rol512_128( v1, v2 ) \
do { \
   __m256i t = _mm256_permute2x128( v1, v2, 0x03 ); \
   v2 = _mm256_permute2x128( v2, v1, 0x21 ); \
   v1 = t; \
} while(0)

#endif // __AVX2__
#endif // SIMD_256_H__

