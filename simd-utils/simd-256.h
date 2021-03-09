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
#define mm256_mov64_256( i ) _mm256_castsi128_si256( mm128_mov64_128( i ) )
#define mm256_mov32_256( i ) _mm256_castsi128_si256( mm128_mov32_128( i ) )

// Mo0ve low element of vector to integer.
#define mm256_mov256_64( v ) mm128_mov128_64( _mm256_castsi256_si128( v ) )
#define mm256_mov256_32( v ) mm128_mov128_32( _mm256_castsi256_si128( v ) )

// concatenate two 128 bit vectors into one 256 bit vector: { hi, lo }
#define mm256_concat_128( hi, lo ) \
   _mm256_inserti128_si256( _mm256_castsi128_si256( lo ), hi, 1 )


// Equivalent of set, move 64 bit integer constants to respective 64 bit
// elements.
static inline __m256i m256_const_64( const uint64_t i3, const uint64_t i2,
                                     const uint64_t i1, const uint64_t i0 )
{
  union { __m256i m256i;
          uint64_t u64[4]; } v;
  v.u64[0] = i0; v.u64[1] = i1; v.u64[2] = i2; v.u64[3] = i3;
  return v.m256i;
}

// Equivalent of set1.
// 128 bit vector argument
#define m256_const1_128( v ) \
   _mm256_permute4x64_epi64( _mm256_castsi128_si256( v ), 0x44 )
// 64 bit integer argument
#define m256_const1_i128( i ) m256_const1_128( mm128_mov64_128( i ) )
#define m256_const1_64( i )  _mm256_broadcastq_epi64( mm128_mov64_128( i ) )
#define m256_const1_32( i )  _mm256_broadcastd_epi32( mm128_mov32_128( i ) )
#define m256_const1_16( i )  _mm256_broadcastw_epi16( mm128_mov32_128( i ) )
#define m256_const1_8 ( i )  _mm256_broadcastb_epi8 ( mm128_mov32_128( i ) )

#define m256_const2_64( i1, i0 ) \
  m256_const1_128( m128_const_64( i1, i0 ) )

//
// All SIMD constant macros are actually functions containing executable
// code and therefore can't be used as compile time initializers.

#define m256_zero      _mm256_setzero_si256()
#define m256_one_256   mm256_mov64_256( 1 )
#define m256_one_128   m256_const1_i128( 1 )
#define m256_one_64    _mm256_broadcastq_epi64( mm128_mov64_128( 1 ) )
#define m256_one_32    _mm256_broadcastd_epi32( mm128_mov64_128( 1 ) )
#define m256_one_16    _mm256_broadcastw_epi16( mm128_mov64_128( 1 ) )
#define m256_one_8     _mm256_broadcastb_epi8 ( mm128_mov64_128( 1 ) )

static inline __m256i mm256_neg1_fn()
{
   __m256i v;
   asm( "vpcmpeqq %0, %0, %0\n\t" : "=x"(v) );
   return v;
}
#define m256_neg1  mm256_neg1_fn()

// Consistent naming for similar operations.
#define mm128_extr_lo128_256( v ) _mm256_castsi256_si128( v )
#define mm128_extr_hi128_256( v ) _mm256_extracti128_si256( v, 1 )

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

// Bitwise not ( ~v )
#define mm256_not( v )       _mm256_xor_si256( v, m256_neg1 ) \

// Unary negation of each element ( -v )
#define mm256_negate_64( v ) _mm256_sub_epi64( m256_zero, v )
#define mm256_negate_32( v ) _mm256_sub_epi32( m256_zero, v )
#define mm256_negate_16( v ) _mm256_sub_epi16( m256_zero, v )


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

#else   // AVX2

#define mm256_ror_64    mm256_ror_var_64 
#define mm256_rol_64    mm256_rol_var_64
#define mm256_ror_32    mm256_ror_var_32
#define mm256_rol_32    mm256_rol_var_32

#endif     // AVX512 else AVX2

#define  mm256_ror_16( v, c ) \
   _mm256_or_si256( _mm256_srli_epi16( v, c ), \
                    _mm256_slli_epi16( v, 16-(c) ) )

#define mm256_rol_16( v, c ) \
   _mm256_or_si256( _mm256_slli_epi16( v, c ), \
                    _mm256_srli_epi16( v, 16-(c) ) )


//
// Rotate elements accross all lanes.
//
// AVX2 has no full vector permute for elements less than 32 bits.
// AVX512 has finer granularity full vector permutes.
// AVX512 has full vector alignr which might be faster, especially for 32 bit


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

static inline __m256i mm256_swap_128( const __m256i v )
{ return _mm256_alignr_epi64( v, v, 2 ); }

static inline __m256i mm256_ror_1x64( const __m256i v )
{ return _mm256_alignr_epi64( v, v, 1 ); }

static inline __m256i mm256_rol_1x64( const __m256i v )
{ return _mm256_alignr_epi64( v, v, 3 ); }

static inline __m256i mm256_ror_1x32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 1 ); }

static inline __m256i mm256_rol_1x32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 7 ); }

static inline __m256i mm256_ror_3x32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 3 ); }

static inline __m256i mm256_rol_3x32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 5 ); }

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

//
// Rotate elements within each 128 bit lane of 256 bit vector.

#define mm256_swap128_64( v )  _mm256_shuffle_epi32( v, 0x4e )
#define mm256_ror128_32( v )   _mm256_shuffle_epi32( v, 0x39 )
#define mm256_rol128_32( v )   _mm256_shuffle_epi32( v, 0x93 )

static inline __m256i mm256_ror128_x8( const __m256i v, const int c )
{ return _mm256_alignr_epi8( v, v, c ); }

// Swap 32 bit elements in each 64 bit lane.
#define mm256_swap64_32( v )   _mm256_shuffle_epi32( v, 0xb1 )

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

