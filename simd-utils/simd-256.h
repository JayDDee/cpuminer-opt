#if !defined(SIMD_256_H__)
#define SIMD_256_H__ 1

/////////////////////////////////////////////////////////////////////
//
//             AVX2 256 bit vectors
//
// Basic support for 256 bit vectors is available with AVX but integer
// support requires AVX2.
//
// AVX512VL backports some AVX512 features to 256 bit vectors and can produce
// more efficient implementations of some functions. They will be selected
// automatically but their use is limited because 256 bit vectors are less
// likely to be used when 512 is available.
//
// "_mm256_shuffle_epi8" and "_mm256_alignr_epi8" are restricted to 128 bit
// lanes and data can't cross the 128 bit lane boundary.  
// Some usage may have the index vector encoded as if full vector
// shuffles are supported. This has no side effects and would have the same
// results using either version.
// If the need arises and AVX512VL is available, 256 bit full vector shuffles
// can be implemented using the AVX512 zero-mask feature with a NULL mask.
// Using intrinsics it's simple:   _mm256_maskz_shuffle_epi8( 0, v, c )
// With asm it's a bit more complicated with the addition of the mask register
// and zero tag:   vpshufb ymm0{k0}{z}, ymm1, ymm2 

#if defined(__AVX__)

// Used instead of casting.
typedef union
{
   __m256i m256;
   __m128i m128[2];
   uint64_t u64[4];
   uint32_t u32[8];
} __attribute__ ((aligned (32))) m256_ovly;

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

#endif

#if defined(__AVX2__)

// Move integer to low element of vector, other elements are set to zero.
#define mm256_mov64_256( i ) _mm256_castsi128_si256( mm128_mov64_128( i ) )
#define mm256_mov32_256( i ) _mm256_castsi128_si256( mm128_mov32_128( i ) )

// Move low element of vector to integer.
#define u64_mov256_64( v ) u64_mov128_64( _mm256_castsi256_si128( v ) )
#define u32_mov256_32( v ) u32_mov128_32( _mm256_castsi256_si128( v ) )

// deprecated
//#define mm256_mov256_64 u64_mov256_64 
//#define mm256_mov256_32 u32_mov256_32

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
// 64 bit integer argument zero extended to 128 bits.
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
#if defined(__AVX512VL__)

static inline __m256i mm256_not( const __m256i v )
{  return _mm256_ternarylogic_epi64( v, v, v, 1 ); }

#else

#define mm256_not( v )       _mm256_xor_si256( v, m256_neg1 ) \

#endif

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

#if defined(__AVX512VL__)

// AVX512 has ternary logic that supports any 3 input boolean expression.

// a ^ b ^ c
#define mm256_xor3( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0x96 )

// legacy convenience only
#define mm256_xor4( a, b, c, d ) \
   _mm256_xor_si256( a, mm256_xor3( b, c, d ) )

// a & b & c
#define mm256_and3( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0x80 )

// a | b | c
#define mm256_or3( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0xfe )

// a ^ ( b & c )
#define mm256_xorand( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0x78 )

// a & ( b ^ c )
#define mm256_andxor( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0x60 )

// a ^ ( b | c )
#define mm256_xoror( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0x1e )

// a ^ ( ~b & c )   
#define mm256_xorandnot( a, b, c ) \
  _mm256_ternarylogic_epi64( a, b, c, 0xd2 )

// a | ( b & c )
#define mm256_orand( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0xf8  )

// ~( a ^ b ), same as (~a) ^ b
#define mm256_xnor( a, b ) \
   _mm256_ternarylogic_epi64( a, b, b, 0x81  )
    
#else

#define mm256_xor3( a, b, c ) \
   _mm256_xor_si256( a, _mm256_xor_si256( b, c ) )

#define mm256_xor4( a, b, c, d ) \
   _mm256_xor_si256( _mm256_xor_si256( a, b ), _mm256_xor_si256( c, d ) )

#define mm256_and3( a, b, c ) \
   _mm256_and_si256( a, _mm256_and_si256( b, c ) )

#define mm256_or3( a, b, c ) \
   _mm256_or_si256( a, _mm256_or_si256( b, c ) )

#define mm256_xorand( a, b, c ) \
 _mm256_xor_si256( a, _mm256_and_si256( b, c ) )

#define mm256_andxor( a, b, c ) \
  _mm256_and_si256( a, _mm256_xor_si256( b, c ))

#define mm256_xoror( a, b, c ) \
 _mm256_xor_si256( a, _mm256_or_si256( b, c ) )

#define mm256_xorandnot( a, b, c ) \
 _mm256_xor_si256( a, _mm256_andnot_si256( b, c ) )

#define mm256_orand( a, b, c ) \
 _mm256_or_si256( a, _mm256_and_si256( b, c ) )

#define mm256_xnor( a, b ) \
  mm256_not( _mm256_xor_si256( a, b ) )

#endif

// Mask making
// Equivalent of AVX512 _mm256_movepi64_mask & _mm256_movepi32_mask.
// Returns 4 or 8 bit integer mask from MSB of 64 or 32 bit elements.
// Effectively a sign test.

#define mm256_movmask_64( v ) \
   _mm256_castpd_si256( _mm256_movmask_pd( _mm256_castsi256_pd( v ) ) )

#define mm256_movmask_32( v ) \
   _mm256_castps_si256( _mm256_movmask_ps( _mm256_castsi256_ps( v ) ) )


// Diagonal blending

// Blend 4 64 bit elements from 4 vectors
#define mm256_diagonal_64( v3, v2, v1, v0 ) \
  mm256_blend_epi32( _mm256_blend_epi32( v3, v2, 0x30 ), \
                     _mm256_blend_epi32( v1, v0, 0x03 ), 0x0f )

// Blend 8 32 bit elements from 8 vectors
#define mm256_diagonal_32( v7, v6, v5, v4, v3, v2, v1, v0 ) \
  _mm256_blend_epi32( \
        _mm256_blend_epi32( \
               _mm256_blend_epi32( v7, v6, 0x40 ), \
               _mm256_blend_epi32( v5, v4, 0x10 ) 0x30 ), \
        _mm256_blend_epi32( \
               _mm256_blend_epi32( v3, v2, 0x04) \
               _mm256_blend_epi32( v1, v0, 0x01 ), 0x03 ), 0x0f )  


// Blend 4 32 bit elements from each 128 bit lane.
#define mm256_diagonal128_32( v3, v2, v1, v0 ) \
    _mm256_blend_epi32( \
           _mm256_blend_epi32( v3, v2, 0x44) \
           _mm256_blend_epi32( v1, v0, 0x11 ) )  

/*
//
// Extended bit shift for concatenated packed elements from 2 vectors.
// Shift right returns low half, shift left return high half.

#if defined(__AVX512VBMI2__) && defined(__AVX512VL__)

#define mm256_shl2_64( v1, v2, c )    _mm256_shldi_epi64( v1, v2, c )
#define mm256_shr2_64( v1, v2, c )    _mm256_shrdi_epi64( v1, v2, c )

#define mm256_shl2_32( v1, v2, c )    _mm256_shldi_epi32( v1, v2, c )
#define mm256_shr2_32( v1, v2, c )    _mm256_shrdi_epi32( v1, v2, c )

#define mm256_shl2_16( v1, v2, c )    _mm256_shldi_epi16( v1, v2, c )
#define mm256_shr2_16( v1, v2, c )    _mm256_shrdi_epi16( v1, v2, c )

#else

#define mm256_shl2i_64( v1, v2, c ) \
                     _mm256_or_si256( _mm256_slli_epi64( v1, c ), \
                                      _mm256_srli_epi64( v2, 64 - (c) ) )

#define mm512_shr2_64( v1, v2, c ) \
                    _mm256_or_si256( _mm256_srli_epi64( v2, c ), \
                                     _mm256_slli_epi64( v1, 64 - (c) ) )

#define mm256_shl2_32( v1, v2, c ) \
                    _mm256_or_si256( _mm256_slli_epi32( v1, c ), \
                                     _mm256_srli_epi32( v2, 32 - (c) ) )

#define mm256_shr2_32( v1, v2, c ) \
                    _mm256_or_si256( _mm256_srli_epi32( v2, c ), \
                                     _mm256_slli_epi32( v1, 32 - (c) ) )

#define mm256_shl2_16( v1, v2, c ) \
                    _mm256_or_si256( _mm256_slli_epi16( v1, c ), \
                                     _mm256_srli_epi16( v2, 16 - (c) ) )

#define mm256_shr2_16( v1, v2, c ) \
                    _mm256_or_si256( _mm256_srli_epi16( v2, c ), \
                                     _mm256_slli_epi16( v1, 16 - (c) ) )

#endif
*/

//
//           Bit rotations.
//
// x2 rotates elements in 2 individual vectors in a double buffered
// optimization for AVX2, does nothing for AVX512 but is here for
// transparency.

#if defined(__AVX512VL__)

#define mm256_ror_64    _mm256_ror_epi64
#define mm256_rol_64    _mm256_rol_epi64
#define mm256_ror_32    _mm256_ror_epi32
#define mm256_rol_32    _mm256_rol_epi32

#define mm256_rorx2_64( v1, v0, c ) \
   _mm256_ror_epi64( v0, c ); \
   _mm256_ror_epi64( v1, c )

#define mm256_rolx2_64( v1, v0, c ) \
   _mm256_rol_epi64( v0, c ); \
   _mm256_rol_epi64( v1, c )

#define mm256_rorx2_32( v1, v0, c ) \
   _mm256_ror_epi32( v0, c ); \
   _mm256_ror_epi32( v1, c )

#define mm256_rolx2_32( v1, v0, c ) \
   _mm256_rol_epi32( v0, c ); \
   _mm256_rol_epi32( v1, c )

#else   // AVX2

// use shuflr64 shuflr32 below for optimized bit rotations of multiples of 8.

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

#define mm256_rorx2_64( v1, v0, c ) \
{ \
 __m256i t0 = _mm256_srli_epi64( v0, c ); \
 __m256i t1 = _mm256_srli_epi64( v1, c ); \
 v0 = _mm256_slli_epi64( v0, 64-(c) ); \
 v1 = _mm256_slli_epi64( v1, 64-(c) ); \
 v0 = _mm256_or_si256( v0, t0 ); \
 v1 = _mm256_or_si256( v1, t1 ); \
}

#define mm256_rolx2_64( v1, v0, c ) \
{ \
 __m256i t0 = _mm256_slli_epi64( v0, c ); \
 __m256i t1 = _mm256_slli_epi64( v1, c ); \
 v0 = _mm256_srli_epi64( v0, 64-(c) ); \
 v1 = _mm256_srli_epi64( v1, 64-(c) ); \
 v0 = _mm256_or_si256( v0, t0 ); \
 v1 = _mm256_or_si256( v1, t1 ); \
}

#define mm256_rorx2_32( v1, v0, c ) \
{ \
 __m256i t0 = _mm256_srli_epi32( v0, c ); \
 __m256i t1 = _mm256_srli_epi32( v1, c ); \
 v0 = _mm256_slli_epi32( v0, 32-(c) ); \
 v1 = _mm256_slli_epi32( v1, 32-(c) ); \
 v0 = _mm256_or_si256( v0, t0 ); \
 v1 = _mm256_or_si256( v1, t1 ); \
}

#define mm256_rolx2_32( v1, v0, c ) \
{ \
 __m256i t0 = _mm256_slli_epi32( v0, c ); \
 __m256i t1 = _mm256_slli_epi32( v1, c ); \
 v0 = _mm256_srli_epi32( v0, 32-(c) ); \
 v1 = _mm256_srli_epi32( v1, 32-(c) ); \
 v0 = _mm256_or_si256( v0, t0 ); \
 v1 = _mm256_or_si256( v1, t1 ); \
}

#endif     // AVX512 else AVX2

#define  mm256_ror_16( v, c ) \
   _mm256_or_si256( _mm256_srli_epi16( v, c ), \
                    _mm256_slli_epi16( v, 16-(c) ) )

#define mm256_rol_16( v, c ) \
   _mm256_or_si256( _mm256_slli_epi16( v, c ), \
                    _mm256_srli_epi16( v, 16-(c) ) )

// Deprecated.
#define mm256_rol_var_32( v, c ) \
   _mm256_or_si256( _mm256_slli_epi32( v, c ), \
                    _mm256_srli_epi32( v, 32-(c) ) )

//
// Rotate elements accross all lanes.

// Swap 128 bit elements in 256 bit vector.
#define mm256_swap_128( v )     _mm256_permute4x64_epi64( v, 0x4e )
#define mm256_shuflr_128 mm256_swap_128
#define mm256_shufll_128 mm256_swap_128

// Rotate 256 bit vector by one 64 bit element
#define mm256_shuflr_64( v )    _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_shufll_64( v )    _mm256_permute4x64_epi64( v, 0x93 )

// Rotate 256 bit vector by one 32 bit element.
#define mm256_shuflr_32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                     m256_const_64( 0x0000000000000007, 0x0000000600000005, \
                                    0x0000000400000003, 0x0000000200000001 ) )

#define mm256_shufll_32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                     m256_const_64( 0x0000000600000005,  0x0000000400000003, \
                                    0x0000000200000001,  0x0000000000000007 ) )

//
// Rotate elements within each 128 bit lane of 256 bit vector.

// Limited 2 input shuffle
#define mm256_shuffle2_64( v1, v2, c ) \
   _mm256_castpd_si256( _mm256_shuffle_pd( _mm256_castsi256_pd( v1 ), \
                                           _mm256_castsi256_pd( v2 ), c ) ); 

#define mm256_shuffle2_32( v1, v2, c ) \
   _mm256_castps_si256( _mm256_shuffle_ps( _mm256_castsi256_ps( v1 ), \
                                           _mm256_castsi256_ps( v2 ), c ) ); 

#define mm256_swap128_64( v )  _mm256_shuffle_epi32( v, 0x4e )
#define mm256_shuflr128_64 mm256_swap128_64
#define mm256_shufll128_64 mm256_swap128_64

#define mm256_shuflr128_32( v )   _mm256_shuffle_epi32( v, 0x39 )
#define mm256_shufll128_32( v )   _mm256_shuffle_epi32( v, 0x93 )

static inline __m256i mm256_shuflr128_x8( const __m256i v, const int c )
{ return _mm256_alignr_epi8( v, v, c ); }

// Rotate byte elements within 64 or 32 bit lanes, AKA optimized bit
// rotations for multiples of 8 bits. Uses faster ror/rol instructions when
// AVX512 is available.

#define mm256_swap64_32( v )   _mm256_shuffle_epi32( v, 0xb1 )
#define mm256_shuflr64_32 mm256_swap64_32
#define mm256_shufll64_32 mm256_swap64_32

#if defined(__AVX512VL__)
  #define mm256_shuflr64_24( v )  _mm256_ror_epi64( v, 24 )
#else
  #define mm256_shuflr64_24( v ) \
    _mm256_shuffle_epi8( v, _mm256_set_epi64x( \
                                    0x0a09080f0e0d0c0b, 0x0201000706050403, \
                                    0x0a09080f0e0d0c0b, 0x0201000706050403 ) )
#endif

#if defined(__AVX512VL__)
  #define mm256_shuflr64_16( v )  _mm256_ror_epi64( v, 16 )
#else
  #define mm256_shuflr64_16( v ) \
    _mm256_shuffle_epi8( v, _mm256_set_epi64x( \
                                    0x09080f0e0d0c0b0a, 0x0100070605040302, \
                                    0x09080f0e0d0c0b0a, 0x0100070605040302 ) )
#endif

#if defined(__AVX512VL__)
  #define mm256_swap32_16( v )  _mm256_ror_epi32( v, 16 )
#else
  #define mm256_swap32_16( v ) \
    _mm256_shuffle_epi8( v, _mm256_set_epi64x( \
                                    0x0d0c0f0e09080b0a, 0x0504070601000302, \
                                    0x0d0c0f0e09080b0a, 0x0504070601000302 ) )
#endif
#define mm256_shuflr32_16 mm256_swap32_16
#define mm256_shufll32_16 mm256_swap32_16

#if defined(__AVX512VL__)
  #define mm256_shuflr32_8( v )  _mm256_ror_epi32( v, 8 )
#else
  #define mm256_shuflr32_8( v ) \
    _mm256_shuffle_epi8( v, _mm256_set_epi64x( \
                                    0x0c0f0e0d080b0a09, 0x0407060500030201, \
                                    0x0c0f0e0d080b0a09, 0x0407060500030201 ) )
#endif

// NOTE: _mm256_shuffle_epi8, like most shuffles, is restricted to 128 bit
// lanes. AVX512, however, supports full vector 8 bit shuffle. The AVX512VL +
// AVX512BW intrinsic _mm256_mask_shuffle_epi8 with a NULL mask, can be used if
// needed for a shuffle that crosses 128 bit lanes. BSWAP doesn't therefore the
// AVX2 version will work here. The bswap control vector is coded to work
// with both versions, bit 4 is ignored in AVX2. 

// Reverse byte order in elements, endian bswap.
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

// swap 256 bit vectors in place.
// This should be avoided, it's more efficient to switch references.
#define mm256_swap512_256( v1, v2 ) \
   v1 = _mm256_xor_si256( v1, v2 ); \
   v2 = _mm256_xor_si256( v1, v2 ); \
   v1 = _mm256_xor_si256( v1, v2 );

#endif // __AVX2__
#endif // SIMD_256_H__

