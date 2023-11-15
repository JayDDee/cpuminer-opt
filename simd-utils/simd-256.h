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
// AVX10_256 will support AVX512VL instructions on CPUs limited to 256 bit
// vectors. This will require enabling when the compiler's AVX10 feature
// macros are known.
//
// "_mm256_shuffle_epi8" and "_mm256_alignr_epi8" are restricted to 128 bit
// lanes and data can't cross the 128 bit lane boundary.  
// Instructions that can move data across 128 bit lane boundary incur a
// performance penalty over those that can't.

#if defined(__x86_64__) && defined(__AVX__)

// Used instead of casting.
typedef union
{
   __m256i m256;
   __m128i m128[2];
   uint64_t u64[4];
   uint32_t u32[8];
} __attribute__ ((aligned (32))) m256_ovly;


#define v256_64(i)    _mm256_set1_epi64x(i)
#define v256_32(i)    _mm256_set1_epi32(i)

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

// Broadcast, ie set1, from 128 bit vector input.
#define mm256_bcast_m128( v ) \
   _mm256_permute4x64_epi64( _mm256_castsi128_si256( v ), 0x44 )

// Set either the low or high 64 bit elements in 128 bit lanes, other elements
// are set to zero.
#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

#define mm256_bcast128lo_64( i64 )     _mm256_maskz_set1_epi64( 0x55, i64 )
#define mm256_bcast128hi_64( i64 )     _mm256_maskz_set1_epi64( 0xaa, i64 )

#else

#define mm256_bcast128lo_64( i64 )   mm256_bcast_m128( mm128_mov64_128( i64 ) )

#define mm256_bcast128hi_64( i64 )   _mm256_permute4x64_epi64( \
                   _mm256_castsi128_si256( mm128_mov64_128( i64 ) ), 0x11 )

#endif

#define mm256_set2_64( i1, i0 )   mm256_bcast_m128( _mm_set_epi64x( i1, i0 ) )

#define mm256_set4_32( i3, i2, i1, i0 ) \
   mm256_bcast_m128( _mm_set_epi32( i3, i2, i1, i0 ) )

// All SIMD constant macros are actually functions containing executable
// code and therefore can't be used as compile time initializers.

#define m256_zero            _mm256_setzero_si256()
#define m256_one_128         mm256_bcast_m128( v128_one )

static inline __m256i mm256_neg1_fn()
{
   __m256i v;
   asm( "vpcmpeqq %0, %0, %0\n\t" : "=x"(v) );
   return v;
}
#define m256_neg1  mm256_neg1_fn()

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

#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

static inline __m256i mm256_not( const __m256i v )
{  return _mm256_ternarylogic_epi64( v, v, v, 1 ); }

#else

#define mm256_not( v )       _mm256_xor_si256( v, m256_neg1 ) \

#endif

// Add 4 values, fewer dependencies than sequential addition.

#define mm256_add4_64( a, b, c, d ) \
   _mm256_add_epi64( _mm256_add_epi64( a, b ), _mm256_add_epi64( c, d ) )

#define mm256_add4_32( a, b, c, d ) \
   _mm256_add_epi32( _mm256_add_epi32( a, b ), _mm256_add_epi32( c, d ) )

#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

// a ^ b ^ c
#define mm256_xor3( a, b, c )      _mm256_ternarylogic_epi64( a, b, c, 0x96 )

// legacy convenience only
#define mm256_xor4( a, b, c, d )   _mm256_xor_si256( a, mm256_xor3( b, c, d ) )

// a & b & c
#define mm256_and3( a, b, c )      _mm256_ternarylogic_epi64( a, b, c, 0x80 )

// a | b | c
#define mm256_or3( a, b, c )       _mm256_ternarylogic_epi64( a, b, c, 0xfe )

// a ^ ( b & c )
#define mm256_xorand( a, b, c )    _mm256_ternarylogic_epi64( a, b, c, 0x78 )

// a & ( b ^ c )
#define mm256_andxor( a, b, c )    _mm256_ternarylogic_epi64( a, b, c, 0x60 )

// a ^ ( b | c )
#define mm256_xoror( a, b, c )     _mm256_ternarylogic_epi64( a, b, c, 0x1e )

// a ^ ( ~b & c )   
#define mm256_xorandnot( a, b, c ) _mm256_ternarylogic_epi64( a, b, c, 0xd2 )

// a | ( b & c )
#define mm256_orand( a, b, c )     _mm256_ternarylogic_epi64( a, b, c, 0xf8 )

// ~( a ^ b ), same as (~a) ^ b
#define mm256_xnor( a, b )         _mm256_ternarylogic_epi64( a, b, b, 0x81 )
    
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
// Returns 4 or 8 bit integer mask from MSBit of 64 or 32 bit elements.
// Effectively a sign test.

#define mm256_movmask_64( v ) \
   _mm256_movemask_pd( _mm256_castsi256_pd( v ) )

#define mm256_movmask_32( v ) \
   _mm256_movemask_ps( _mm256_castsi256_ps( v ) )

//
//           Bit rotations.

#define mm256_shuffle16( v, c ) \
   _mm256_shufflehi_epi16( _mm256_shufflelo_epi16( v, c ), c )

#define mm256_qrev32(v)    _mm256_shuffle_epi32( v, 0xb1 )
#define mm256_swap64_32    mm256_qrev32       // grandfathered

#define mm256_qrev16(v)    mm256_shuffle16( v, 0x1b )

#define mm256_qrev8(v) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                         v128_64( 0x08090a0b0c0d0e0f, 0x0001020304050607 ) ) )

#define mm256_lrev16(v)    mm256_shuffle16( v, 0xb1 )

#define mm256_lrev8(v) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                         v128_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 ) ) )

#define mm256_wrev8(v)  \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                         v128_64( 0x0e0f0c0d0a0b0809, 0x0607040502030001 ) ) )

// These should never be called directly by applications.
#define mm256_ror_64_avx2( v, c ) \
   _mm256_or_si256( _mm256_srli_epi64( v, c ), \
                    _mm256_slli_epi64( v, 64-(c) ) )

#define mm256_rol_64_avx2( v, c ) \
   _mm256_or_si256( _mm256_slli_epi64( v, c ), \
                    _mm256_srli_epi64( v, 64-(c) ) )

#define mm256_ror_32_avx2( v, c ) \
   _mm256_or_si256( _mm256_srli_epi32( v, c ), \
                    _mm256_slli_epi32( v, 32-(c) ) )

#define mm256_rol_32_avx2( v, c ) \
   _mm256_or_si256( _mm256_slli_epi32( v, c ), \
                    _mm256_srli_epi32( v, 32-(c) ) )

#if defined(__AVX512VL__)

#define mm256_ror_64    _mm256_ror_epi64
#define mm256_rol_64    _mm256_rol_epi64
#define mm256_ror_32    _mm256_ror_epi32
#define mm256_rol_32    _mm256_rol_epi32

// Redundant but naming may be a better fit in some applications.
#define mm126_shuflr64_8( v)      _mm256_ror_epi64( v,  8 )
#define mm156_shufll64_8( v)      _mm256_rol_epi64( v,  8 )
#define mm256_shuflr64_16(v)      _mm256_ror_epi64( v, 16 )
#define mm256_shufll64_16(v)      _mm256_rol_epi64( v, 16 )
#define mm256_shuflr64_24(v)      _mm256_ror_epi64( v, 24 )
#define mm256_shufll64_24(v)      _mm256_rol_epi64( v, 24 )
#define mm256_shuflr32_8( v)      _mm256_ror_epi32( v,  8 )
#define mm256_shufll32_8( v)      _mm256_rol_epi32( v,  8 )
#define mm256_shuflr32_16(v)      _mm256_ror_epi32( v, 16 )
#define mm256_shufll32_16(v)      _mm256_rol_epi32( v, 16 )

#else

// ROR & ROL will always find the fastest but these names may be a better fit
// in some applications.
#define mm256_shuflr64_8( v ) \
    _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                 _mm_set_epi64x( 0x080f0e0d0c0b0a09, 0x0007060504030201 ) ) )

#define mm256_shufll64_8( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                 _mm_set_epi64x( 0x0e0d0c0b0a09080f, 0x0605040302010007 ) ) )

#define mm256_shuflr64_24( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                  _mm_set_epi64x( 0x0a09080f0e0d0c0b, 0x0201000706050403 ) ) )

#define mm256_shufll64_24( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                  _mm_set_epi64x( 0x0c0b0a09080f0e0d, 0x0403020100070605 ) ) )

#define mm256_shuflr32_8( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                  _mm_set_epi64x( 0x0c0f0e0d080b0a09, 0x0407060500030201 ) ) )

#define mm256_shufll32_8( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( \
                  _mm_set_epi64x( 0x0e0d0c0f0a09080b, 0x0605040702010003 ) ) )

#define mm256_ror_64( v, c ) \
   ( (c) ==  8 ) ? mm256_shuflr64_8( v ) \
 : ( (c) == 16 ) ? mm256_shuffle16( v, 0x39 ) \
 : ( (c) == 24 ) ? mm256_shuflr64_24( v ) \
 : ( (c) == 32 ) ? _mm256_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 40 ) ? mm256_shufll64_24( v ) \
 : ( (c) == 48 ) ? mm256_shuffle16( v, 0x93 ) \
 : ( (c) == 56 ) ? mm256_shufll64_8( v ) \
 : mm256_ror_64_avx2( v, c )

#define mm256_rol_64( v, c ) \
   ( (c) ==  8 ) ? mm256_shufll64_8( v ) \
 : ( (c) == 16 ) ? mm256_shuffle16( v, 0x93 ) \
 : ( (c) == 24 ) ? mm256_shufll64_24( v ) \
 : ( (c) == 32 ) ? _mm256_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 40 ) ? mm256_shuflr64_24( v ) \
 : ( (c) == 48 ) ? mm256_shuffle16( v, 0x39 ) \
 : ( (c) == 56 ) ? mm256_shuflr64_8( v ) \
 : mm256_rol_64_avx2( v, c )

#define mm256_ror_32( v, c ) \
   ( (c) ==  8 ) ? mm256_shuflr32_8( v ) \
 : ( (c) == 16 ) ? mm256_lrev16( v ) \
 : ( (c) == 24 ) ? mm256_shufll32_8( v ) \
 : mm256_ror_32_avx2( v, c )

#define mm256_rol_32( v, c ) \
   ( (c) ==  8 ) ? mm256_shufll32_8( v ) \
 : ( (c) == 16 ) ? mm256_lrev16( v ) \
 : ( (c) == 24 ) ? mm256_shuflr32_8( v ) \
 : mm256_rol_32_avx2( v, c )

#endif

//
// x2 rotates elements in 2 individual vectors in a double buffered
// optimization for AVX2, does nothing for AVX512 but is here for
// transparency.

#if defined(__AVX512VL__)
//TODO Enable for AVX10_256
/*
#define mm256_ror_64    _mm256_ror_epi64
#define mm256_rol_64    _mm256_rol_epi64
#define mm256_ror_32    _mm256_ror_epi32
#define mm256_rol_32    _mm256_rol_epi32
*/
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
/*
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
*/
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

//
// Cross lane shuffles
//
// Rotate elements accross all lanes.
#define mm256_shuffle_16( v, c ) \
   _mm256_or_si256( _mm256_shufflehi_epi16( v, c ), \
                    _mm256_shufflelo_epi16( v, c ) )

// Swap 128 bit elements in 256 bit vector.
#define mm256_swap_128( v )     _mm256_permute4x64_epi64( v, 0x4e )
#define mm256_rev_128( v )      _mm256_permute4x64_epi64( v, 0x4e )

// Rotate 256 bit vector by one 64 bit element
#define mm256_shuflr_64( v )    _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_shufll_64( v )    _mm256_permute4x64_epi64( v, 0x93 )

// Reverse 64 bit elements 
#define mm256_rev_64( v )       _mm256_permute4x64_epi64( v, 0x1b )

#define mm256_rev_32( v ) \
   _mm256_permute8x32_epi64( v, 0x0000000000000001, 0x0000000200000003, \
                                0x0000000400000005, 0x0000000600000007 )

#define mm256_rev_16( v ) \
   _mm256_permute4x64_epi64( mm256_shuffle_16( v, 0x1b ), 0x4e )

/* Not used
// Rotate 256 bit vector by one 32 bit element.
#if defined(__AVX512VL__)
static inline __m256i mm256_shuflr_32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 1 ); }
static inline __m256i mm256_shufll_32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 15 ); }
#else
#define mm256_shuflr_32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                 _mm256_set_spi64x( 0x0000000000000007, 0x0000000600000005, \
                                    0x0000000400000003, 0x0000000200000001 ) )
#define mm256_shufll_32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                 _mm256_set_epi64x( 0x0000000600000005,  0x0000000400000003, \
                                    0x0000000200000001,  0x0000000000000007 ) )
#endif
*/

//
// Rotate elements within each 128 bit lane of 256 bit vector.

// Limited 2 input shuffle
#define mm256_shuffle2_64( v1, v2, c ) \
   _mm256_castpd_si256( _mm256_shuffle_pd( _mm256_castsi256_pd( v1 ), \
                                           _mm256_castsi256_pd( v2 ), c ) ); 

#define mm256_shuffle2_32( v1, v2, c ) \
   _mm256_castps_si256( _mm256_shuffle_ps( _mm256_castsi256_ps( v1 ), \
                                           _mm256_castsi256_ps( v2 ), c ) ); 

#define mm256_swap128_64(v)     _mm256_shuffle_epi32( v, 0x4e )
#define mm256_rev128_64(v)      _mm256_shuffle_epi32( v, 0x4e )
#define mm256_rev128_32(v)      _mm256_shuffle_epi32( v, 0x1b )
#define mm256_rev128_16(v)      mm256_shuffle_16( v, 0x1b )

#define mm256_shuflr128_32(v)   _mm256_shuffle_epi32( v, 0x39 )
#define mm256_shufll128_32(v)   _mm256_shuffle_epi32( v, 0x93 )

#define mm256_shuflr128_16(v)   _mm256_shuffle_epi16( v, 0x39 )
#define mm256_shufll128_16(v)   _mm256_shuffle_epi16( v, 0x93 )

/* Not used
static inline __m256i mm256_shuflr128_x8( const __m256i v, const int c )
{ return _mm256_alignr_epi8( v, v, c ); }
*/

// Reverse byte order in elements, endian bswap.
#define mm256_bswap_64( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( _mm_set_epi64x( \
                               0x08090a0b0c0d0e0f, 0x0001020304050607 ) ) )

#define mm256_bswap_32( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( _mm_set_epi64x( \
                                0x0c0d0e0f08090a0b, 0x0405060700010203 ) ) )

#define mm256_bswap_16( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast_m128( _mm_set_epi64x( \
                                0x0e0f0c0d0a0b0809, 0x0607040502030001 ) ) )
//

// Source and destination are pointers, may point to same memory.
// 8 byte qword * 8 qwords * 4 lanes = 256 bytes
#define mm256_block_bswap_64( d, s ) \
{ \
  __m256i ctl = mm256_bcast_m128( _mm_set_epi64x( 0x08090a0b0c0d0e0f, \
                                                  0x0001020304050607 ) ); \
  casti_m256i( d, 0 ) = _mm256_shuffle_epi8( casti_m256i( s, 0 ), ctl ); \
  casti_m256i( d, 1 ) = _mm256_shuffle_epi8( casti_m256i( s, 1 ), ctl ); \
  casti_m256i( d, 2 ) = _mm256_shuffle_epi8( casti_m256i( s, 2 ), ctl ); \
  casti_m256i( d, 3 ) = _mm256_shuffle_epi8( casti_m256i( s, 3 ), ctl ); \
  casti_m256i( d, 4 ) = _mm256_shuffle_epi8( casti_m256i( s, 4 ), ctl ); \
  casti_m256i( d, 5 ) = _mm256_shuffle_epi8( casti_m256i( s, 5 ), ctl ); \
  casti_m256i( d, 6 ) = _mm256_shuffle_epi8( casti_m256i( s, 6 ), ctl ); \
  casti_m256i( d, 7 ) = _mm256_shuffle_epi8( casti_m256i( s, 7 ), ctl ); \
}
#define mm256_block_bswap64_512   mm256_block_bswap_64

#define mm256_block_bswap64_1024( d, s ) \
{ \
  __m256i ctl = mm256_bcast_m128( _mm_set_epi64x( 0x08090a0b0c0d0e0f, \
                                                  0x0001020304050607 ) ); \
  casti_m256i( d, 0 ) = _mm256_shuffle_epi8( casti_m256i( s, 0 ), ctl ); \
  casti_m256i( d, 1 ) = _mm256_shuffle_epi8( casti_m256i( s, 1 ), ctl ); \
  casti_m256i( d, 2 ) = _mm256_shuffle_epi8( casti_m256i( s, 2 ), ctl ); \
  casti_m256i( d, 3 ) = _mm256_shuffle_epi8( casti_m256i( s, 3 ), ctl ); \
  casti_m256i( d, 4 ) = _mm256_shuffle_epi8( casti_m256i( s, 4 ), ctl ); \
  casti_m256i( d, 5 ) = _mm256_shuffle_epi8( casti_m256i( s, 5 ), ctl ); \
  casti_m256i( d, 6 ) = _mm256_shuffle_epi8( casti_m256i( s, 6 ), ctl ); \
  casti_m256i( d, 7 ) = _mm256_shuffle_epi8( casti_m256i( s, 7 ), ctl ); \
  casti_m256i( d, 8 ) = _mm256_shuffle_epi8( casti_m256i( s, 8 ), ctl ); \
  casti_m256i( d, 9 ) = _mm256_shuffle_epi8( casti_m256i( s, 9 ), ctl ); \
  casti_m256i( d,10 ) = _mm256_shuffle_epi8( casti_m256i( s,10 ), ctl ); \
  casti_m256i( d,11 ) = _mm256_shuffle_epi8( casti_m256i( s,11 ), ctl ); \
  casti_m256i( d,12 ) = _mm256_shuffle_epi8( casti_m256i( s,12 ), ctl ); \
  casti_m256i( d,13 ) = _mm256_shuffle_epi8( casti_m256i( s,13 ), ctl ); \
  casti_m256i( d,14 ) = _mm256_shuffle_epi8( casti_m256i( s,14 ), ctl ); \
  casti_m256i( d,15 ) = _mm256_shuffle_epi8( casti_m256i( s,15 ), ctl ); \
}

// 4 byte dword * 8 dwords * 8 lanes = 256 bytes
#define mm256_block_bswap_32( d, s ) \
{ \
  __m256i ctl = mm256_bcast_m128( _mm_set_epi64x( 0x0c0d0e0f08090a0b, \
                                                  0x0405060700010203 ) ); \
  casti_m256i( d, 0 ) = _mm256_shuffle_epi8( casti_m256i( s, 0 ), ctl ); \
  casti_m256i( d, 1 ) = _mm256_shuffle_epi8( casti_m256i( s, 1 ), ctl ); \
  casti_m256i( d, 2 ) = _mm256_shuffle_epi8( casti_m256i( s, 2 ), ctl ); \
  casti_m256i( d, 3 ) = _mm256_shuffle_epi8( casti_m256i( s, 3 ), ctl ); \
  casti_m256i( d, 4 ) = _mm256_shuffle_epi8( casti_m256i( s, 4 ), ctl ); \
  casti_m256i( d, 5 ) = _mm256_shuffle_epi8( casti_m256i( s, 5 ), ctl ); \
  casti_m256i( d, 6 ) = _mm256_shuffle_epi8( casti_m256i( s, 6 ), ctl ); \
  casti_m256i( d, 7 ) = _mm256_shuffle_epi8( casti_m256i( s, 7 ), ctl ); \
}
#define mm256_block_bswap32_256      mm256_block_bswap_32

#define mm256_block_bswap32_512( d, s ) \
{ \
  __m256i ctl = mm256_bcast_m128( _mm_set_epi64x( 0x0c0d0e0f08090a0b, \
                                                  0x0405060700010203 ) ); \
  casti_m256i( d, 0 ) = _mm256_shuffle_epi8( casti_m256i( s, 0 ), ctl ); \
  casti_m256i( d, 1 ) = _mm256_shuffle_epi8( casti_m256i( s, 1 ), ctl ); \
  casti_m256i( d, 2 ) = _mm256_shuffle_epi8( casti_m256i( s, 2 ), ctl ); \
  casti_m256i( d, 3 ) = _mm256_shuffle_epi8( casti_m256i( s, 3 ), ctl ); \
  casti_m256i( d, 4 ) = _mm256_shuffle_epi8( casti_m256i( s, 4 ), ctl ); \
  casti_m256i( d, 5 ) = _mm256_shuffle_epi8( casti_m256i( s, 5 ), ctl ); \
  casti_m256i( d, 6 ) = _mm256_shuffle_epi8( casti_m256i( s, 6 ), ctl ); \
  casti_m256i( d, 7 ) = _mm256_shuffle_epi8( casti_m256i( s, 7 ), ctl ); \
  casti_m256i( d, 8 ) = _mm256_shuffle_epi8( casti_m256i( s, 8 ), ctl ); \
  casti_m256i( d, 9 ) = _mm256_shuffle_epi8( casti_m256i( s, 9 ), ctl ); \
  casti_m256i( d,10 ) = _mm256_shuffle_epi8( casti_m256i( s,10 ), ctl ); \
  casti_m256i( d,11 ) = _mm256_shuffle_epi8( casti_m256i( s,11 ), ctl ); \
  casti_m256i( d,12 ) = _mm256_shuffle_epi8( casti_m256i( s,12 ), ctl ); \
  casti_m256i( d,13 ) = _mm256_shuffle_epi8( casti_m256i( s,13 ), ctl ); \
  casti_m256i( d,14 ) = _mm256_shuffle_epi8( casti_m256i( s,14 ), ctl ); \
  casti_m256i( d,15 ) = _mm256_shuffle_epi8( casti_m256i( s,15 ), ctl ); \
}


#endif // __AVX2__
#endif // SIMD_256_H__

