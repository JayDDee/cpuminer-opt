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
#define mm256_bcast128( v ) \
   _mm256_permute4x64_epi64( _mm256_castsi128_si256( v ), 0x44 )
// deprecated
#define mm256_bcast_m128    mm256_bcast128

// Set either the low or high 64 bit elements in 128 bit lanes, other elements
// are set to zero.
#if defined(VL256)

#define mm256_bcast128lo_64( i64 )     _mm256_maskz_set1_epi64( 0x55, i64 )
#define mm256_bcast128hi_64( i64 )     _mm256_maskz_set1_epi64( 0xaa, i64 )

#else

#define mm256_bcast128lo_64( i64 )     mm256_bcast128( v128_mov64( i64 ) )

#define mm256_bcast128hi_64( i64 )   _mm256_permute4x64_epi64( \
                   _mm256_castsi128_si256( v128_mov64( i64 ) ), 0x11 )

#endif

#define mm256_set2_64( i1, i0 )   mm256_bcast128( _mm_set_epi64x( i1, i0 ) )

#define mm256_set4_32( i3, i2, i1, i0 ) \
   mm256_bcast128( _mm_set_epi32( i3, i2, i1, i0 ) )

// All SIMD constant macros are actually functions containing executable
// code and therefore can't be used as compile time initializers.

#define m256_zero            _mm256_setzero_si256()
#define m256_one_128         mm256_bcast128( v128_one )

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

#if defined(VL256)

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

#if defined(VL256)

// ~v1 | v0
#define mm256_ornot( v1, v0 )      _mm256_ternarylogic_epi64( v1, v0, v0, 0xcf )

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
#define mm256_nxor( a, b )         _mm256_ternarylogic_epi64( a, b, b, 0x81 )
    
#else

#define mm256_ornot( v1, v0 )      _mm256_or_si256( mm256_not( v1 ), v0 )

// usage hints to improve performance when ternary logic is not avalable:
// If overwriting an input arg put that arg first so the intermediate
// result can be stored in the dest.
// Put an arg with the nearest dependency last so independant args can be
// processed first.
#define mm256_xor3( a, b, c ) \
  _mm256_xor_si256( _mm256_xor_si256( a, b ), c )

#define mm256_xor4( a, b, c, d ) \
  _mm256_xor_si256( _mm256_xor_si256( a, b ), _mm256_xor_si256( c, d ) )

#define mm256_and3( a, b, c ) \
  _mm256_and_si256( _mm256_and_si256( a, b ), c )

#define mm256_or3( a, b, c ) \
   _mm256_or_si256( _mm256_or_si256( a, b ), c )

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

#define mm256_nxor( a, b ) \
  mm256_not( _mm256_xor_si256( a, b ) )

#endif

// Mask making
// Equivalent of AVX512 _mm256_movepi64_mask & _mm256_movepi32_mask.
// Returns 4 or 8 bit integer mask from MSBit of 64 or 32 bit elements.
// Effectively a sign test.
// The functions return int which can promote small integers to int when used
// in an expression. Users should mask the slack bits strategically to maintain
// data integrity.
#define mm256_movmask_64( v ) \
   _mm256_movemask_pd( _mm256_castsi256_pd( v ) )

#define mm256_movmask_32( v ) \
   _mm256_movemask_ps( _mm256_castsi256_ps( v ) )

// shuffle 16 bit elements within 64 bit lanes.
#define mm256_shuffle16( v, c ) \
   _mm256_shufflehi_epi16( _mm256_shufflelo_epi16( v, c ), c )

// reverse elements within lanes.
#define mm256_qrev32(v)    _mm256_shuffle_epi32( v, 0xb1 )
#define mm256_swap64_32    mm256_qrev32       // grandfathered

#define mm256_qrev16(v)    mm256_shuffle16( v, 0x1b )
#define mm256_lrev16(v)    mm256_shuffle16( v, 0xb1 )

//
//           Bit rotations.

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

#if defined(VL256)

#define mm256_ror_64            _mm256_ror_epi64
#define mm256_rol_64            _mm256_rol_epi64
#define mm256_ror_32            _mm256_ror_epi32
#define mm256_rol_32            _mm256_rol_epi32

// Redundant but naming may be a better fit in some applications.
#define mm256_shuflr64_8( v)    _mm256_ror_epi64( v,  8 )
#define mm256_shufll64_8( v)    _mm256_rol_epi64( v,  8 )
#define mm256_shuflr64_16(v)    _mm256_ror_epi64( v, 16 )
#define mm256_shufll64_16(v)    _mm256_rol_epi64( v, 16 )
#define mm256_shuflr64_24(v)    _mm256_ror_epi64( v, 24 )
#define mm256_shufll64_24(v)    _mm256_rol_epi64( v, 24 )
#define mm256_shuflr32_8( v)    _mm256_ror_epi32( v,  8 )
#define mm256_shufll32_8( v)    _mm256_rol_epi32( v,  8 )
#define mm256_shuflr32_16(v)    _mm256_ror_epi32( v, 16 )
#define mm256_shufll32_16(v)    _mm256_rol_epi32( v, 16 )

#else

// ROR & ROL will always find the fastest but these names may be a better fit
// in some applications.
#define mm256_shuflr64_8( v )   _mm256_shuffle_epi8( v, V256_SHUFLR64_8 )
#define mm256_shufll64_8( v )   _mm256_shuffle_epi8( v, V256_SHUFLL64_8 )
#define mm256_shuflr64_24(v )   _mm256_shuffle_epi8( v, V256_SHUFLR64_24 )
#define mm256_shufll64_24(v )   _mm256_shuffle_epi8( v, V256_SHUFLL64_24 )
#define mm256_shuflr32_8( v )   _mm256_shuffle_epi8( v, V256_SHUFLR32_8 )
#define mm256_shufll32_8( v )   _mm256_shuffle_epi8( v, V256_SHUFLL32_8 )

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

#if defined(__AVX2__)

// 128 bit version of unpack
#define v256_unpacklo128( v1, v0 )   _mm256_permute2x128_si256( v1, v0, 0x20 )
#define v256_unpackhi128( v1, v0 )   _mm256_permute2x128_si256( v1, v0, 0x31 )

#else

#define v256_unpacklo128( v1, v0 )   _mm256_permute2f128_si256( v1, v0, 0x20 )
#define v256_unpackhi128( v1, v0 )   _mm256_permute2f128_si256( v1, v0, 0x31 )

#endif

//
// Cross lane shuffles
//

// Swap 128 bit elements in 256 bit vector.
#define mm256_rev_128( v )      _mm256_permute4x64_epi64( v, 0x4e )
#define mm256_swap_128          mm256_rev_128    // grandfathered


/* not used
// Reverse elements 
#define mm256_rev_64( v )       _mm256_permute4x64_epi64( v, 0x1b )

#define mm256_rev_32( v ) \
   _mm256_permute8x32_epi64( v, 0x0000000000000001, 0x0000000200000003, \
                                0x0000000400000005, 0x0000000600000007 )

#define mm256_rev_16( v ) \
   _mm256_permute4x64_epi64( mm256_shuffle16( v, 0x1b ), 0x4e )
*/

// Rotate 256 bit vector by one 64 bit element
#define mm256_shuflr_64( v )    _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_shufll_64( v )    _mm256_permute4x64_epi64( v, 0x93 )

/* Not used
// Rotate 256 bit vector by one 32 bit element.
#if defined(VL256)
static inline __m256i mm256_shuflr_32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 1 ); }
static inline __m256i mm256_shufll_32( const __m256i v )
{ return _mm256_alignr_epi32( v, v, 15 ); }
#else
#define mm256_shuflr_32( v ) \
    _mm256_permutevar8x32_epi32( v, \
                 _mm256_set_epi64x( 0x0000000000000007, 0x0000000600000005, \
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

#define mm256_rev128_64(v)      _mm256_shuffle_epi32( v, 0x4e )
#define mm256_swap128_64        mm256_rev128_64   // grandfathered

/*not used
#define mm256_rev128_32(v)      _mm256_shuffle_epi32( v, 0x1b )
#define mm256_rev128_16(v)      mm256_shuffle16( v, 0x1b )
*/

#define mm256_shuflr128_32(v)   _mm256_shuffle_epi32( v, 0x39 )
#define mm256_shufll128_32(v)   _mm256_shuffle_epi32( v, 0x93 )

/* not used
#define mm256_shuflr128_16(v)   mm256_shuffle16( v, 0x39 )
#define mm256_shufll128_16(v)   mm256_shuffle16( v, 0x93 )

static inline __m256i mm256_shuflr128_x8( const __m256i v, const int c )
{ return _mm256_alignr_epi8( v, v, c ); }
*/

// Reverse byte order in elements, endian bswap.
#define mm256_bswap_64( v )     _mm256_shuffle_epi8( v, V256_BSWAP64 )

#define mm256_bswap_32( v )     _mm256_shuffle_epi8( v, V256_BSWAP32 )

/* not used
#define mm256_bswap_16( v ) \
   _mm256_shuffle_epi8( v, mm256_bcast128( _mm_set_epi64x( \
                                0x0e0f0c0d0a0b0809, 0x0607040502030001 ) ) )
*/

// Source and destination are pointers, may point to same memory.
// 8 byte qword * 8 qwords * 4 lanes = 256 bytes
#define mm256_block_bswap_64( d, s ) \
{ \
  casti_m256i( d,0 ) = mm256_bswap_64( casti_m256i( s,0 ) ); \
  casti_m256i( d,1 ) = mm256_bswap_64( casti_m256i( s,1 ) ); \
  casti_m256i( d,2 ) = mm256_bswap_64( casti_m256i( s,2 ) ); \
  casti_m256i( d,3 ) = mm256_bswap_64( casti_m256i( s,3 ) ); \
  casti_m256i( d,4 ) = mm256_bswap_64( casti_m256i( s,4 ) ); \
  casti_m256i( d,5 ) = mm256_bswap_64( casti_m256i( s,5 ) ); \
  casti_m256i( d,6 ) = mm256_bswap_64( casti_m256i( s,6 ) ); \
  casti_m256i( d,7 ) = mm256_bswap_64( casti_m256i( s,7 ) ); \
}

// 4 byte dword * 8 dwords * 8 lanes = 256 bytes
#define mm256_block_bswap_32( d, s ) \
{ \
  casti_m256i( d, 0 ) = mm256_bswap_32( casti_m256i( s, 0 ) ); \
  casti_m256i( d, 1 ) = mm256_bswap_32( casti_m256i( s, 1 ) ); \
  casti_m256i( d, 2 ) = mm256_bswap_32( casti_m256i( s, 2 ) ); \
  casti_m256i( d, 3 ) = mm256_bswap_32( casti_m256i( s, 3 ) ); \
  casti_m256i( d, 4 ) = mm256_bswap_32( casti_m256i( s, 4 ) ); \
  casti_m256i( d, 5 ) = mm256_bswap_32( casti_m256i( s, 5 ) ); \
  casti_m256i( d, 6 ) = mm256_bswap_32( casti_m256i( s, 6 ) ); \
  casti_m256i( d, 7 ) = mm256_bswap_32( casti_m256i( s, 7 ) ); \
}
#define mm256_block_bswap32_256      mm256_block_bswap_32

#if defined(VL256)

#define mm256_alignr64      _mm256_alignr_epi64

#else

#define mm256_alignr64( v1, v0, c ) \
    ( ( (c) & 3 ) == 1 ) ? _mm256_blend_epi32( mm256_shuflr_64( v1 ), \
                                               mm256_shuflr_64( v0 ), 0x3f ) \
  : ( ( (c) & 3 ) == 2 ) ? _mm256_blend_epi32( mm256_rev_128( v1 ), \
                                               mm256_rev_128( v0 ), 0x0f ) \
  : ( ( (c) & 3 ) == 3 ) ? _mm256_blend_epi32( mm256_shufll_64( v1 ), \
                                               mm256_shufll_64( v0 ), 0x03 ) \
  : v0

#endif

#endif // __AVX2__
#endif // SIMD_256_H__

