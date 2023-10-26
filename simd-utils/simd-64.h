#if !defined(SIMD_64_H__)
#define SIMD_64_H__ 1

#if defined(__x86_64__) && defined(__MMX__)

////////////////////////////////////////////////////////////////
//
//               64 bit MMX vectors.
//
// This code is not used anywhere annd likely never will. It's intent was
// to support 2 way parallel hashing using  MMX, or NEON for 32 bit hash
// functions, but hasn't been implementedwas never implemented.
// 

#define v64_t                        __m64
#define v64u32_t                     v64_t

#define v64_load                      _mm_load_si64
#define v64_store                     _mm_store_si64

#define v64_64(i64)                   ((__m64)(i64))
#define v64_32                        _mm_set1_pi32
#define v64_16                        _mm_set1_pi16
#define v64_8                         _mm_set1_pi8

#define v64_add32                     _mm_add_pi32
#define v64_add16                     _mm_add_pi16
#define v64_add8                      _mm_add_pi8

#define v64_mul32                     _mm_mullo_pi32
#define v64_mul16                     _mm_mullo_pi16

// compare
#define v64_cmpeq32                   _mm_cmpeq_epi32
#define v64_cmpeq16                   _mm_cmpeq_epi16
#define v64_cmpeq8                    _mm_cmpeq_epi8

#define v64_cmpgt32                   _mm_cmpgt_epi32
#define v64_cmpgt16                   _mm_cmpgt_epi16
#define v64_cmpgt8                    _mm_cmpgt_epi8

#define v64_cmplt32                   _mm_cmplt_epi32
#define v64_cmplt16                   _mm_cmplt_epi16
#define v64_cmplt8                    _mm_cmplt_epi8

// bit shift
#define v64_sl32                      _mm_slli_epi32
#define v64_sl16                      _mm_slli_epi16
#define v64_sl8                       _mm_slli_epi8

#define v64_sr32                      _mm_srli_epi32
#define v64_sr16                      _mm_srli_epi16
#define v64_sr8                       _mm_srli_epi8

#define v64_sra32                     _mm_srai_epi32
#define v64_sra16                     _mm_srai_epi16
#define v64_sra8                      _mm_srai_epi8

#define v64_alignr8                   _mm_alignr_pi8
#define v64_unpacklo32                _mm_unpacklo_pi32
#define v64_unpackhi32                _mm_unpackhi_pi32
#define v64_unpacklo16                _mm_unpacklo_pi16
#define v64_unpackhi16                _mm_unpacklhi_pi16
#define v64_unpacklo8                 _mm_unpacklo_pi8
#define v64_unpackhi8                 _mm_unpackhi_pi16

// Pseudo constants

#define v64_zero        _mm_setzero_si64()
#define v64_one_64      _mm_set_pi32(  0UL, 1UL )
#define v64_one_32      v64_32( 1UL )
#define v64_one_16      v64_16( 1U )
#define v64_one_8       v64_8(  1U );
#define v64_neg1        v64_32( 0xFFFFFFFFUL )

#define casti_v64(p,i) (((v64_t*)(p))[(i)])

// Bitwise not: ~(a)
//#define mm64_not( a ) _mm_xor_si64( (__m64)a, m64_neg1 )
#define v64_not( a ) ( (v64_t)( ~( (uint64_t)(a) ) )

/*      
// Unary negate elements
#define mm64_negate_32( v ) _mm_sub_pi32( m64_zero, v )
#define mm64_negate_16( v ) _mm_sub_pi16( m64_zero, v )
#define mm64_negate_8(  v ) _mm_sub_pi8(  m64_zero, v )
*/

static inline void v64_memset_zero( __m64 *dst,  const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = v64_zero; }

static inline void v64_memset( __m64 *dst, const __m64 a, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void v64_memcpy( __m64 *dst, const __m64 *src, const int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }
      
#define v64_or                       _mm_or_si64
#define v64_and                      _mm_and_si64
#define v64_xor                      _mm_xor_si64
#define v64_andnot                   _mm_andnot_si64
#define v64_xor3( v2, v1, v0 )       v64_xor( v2, v64_andnot( v1, v0 ) )
#define v64_xorandnot( v2, v1, v0 )  v64_xor( v2, v64_andnot( v1, v0 ) )


// Rotate bits in packed elements of 64 bit vector
#define v64_rol64( a, n ) \
   _mm_or_si64( _mm_slli_si64( a, n ), \
                _mm_srli_si64( a, 64-(n) ) )

#define v64_ror64( a, n ) \
   _mm_or_si64( _mm_srli_si64( a, n ), \
                _mm_slli_si64( a, 64-(n) ) )

#define v64_rol32( a, n ) \
   _mm_or_si64( _mm_slli_pi32( a, n ), \
                _mm_srli_pi32( a, 32-(n) ) )

#define v64_ror32( a, n ) \
   _mm_or_si64( _mm_srli_pi32( a, n ), \
                _mm_slli_pi32( a, 32-(n) ) )

#define v64_rol16( a, n ) \
   _mm_or_si64( _mm_slli_pi16( a, n ), \
                _mm_srli_pi16( a, 16-(n) ) )

#define v64_ror16( a, n ) \
   _mm_or_si64( _mm_srli_pi16( a, n ), \
                _mm_slli_pi16( a, 16-(n) ) )

// Rotate packed elements accross lanes. Useful for byte swap and byte
// rotation.

#if defined(__SSE__)

// Swap hi & lo 32 bits.
#define v64_swap32( a )      _mm_shuffle_pi16( a, 0x4e )

#define v64_shulfr16( a )     _mm_shuffle_pi16( a, 0x39 ) 
#define v64_shufll16( a )     _mm_shuffle_pi16( a, 0x93 ) 

// Swap hi & lo 16 bits of each 32 bit element
#define v64_swap32_16( a )    _mm_shuffle_pi16( a, 0xb1 )

#endif   // SSE

#if defined(__SSSE3__)

// Endian byte swap packed elements

#define v64_bswap32( v ) \
    _mm_shuffle_pi8( v, (__m64)0x0405060700010203 )

#define v64_bswap16( v ) \
    _mm_shuffle_pi8( v, (__m64)0x0607040502030001 );

// Rotate right by c bytes
static inline v64_t v64_shuflr_x8( __m64 v, const int c )
{ return _mm_alignr_pi8( v, v, c ); }

#else

#define v64_bswap32( v ) \
   _mm_set_pi32( __builtin_bswap32( ((uint32_t*)&v)[1] ), \
                 __builtin_bswap32( ((uint32_t*)&v)[0] )  )

#define v64_bswap16( v ) \
   _mm_set_pi16( __builtin_bswap16( ((uint16_t*)&v)[3] ), \
                 __builtin_bswap16( ((uint16_t*)&v)[2] ), \
                 __builtin_bswap16( ((uint16_t*)&v)[1] ), \
                 __builtin_bswap16( ((uint16_t*)&v)[0] )  )

#endif   // SSSE3

#define v64_blendv( v1, v0, mask ) \
   v64_or( v64_and( mask, v1 ), v64_andnot( mask, v0 ) )


#endif // MMX

#endif // SIMD_64_H__

