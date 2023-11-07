#if !defined(SIMD_128_H__)
#define SIMD_128_H__ 1

#if defined(__x86_64__) && defined(__SSE2__)

///////////////////////////////////////////////////////////////////////////////
//
//                 128 bit SSE vectors
//
// SSE2 is required for 128 bit integer support. Some functions are also
// optimized with SSSE3, SSE4.1 or AVX. Some of these more optimized
// functions don't have SSE2 equivalents and their use would break SSE2
// compatibility.
//
// Constants are an issue with simd. Simply put, immediate constants don't
// exist. All simd constants either reside in memory or a register and
// must be loaded from memory or generated at run time.
//
// Due to the cost of generating constants it is more efficient to
// define a local const for repeated references to the same constant.
//
// One common use for simd constants is as a control index for vector
// shuffle instructions. Alhough the ultimate instruction may execute in a
// single clock cycle, generating the control index adds several more cycles
// to the entire operation. 
//
// All of the utilities here assume all data is in registers except
// in rare cases where arguments are pointers.
//
// Some constants are generated using a memory overlay on the stack.
//
// Intrinsics automatically promote from REX to VEX when AVX is available
// but ASM needs to be done manually.
//
///////////////////////////////////////////////////////////////////////////////

// New architecturally agnostic syntax: 
//    All users of 128 bit SIMD should use new syntax or protect SSE2 only
//    code segments.
//    Other vector sizes continue with old syntax for now.
//    Definitionns here will gradually be converted to new synytax.
//    For consistency the larger vector utilities should do the same.


// direct translation of native intrinsics

#define v128_t                         __m128i 
// Needed for ARM
#define v128u64_t                      v128_t
#define v128u32_t                      v128_t
#define v128u16_t                      v128_t
#define v128u8_t                       v128_t

#define v128_load                      _mm_load_si128
#define v128_store                     _mm_store_si128

// Needed for ARM, Doesn't do anything special on x86_64
#define v128_load1_64(p)               _mm_set1_epi64x(*(uint64_t*)(p) )
#define v128_load1_32(p)               _mm_set_epi32(  *(uint32_t*)(p) )
#define v128_load1_16(p)               _mm_set_epi16(  *(uint16_t*)(p) )
#define v128_load1_8( p)               _mm_set_epi8(   *(uint8_t*) (p) )

// arithmetic
#define v128_add64                     _mm_add_epi64
#define v128_add32                     _mm_add_epi32
#define v128_add16                     _mm_add_epi16
#define v128_add8                      _mm_add_epi8
#define v128_add4_64                   mm128_add4_64
#define v128_add4_32                   mm128_add4_32

#define v128_sub64                     _mm_sub_epi64
#define v128_sub32                     _mm_sub_epi32
#define v128_sub16                     _mm_sub_epi16
#define v128_sub8                      _mm_sub_epi8

// save low half
#define v128_mul64                     _mm_mullo_epi64
#define v128_mul32                     _mm_mullo_epi32
#define v128_mul16                     _mm_mullo_epi16

// widen
#define v128_mulw32                    _mm_mul_epu32
#define v128_mulw16                    _mm_mul_epu16

// compare
#define v128_cmpeq64                   _mm_cmpeq_epi64
#define v128_cmpeq32                   _mm_cmpeq_epi32
#define v128_cmpeq16                   _mm_cmpeq_epi16
#define v128_cmpeq8                    _mm_cmpeq_epi8

#define v128_cmpgt64                   _mm_cmpgt_epi64
#define v128_cmpgt32                   _mm_cmpgt_epi32
#define v128_cmpgt16                   _mm_cmpgt_epi16
#define v128_cmpgt8                    _mm_cmpgt_epi8

#define v128_cmplt64                   _mm_cmplt_epi64
#define v128_cmplt32                   _mm_cmplt_epi32
#define v128_cmplt16                   _mm_cmplt_epi16
#define v128_cmplt8                    _mm_cmplt_epi8

// bit shift
#define v128_sl64                      _mm_slli_epi64
#define v128_sl32                      _mm_slli_epi32
#define v128_sl16                      _mm_slli_epi16
#define v128_sl8                       _mm_slli_epi8

#define v128_sr64                      _mm_srli_epi64
#define v128_sr32                      _mm_srli_epi32
#define v128_sr16                      _mm_srli_epi16
#define v128_sr8                       _mm_srli_epi8

#define v128_sra64                     _mm_srai_epi64
#define v128_sra32                     _mm_srai_epi32
#define v128_sra16                     _mm_srai_epi16
#define v128_sra8                      _mm_srai_epi8

// logic
#define v128_or                        _mm_or_si128
#define v128_and                       _mm_and_si128
#define v128_xor                       _mm_xor_si128
#define v128_xorq                      _mm_xor_si128
#define v128_andnot                    _mm_andnot_si128
#define v128_xnor( a, b )              mm128_not( _mm_xor_si128( a, b ) )
#define v128_ornot( a, b )             mm128_or( a, mm128_not( b ) ) 

// ternary
#define v128_xorandnot( v2, v1, v0 ) \
                               _mm_xor_si128( v2, _mm_andnot_si128( v1, v0 ) )
#define v128_xor3( v2, v1, v0 ) \
                               _mm_xor_si128( v2, _mm_xor_si128( v1, v0 ) )
#define v128_and3( a, b, c )           _mm_and_si128( a, _mm_and_si128( b, c ) )
#define v128_or3( a, b, c )            _mm_or_si128( a, _mm_or_si128( b, c ) )
#define v128_xorand( a, b, c )         _mm_xor_si128( a, _mm_and_si128( b, c ) )
#define v128_andxor( a, b, c )         _mm_and_si128( a, _mm_xor_si128( b, c ))
#define v128_xoror( a, b, c )          _mm_xor_si128( a, _mm_or_si128( b, c ) )
#define v128_orand( a, b, c )          _mm_or_si128( a, _mm_and_si128( b, c ) )

// shift 2 concatenated vectors right
#define v128_alignr64                  mm128_alignr_64
#define v128_alignr32                  mm128_alignr_32
#if defined(__SSSE3__)
  #define v128_alignr8                 _mm_alignr_epi8
#endif

// unpack
#define v128_unpacklo64                _mm_unpacklo_epi64
#define v128_unpackhi64                _mm_unpackhi_epi64
#define v128_unpacklo32                _mm_unpacklo_epi32
#define v128_unpackhi32                _mm_unpackhi_epi32
#define v128_unpacklo16                _mm_unpacklo_epi16
#define v128_unpackhi16                _mm_unpackhi_epi16
#define v128_unpacklo8                 _mm_unpacklo_epi8
#define v128_unpackhi8                 _mm_unpackhi_epi8

// AES
#define v128_aesenc                    _mm_aesenc_si128
#define v128_aesenclast                _mm_aesenclast_si128
#define v128_aesdec                    _mm_aesdec_si128
#define v128_aesdeclast                _mm_aesdeclast_si128

// Used instead if casting.
typedef union
{
   v128_t   v128;
   __m128i  m128;
   uint32_t u32[4];
} __attribute__ ((aligned (16))) m128_ovly;
#define v128_ovly   m128_ovly

// use for immediate constants, use load1 for mem.
#define v128_64                        _mm_set1_epi64x
#define v128_32                        _mm_set1_epi32
#define v128_16                        _mm_set1_epi16
#define v128_8                         _mm_set1_epi8

#define v128_set64                     _mm_set_epi64x
#define v128_set32                     _mm_set_epi32
#define v128_set16                     _mm_set_epi16
#define v128_set8                      _mm_set_epi8

// Deprecated. AVX512 adds EVEX encoding (3rd operand) and other improvements
// that make these functions either unnecessary or inefficient.
// In cases where an explicit move betweeen GP & SIMD registers is still
// necessary the cvt, set, or set1 intrinsics can be used allowing the
// compiler to exploit new features to produce optimum code.
// Currently only used internally and by Luffa.

static inline __m128i mm128_mov64_128( const uint64_t n )
{
  __m128i a;
#if defined(__AVX__)
  asm( "vmovq %1, %0\n\t" : "=x"(a) : "r"(n) );
#else
  asm( "movq %1, %0\n\t" : "=x"(a) : "r"(n) );
#endif
  return a;
}
//#define v128_mov64( u64 )              mm128_mov64_128( u64 )


static inline __m128i mm128_mov32_128( const uint32_t n )
{
  __m128i a;
#if defined(__AVX__)
  asm( "vmovd %1, %0\n\t" : "=x"(a) : "r"(n) );
#else  
  asm( "movd %1, %0\n\t" : "=x"(a) : "r"(n) );
#endif
  return a;
}

// broadcast lane 0 to all lanes
#define v128_bcast64(v)                 _mm_shuffle_epi32( v, 0x44 )
#define v128_bcast32(v)                 _mm_shuffle_epi32( v, 0x00 )

#if defined(__AVX2__)

#define v128_bcast16(v)                 _mm_broadcastw_epi16(v)

#else

#define v128_bcast16(v) \
   v128_bcast32( v128_or( v128_sl32( v, 16 ), v ) )

#endif

// broadcast lane l to all lanes
#define v128_replane64( v, l ) \
   ( (l) == 0 ) ? _mm_shuffle_epi32( v, 0x44 ) \
                : _mm_shuffle_epi32( v, 0xee )

#define v128_replane32( v, l ) \
    ( (l) == 0 ) ? _mm_shuffle_epi32( v, 0x00 ) \
  : ( (l) == 1 ) ? _mm_shuffle_epi32( v, 0x55 ) \
  : ( (l) == 2 ) ? _mm_shuffle_epi32( v, 0xaa ) \
  :                _mm_shuffle_epi32( v, 0xff )

// Pseudo constants
#define v128_zero                       _mm_setzero_si128()
#define m128_zero                       _mm_setzero_si128()


#if defined(__SSE4_1__)

// Bitwise AND, return 1 if result is all bits clear.
#define v128_and_eq0                    _mm_testz_si128

static inline int v128_cmpeq0( v128_t v )
{  return v128_and_eq0( v, v ); }

#endif

// Bitwise compare return 1 if all bits set.
#define v128_cmpeq1                      _mm_test_all ones

#define v128_one                         mm128_mov64_128( 1 )
#define m128_one_128                     v128_one

// ASM avoids the need to initialize return variable to avoid compiler warning.
// Macro abstracts function parentheses to look like an identifier.
static inline __m128i v128_neg1_fn()
{
   __m128i a;
#if defined(__AVX__) 
   asm( "vpcmpeqq %0, %0, %0\n\t" : "=x"(a) );
#else
   asm( "pcmpeqq %0, %0\n\t" : "=x"(a) );
#endif
   return a;
}
#define m128_neg1_fn                     v128_neg1_fn
#define v128_neg1                        v128_neg1_fn()
#define m128_neg1                        v128_neg1

//
// Vector pointer cast

// p = any aligned pointer
// returns p as pointer to vector type
#define castp_m128i(p)    ((__m128i*)(p))
#define castp_v128        castp_m128i
#define castp_v128u64     castp_v128
#define castp_v128u32     castp_v128
#define castp_v128u16     castp_v128
#define castp_v128u8      castp_v128

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_m128i(p)     (*((__m128i*)(p)))
#define cast_v128         cast_m128i
#define cast_v128u64      cast_v128
#define cast_v128u32      cast_v128
#define cast_v128u16      cast_v128
#define cast_v128u8       cast_v128

// p = any aligned pointer, i = scaled array index
// returns value p[i]
#define casti_m128i(p,i)   (((__m128i*)(p))[(i)])
#define casti_v128         casti_m128i
#define casti_v128u64      casti_v128
#define casti_v128u32      casti_v128
#define casti_v128u16      casti_v128
#define casti_v128u8       casti_v128

// p = any aligned pointer, o = scaled offset
// returns pointer p+o
#define casto_m128i(p,o) (((__m128i*)(p))+(o))

#if defined(__SSE4_1__)
#define v128_get64( v, l )         _mm_extract_epi64( v, l )
#define v128_get32( v, l )         _mm_extract_epi32( v, l )
#define v128_get16( v, l )         _mm_extract_epi16( v, l )
#define v128_get8(  v, l )         _mm_extract_epi8(  v, l )

#define v128_put64( v, u64, l )    _mm_insert_epi64( v, u64, l )
#define v128_put32( v, u32, l )    _mm_insert_epi64( v, u32, l )
#define v128_put16( v, u16, l )    _mm_insert_epi16( v, u16, l )
#define v128_put8(  v, u8,  l )    _mm_insert_epi8(  v, u8,  l )

/////////////////////////////////////////////////////////////
//
//      _mm_insert_ps( _mm128i v1, __m128i v2, imm8 c )
//
// Fast and powerful but very limited in its application.
// It requires SSE4.1 but only works with 128 bit vectors with 32 bit
// elements. There is no equivalent instruction for 256 bit or 512 bit vectors.
// There's no integer version. There's no 64 bit, 16 bit or byte element
// sizing. It's unique.
//
// It can:
//   - zero any number of 32 bit elements of a 128 bit vector.
//   - extract any 32 bit element from one 128 bit vector and insert the
//     data to any 32 bit element of another 128 bit vector, or the same vector.
//   - do both simultaneoulsly.
//
//   It can be used as a more efficient replacement for _mm_insert_epi32
//   or _mm_extract_epi32.
//
// Control byte definition:
//    c[3:0] zero mask
//    c[5:4] destination element selector
//    c[7:6] source element selector

// Convert type and abbreviate name: eXtract Insert Mask = XIM
#define mm128_xim_32( v1, v0, c ) \
   _mm_castps_si128( _mm_insert_ps( _mm_castsi128_ps( v1 ), \
                                    _mm_castsi128_ps( v0 ), c ) )

// Examples of simple operations using xim:
/*
// Copy i32 to element c of dest and copy remaining elemnts from v.
#define v128_put32( v, i32, c ) \
      mm128_xim_32( v, mm128_mov32_128( i32 ), (c)<<4 )
*/


#define mm128_mask_32( v, m )    mm128_xim_32( v, v, m )

// Zero 32 bit elements when corresponding bit in 4 bit mask is set.
//static inline __m128i mm128_mask_32( const __m128i v, const int m ) 
//{   return mm128_xim_32( v, v, m ); }
#define v128_mask32    mm128_mask_32

// Copy element i2 of v2 to element i1 of dest and copy remaining elements from v1.
#define v128_movlane32( v1, l1, v0, l0 ) \
  mm128_xim_32( v1, v0, ( (l1)<<4 ) | ( (l0)<<6 ) )

#endif  // SSE4_1

//
// Basic operations without equivalent SIMD intrinsic

// Bitwise not (~v)  
#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

static inline __m128i mm128_not( const __m128i v )
{  return _mm_ternarylogic_epi64( v, v, v, 1 ); }

#else

#define mm128_not( v )          _mm_xor_si128( v, m128_neg1 ) 

#endif
#define v128_not                mm128_not

static inline __m128i mm128_negate_64( __m128i v )
{ return _mm_sub_epi64( _mm_xor_si128( v, v ), v ); }
#define v128_negate64                 mm128_negate_64

static inline __m128i mm128_negate_32( __m128i v )
{ return _mm_sub_epi32( _mm_xor_si128( v, v ), v ); }
#define v128_negate32                 mm128_negate_32

static inline __m128i mm128_negate_16( __m128i v ) 
{ return _mm_sub_epi16( _mm_xor_si128( v, v ), v ); }
#define v128_negate16                 mm128_negate_16


// Add 4 values, fewer dependencies than sequential addition.
#define mm128_add4_64( a, b, c, d ) \
   _mm_add_epi64( _mm_add_epi64( a, b ), _mm_add_epi64( c, d ) )

#define mm128_add4_32( a, b, c, d ) \
   _mm_add_epi32( _mm_add_epi32( a, b ), _mm_add_epi32( c, d ) )
#define v128_add4_32                   mm128_add4_32

#define mm128_add4_16( a, b, c, d ) \
   _mm_add_epi16( _mm_add_epi16( a, b ), _mm_add_epi16( c, d ) )

#define mm128_add4_8( a, b, c, d ) \
   _mm_add_epi8( _mm_add_epi8( a, b ), _mm_add_epi8( c, d ) )

#define mm128_xor4( a, b, c, d ) \
   _mm_xor_si128( _mm_xor_si128( a, b ), _mm_xor_si128( c, d ) )

// Memory functions
// Mostly for convenience, avoids calculating bytes.
// Assumes data is alinged and integral.
// n = number of __m128i, bytes/16

static inline void memset_zero_128( __m128i *dst,  const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m128_zero; }
#define v128_memset_zero               memset_zero_128

static inline void memset_128( __m128i *dst, const __m128i a, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }
#define v128_memset                    memset_128

static inline void memcpy_128( __m128i *dst, const __m128i *src, const int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }
#define v128_memcpy                    memcpy_128

#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

// a ^ b ^ c
#define mm128_xor3( a, b, c )      _mm_ternarylogic_epi64( a, b, c, 0x96 )

// a & b & c
#define mm128_and3( a, b, c )      _mm_ternarylogic_epi64( a, b, c, 0x80 )

// a | b | c
#define mm128_or3( a, b, c )       _mm_ternarylogic_epi64( a, b, c, 0xfe )

// a ^ ( b & c )
#define mm128_xorand( a, b, c )    _mm_ternarylogic_epi64( a, b, c, 0x78 )

// a & ( b ^ c )
#define mm128_andxor( a, b, c )    _mm_ternarylogic_epi64( a, b, c, 0x60 )

// a ^ ( b | c )
#define mm128_xoror( a, b, c )     _mm_ternarylogic_epi64( a, b, c, 0x1e )

// a ^ ( ~b & c )
#define mm128_xorandnot( a, b, c ) _mm_ternarylogic_epi64( a, b, c, 0xd2 )

// a | ( b & c )
#define mm128_orand( a, b, c )     _mm_ternarylogic_epi64( a, b, c, 0xf8 )

// ~( a ^ b ), same as (~a) ^ b
#define mm128_xnor( a, b )         _mm_ternarylogic_epi64( a, b, b, 0x81 )

#else

#define mm128_xor3( a, b, c )      _mm_xor_si128( a, _mm_xor_si128( b, c ) )

#define mm128_and3( a, b, c )      _mm_and_si128( a, _mm_and_si128( b, c ) )

#define mm128_or3( a, b, c )       _mm_or_si128( a, _mm_or_si128( b, c ) )

#define mm128_xorand( a, b, c )    _mm_xor_si128( a, _mm_and_si128( b, c ) )

#define mm128_andxor( a, b, c )    _mm_and_si128( a, _mm_xor_si128( b, c ))

#define mm128_xoror( a, b, c )     _mm_xor_si128( a, _mm_or_si128( b, c ) )

#define mm128_xorandnot( a, b, c ) _mm_xor_si128( a, _mm_andnot_si128( b, c ) )

#define mm128_orand( a, b, c )     _mm_or_si128( a, _mm_and_si128( b, c ) )

#define mm128_xnor( a, b )         mm128_not( _mm_xor_si128( a, b ) )

#endif

// Mask making
// Equivalent of AVX512 _mm_movepi64_mask & _mm_movepi32_mask.
// Returns 2 or 4 bit integer mask from MSBit of 64 or 32 bit elements.
// Effectively a sign test.

#define mm128_movmask_64( v ) \
   _mm_movemask_pd( (__m128d)(v) )
#define v128_movmask64                 mm128_movmask_64

#define mm128_movmask_32( v ) \
   _mm_movemask_ps( (__m128)(v) )
#define v128_movmask32                 mm128_movmask_32

//
// Bit rotations

// Slow bit rotation, used as last resort
#define mm128_ror_64_sse2( v, c ) \
   _mm_or_si128( _mm_srli_epi64( v, c ), _mm_slli_epi64( v, 64-(c) ) )

#define mm128_rol_64_sse2( v, c ) \
   _mm_or_si128( _mm_slli_epi64( v, c ), _mm_srli_epi64( v, 64-(c) ) )

#define mm128_ror_32_sse2( v, c ) \
   _mm_or_si128( _mm_srli_epi32( v, c ), _mm_slli_epi32( v, 32-(c) ) )

#define mm128_rol_32_sse2( v, c ) \
   _mm_or_si128( _mm_slli_epi32( v, c ), _mm_srli_epi32( v, 32-(c) ) )

#if defined(__AVX512VL__)

#define mm128_ror_64    _mm_ror_epi64
#define mm128_rol_64    _mm_rol_epi64
#define mm128_ror_32    _mm_ror_epi32
#define mm128_rol_32    _mm_rol_epi32

// optimized byte wise rotation
#elif defined(__SSSE3__)

#define mm128_ror_64( v, c ) \
   ( (c) == 32 ) ? _mm_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 24 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0a09080f0e0d0c0b, 0x0201000706050403 ) ) \
 : ( (c) == 16 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x09080f0e0d0c0b0a, 0x0100070605040302 ) ) \
 : ( (c) ==  8 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x080f0e0d0c0b0a09, 0x0007060504030201 ) ) \
 : mm128_ror_64_sse2( v, c ) 

#define mm128_rol_64( v, c ) \
   ( (c) == 32 ) ? _mm_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 24 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0c0b0a09080f0e0d, 0x0403020100070605 ) ) \
 : ( (c) == 16 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0d0c0b0a09080f0e, 0x0504030201000706 ) ) \
 : ( (c) ==  8 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0e0d0c0b0a09080f, 0x0605040302010007 ) ) \
 : mm128_rol_64_sse2( v, c ) 

#define mm128_ror_32( v, c ) \
   ( (c) == 16 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0d0c0f0e09080b0a, 0x0504070601000302 ) ) \
 : ( (c) ==  8 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0c0f0e0d080b0a09, 0x0407060500030201 ) ) \
 : mm128_ror_32_sse2( v, c ) 

#define mm128_rol_32( v, c ) \
   ( (c) == 16 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0d0c0f0e09080b0a, 0x0504070601000302 ) ) \
 : ( (c) ==  8 ) ? _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0e0d0c0f0a09080b, 0x0605040702010003 ) ) \
 : mm128_rol_32_sse2( v, c )

#else 

#define mm128_ror_64         mm128_ror_64_sse2
#define mm128_rol_64         mm128_rol_64_sse2
#define mm128_ror_32         mm128_ror_32_sse2
#define mm128_rol_32         mm128_rol_32_sse2

#endif

// Architecturally agnostic naming
#define v128_ror64            mm128_ror_64
#define v128_rol64            mm128_rol_64
#define v128_ror32            mm128_ror_32
#define v128_rol32            mm128_rol_32


// x2 rotates elements in 2 individual vectors in a double buffered
// optimization for SSE2, does nothing for AVX512 but is there for
// transparency.

#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

#define mm128_rorx2_64( v1, v0, c ) \
   _mm_ror_epi64( v0, c ); \
   _mm_ror_epi64( v1, c )

#define mm128_rolx2_64( v1, v0, c ) \
   _mm_rol_epi64( v0, c ); \
   _mm_rol_epi64( v1, c )

#define mm128_rorx2_32( v1, v0, c ) \
   _mm_ror_epi32( v0, c ); \
   _mm_ror_epi32( v1, c )

#define mm128_rolx2_32( v1, v0, c ) \
   _mm_rol_epi32( v0, c ); \
   _mm_rol_epi32( v1, c )

#else  // SSE2

#define mm128_rorx2_64( v1, v0, c ) \
{ \
 __m128i t0 = _mm_srli_epi64( v0, c ); \
 __m128i t1 = _mm_srli_epi64( v1, c ); \
 v0 = _mm_slli_epi64( v0, 64-(c) ); \
 v1 = _mm_slli_epi64( v1, 64-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#define mm128_rolx2_64( v1, v0, c ) \
{ \
 __m128i t0 = _mm_slli_epi64( v0, c ); \
 __m128i t1 = _mm_slli_epi64( v1, c ); \
 v0 = _mm_srli_epi64( v0, 64-(c) ); \
 v1 = _mm_srli_epi64( v1, 64-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#define mm128_rorx2_32( v1, v0, c ) \
{ \
 __m128i t0 = _mm_srli_epi32( v0, c ); \
 __m128i t1 = _mm_srli_epi32( v1, c ); \
 v0 = _mm_slli_epi32( v0, 32-(c) ); \
 v1 = _mm_slli_epi32( v1, 32-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#define mm128_rolx2_32( v1, v0, c ) \
{ \
 __m128i t0 = _mm_slli_epi32( v0, c ); \
 __m128i t1 = _mm_slli_epi32( v1, c ); \
 v0 = _mm_srli_epi32( v0, 32-(c) ); \
 v1 = _mm_srli_epi32( v1, 32-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#endif   // AVX512 else SSE2

#define v128_2ror64            mm128_rorx2_64
#define v128_2rol64            mm128_rolx2_64
#define v128_2ror32            mm128_rorx2_32
#define v128_2rol32            mm128_rolx2_32


// Cross lane shuffles

#define v128_shuffle32     _mm_shuffle_epi32

// shuffle using vector mask, for compatibility with NEON
#define v128_shufflev32( v, vmask ) \
  v128_shuffle32( v, mm128_movmask_32( vmask ) )

#define v128_shuffle8     _mm_shuffle_epi8

// Limited 2 input shuffle, combines shuffle with blend. The destination low
// half is always taken from v1, and the high half from v2.
#define v128_shuffle2_64( v1, v2, c ) \
   _mm_castpd_si128( _mm_shuffle_pd( _mm_castsi128_pd( v1 ), \
                                     _mm_castsi128_pd( v2 ), c ) ); 
#define mm128_shuffle2_64   v128_shuffle2_64

#define v128_shuffle2_32( v1, v2, c ) \
   _mm_castps_si128( _mm_shuffle_ps( _mm_castsi128_ps( v1 ), \
                                     _mm_castsi128_ps( v2 ), c ) ); 
#define mm128_shuffle2_32   v128_shuffle2_32

// Rotate vector elements accross all lanes

#define v128_shuffle16( v, c ) \
   _mm_or_si128( _mm_shufflehi_epi16( v, c ), _mm_shufflelo_epi16( v, c ) )

// reverse elements in vector
#define v128_swap64(v)      _mm_shuffle_epi32( v, 0x4e )  // grandfathered 
#define v128_rev64(v)       _mm_shuffle_epi32( v, 0x4e )  // preferred
#define v128_rev32(v)       _mm_shuffle_epi32( v, 0x1b )
#define v128_rev16(v)       v128_shuffle16( v, 0x1b )

// rotate vector elements
#define v128_shuflr32(v)    _mm_shuffle_epi32( v, 0x39 )
#define v128_shufll32(v)    _mm_shuffle_epi32( v, 0x93 )

#define v128_shuflr16(v)    v128_shuffle16( v, 0x39 )
#define v128_shufll16(v)    v128_shuffle16( v, 0x93 )

// Some sub-vector shuffles are identical to bit rotation. Shuffle is faster.
// Bit rotation already promotes faster widths. Usage of these versions
// are context sensitive.

// reverse elements in vector lanes
#define v128_qrev32(v)      v128_ror64( v, 32 )
#define v128_swap64_32(v)   v128_ror64( v, 32 )   // grandfathered

#define v128_qrev16(v) \
    _mm_or_si128( _mm_shufflehi_epi16( v, v128u16( 0x1b ) ) \
                  _mm_shufflelo_epi16( v, v128u16( 0x1b ) ) )

#define v128_lrev16(v)      v128_ror32( v, 16 )

// alias bswap
#define v128_qrev8(v)       _mm_shuffle_epi8( v, v128_8( 0,1,2,3,4,5,6,7 ) )
#define v128_lrev8(v)       _mm_shuffle_epi8( v, v128_8( 4,5,6,7, 0,1,2,3 ) )
#define v128_wrev8(v)       _mm_shuffle_epi8( v, v128_8( 6,7, 4,5, 2,3, 1,0 ) )
   
// reverse bits, can it be done?
//#define v128_bitrev8( v )              vrbitq_u8

/* Not used
#if defined(__SSSE3__)

// Rotate right by c bytes, no SSE2 equivalent.
static inline __m128i mm128_shuflr_x8( const __m128i v, const int c )
{ return _mm_alignr_epi8( v, v, c ); }

#endif
*/

// Endian byte swap.

#if defined(__SSSE3__)

#define mm128_bswap_128( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x0001020304050607, \
                                        0x08090a0b0c0d0e0f ) )

#define mm128_bswap_64( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x08090a0b0c0d0e0f, \
                                        0x0001020304050607 ) )

#define mm128_bswap_32( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x0c0d0e0f08090a0b, \
                                        0x0405060700010203 ) )

#define mm128_bswap_16( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x0e0f0c0d0a0b0809, \
                                        0x0607040502030001 )

// 8 byte qword * 8 qwords * 2 lanes = 128 bytes
#define mm128_block_bswap_64( d, s ) \
{ \
   __m128i ctl = _mm_set_epi64x(  0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  casti_m128i( d,0 ) = _mm_shuffle_epi8( casti_m128i( s,0 ), ctl ); \
  casti_m128i( d,1 ) = _mm_shuffle_epi8( casti_m128i( s,1 ), ctl ); \
  casti_m128i( d,2 ) = _mm_shuffle_epi8( casti_m128i( s,2 ), ctl ); \
  casti_m128i( d,3 ) = _mm_shuffle_epi8( casti_m128i( s,3 ), ctl ); \
  casti_m128i( d,4 ) = _mm_shuffle_epi8( casti_m128i( s,4 ), ctl ); \
  casti_m128i( d,5 ) = _mm_shuffle_epi8( casti_m128i( s,5 ), ctl ); \
  casti_m128i( d,6 ) = _mm_shuffle_epi8( casti_m128i( s,6 ), ctl ); \
  casti_m128i( d,7 ) = _mm_shuffle_epi8( casti_m128i( s,7 ), ctl ); \
}
#define mm128_block_bswap64_512    mm128_block_bswap_64
#define v128_block_bswap64_512     mm128_block_bswap_64

#define v128_block_bswap64_1024( d, s ) \
{ \
   __m128i ctl = _mm_set_epi64x(  0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  casti_m128i( d, 0 ) = _mm_shuffle_epi8( casti_m128i( s, 0 ), ctl ); \
  casti_m128i( d, 1 ) = _mm_shuffle_epi8( casti_m128i( s, 1 ), ctl ); \
  casti_m128i( d, 2 ) = _mm_shuffle_epi8( casti_m128i( s, 2 ), ctl ); \
  casti_m128i( d, 3 ) = _mm_shuffle_epi8( casti_m128i( s, 3 ), ctl ); \
  casti_m128i( d, 4 ) = _mm_shuffle_epi8( casti_m128i( s, 4 ), ctl ); \
  casti_m128i( d, 5 ) = _mm_shuffle_epi8( casti_m128i( s, 5 ), ctl ); \
  casti_m128i( d, 6 ) = _mm_shuffle_epi8( casti_m128i( s, 6 ), ctl ); \
  casti_m128i( d, 7 ) = _mm_shuffle_epi8( casti_m128i( s, 7 ), ctl ); \
  casti_m128i( d, 8 ) = _mm_shuffle_epi8( casti_m128i( s, 8 ), ctl ); \
  casti_m128i( d, 9 ) = _mm_shuffle_epi8( casti_m128i( s, 9 ), ctl ); \
  casti_m128i( d,10 ) = _mm_shuffle_epi8( casti_m128i( s,10 ), ctl ); \
  casti_m128i( d,11 ) = _mm_shuffle_epi8( casti_m128i( s,11 ), ctl ); \
  casti_m128i( d,12 ) = _mm_shuffle_epi8( casti_m128i( s,12 ), ctl ); \
  casti_m128i( d,13 ) = _mm_shuffle_epi8( casti_m128i( s,13 ), ctl ); \
  casti_m128i( d,14 ) = _mm_shuffle_epi8( casti_m128i( s,14 ), ctl ); \
  casti_m128i( d,15 ) = _mm_shuffle_epi8( casti_m128i( s,15 ), ctl ); \
}

// 4 byte dword * 8 dwords * 4 lanes = 128 bytes
#define mm128_block_bswap_32( d, s ) \
{ \
   __m128i ctl = _mm_set_epi64x( 0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_m128i( d,0 ) = _mm_shuffle_epi8( casti_m128i( s,0 ), ctl ); \
  casti_m128i( d,1 ) = _mm_shuffle_epi8( casti_m128i( s,1 ), ctl ); \
  casti_m128i( d,2 ) = _mm_shuffle_epi8( casti_m128i( s,2 ), ctl ); \
  casti_m128i( d,3 ) = _mm_shuffle_epi8( casti_m128i( s,3 ), ctl ); \
  casti_m128i( d,4 ) = _mm_shuffle_epi8( casti_m128i( s,4 ), ctl ); \
  casti_m128i( d,5 ) = _mm_shuffle_epi8( casti_m128i( s,5 ), ctl ); \
  casti_m128i( d,6 ) = _mm_shuffle_epi8( casti_m128i( s,6 ), ctl ); \
  casti_m128i( d,7 ) = _mm_shuffle_epi8( casti_m128i( s,7 ), ctl ); \
}
#define mm128_block_bswap32_256      mm128_block_bswap_32
#define v128_block_bswap32_256       mm128_block_bswap_32

#define v128_block_bswap32_512( d, s ) \
{ \
   __m128i ctl = _mm_set_epi64x( 0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_m128i( d, 0 ) = _mm_shuffle_epi8( casti_m128i( s, 0 ), ctl ); \
  casti_m128i( d, 1 ) = _mm_shuffle_epi8( casti_m128i( s, 1 ), ctl ); \
  casti_m128i( d, 2 ) = _mm_shuffle_epi8( casti_m128i( s, 2 ), ctl ); \
  casti_m128i( d, 3 ) = _mm_shuffle_epi8( casti_m128i( s, 3 ), ctl ); \
  casti_m128i( d, 4 ) = _mm_shuffle_epi8( casti_m128i( s, 4 ), ctl ); \
  casti_m128i( d, 5 ) = _mm_shuffle_epi8( casti_m128i( s, 5 ), ctl ); \
  casti_m128i( d, 6 ) = _mm_shuffle_epi8( casti_m128i( s, 6 ), ctl ); \
  casti_m128i( d, 7 ) = _mm_shuffle_epi8( casti_m128i( s, 7 ), ctl ); \
  casti_m128i( d, 8 ) = _mm_shuffle_epi8( casti_m128i( s, 8 ), ctl ); \
  casti_m128i( d, 9 ) = _mm_shuffle_epi8( casti_m128i( s, 9 ), ctl ); \
  casti_m128i( d,10 ) = _mm_shuffle_epi8( casti_m128i( s,10 ), ctl ); \
  casti_m128i( d,11 ) = _mm_shuffle_epi8( casti_m128i( s,11 ), ctl ); \
  casti_m128i( d,12 ) = _mm_shuffle_epi8( casti_m128i( s,12 ), ctl ); \
  casti_m128i( d,13 ) = _mm_shuffle_epi8( casti_m128i( s,13 ), ctl ); \
  casti_m128i( d,14 ) = _mm_shuffle_epi8( casti_m128i( s,14 ), ctl ); \
  casti_m128i( d,15 ) = _mm_shuffle_epi8( casti_m128i( s,15 ), ctl ); \
}

#else  // SSE2

static inline __m128i mm128_bswap_64( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
}

static inline __m128i mm128_bswap_32( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
}

static inline __m128i mm128_bswap_16( __m128i v )
{
  return _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
}

#define mm128_bswap_128( v )   v128_qrev32( v128_bswap64( v ) )

static inline void mm128_block_bswap_64( __m128i *d, const __m128i *s )
{
   d[0] = mm128_bswap_64( s[0] );
   d[1] = mm128_bswap_64( s[1] );
   d[2] = mm128_bswap_64( s[2] );
   d[3] = mm128_bswap_64( s[3] );
   d[4] = mm128_bswap_64( s[4] );
   d[5] = mm128_bswap_64( s[5] );
   d[6] = mm128_bswap_64( s[6] );
   d[7] = mm128_bswap_64( s[7] );
}
#define v128_block_bswap64_512 mm128_block_bswap_64

static inline void mm128_block_bswap64_1024( __m128i *d, const __m128i *s )
{
   d[ 0] = mm128_bswap_64( s[ 0] );
   d[ 1] = mm128_bswap_64( s[ 1] );
   d[ 2] = mm128_bswap_64( s[ 2] );
   d[ 3] = mm128_bswap_64( s[ 3] );
   d[ 4] = mm128_bswap_64( s[ 4] );
   d[ 5] = mm128_bswap_64( s[ 5] );
   d[ 6] = mm128_bswap_64( s[ 6] );
   d[ 7] = mm128_bswap_64( s[ 7] );
   d[ 8] = mm128_bswap_64( s[ 8] );
   d[ 9] = mm128_bswap_64( s[ 9] );
   d[10] = mm128_bswap_64( s[10] );
   d[11] = mm128_bswap_64( s[11] );
   d[14] = mm128_bswap_64( s[12] );
   d[13] = mm128_bswap_64( s[13] );
   d[14] = mm128_bswap_64( s[14] );
   d[15] = mm128_bswap_64( s[15] );
}

static inline void mm128_block_bswap_32( __m128i *d, const __m128i *s )
{
   d[0] = mm128_bswap_32( s[0] );
   d[1] = mm128_bswap_32( s[1] );
   d[2] = mm128_bswap_32( s[2] );
   d[3] = mm128_bswap_32( s[3] );
   d[4] = mm128_bswap_32( s[4] );
   d[5] = mm128_bswap_32( s[5] );
   d[6] = mm128_bswap_32( s[6] );
   d[7] = mm128_bswap_32( s[7] );
}
#define mm128_block_bswap32_256 mm128_block_bswap_32
#define v128_block_bswap32_256  mm128_block_bswap_32

static inline void mm128_block_bswap32_512( __m128i *d, const __m128i *s )
{
   d[ 0] = mm128_bswap_32( s[ 0] );
   d[ 1] = mm128_bswap_32( s[ 1] );
   d[ 2] = mm128_bswap_32( s[ 2] );
   d[ 3] = mm128_bswap_32( s[ 3] );
   d[ 4] = mm128_bswap_32( s[ 4] );
   d[ 5] = mm128_bswap_32( s[ 5] );
   d[ 6] = mm128_bswap_32( s[ 6] );
   d[ 7] = mm128_bswap_32( s[ 7] );
   d[ 8] = mm128_bswap_32( s[ 8] );
   d[ 9] = mm128_bswap_32( s[ 9] );
   d[10] = mm128_bswap_32( s[10] );
   d[11] = mm128_bswap_32( s[11] );
   d[12] = mm128_bswap_32( s[12] );
   d[13] = mm128_bswap_32( s[13] );
   d[14] = mm128_bswap_32( s[14] );
   d[15] = mm128_bswap_32( s[15] );
}

#endif // SSSE3 else SSE2

#define v128_bswap32                   mm128_bswap_32
#define v128_bswap64                   mm128_bswap_64
#define v128_bswap128                  mm128_bswap_128
#define v128_block_bswap32             mm128_block_bswap_32
#define v128_block_bswap64             mm128_block_bswap_64


// alignr instruction for 32 & 64 bit elements is only available with AVX512
// but emulated here. Behaviour is consistent with Intel alignr intrinsics.

#if defined(__SSSE3__)

#define mm128_alignr_64( hi, lo, c )    _mm_alignr_epi8( hi, lo, (c)*8 )
#define mm128_alignr_32( hi, lo, c )    _mm_alignr_epi8( hi, lo, (c)*4 )

#else

#define mm128_alignr_64( hi, lo, c ) \
   _mm_or_si128( _mm_slli_si128( hi, (c)*8 ), _mm_srli_si128( lo, (c)*8 ) )

#define mm128_alignr_32( hi, lo, c ) \
   _mm_or_si128( _mm_slli_si128( lo, (c)*4 ), _mm_srli_si128( hi, (c)*4 ) )

#endif

// NEON only uses vector mask. x86 blend selects second arg when control bit
// is set. Blendv selects second arg when sign bit is set. And masking is the
// opposite, elements are selected from the first arg if the mask bits are set.
// Arm blend is a bit by bit blend while x76 is an elenet blend.
// Reverse the logic so the use mask is consistent with both formats.
#if defined(__SSE4_1__)

#define v128_blendv                    _mm_blendv_epi8

#else

#define v128_blendv( v1, v0, mask ) \
   v128_or( v128_andnot( mask, v0 ), v128_and( mask, v1 ) )

#endif

#endif // __SSE2__
#endif // SIMD_128_H__
