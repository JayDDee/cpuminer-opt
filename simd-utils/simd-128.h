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
//
//           __m128i -> v128_t
//           _mm_    -> v128_
//           mm128_  -> v128_
// 
//    There is also new syntax to accomodate ARM's stricter type checking of
//    vector element size. They have no effect on x86_64.

// direct translation of native intrinsics

#define v128_t                         __m128i 
#define v128u64_t                      v128_t
#define v128u32_t                      v128_t
#define v128u16_t                      v128_t
#define v128u8_t                       v128_t

#define v128_load                      _mm_load_si128
#define v128_store                     _mm_store_si128

// Needed for ARM, Doesn't do anything special on x86_64
#define v128_load1_64(p)               _mm_set1_epi64x(*(uint64_t*)(p) )
#define v128_load1_32(p)               _mm_set1_epi32( *(uint32_t*)(p) )
#define v128_load1_16(p)               _mm_set1_epi16( *(uint16_t*)(p) )
#define v128_load1_8( p)               _mm_set1_epi8(  *(uint8_t*) (p) )

// arithmetic
#define v128_add64                     _mm_add_epi64
#define v128_add32                     _mm_add_epi32
#define v128_add16                     _mm_add_epi16
#define v128_add8                      _mm_add_epi8

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

// signed compare
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
// Nokey means nothing on x86_64 but it saves an instruction and a register
// on ARM.
#define v128_aesenc                    _mm_aesenc_si128
#define v128_aesenc_nokey(v)           _mm_aesenc_si128( v, v128_zero )
#define v128_aesenclast                _mm_aesenclast_si128
#define v128_aesenclast_nokey(v)       _mm_aesenclast_si128( v, v128_zero )
#define v128_aesdec                    _mm_aesdec_si128
#define v128_aesdec_nokey(v)           _mm_aesdec_si128( v, v128_zero )
#define v128_aesdeclast                _mm_aesdeclast_si128
#define v128_aesdeclast_nokey(v)       _mm_aesdeclast_si128( v, v128_zero )

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

// broadcast (replicate) lane l to all lanes
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

#if defined(__SSE4_1__)

// Bitwise AND, return 1 if result is all bits clear.
#define v128_and_eq0(v1, v0)            _mm_testz_si128(v1, v0)

// v128_is_zero?
static inline int v128_cmpeq0( v128_t v )
{  return v128_and_eq0( v, v ); }

#endif

// Bitwise compare return 1 if all bits set.
#define v128_cmpeq1(v)                   _mm_test_all ones(v)

#define v128_one                         mm128_mov64_128(1)

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
#define v128_neg1                        v128_neg1_fn()

//
// Vector pointer cast

// p = any aligned pointer
// returns p as pointer to vector type
#define castp_v128(p)     ((__m128i*)(p))
#define castp_v128u64     castp_v128
#define castp_v128u32     castp_v128
#define castp_v128u16     castp_v128
#define castp_v128u8      castp_v128

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_v128(p)      (*((__m128i*)(p)))
#define cast_v128u64      cast_v128
#define cast_v128u32      cast_v128
#define cast_v128u16      cast_v128
#define cast_v128u8       cast_v128

// p = any aligned pointer, i = scaled array index
// returns value p[i]
#define casti_v128(p,i)    (((__m128i*)(p))[(i)])
#define casti_m128i        casti_v128     // deprecated
#define casti_v128u64      casti_v128
#define casti_v128u32      casti_v128
#define casti_v128u16      casti_v128
#define casti_v128u8       casti_v128

// p = any aligned pointer, o = scaled offset
// returns pointer p+o
#define casto_v128(p,o) (((__m128i*)(p))+(o))

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
//      _mm_insert_ps( __m128i v1, __m128i v2, imm8 c )
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
#define v128_xim32( v1, v0, c ) \
   _mm_castps_si128( _mm_insert_ps( _mm_castsi128_ps( v1 ), \
                                    _mm_castsi128_ps( v0 ), c ) )

// Examples of simple operations using xim:
/*
// Copy i32 to element c of dest and copy remaining elemnts from v.
#define v128_put32( v, i32, c ) \
      v128_xim_32( v, mm128_mov32_128( i32 ), (c)<<4 )
*/


#define v128_mask32( v, m )    v128_xim32( v, v, m & 0xf )

// Zero 32 bit elements when corresponding bit in 4 bit mask is set.
//static inline __m128i v128_mask32( const __m128i v, const int m ) 
//{   return v128_xim32( v, v, m ); }

// Copy element l0 of v0 to element l1 of dest and copy remaining elements from v1.
#define v128_movlane32( v1, l1, v0, l0 ) \
  v128_xim32( v1, v0, ( (l1)<<4 ) | ( (l0)<<6 ) )

#endif  // SSE4_1

//
// Basic operations without equivalent SIMD intrinsic

// Bitwise not (~v)  
#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

static inline __m128i v128_not( const __m128i v )
{  return _mm_ternarylogic_epi64( v, v, v, 1 ); }

#else

#define v128_not( v )          _mm_xor_si128( v, v128_neg1 ) 

#endif

static inline v128u64_t v128_negate_64( v128u64_t v )
{ return _mm_sub_epi64( _mm_xor_si128( v, v ), v ); }

static inline v128u32_t v128_negate_32( v128u32_t v )
{ return _mm_sub_epi32( _mm_xor_si128( v, v ), v ); }

static inline v128u16_t v128_negate_16( v128u16_t v ) 
{ return _mm_sub_epi16( _mm_xor_si128( v, v ), v ); }


// Add 4 values, fewer dependencies than sequential addition.
#define v128_add4_64( a, b, c, d ) \
   _mm_add_epi64( _mm_add_epi64( a, b ), _mm_add_epi64( c, d ) )

#define v128_add4_32( a, b, c, d ) \
   _mm_add_epi32( _mm_add_epi32( a, b ), _mm_add_epi32( c, d ) )

#define v128_add4_16( a, b, c, d ) \
   _mm_add_epi16( _mm_add_epi16( a, b ), _mm_add_epi16( c, d ) )

#define v128_add4_8( a, b, c, d ) \
   _mm_add_epi8( _mm_add_epi8( a, b ), _mm_add_epi8( c, d ) )

#define v128_xor4( a, b, c, d ) \
   _mm_xor_si128( _mm_xor_si128( a, b ), _mm_xor_si128( c, d ) )


// Memory functions
// Mostly for convenience, avoids calculating bytes.
// Assumes data is alinged and integral.
// n = number of __m128i, bytes/16

static inline void v128_memset_zero( v128_t *dst,  const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = v128_zero; }
#define memset_zero_128      v128_memset_zero

static inline void v128_memset( v128_t *dst, const v128_t a, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void v128_memcpy( v128_t *dst, const v128_t *src, const int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }
#define  memcpy_128           v128_memcpy  

#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

// a ^ b ^ c
#define v128_xor3( a, b, c )      _mm_ternarylogic_epi64( a, b, c, 0x96 )

// a & b & c
#define v128_and3( a, b, c )      _mm_ternarylogic_epi64( a, b, c, 0x80 )

// a | b | c
#define v128_or3( a, b, c )       _mm_ternarylogic_epi64( a, b, c, 0xfe )

// a ^ ( b & c )
#define v128_xorand( a, b, c )    _mm_ternarylogic_epi64( a, b, c, 0x78 )

// a & ( b ^ c )
#define v128_andxor( a, b, c )    _mm_ternarylogic_epi64( a, b, c, 0x60 )

// a ^ ( b | c )
#define v128_xoror( a, b, c )     _mm_ternarylogic_epi64( a, b, c, 0x1e )

// a ^ ( ~b & c )
#define v128_xorandnot( a, b, c ) _mm_ternarylogic_epi64( a, b, c, 0xd2 )

// a | ( b & c )
#define v128_orand( a, b, c )     _mm_ternarylogic_epi64( a, b, c, 0xf8 )

// ~( a ^ b ), same as (~a) ^ b
#define v128_xnor( a, b )         _mm_ternarylogic_epi64( a, b, b, 0x81 )

#else

#define v128_xor3( a, b, c )      _mm_xor_si128( a, _mm_xor_si128( b, c ) )

#define v128_and3( a, b, c )      _mm_and_si128( a, _mm_and_si128( b, c ) )

#define v128_or3( a, b, c )       _mm_or_si128( a, _mm_or_si128( b, c ) )

#define v128_xorand( a, b, c )    _mm_xor_si128( a, _mm_and_si128( b, c ) )

#define v128_andxor( a, b, c )    _mm_and_si128( a, _mm_xor_si128( b, c ))

#define v128_xoror( a, b, c )     _mm_xor_si128( a, _mm_or_si128( b, c ) )

#define v128_xorandnot( a, b, c ) _mm_xor_si128( a, _mm_andnot_si128( b, c ) )

#define v128_orand( a, b, c )     _mm_or_si128( a, _mm_and_si128( b, c ) )

#define v128_xnor( a, b )         v128_not( _mm_xor_si128( a, b ) )

#endif

#define v128_ornot( a, b )             _mm_or_si128( a, v128_not( b ) )

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

#define v128_shuffle16( v, c ) \
       _mm_shufflehi_epi16( _mm_shufflelo_epi16( v, c ), c )

#define v128_qrev32(v)      _mm_shuffle_epi32( v, 0xb1 )
#define v128_swap64_32(v)   _mm_shuffle_epi32( v, 0xb1 )  // grandfathered

#define v128_qrev16(v)      v128_shuffle16( v, 0x1b )
#define v128_lrev16(v)      v128_shuffle16( v, 0xb1 )

// Internal use only, should never be callled from application code.
#define v128_ror64_sse2( v, c ) \
   _mm_or_si128( _mm_srli_epi64( v, c ), _mm_slli_epi64( v, 64-(c) ) )

#define v128_rol64_sse2( v, c ) \
   _mm_or_si128( _mm_slli_epi64( v, c ), _mm_srli_epi64( v, 64-(c) ) )

#define v128_ror32_sse2( v, c ) \
   _mm_or_si128( _mm_srli_epi32( v, c ), _mm_slli_epi32( v, 32-(c) ) )

#define v128_rol32_sse2( v, c ) \
   _mm_or_si128( _mm_slli_epi32( v, c ), _mm_srli_epi32( v, 32-(c) ) )

#if defined(__AVX512VL__)

// AVX512 fastest for all rotations.
#define v128_ror64                _mm_ror_epi64
#define v128_rol64                _mm_rol_epi64
#define v128_ror32                _mm_ror_epi32
#define v128_rol32                _mm_rol_epi32

// ror/rol will always find the fastest but these names may fit better with
// application code performing byte operations rather than bit rotations.
#define v128_shuflr64_8( v)         _mm_ror_epi64( v,  8 )
#define v128_shufll64_8( v)         _mm_rol_epi64( v,  8 )
#define v128_shuflr64_16(v)         _mm_ror_epi64( v, 16 )
#define v128_shufll64_16(v)         _mm_rol_epi64( v, 16 )
#define v128_shuflr64_24(v)         _mm_ror_epi64( v, 24 )
#define v128_shufll64_24(v)         _mm_rol_epi64( v, 24 )
#define v128_shuflr32_8( v)         _mm_ror_epi32( v,  8 )
#define v128_shufll32_8( v)         _mm_rol_epi32( v,  8 )
#define v128_shuflr32_16(v)         _mm_ror_epi32( v, 16 )
#define v128_shufll32_16(v)         _mm_rol_epi32( v, 16 )

#elif defined(__SSSE3__)
// SSSE3: fastest 32 bit, very fast 16, fast 8

#define v128_shuflr64_8( v ) \
    _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x080f0e0d0c0b0a09, 0x0007060504030201 ) )

#define v128_shufll64_8( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0e0d0c0b0a09080f, 0x0605040302010007 ) )

#define v128_shuflr64_24( v ) \
    _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0a09080f0e0d0c0b, 0x0201000706050403 ) )

#define v128_shufll64_24( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0c0b0a09080f0e0d, 0x0403020100070605 ) )

#define v128_shuflr32_8( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0c0f0e0d080b0a09, 0x0407060500030201 ) )

#define v128_shufll32_8( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( \
                                  0x0e0d0c0f0a09080b, 0x0605040702010003 ) )

#define v128_ror64( v, c ) \
   ( (c) ==  8 ) ? v128_shuflr64_8( v ) \
 : ( (c) == 16 ) ? v128_shuffle16( v, 0x39 ) \
 : ( (c) == 24 ) ? v128_shuflr64_24( v ) \
 : ( (c) == 32 ) ? _mm_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 40 ) ? v128_shufll64_24( v ) \
 : ( (c) == 48 ) ? v128_shuffle16( v, 0x93 ) \
 : ( (c) == 56 ) ? v128_shufll64_8( v ) \
 : v128_ror64_sse2( v, c ) 

#define v128_rol64( v, c ) \
   ( (c) ==  8 ) ? v128_shufll64_8( v ) \
 : ( (c) == 16 ) ? v128_shuffle16( v, 0x93 ) \
 : ( (c) == 24 ) ? v128_shufll64_24( v ) \
 : ( (c) == 32 ) ? _mm_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 40 ) ? v128_shuflr64_24( v ) \
 : ( (c) == 48 ) ? v128_shuffle16( v, 0x39 ) \
 : ( (c) == 56 ) ? v128_shuflr64_8( v ) \
 : v128_rol64_sse2( v, c ) 

#define v128_ror32( v, c ) \
   ( (c) ==  8 ) ? v128_shuflr32_8( v ) \
 : ( (c) == 16 ) ? v128_lrev16( v ) \
 : ( (c) == 24 ) ? v128_shufll32_8( v ) \
 : v128_ror32_sse2( v, c ) 

#define v128_rol32( v, c ) \
   ( (c) ==  8 ) ? v128_shufll32_8( v ) \
 : ( (c) == 16 ) ? v128_lrev16( v ) \
 : ( (c) == 24 ) ? v128_shuflr32_8( v ) \
 : v128_rol32_sse2( v, c )

#elif defined(__SSE2__)
// SSE2: fastest 32 bit, very fast 16, all else slow

#define v128_ror64( v, c ) \
   ( (c) == 16 ) ? v128_shuffle16( v, 0x39 ) \
 : ( (c) == 32 ) ? _mm_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 48 ) ? v128_shuffle16( v, 0x93 ) \
 : v128_ror64_sse2( v, c )

#define v128_rol64( v, c ) \
   ( (c) == 16 ) ? v128_shuffle16( v, 0x93 ) \
 : ( (c) == 32 ) ? _mm_shuffle_epi32( v, 0xb1 ) \
 : ( (c) == 48 ) ? v128_shuffle16( v, 0x39 ) \
 : v128_rol64_sse2( v, c )

#define v128_ror32( v, c ) \
  ( (c) == 16 ) ? v128_lrev16( v ) \
 : v128_ror32_sse2( v, c )

#define v128_rol32( v, c ) \
  ( (c) == 16 ) ? v128_lrev16( v ) \
 : v128_rol32_sse2( v, c )

#else 

#define v128_ror64         v128_ror64_sse2
#define v128_rol64         v128_rol64_sse2
#define v128_ror32         v128_ror32_sse2
#define v128_rol32         v128_rol32_sse2

#endif

// deprecated
#define mm128_rol_32        v128_rol32

/* not used
// x2 rotates elements in 2 individual vectors in a double buffered
// optimization for SSE2, does nothing for AVX512 but is there for
// transparency.

#if defined(__AVX512VL__)
//TODO Enable for AVX10_256

#define v128_2ror64( v1, v0, c ) \
   _mm_ror_epi64( v0, c ); \
   _mm_ror_epi64( v1, c )

#define v128_2rol64( v1, v0, c ) \
   _mm_rol_epi64( v0, c ); \
   _mm_rol_epi64( v1, c )

#define v128_2ror32( v1, v0, c ) \
   _mm_ror_epi32( v0, c ); \
   _mm_ror_epi32( v1, c )

#define v128_2rol32( v1, v0, c ) \
   _mm_rol_epi32( v0, c ); \
   _mm_rol_epi32( v1, c )

#else  // SSE2

#define v128_2ror64( v1, v0, c ) \
{ \
 __m128i t0 = _mm_srli_epi64( v0, c ); \
 __m128i t1 = _mm_srli_epi64( v1, c ); \
 v0 = _mm_slli_epi64( v0, 64-(c) ); \
 v1 = _mm_slli_epi64( v1, 64-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#define v128_2rol64( v1, v0, c ) \
{ \
 __m128i t0 = _mm_slli_epi64( v0, c ); \
 __m128i t1 = _mm_slli_epi64( v1, c ); \
 v0 = _mm_srli_epi64( v0, 64-(c) ); \
 v1 = _mm_srli_epi64( v1, 64-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#define v128_2ror32( v1, v0, c ) \
{ \
 __m128i t0 = _mm_srli_epi32( v0, c ); \
 __m128i t1 = _mm_srli_epi32( v1, c ); \
 v0 = _mm_slli_epi32( v0, 32-(c) ); \
 v1 = _mm_slli_epi32( v1, 32-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#define v128_2rol32( v1, v0, c ) \
{ \
 __m128i t0 = _mm_slli_epi32( v0, c ); \
 __m128i t1 = _mm_slli_epi32( v1, c ); \
 v0 = _mm_srli_epi32( v0, 32-(c) ); \
 v1 = _mm_srli_epi32( v1, 32-(c) ); \
 v0 = _mm_or_si256( v0, t0 ); \
 v1 = _mm_or_si256( v1, t1 ); \
}

#endif   // AVX512 else SSE2
*/

// Cross lane shuffles

// No NEON version
#define v128_shuffle32     _mm_shuffle_epi32

/* Not used, exists only for compatibility with NEON if ever needed.
#define v128_shufflev32( v, vmask ) \
  v128_shuffle32( v, mm128_movmask_32( vmask ) )
*/

#define v128_shuffle8     _mm_shuffle_epi8

// Limited 2 input shuffle, combines shuffle with blend. The destination low
// half is always taken from v1, and the high half from v2.
#define v128_shuffle2_64( v1, v2, c ) \
   _mm_castpd_si128( _mm_shuffle_pd( _mm_castsi128_pd( v1 ), \
                                     _mm_castsi128_pd( v2 ), c ) ); 

#define v128_shuffle2_32( v1, v2, c ) \
   _mm_castps_si128( _mm_shuffle_ps( _mm_castsi128_ps( v1 ), \
                                     _mm_castsi128_ps( v2 ), c ) ); 

// Rotate vector elements accross all lanes

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

// Endian byte swap.

#if defined(__SSSE3__)

#define v128_bswap128( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x0001020304050607, \
                                        0x08090a0b0c0d0e0f ) )

#define v128_bswap64( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x08090a0b0c0d0e0f, \
                                        0x0001020304050607 ) )

#define v128_bswap32( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x0c0d0e0f08090a0b, \
                                        0x0405060700010203 ) )
// deprecated
#define mm128_bswap_32      v128_bswap32

#define v128_bswap16( v ) \
   _mm_shuffle_epi8( v, _mm_set_epi64x( 0x0e0f0c0d0a0b0809, \
                                        0x0607040502030001 )

// 8 byte qword * 8 qwords * 2 lanes = 128 bytes
#define mm128_block_bswap_64( d, s ) \
{ \
  v128_t ctl = _mm_set_epi64x(  0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  casti_v128( d,0 ) = _mm_shuffle_epi8( casti_v128( s,0 ), ctl ); \
  casti_v128( d,1 ) = _mm_shuffle_epi8( casti_v128( s,1 ), ctl ); \
  casti_v128( d,2 ) = _mm_shuffle_epi8( casti_v128( s,2 ), ctl ); \
  casti_v128( d,3 ) = _mm_shuffle_epi8( casti_v128( s,3 ), ctl ); \
  casti_v128( d,4 ) = _mm_shuffle_epi8( casti_v128( s,4 ), ctl ); \
  casti_v128( d,5 ) = _mm_shuffle_epi8( casti_v128( s,5 ), ctl ); \
  casti_v128( d,6 ) = _mm_shuffle_epi8( casti_v128( s,6 ), ctl ); \
  casti_v128( d,7 ) = _mm_shuffle_epi8( casti_v128( s,7 ), ctl ); \
}
#define mm128_block_bswap64_512    mm128_block_bswap_64
#define v128_block_bswap64_512     mm128_block_bswap_64

#define v128_block_bswap64_1024( d, s ) \
{ \
  v128_t ctl = _mm_set_epi64x(  0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
  casti_v128( d, 0 ) = _mm_shuffle_epi8( casti_v128( s, 0 ), ctl ); \
  casti_v128( d, 1 ) = _mm_shuffle_epi8( casti_v128( s, 1 ), ctl ); \
  casti_v128( d, 2 ) = _mm_shuffle_epi8( casti_v128( s, 2 ), ctl ); \
  casti_v128( d, 3 ) = _mm_shuffle_epi8( casti_v128( s, 3 ), ctl ); \
  casti_v128( d, 4 ) = _mm_shuffle_epi8( casti_v128( s, 4 ), ctl ); \
  casti_v128( d, 5 ) = _mm_shuffle_epi8( casti_v128( s, 5 ), ctl ); \
  casti_v128( d, 6 ) = _mm_shuffle_epi8( casti_v128( s, 6 ), ctl ); \
  casti_v128( d, 7 ) = _mm_shuffle_epi8( casti_v128( s, 7 ), ctl ); \
  casti_v128( d, 8 ) = _mm_shuffle_epi8( casti_v128( s, 8 ), ctl ); \
  casti_v128( d, 9 ) = _mm_shuffle_epi8( casti_v128( s, 9 ), ctl ); \
  casti_v128( d,10 ) = _mm_shuffle_epi8( casti_v128( s,10 ), ctl ); \
  casti_v128( d,11 ) = _mm_shuffle_epi8( casti_v128( s,11 ), ctl ); \
  casti_v128( d,12 ) = _mm_shuffle_epi8( casti_v128( s,12 ), ctl ); \
  casti_v128( d,13 ) = _mm_shuffle_epi8( casti_v128( s,13 ), ctl ); \
  casti_v128( d,14 ) = _mm_shuffle_epi8( casti_v128( s,14 ), ctl ); \
  casti_v128( d,15 ) = _mm_shuffle_epi8( casti_v128( s,15 ), ctl ); \
}

// 4 byte dword * 8 dwords * 4 lanes = 128 bytes
#define mm128_block_bswap_32( d, s ) \
{ \
  v128_t ctl = _mm_set_epi64x( 0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_v128( d,0 ) = _mm_shuffle_epi8( casti_v128( s,0 ), ctl ); \
  casti_v128( d,1 ) = _mm_shuffle_epi8( casti_v128( s,1 ), ctl ); \
  casti_v128( d,2 ) = _mm_shuffle_epi8( casti_v128( s,2 ), ctl ); \
  casti_v128( d,3 ) = _mm_shuffle_epi8( casti_v128( s,3 ), ctl ); \
  casti_v128( d,4 ) = _mm_shuffle_epi8( casti_v128( s,4 ), ctl ); \
  casti_v128( d,5 ) = _mm_shuffle_epi8( casti_v128( s,5 ), ctl ); \
  casti_v128( d,6 ) = _mm_shuffle_epi8( casti_v128( s,6 ), ctl ); \
  casti_v128( d,7 ) = _mm_shuffle_epi8( casti_v128( s,7 ), ctl ); \
}
#define mm128_block_bswap32_256      mm128_block_bswap_32
#define v128_block_bswap32_256       mm128_block_bswap_32


#define mm128_block_bswap32_128( d, s ) \
{ \
  v128_t ctl = _mm_set_epi64x( 0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_v128( d,0 ) = _mm_shuffle_epi8( casti_v128( s,0 ), ctl ); \
  casti_v128( d,1 ) = _mm_shuffle_epi8( casti_v128( s,1 ), ctl ); \
  casti_v128( d,2 ) = _mm_shuffle_epi8( casti_v128( s,2 ), ctl ); \
  casti_v128( d,3 ) = _mm_shuffle_epi8( casti_v128( s,3 ), ctl ); \
}   

#define v128_block_bswap32_512( d, s ) \
{ \
  v128_t ctl = _mm_set_epi64x( 0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_v128( d, 0 ) = _mm_shuffle_epi8( casti_v128( s, 0 ), ctl ); \
  casti_v128( d, 1 ) = _mm_shuffle_epi8( casti_v128( s, 1 ), ctl ); \
  casti_v128( d, 2 ) = _mm_shuffle_epi8( casti_v128( s, 2 ), ctl ); \
  casti_v128( d, 3 ) = _mm_shuffle_epi8( casti_v128( s, 3 ), ctl ); \
  casti_v128( d, 4 ) = _mm_shuffle_epi8( casti_v128( s, 4 ), ctl ); \
  casti_v128( d, 5 ) = _mm_shuffle_epi8( casti_v128( s, 5 ), ctl ); \
  casti_v128( d, 6 ) = _mm_shuffle_epi8( casti_v128( s, 6 ), ctl ); \
  casti_v128( d, 7 ) = _mm_shuffle_epi8( casti_v128( s, 7 ), ctl ); \
  casti_v128( d, 8 ) = _mm_shuffle_epi8( casti_v128( s, 8 ), ctl ); \
  casti_v128( d, 9 ) = _mm_shuffle_epi8( casti_v128( s, 9 ), ctl ); \
  casti_v128( d,10 ) = _mm_shuffle_epi8( casti_v128( s,10 ), ctl ); \
  casti_v128( d,11 ) = _mm_shuffle_epi8( casti_v128( s,11 ), ctl ); \
  casti_v128( d,12 ) = _mm_shuffle_epi8( casti_v128( s,12 ), ctl ); \
  casti_v128( d,13 ) = _mm_shuffle_epi8( casti_v128( s,13 ), ctl ); \
  casti_v128( d,14 ) = _mm_shuffle_epi8( casti_v128( s,14 ), ctl ); \
  casti_v128( d,15 ) = _mm_shuffle_epi8( casti_v128( s,15 ), ctl ); \
}

#else  // SSE2

static inline v128_t v128_bswap64( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 0, 1, 2, 3 ) );
}

static inline v128_t v128_bswap32( __m128i v )
{
      v = _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
      v = _mm_shufflelo_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
  return  _mm_shufflehi_epi16( v, _MM_SHUFFLE( 2, 3, 0, 1 ) );
}
#define mm128_bswap_32      v128_bswap32 

static inline v128_t v128_bswap16( __m128i v )
{
  return _mm_or_si128( _mm_slli_epi16( v, 8 ), _mm_srli_epi16( v, 8 ) );
}

#define v128_bswap128( v )   v128_qrev32( v128_bswap64( v ) )

static inline void mm128_block_bswap_64( __m128i *d, const __m128i *s )
{
   d[0] = v128_bswap64( s[0] );
   d[1] = v128_bswap64( s[1] );
   d[2] = v128_bswap64( s[2] );
   d[3] = v128_bswap64( s[3] );
   d[4] = v128_bswap64( s[4] );
   d[5] = v128_bswap64( s[5] );
   d[6] = v128_bswap64( s[6] );
   d[7] = v128_bswap64( s[7] );
}
#define v128_block_bswap64_512 mm128_block_bswap_64

static inline void mm128_block_bswap64_1024( __m128i *d, const __m128i *s )
{
   d[ 0] = v128_bswap64( s[ 0] );
   d[ 1] = v128_bswap64( s[ 1] );
   d[ 2] = v128_bswap64( s[ 2] );
   d[ 3] = v128_bswap64( s[ 3] );
   d[ 4] = v128_bswap64( s[ 4] );
   d[ 5] = v128_bswap64( s[ 5] );
   d[ 6] = v128_bswap64( s[ 6] );
   d[ 7] = v128_bswap64( s[ 7] );
   d[ 8] = v128_bswap64( s[ 8] );
   d[ 9] = v128_bswap64( s[ 9] );
   d[10] = v128_bswap64( s[10] );
   d[11] = v128_bswap64( s[11] );
   d[14] = v128_bswap64( s[12] );
   d[13] = v128_bswap64( s[13] );
   d[14] = v128_bswap64( s[14] );
   d[15] = v128_bswap64( s[15] );
}

static inline void mm128_block_bswap_32( __m128i *d, const __m128i *s )
{
   d[0] = v128_bswap32( s[0] );
   d[1] = v128_bswap32( s[1] );
   d[2] = v128_bswap32( s[2] );
   d[3] = v128_bswap32( s[3] );
   d[4] = v128_bswap32( s[4] );
   d[5] = v128_bswap32( s[5] );
   d[6] = v128_bswap32( s[6] );
   d[7] = v128_bswap32( s[7] );
}
#define mm128_block_bswap32_256 mm128_block_bswap_32
#define v128_block_bswap32_256  mm128_block_bswap_32

static inline void mm128_block_bswap32_512( __m128i *d, const __m128i *s )
{
   d[ 0] = v128_bswap32( s[ 0] );
   d[ 1] = v128_bswap32( s[ 1] );
   d[ 2] = v128_bswap32( s[ 2] );
   d[ 3] = v128_bswap32( s[ 3] );
   d[ 4] = v128_bswap32( s[ 4] );
   d[ 5] = v128_bswap32( s[ 5] );
   d[ 6] = v128_bswap32( s[ 6] );
   d[ 7] = v128_bswap32( s[ 7] );
   d[ 8] = v128_bswap32( s[ 8] );
   d[ 9] = v128_bswap32( s[ 9] );
   d[10] = v128_bswap32( s[10] );
   d[11] = v128_bswap32( s[11] );
   d[12] = v128_bswap32( s[12] );
   d[13] = v128_bswap32( s[13] );
   d[14] = v128_bswap32( s[14] );
   d[15] = v128_bswap32( s[15] );
}

#endif // SSSE3 else SSE2

#define v128_block_bswap32             mm128_block_bswap_32
#define v128_block_bswap64             mm128_block_bswap_64


// alignr instruction for 32 & 64 bit elements is only available with AVX512
// but emulated here. Behaviour is consistent with Intel alignr intrinsics.

#if defined(__SSSE3__)

#define v128_alignr8                   _mm_alignr_epi8
#define v128_alignr64( hi, lo, c )     _mm_alignr_epi8( hi, lo, (c)*8 )
#define v128_alignr32( hi, lo, c )     _mm_alignr_epi8( hi, lo, (c)*4 )

#else

#define v128_alignr64( hi, lo, c ) \
   _mm_or_si128( _mm_slli_si128( hi, (c)*8 ), _mm_srli_si128( lo, (c)*8 ) )

#define v128_alignr32( hi, lo, c ) \
   _mm_or_si128( _mm_slli_si128( lo, (c)*4 ), _mm_srli_si128( hi, (c)*4 ) )

#endif

#if defined(__SSE4_1__)

#define v128_blendv                    _mm_blendv_epi8

#else

#define v128_blendv( v1, v0, mask ) \
   v128_or( v128_andnot( mask, v1 ), v128_and( mask, v0 ) )

#endif

#endif // __SSE2__
#endif // SIMD_128_H__
