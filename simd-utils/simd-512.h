#if !defined(SIMD_512_H__)
#define SIMD_512_H__ 1

////////////////////////////////////////////////////////////////////////
//
//       AVX-512
//
//   The baseline for these utilities is AVX512F, AVX512DQ, AVX512BW
//   and AVX512VL, first available in quantity in Skylake-X.
//   Some utilities may require additional features available in subsequent
//   architectures and are noted. 


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

//  AVX512 intrinsics have a few changes from previous conventions.
//
//    cmp instruction now returns a bitmask isnstead of a vector mask.
//    This eliminates the need for the blendv instruction.
//
//    The new rotate instructions require the count to be an 8 bit
//    immediate value only. Compilation fails if a variable is used.
//    The documentation is the same as for shift and it works with
//    variables.
//
//    _mm512_permutex_epi64 only shuffles within 256 bit lanes. Permute
//    usually shuffles accross all lanes.
//
//    permutexvar has args reversed, index is first arg. Previously all
//    permutes and shuffles have the index last.
//
//    _mm512_permutexvar_epi8 requires AVX512-VBMI, larger elements don't.
//    It also performs the same op as _mm512_shuffle_epi8.
//
//    shuffle_epi8 shuffles accross entire 512 bits. Shuffle usually
//    doesn't cross 128 bit lane boundaries but is consistent with AVX2
//    where shuffle_epi8 spans the entire vector.
//
//    There are 2 areas where overhead is aconcern: constants and
//    permutations.
//
//    Constants need to be composed at run time by assembling individual
//    elements, very expensive. The cost is proportional to the number of
//    different elements therefore use the largest element size possible,
//    merge smaller integer elements to 64 bits, and group repeated elements.
//
//    Constants with repeating patterns can be optimized with the smaller
//    patterns repeated more frequently being more efficient.
//
//    Some specific constants can be very efficient. Zero is very efficient,
//    1 and -1 slightly less so. 
//
//    If an expensive constant is to be reused in the same function it should
//    be declared as a local variable defined once and reused.
//
//    Permutations can be very expensive if they use a vector control index,
//    even if the permutation itself is quite efficient.
//    The index is essentially a constant with all the baggage that brings.
//    The same rules apply, if an index is to be reused it should be defined
//    as a local. This applies specifically to bswap operations.
//
//    Additionally, permutations using smaller vectors can be more efficient
//    if the permutation doesn't cross lane boundaries, typically 128 bits,
//    and the smnaller vector can use an imm comtrol.
//
//    If the permutation doesn't cross lane boundaries a shuffle instructions
//    can be used with imm control instead of permute.

//////////////////////////////////////////////////////////////
//
//   AVX512 512 bit vectors
//
// Other AVX512 extensions that may be required for some functions.
// __AVX512VBMI__  __AVX512VAES__
//

// Move integer to/from element 0 of vector.

#define mm512_mov64_512( n ) _mm512_castsi128_si512( mm128_mov64_128( n ) )
#define mm512_mov32_512( n ) _mm512_castsi128_si512( mm128_mov32_128( n ) )

#define mm512_mov256_64( a ) mm128_mov128_64( _mm256_castsi512_si128( a ) )
#define mm512_mov256_32( a ) mm128_mov128_32( _mm256_castsi512_si128( a ) )

// A simple 128 bit permute, using function instead of macro avoids
// problems if the v arg passed as an expression.
static inline __m512i mm512_perm_128( const __m512i v, const int c )
{  return _mm512_shuffle_i64x2( v, v, c ); }

// Concatenate two 256 bit vectors into one 512 bit vector {hi, lo}
#define mm512_concat_256( hi, lo ) \
   _mm512_inserti64x4( _mm512_castsi256_si512( lo ), hi, 1 )

// Equivalent of set, assign 64 bit integers to respective 64 bit elements.
// Use stack memory overlay
static inline __m512i m512_const_64( const uint64_t i7, const uint64_t i6,
                                     const uint64_t i5, const uint64_t i4,
                                     const uint64_t i3, const uint64_t i2,
                                     const uint64_t i1, const uint64_t i0 )
{
  union { __m512i m512i;
          uint64_t u64[8]; } v;   
  v.u64[0] = i0;     v.u64[1] = i1;
  v.u64[2] = i2;     v.u64[3] = i3;
  v.u64[4] = i4;     v.u64[5] = i5;
  v.u64[6] = i6;     v.u64[7] = i7;
  return v.m512i;
}

// Equivalent of set1, broadcast lo element all elements.
static inline __m512i m512_const1_256( const __m256i v )
{ return _mm512_inserti64x4( _mm512_castsi256_si512( v ), v, 1 ); }  

#define m512_const1_128( v ) \
    mm512_perm_128( _mm512_castsi128_si512( v ), 0 )
// Integer input argument up to 64 bits
#define m512_const1_i128( i ) \
    mm512_perm_128( _mm512_castsi128_si512( mm128_mov64_128( i ) ), 0 )

//#define m512_const1_256( v )   _mm512_broadcast_i64x4( v )
//#define m512_const1_128( v )   _mm512_broadcast_i64x2( v )
#define m512_const1_64( i )    _mm512_broadcastq_epi64( mm128_mov64_128( i ) )
#define m512_const1_32( i )    _mm512_broadcastd_epi32( mm128_mov32_128( i ) )
#define m512_const1_16( i )    _mm512_broadcastw_epi16( mm128_mov32_128( i ) )
#define m512_const1_8( i )     _mm512_broadcastb_epi8 ( mm128_mov32_128( i ) )

#define m512_const2_128( v1, v0 ) \
   m512_const1_256( _mm512_inserti64x2( _mm512_castsi128_si512( v0 ), v1, 1 ) )

#define m512_const2_64( i1, i0 ) \
   m512_const1_128( m128_const_64( i1, i0 ) )


static inline __m512i m512_const4_64( const uint64_t i3, const uint64_t i2,
                                      const uint64_t i1, const uint64_t i0 )
{
  union  {  __m512i m512i;
            uint64_t u64[8];   } v;
  v.u64[0] = v.u64[4] = i0;
  v.u64[1] = v.u64[5] = i1;
  v.u64[2] = v.u64[6] = i2;
  v.u64[3] = v.u64[7] = i3;
  return v.m512i;
}

//
// Pseudo constants.

// _mm512_setzero_si512 uses xor instruction. If needed frequently
// in a function is it better to define a register variable (const?)
// initialized to zero.

#define m512_zero       _mm512_setzero_si512()
#define m512_one_512    mm512_mov64_512( 1 )
#define m512_one_256    _mm512_inserti64x4( m512_one_512, m256_one_256, 1 )  
#define m512_one_128    m512_const1_i128( 1 )
#define m512_one_64     m512_const1_64( 1 )
#define m512_one_32     m512_const1_32( 1 )
#define m512_one_16     m512_const1_16( 1 )
#define m512_one_8      m512_const1_8( 1 )

//#define m512_neg1 m512_const1_64( 0xffffffffffffffff )
#define m512_neg1 _mm512_movm_epi64( 0xff )

//
// Basic operations without SIMD equivalent

// ~x
#define mm512_not( x )       _mm512_xor_si512( x, m512_neg1 )

// -x
#define mm512_negate_64( x ) _mm512_sub_epi64( m512_zero, x )
#define mm512_negate_32( x ) _mm512_sub_epi32( m512_zero, x )  
#define mm512_negate_16( x ) _mm512_sub_epi16( m512_zero, x )  


//
// Pointer casting

// p = any aligned pointer
// i = scaled array index
// o = scaled address offset

// returns p as pointer to vector
#define castp_m512i(p) ((__m512i*)(p))

// returns *p as vector value
#define cast_m512i(p) (*((__m512i*)(p)))

// returns p[i] as vector value
#define casti_m512i(p,i) (((__m512i*)(p))[(i)])

// returns p+o as pointer to vector
#define casto_m512i(p,o) (((__m512i*)(p))+(o))

//
// Memory functions
// n = number of 512 bit (64 byte) vectors

static inline void memset_zero_512( __m512i *dst, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m512_zero; }

static inline void memset_512( __m512i *dst, const __m512i a, const int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_512( __m512i *dst, const __m512i *src, const int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }


// Sum 4 values, fewer dependencies than sequential addition.

#define mm512_add4_64( a, b, c, d ) \
   _mm512_add_epi64( _mm512_add_epi64( a, b ), _mm512_add_epi64( c, d ) )

#define mm512_add4_32( a, b, c, d ) \
   _mm512_add_epi32( _mm512_add_epi32( a, b ), _mm512_add_epi32( c, d ) )

#define mm512_add4_16( a, b, c, d ) \
   _mm512_add_epi16( _mm512_add_epi16( a, b ), _mm512_add_epi16( c, d ) )

#define mm512_add4_8( a, b, c, d ) \
   _mm512_add_epi8( _mm512_add_epi8( a, b ), _mm512_add_epi8( c, d ) )

#define mm512_xor4( a, b, c, d ) \
   _mm512_xor_si512( _mm512_xor_si512( a, b ), _mm512_xor_si512( c, d ) )


//
// Bit rotations.

// AVX512F has built-in fixed and variable bit rotation for 64 & 32 bit
// elements and can be called directly. But they only accept immediate 8
// for control arg. 
//
// _mm512_rol_epi64,  _mm512_ror_epi64,  _mm512_rol_epi32,  _mm512_ror_epi32
// _mm512_rolv_epi64, _mm512_rorv_epi64, _mm512_rolv_epi32, _mm512_rorv_epi32
//

// For convenience and consistency with AVX2
#define mm512_ror_64 _mm512_ror_epi64
#define mm512_rol_64 _mm512_rol_epi64
#define mm512_ror_32 _mm512_ror_epi32
#define mm512_rol_32 _mm512_rol_epi32

static inline __m512i mm512_ror_var_64( const __m512i v, const int c )
{
   return _mm512_or_si512( _mm512_srli_epi64( v, c ),
                           _mm512_slli_epi64( v, 64-c ) );
}

static inline __m512i mm512_rol_var_64( const __m512i v, const int c )
{
   return _mm512_or_si512( _mm512_slli_epi64( v, c ),
                           _mm512_srli_epi64( v, 64-c ) );
}

static inline __m512i mm512_ror_var_32( const __m512i v, const int c )
{
   return _mm512_or_si512( _mm512_srli_epi32( v, c ),
                           _mm512_slli_epi32( v, 32-c ) );
}

static inline __m512i mm512_rol_var_32( const __m512i v, const int c )
{
   return _mm512_or_si512( _mm512_slli_epi32( v, c ),
                           _mm512_srli_epi32( v, 32-c ) );
}

static inline __m512i mm512_ror_16( __m512i const v, const int c )
{
   return _mm512_or_si512( _mm512_srli_epi16( v, c ),
                           _mm512_slli_epi16( v, 16-c ) );
}

static inline __m512i mm512_rol_16( const __m512i v, const int c )
{
   return _mm512_or_si512( _mm512_slli_epi16( v, c ),
                           _mm512_srli_epi16( v, 16-c ) );
}

// Rotations using a vector control index are very slow due to overhead
// to generate the index vector. Repeated rotations using the same index
// are better handled by the calling function where the index only needs
// to be generated once then reused very efficiently.
// Permutes and shuffles using an immediate index are significantly faster.

//
// Swap bytes in vector elements, vectorized endian conversion.

#define mm512_bswap_64( v ) \
   _mm512_shuffle_epi8( v, \
               m512_const_64( 0x38393a3b3c3d3e3f, 0x3031323334353637, \
                              0x28292a2b2c2d2e2f, 0x2021222324252627, \
                              0x18191a1b1c1d1e1f, 0x1011121314151617, \
                              0x08090a0b0c0d0e0f, 0x0001020304050607 ) )

#define mm512_bswap_32( v ) \
   _mm512_shuffle_epi8( v, \
               m512_const_64( 0x3c3d3e3f38393a3b, 0x3435363730313233, \
                              0x2c2d2e2f28292a2b, 0x2425262720212223, \
                              0x1c1d1e1f18191a1b, 0x1415161710111213, \
                              0x0c0d0e0f08090a0b, 0x0405060700010203 ) )

#define mm512_bswap_16( v ) \
   _mm512_shuffle_epi8( v, \
               m512_const_64( 0x3e3f3c3d3a3b3839, 0x3637343532333031, \
                              0x2e2f2c2d2a2b2829, 0x2627242522232021, \
                              0x1e1f1c1d1a1b1819, 0x1617141512131011, \
                              0x0e0f0c0d0a0b0809, 0x0607040502030001 ) )

// Source and destination are pointers, may point to same memory.
// 8 lanes of 64 bytes each
#define mm512_block_bswap_64( d, s ) do \
{ \
  __m512i ctl = m512_const_64( 0x38393a3b3c3d3e3f, 0x3031323334353637, \
                               0x28292a2b2c2d2e2f, 0x2021222324252627, \
                               0x18191a1b1c1d1e1f, 0x1011121314151617, \
                               0x08090a0b0c0d0e0f, 0x0001020304050607  ); \
  casti_m512i( d, 0 ) = _mm512_shuffle_epi8( casti_m512i( s, 0 ), ctl ); \
  casti_m512i( d, 1 ) = _mm512_shuffle_epi8( casti_m512i( s, 1 ), ctl ); \
  casti_m512i( d, 2 ) = _mm512_shuffle_epi8( casti_m512i( s, 2 ), ctl ); \
  casti_m512i( d, 3 ) = _mm512_shuffle_epi8( casti_m512i( s, 3 ), ctl ); \
  casti_m512i( d, 4 ) = _mm512_shuffle_epi8( casti_m512i( s, 4 ), ctl ); \
  casti_m512i( d, 5 ) = _mm512_shuffle_epi8( casti_m512i( s, 5 ), ctl ); \
  casti_m512i( d, 6 ) = _mm512_shuffle_epi8( casti_m512i( s, 6 ), ctl ); \
  casti_m512i( d, 7 ) = _mm512_shuffle_epi8( casti_m512i( s, 7 ), ctl ); \
} while(0)

// 16 lanes of 32 bytes each
#define mm512_block_bswap_32( d, s ) do \
{ \
  __m512i ctl = m512_const_64( 0x3c3d3e3f38393a3b, 0x3435363730313233, \
                               0x2c2d2e2f28292a2b, 0x2425262720212223, \
                               0x1c1d1e1f18191a1b, 0x1415161710111213, \
                               0x0c0d0e0f08090a0b, 0x0405060700010203 ); \
  casti_m512i( d, 0 ) = _mm512_shuffle_epi8( casti_m512i( s, 0 ), ctl ); \
  casti_m512i( d, 1 ) = _mm512_shuffle_epi8( casti_m512i( s, 1 ), ctl ); \
  casti_m512i( d, 2 ) = _mm512_shuffle_epi8( casti_m512i( s, 2 ), ctl ); \
  casti_m512i( d, 3 ) = _mm512_shuffle_epi8( casti_m512i( s, 3 ), ctl ); \
  casti_m512i( d, 4 ) = _mm512_shuffle_epi8( casti_m512i( s, 4 ), ctl ); \
  casti_m512i( d, 5 ) = _mm512_shuffle_epi8( casti_m512i( s, 5 ), ctl ); \
  casti_m512i( d, 6 ) = _mm512_shuffle_epi8( casti_m512i( s, 6 ), ctl ); \
  casti_m512i( d, 7 ) = _mm512_shuffle_epi8( casti_m512i( s, 7 ), ctl ); \
} while(0)


//
// Rotate elements in 512 bit vector.

static inline __m512i mm512_swap_256( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 4 ); }

static inline __m512i mm512_ror_1x128( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 2 ); }

static inline __m512i mm512_rol_1x128( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 6 ); }

static inline __m512i mm512_ror_1x64( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 1 ); }

static inline __m512i mm512_rol_1x64( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 7 ); }

static inline __m512i mm512_ror_1x32( const __m512i v )
{ return _mm512_alignr_epi32( v, v, 1 ); }

static inline __m512i mm512_rol_1x32( const __m512i v )
{ return _mm512_alignr_epi32( v, v, 15 ); }

static inline __m512i mm512_ror_x64( const __m512i v, const int n )
{ return _mm512_alignr_epi64( v, v, n ); }

static inline __m512i mm512_ror_x32( const __m512i v, const int n )
{ return _mm512_alignr_epi32( v, v, n ); }

#define mm512_ror_1x16( v ) \
   _mm512_permutexvar_epi16( m512_const_64( \
                       0x0000001F001E001D, 0x001C001B001A0019, \
                       0X0018001700160015, 0X0014001300120011, \
                       0X0010000F000E000D, 0X000C000B000A0009, \
                       0X0008000700060005, 0X0004000300020001 ), v )

#define mm512_rol_1x16( v ) \
   _mm512_permutexvar_epi16( m512_const_64( \
                       0x001E001D001C001B, 0x001A001900180017, \
                       0X0016001500140013, 0X001200110010000F, \
                       0X000E000D000C000B, 0X000A000900080007, \
                       0X0006000500040003, 0X000200010000001F ), v )

#define mm512_ror_1x8( v ) \
   _mm512_shuffle_epi8( v, m512_const_64( \
                       0x003F3E3D3C3B3A39, 0x3837363534333231, \
                       0x302F2E2D2C2B2A29, 0x2827262524232221, \
                       0x201F1E1D1C1B1A19. 0x1817161514131211, \
                       0x100F0E0D0C0B0A09, 0x0807060504030201 ) )

#define mm512_rol_1x8( v ) \
   _mm512_shuffle_epi8( v, m512_const_64( \
                       0x3E3D3C3B3A393837, 0x363534333231302F. \
                       0x2E2D2C2B2A292827, 0x262524232221201F, \
                       0x1E1D1C1B1A191817, 0x161514131211100F, \
                       0x0E0D0C0B0A090807, 0x060504030201003F ) )

//
// Rotate elements within 256 bit lanes of 512 bit vector.

// Swap hi & lo 128 bits in each 256 bit lane
#define mm512_swap256_128( v )   _mm512_permutex_epi64( v, 0x4e )

// Rotate 256 bit lanes by one 64 bit element
#define mm512_ror256_64( v )     _mm512_permutex_epi64( v, 0x39 )
#define mm512_rol256_64( v )     _mm512_permutex_epi64( v, 0x93 )

// Rotate 256 bit lanes by one 32 bit element
#define mm512_ror256_32( v ) \
   _mm512_permutexvar_epi32( m512_const_64( \
                      0x000000080000000f, 0x0000000e0000000d, \
                      0x0000000c0000000b, 0x0000000a00000009, \
                      0x0000000000000007, 0x0000000600000005, \
                      0x0000000400000003, 0x0000000200000001 ), v )

#define mm512_rol256_32( v ) \
   _mm512_permutexvar_epi32( m512_const_64( \
                      0x0000000e0000000d, 0x0000000c0000000b, \
                      0x0000000a00000009, 0x000000080000000f, \
                      0x0000000600000005, 0x0000000400000003, \
                      0x0000000200000001, 0x0000000000000007 ), v )

#define mm512_ror256_16( v ) \
   _mm512_permutexvar_epi16( m512_const_64( \
                     0x00100001001e001d, 0x001c001b001a0019, \
                     0x0018001700160015, 0x0014001300120011, \
                     0x0000000f000e000d, 0x000c000b000a0009, \
                     0x0008000700060005, 0x0004000300020001 ), v )

#define mm512_rol256_16( v ) \
   _mm512_permutexvar_epi16( m512_const_64( \
                     0x001e001d001c001b, 0x001a001900180017, \
                     0x0016001500140013, 0x001200110010001f, \
                     0x000e000d000c000b, 0x000a000900080007, \
                     0x0006000500040003, 0x000200010000000f ), v )

#define mm512_ror256_8( v ) \
   _mm512_shuffle_epi8( v, m512_const_64( \
                     0x203f3e3d3c3b3a39, 0x3837363534333231, \
                     0x302f2e2d2c2b2a29, 0x2827262524232221, \
                     0x001f1e1d1c1b1a19, 0x1817161514131211, \
                     0x100f0e0d0c0b0a09, 0x0807060504030201 ) )

#define mm512_rol256_8( v ) \
   _mm512_shuffle_epi8( v, m512_const_64( \
                     0x3e3d3c3b3a393837, 0x363534333231302f, \
                     0x2e2d2c2b2a292827, 0x262524232221203f, \
                     0x1e1d1c1b1a191817, 0x161514131211100f, \
                     0x0e0d0c0b0a090807, 0x060504030201001f ) )

//
// Rotate elements within 128 bit lanes of 512 bit vector.

// Swap 64 bits in each 128 bit lane
#define mm512_swap128_64( v )   _mm512_shuffle_epi32( v, 0x4e )

// Rotate 128 bit lanes by one 32 bit element
#define mm512_ror128_32( v )    _mm512_shuffle_epi32( v, 0x39 )
#define mm512_rol128_32( v )    _mm512_shuffle_epi32( v, 0x93 )

// Rotate right 128 bit lanes by c bytes
static inline __m512i mm512_ror128_x8( const __m512i v, const int c )
{  return _mm512_alignr_epi8( v, v, c ); }

// Swap 32 bits in each 64 bit lane.
#define mm512_swap64_32( v )    _mm512_shuffle_epi32( v, 0xb1 )


//
//  Rotate elements from 2 512 bit vectors in place, source arguments
//  are overwritten.

#define mm512_swap1024_512( v1, v2 ) \
   v1 = _mm512_xor_si512( v1, v2 ); \
   v2 = _mm512_xor_si512( v1, v2 ); \
   v1 = _mm512_xor_si512( v1, v2 );

#define mm512_ror1024_256( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 4 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 4 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_256( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 4 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 4 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_128( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 2 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_128( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 6 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 6 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_64( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_64( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 7 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 7 ); \
   v1 = t; \
} while(0)

#define mm512_ror1024_32( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi32( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi32( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1024_32( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi32( v1, v2, 15 ); \
   v2 = _mm512_alignr_epi32( v2, v1, 15 ); \
   v1 = t; \
} while(0)

#endif // AVX512
#endif // SIMD_512_H__
