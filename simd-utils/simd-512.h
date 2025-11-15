#if !defined(SIMD_512_H__)
#define SIMD_512_H__ 1

////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//
//   AVX512 512 bit vectors
//
//   The baseline for these utilities is AVX512F, AVX512DQ, AVX512BW
//   and AVX512VL, first available in quantity in Skylake-X.
//   Some utilities may require additional AVX512 extensions available in
//   subsequent architectures and are noted where used. 
//   AVX512VL is used to backport AVX512 instructions to 128 and 256 bit
//   vectors. It is therefore not technically required for any 512 bit vector
//   utilities defined below.

#if defined(SIMD512)

//  AVX512 intrinsics have a few changes from previous conventions.
//
//    "_mm512_cmp" instructions now return a bitmask instead of a vector mask.
//    This removes the need for an explicit movemask instruction. It is also
//    slower than AVX2 cmp. There is no version of AVX512 cmp that returns a
//    vector result resulting in a double penalty if a vector result is needed:
//    slower cmp instruction & extra instruction to convert bit mask into 
//    vector mask. 256 bit & 128 bit still have legacy cmp returning vector
//    while AVX512VL adds masked versions returning bit mask.
//
//    Many previously sizeless (si) instructions now have sized (epi) versions
//    to accomodate masking packed elements.
//
//    Many AVX512 instructions have a different argument order from the AVX2
//    versions of similar instructions. There is also some inconsistency in how
//    different AVX512 instructions position the mask register in the argument
//    list.
//
//    "_mm512_permutex_epi64" only shuffles within 256 bit lanes. All other
//    AVX512 instructions using the permute name can cross all lanes.
//
//    New alignr instructions for epi64 and epi32 operate across the entire
//    vector but slower than epi8 which continues to be restricted to 128 bit
//    lanes.
//
//    "vpbroadcastq/d/w/b" instructions now support integer register source
//    argument in addition to XMM register or mem location. set1 intrinsic uses
//    integer arg, broadcast intrinsic requires xmm. Mask versions of 256 and 
//    128 bit broadcast also inherit this addition.
//
//    "_mm512_permutexvar_epi8" and "_mm512_permutex2var_epi8" require
//    AVX512-VBMI. The same instructions with larger elements don't have this
//    requirement.
//
//    Two coding conventions are used to prevent macro argument side effects:
//      - if a macro arg is used in an expression it must be protected by
//        parentheses to ensure the expression argument is evaluated first.
//      - if an argument is to referenced multiple times a C inline function
//        should be used instead of a macro to prevent an expression argument
//        from being evaluated multiple times (wasteful) or produce side
//        effects (very bad).
//
//    There are 2 areas where overhead is a major concern: constants and
//    permutations.
//
//    Constants need to be composed at run time by assembling individual
//    elements or loaded from memory, very expensive. The cost of runtime
//    construction is proportional to the number of different elements
//    therefore use the largest element size possible merging smaller integer
//    elements to 64 bits, and group repeated elements.
//
//    Constants with repeating patterns can be optimized with the smaller
//    patterns repeated more frequently being more efficient.
//
//    Some specific constants can be very efficient. Zero is very efficient,
//    1 and -1 slightly less so. 
//
//    If an expensive constant is to be reused in the same function it may
//    be declared as a local variable defined once and reused. If frequently
//    used it can be declared as a static const in memory.
//
//    Permutations can be very expensive if they use a vector control index,
//    even if the permute instruction itself is quite efficient.
//    The index is essentially a vector constant with all the baggage that
//    brings. The same rules apply, if an index is to be reused it should either
//    be defined as a local or static const.
//
//    Permutations that cross 128 bit lanes are typically slower and often need
//    a vector control index. If the permutation doesn't need to cross 128 bit
//    lanes a shuffle instruction can often be used with an imm control.
//    
//////////////////////////////////////////////////////////////
//
//   AVX512 512 bit vectors
//
// Other AVX512 extensions that may be required for some functions.
// __AVX512VBMI__  __AVX512VAES__
//

// Used instead of casting.
typedef union
{
   __m512i m512;
   __m128i m128[4];
   uint32_t u32[16];
   uint64_t u64[8];
} __attribute__ ((aligned (64))) m512_ovly;

#define v512_64(i64)    _mm512_set1_epi64(i64)
#define v512_32(i32)    _mm512_set1_epi32(i32)

// A simple 128 bit permute, using function instead of macro avoids
// problems if the v arg passed as an expression.
static inline __m512i mm512_perm128( const __m512i v, const int c )
{  return _mm512_shuffle_i64x2( v, v, c ); }

// Broadcast 128 bit vector to all lanes of 512 bit vector.
#define mm512_bcast128( v )    mm512_perm128( _mm512_castsi128_si512( v ), 0 )
// deprecated
#define mm512_bcast_m128  mm512_bcast128 

// Set either the low or high 64 bit elements in 128 bit lanes, other elements
// are set to zero.
#define mm512_bcast128lo_64( i64 )     _mm512_maskz_set1_epi64( 0x55, i64 )
#define mm512_bcast128hi_64( i64 )     _mm512_maskz_set1_epi64( 0xaa, i64 )

#define mm512_set2_64( i1, i0 ) \
   mm512_bcast128( _mm_set_epi64x( i1, i0 ) )

// Pseudo constants.
#define m512_zero       _mm512_setzero_si512()

// use asm to avoid compiler warning for uninitialized local
static inline __m512i mm512_neg1_fn()
{
   __m512i v;
   asm( "vpternlogq $0xff, %0, %0, %0\n\t" : "=x"(v) );
   return v;
}
#define m512_neg1 mm512_neg1_fn()    

//
// Basic operations without SIMD equivalent

// Bitwise NOT: ~x
static inline __m512i mm512_not( const __m512i x )
{  return _mm512_ternarylogic_epi64( x, x, x, 1 ); }

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

//
// Ternary logic uses 8 bit truth table to define any 3 input logical
// expression using any number or combinations of AND, OR, XOR, NOT.
// Macros with duplicate references to the same argument are
// not expression safe. Switch to inline function if required.

// ~v1 | v0
#define mm512_ornot( v1, v0 )      _mm512_ternarylogic_epi64( v1, v0, v0, 0xcf )

// a ^ b ^ c
#define mm512_xor3( a, b, c )      _mm512_ternarylogic_epi64( a, b, c, 0x96 )

// legacy convenience only
#define mm512_xor4( a, b, c, d )   _mm512_xor_si512( a, mm512_xor3( b, c, d ) )

// a & b & c
#define mm512_and3( a, b, c )      _mm512_ternarylogic_epi64( a, b, c, 0x80 )

// a | b | c
#define mm512_or3( a, b, c )       _mm512_ternarylogic_epi64( a, b, c, 0xfe )

// a ^ ( b & c )
#define mm512_xorand( a, b, c )    _mm512_ternarylogic_epi64( a, b, c, 0x78 )

// a & ( b ^ c )
#define mm512_andxor( a, b, c )    _mm512_ternarylogic_epi64( a, b, c, 0x60 )

// a ^ ( b | c )
#define mm512_xoror( a, b, c )     _mm512_ternarylogic_epi64( a, b, c, 0x1e )

// a ^ ( ~b & c ),     xor( a, andnot( b, c ) )
#define mm512_xorandnot( a, b, c ) _mm512_ternarylogic_epi64( a, b, c, 0xd2 ) 

// a | ( b & c )
#define mm512_orand( a, b, c )     _mm512_ternarylogic_epi64( a, b, c, 0xf8 )

// Some 2 input operations that don't have their own instruction mnemonic.
// Use with caution, args are not expression safe.

// ~( a | b ),  (~a) & (~b)
#define mm512_nor( a, b )          _mm512_ternarylogic_epi64( a, b, b, 0x01 )

// ~( a ^ b ),  (~a) ^ b
#define mm512_nxor( a, b )         _mm512_ternarylogic_epi64( a, b, b, 0x81 )

// ~( a & b )
#define mm512_nand( a, b )         _mm512_ternarylogic_epi64( a, b, b, 0xef )

// Bit rotations.

// AVX512F has built-in fixed and variable bit rotation for 64 & 32 bit
// elements and can be called directly. 
//
// _mm512_rol_epi64,  _mm512_ror_epi64,  _mm512_rol_epi32,  _mm512_ror_epi32
// _mm512_rolv_epi64, _mm512_rorv_epi64, _mm512_rolv_epi32, _mm512_rorv_epi32
//

// For convenience and consistency with AVX2 macros.
#define mm512_ror_64 _mm512_ror_epi64
#define mm512_rol_64 _mm512_rol_epi64
#define mm512_ror_32 _mm512_ror_epi32
#define mm512_rol_32 _mm512_rol_epi32

/* not used
#if defined(__AVX512VBMI2__)

#define mm512_ror_16( v, c )   _mm512_shrdi_epi16( c, v, v )
#define mm512_rol_16( v, c )   _mm512_shldi_epi16( c, v, v )

#endif
*/

//
// Reverse byte order of packed elements, vectorized endian conversion.

#define mm512_bswap_64( v )  _mm512_shuffle_epi8( v, V512_BSWAP64 )

#define mm512_bswap_32( v )  _mm512_shuffle_epi8( v, V512_BSWAP32 )

/* not used
#if defined(__AVX512VBMI2__)

#define mm512_bswap_16( v )  mm512_ror_16( v, 8 )

#else

#define mm512_bswap_16( v ) \
   _mm512_shuffle_epi8( v, mm512_bcast128( _mm_set_epi64x( \
                                0x0e0f0c0d0a0b0809, 0x0607040502030001 ) ) )

#endif
*/

#define mm512_bswap_16( v ) \

// Source and destination are pointers, may point to same memory.
// 8 lanes of 64 bytes each
#define mm512_block_bswap_64( d, s ) \
{ \
  casti_m512i( d, 0 ) = mm512_bswap_64( casti_m512i( s, 0 ) ); \
  casti_m512i( d, 1 ) = mm512_bswap_64( casti_m512i( s, 1 ) ); \
  casti_m512i( d, 2 ) = mm512_bswap_64( casti_m512i( s, 2 ) ); \
  casti_m512i( d, 3 ) = mm512_bswap_64( casti_m512i( s, 3 ) ); \
  casti_m512i( d, 4 ) = mm512_bswap_64( casti_m512i( s, 4 ) ); \
  casti_m512i( d, 5 ) = mm512_bswap_64( casti_m512i( s, 5 ) ); \
  casti_m512i( d, 6 ) = mm512_bswap_64( casti_m512i( s, 6 ) ); \
  casti_m512i( d, 7 ) = mm512_bswap_64( casti_m512i( s, 7 ) ); \
}

// 16 lanes of 32 bytes each
#define mm512_block_bswap_32( d, s ) \
{ \
  casti_m512i( d, 0 ) = mm512_bswap_32( casti_m512i( s, 0 ) ); \
  casti_m512i( d, 1 ) = mm512_bswap_32( casti_m512i( s, 1 ) ); \
  casti_m512i( d, 2 ) = mm512_bswap_32( casti_m512i( s, 2 ) ); \
  casti_m512i( d, 3 ) = mm512_bswap_32( casti_m512i( s, 3 ) ); \
  casti_m512i( d, 4 ) = mm512_bswap_32( casti_m512i( s, 4 ) ); \
  casti_m512i( d, 5 ) = mm512_bswap_32( casti_m512i( s, 5 ) ); \
  casti_m512i( d, 6 ) = mm512_bswap_32( casti_m512i( s, 6 ) ); \
  casti_m512i( d, 7 ) = mm512_bswap_32( casti_m512i( s, 7 ) ); \
}
#define mm512_block_bswap32_256   mm512_block_bswap_32

// Cross-lane shuffles implementing rotation of packed elements.
// 

// shuffle 16 bit elements within 64 bit lanes.
#define mm512_shuffle16( v, c ) \
   _mm512_shufflehi_epi16( _mm512_shufflelo_epi16( v, c ), c )

// Rotate elements across entire vector.
static inline __m512i mm512_rev_256( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 4 ); }
#define mm512_swap_256      mm512_rev_256     // grandfathered

static inline __m512i mm512_shuflr_128( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 2 ); }

static inline __m512i mm512_shufll_128( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 6 ); }

/* Not used
static inline __m512i mm512_shuflr_64( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 1 ); }

static inline __m512i mm512_shufll_64( const __m512i v )
{ return _mm512_alignr_epi64( v, v, 7 ); }

static inline __m512i mm512_shuflr_32( const __m512i v )
{ return _mm512_alignr_epi32( v, v, 1 ); }

static inline __m512i mm512_shufll_32( const __m512i v )
{ return _mm512_alignr_epi32( v, v, 15 ); }
*/

/* Not used
// Generic
static inline __m512i mm512_shuflr_x64( const __m512i v, const int n )
{ return _mm512_alignr_epi64( v, v, n ); }

static inline __m512i mm512_shuflr_x32( const __m512i v, const int n )
{ return _mm512_alignr_epi32( v, v, n ); }

#define mm512_shuflr_16( v ) \
   _mm512_permutexvar_epi16( _mm512_set_epi64( \
                       0x0000001F001E001D, 0x001C001B001A0019, \
                       0x0018001700160015, 0x0014001300120011, \
                       0x0010000F000E000D, 0x000C000B000A0009, \
                       0x0008000700060005, 0x0004000300020001 ), v )

#define mm512_shufll_16( v ) \
   _mm512_permutexvar_epi16( _mm512_set_epi64( \
                       0x001E001D001C001B, 0x001A001900180017, \
                       0x0016001500140013, 0x001200110010000F, \
                       0x000E000D000C000B, 0x000A000900080007, \
                       0x0006000500040003, 0x000200010000001F ), v )
*/

// Rotate elements within 256 bit lanes of 512 bit vector.

// Swap hi & lo 128 bits in each 256 bit lane
#define mm512_rev256_128( v )       _mm512_permutex_epi64( v, 0x4e )
#define mm512_swap256_128           mm512_rev256_128  // grandfathered

// Rotate 256 bit lanes by one 64 bit element
#define mm512_shuflr256_64( v )     _mm512_permutex_epi64( v, 0x39 )
#define mm512_shufll256_64( v )     _mm512_permutex_epi64( v, 0x93 )

/*  Not used
// Rotate 256 bit lanes by one 32 bit element
#define mm512_shuflr256_32( v ) \
   _mm512_permutexvar_epi32( _mm512_set_epi64( \
                      0x000000080000000f, 0x0000000e0000000d, \
                      0x0000000c0000000b, 0x0000000a00000009, \
                      0x0000000000000007, 0x0000000600000005, \
                      0x0000000400000003, 0x0000000200000001 ), v )

#define mm512_shufll256_32( v ) \
   _mm512_permutexvar_epi32( _mm512_set_epi64( \
                      0x0000000e0000000d, 0x0000000c0000000b, \
                      0x0000000a00000009, 0x000000080000000f, \
                      0x0000000600000005, 0x0000000400000003, \
                      0x0000000200000001, 0x0000000000000007 ), v )

#define mm512_shuflr256_16( v ) \
   _mm512_permutexvar_epi16( _mm512_set_epi64( \
                     0x00100001001e001d, 0x001c001b001a0019, \
                     0x0018001700160015, 0x0014001300120011, \
                     0x0000000f000e000d, 0x000c000b000a0009, \
                     0x0008000700060005, 0x0004000300020001 ), v )

#define mm512_shufll256_16( v ) \
   _mm512_permutexvar_epi16( _mm512_set_epi64( \
                     0x001e001d001c001b, 0x001a001900180017, \
                     0x0016001500140013, 0x001200110010001f, \
                     0x000e000d000c000b, 0x000a000900080007, \
                     0x0006000500040003, 0x000200010000000f ), v )

#define mm512_shuflr256_8( v ) \
   _mm512_shuffle_epi8( _mm512_set_epi64( \
                     0x203f3e3d3c3b3a39, 0x3837363534333231, \
                     0x302f2e2d2c2b2a29, 0x2827262524232221, \
                     0x001f1e1d1c1b1a19, 0x1817161514131211, \
                     0x100f0e0d0c0b0a09, 0x0807060504030201 ), v )

#define mm512_shufll256_8( v ) \
   _mm512_shuffle_epi8( _mm512_set_epi64( \
                     0x3e3d3c3b3a393837, 0x363534333231302f, \
                     0x2e2d2c2b2a292827, 0x262524232221203f, \
                     0x1e1d1c1b1a191817, 0x161514131211100f, \
                     0x0e0d0c0b0a090807, 0x060504030201001f ), v )
*/

//
// Shuffle/rotate elements within 128 bit lanes of 512 bit vector.
 
#define mm512_rev128_64( v )      _mm512_shuffle_epi32( v, 0x4e )
#define mm512_swap128_64          mm512_rev128_64   // grandfathered

/*not used
#define mm512_rev128_32(v)        _mm526_shuffle_epi32( v, 0x1b )
#define mm512_rev128_16(v)         mm512_shuffle16( v, 0x1b )
*/

// Rotate 128 bit lanes by one 32 bit element
#define mm512_shuflr128_32( v )    _mm512_shuffle_epi32( v, 0x39 )
#define mm512_shufll128_32( v )    _mm512_shuffle_epi32( v, 0x93 )

/* Not used

#define mm512_shuflr128_16(v)   mm512_shuffle16( v, 0x39 )
#define mm512_shufll128_16(v)   mm512_shuffle16( v, 0x93 )
   
// Rotate 128 bit lanes right by c bytes, versatile and just as fast
static inline __m512i mm512_shuflr128_x8( const __m512i v, const int c )
{  return _mm512_alignr_epi8( v, v, c ); }
*/

// Limited 2 input shuffle, combines shuffle with blend.
// Like most shuffles it's limited to 128 bit lanes and like some shuffles
// destination elements must come from a specific source arg. 
#define mm512_shuffle2_64( v1, v2, c ) \
   _mm512_castpd_si512( _mm512_shuffle_pd( _mm512_castsi512_pd( v1 ), \
                                           _mm512_castsi512_pd( v2 ), c ) ); 

#define mm512_shuffle2_32( v1, v2, c ) \
   _mm512_castps_si512( _mm512_shuffle_ps( _mm512_castsi512_ps( v1 ), \
                                           _mm512_castsi512_ps( v2 ), c ) ); 

// 64 bit lanes
// Redundant with ror & rol but included for consistency with AVX2/SSE.
#define mm512_qrev32( v )       _mm512_shuffle_epi32( v, 0xb1 )
#define mm512_swap64_32         mm512_qrev32        // grandfathered

#define mm512_shuflr64_24( v )  _mm512_ror_epi64( v, 24 )
#define mm512_shufll64_24( v )  _mm512_rol_epi64( v, 24 )

#define mm512_shuflr64_16( v )  _mm512_ror_epi64( v, 16 )
#define mm512_shufll64_16( v )  _mm512_rol_epi64( v, 16 )

#define mm512_shuflr64_8(  v )  _mm512_ror_epi64( v,  8 )
#define mm512_shufll64_8(  v )  _mm512_rol_epi64( v,  8 )

/* Not used
// 32 bit lanes

#define mm512_lrev16( v )       _mm512_ror_epi32( v, 16 )

#define mm512_shuflr32_8( v )   _mm512_ror_epi32( v,  8 )
#define mm512_shufll32_8( v )   _mm512_rol_epi32( v,  8 )
*/

#endif // AVX512
#endif // SIMD_512_H__
