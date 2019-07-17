#if !defined(SIMD_256_H__)
#define SIMD_256_H__ 1

#if defined(__AVX__)

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

//
// Pseudo constants.
// These can't be used for compile time initialization but are preferable
// for simple constant vectors at run time. For repeated use define a local
// constant to avoid multiple calls to the same macro.

#define m256_zero         _mm256_setzero_si256()

#define m256_one_256 \
   _mm256_insertf128_si256( _mm256_castsi128_si256( m128_one_128 ), \
                                                    m128_zero, 1 )

#define m256_one_128 \
   _mm256_insertf128_si256( _mm256_castsi128_si256( m128_one_128 ), \
                                                    m128_one_128, 1 )

// set instructions load memory resident constants, this avoids mem.
// cost 4 pinsert + 1 vinsert, estimate 7 clocks.
// Avoid using, mm128_const_64 twice is still faster.
#define m256_const_64( i3, i2, i1, i0 ) \
   _mm256_insertf128_si256( _mm256_castsi128_si256( m128_const_64( i1, i0 ) ), \
                            m128_const_64( i3, i2 ), 1 )
#define m256_const1_64( i ) m256_const_64( i, i, i, i )

#if defined(__AVX2__)

// These look like a lot of overhead but the compiler optimizes nicely
// and puts the asm inline in the calling function. Usage is like any
// variable expression.
// __m256i foo = m256_one_64; 

static inline __m256i m256_one_64_fn()
{
  __m256i a;
  asm( "vpxor %0, %0, %0\n\t"
       "vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n\t"
       "vpsubq %%ymm1, %0, %0\n\t"
       : "=x"(a)
       :
       : "ymm1" );
  return a;
}
#define m256_one_64    m256_one_64_fn()

static inline __m256i m256_one_32_fn()
{
  __m256i a;
  asm( "vpxor %0, %0, %0\n\t"
       "vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n\t"
       "vpsubd %%ymm1, %0, %0\n\t"
       : "=x"(a)
       :
       : "ymm1" );
  return a;
}
#define m256_one_32    m256_one_32_fn()

static inline __m256i m256_one_16_fn()
{
  __m256i a;
  asm( "vpxor %0, %0, %0\n\t"
       "vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n\t"
       "vpsubw %%ymm1, %0, %0\n\t"
       : "=x"(a)
       :
       : "ymm1" );
  return a;
}
#define m256_one_16    m256_one_16_fn()

static inline __m256i m256_one_8_fn()
{
  __m256i a;
  asm( "vpxor %0, %0, %0\n\t"
       "vpcmpeqd %%ymm1, %%ymm1, %%ymm1\n\t"
       "vpsubb %%ymm1, %0, %0\n\t"
       : "=x"(a)
       :
       : "ymm1" );
  return a;
}
#define m256_one_8    m256_one_8_fn()

static inline __m256i m256_neg1_fn()
{
   __m256i a;
   asm( "vpcmpeqq %0, %0, %0\n\t"
        : "=x"(a) );
   return a;
}
#define m256_neg1    m256_neg1_fn()

#else  // AVX

#define m256_one_64       _mm256_set1_epi64x( 1ULL )
#define m256_one_32       _mm256_set1_epi64x( 0x0000000100000001ULL )
#define m256_one_16       _mm256_set1_epi64x( 0x0001000100010001ULL )
#define m256_one_8        _mm256_set1_epi64x( 0x0101010101010101ULL )

// AVX doesn't have inserti128 but insertf128 will do. 
// Ideally this can be done with 2 instructions and no temporary variables.
static inline __m256i m256_neg1_fn()
{
   __m128i a = m128_neg1;
   return _mm256_insertf128_si256( _mm256_castsi128_si256( a ), a, 1 );
}
#define m256_neg1   m256_neg1_fn()
//#define m256_neg1    _mm256_set1_epi64x( 0xFFFFFFFFFFFFFFFFULL )

#endif  // AVX2 else AVX
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

// Extract 4 u64 from 256 bit vector.
#define mm256_extr_4x64( a0, a1, a2, a3, src ) \
do { \
  __m128i hi = _mm256_extracti128_si256( src, 1 ); \
  a0 = _mm_extract_epi64( _mm256_castsi256_si128( src ), 0 ); \
  a1 = _mm_extract_epi64( _mm256_castsi256_si128( src ), 1 ); \
  a2 = _mm_extract_epi64( hi, 0 ); \
  a3 = _mm_extract_epi64( hi, 1 ); \
} while(0)

#define mm256_extr_8x32( a0, a1, a2, a3, a4, a5, a6, a7, src ) \
do { \
  __m128i hi = _mm256_extracti128_si256( src, 1 ); \
  a0 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 0 ); \
  a1 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 1 ); \
  a2 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 2 ); \
  a3 = _mm_extract_epi32( _mm256_castsi256_si128( src ), 3 ); \
  a4 = _mm_extract_epi32( hi, 0 ); \
  a5 = _mm_extract_epi32( hi, 1 ); \
  a6 = _mm_extract_epi32( hi, 2 ); \
  a7 = _mm_extract_epi32( hi, 3 ); \
} while(0)

// input __m128i, returns __m256i
// To build a 256 bit vector from 2 128 bit vectors lo must be done first.
// lo alone leaves hi undefined, hi alone leaves lo unchanged.
// Both cost one clock while preserving the other half..
// Insert b into specified half of a leaving other half of a unchanged.
#define mm256_ins_lo128_256( a, b )  _mm256_inserti128_si256( a, b, 0 )
#define mm256_ins_hi128_256( a, b )  _mm256_inserti128_si256( a, b, 1 )


// concatenate two 128 bit vectors into one 256 bit vector: { hi, lo }
#define mm256_concat_128( hi, lo ) \
   mm256_ins_hi128_256( _mm256_castsi128_si256( lo ), hi )

// Horizontal vector testing
#if defined(__AVX2__)

#define mm256_allbits0( a )    _mm256_testz_si256(   a, a )
#define mm256_allbits1( a )    _mm256_testc_si256(   a, m256_neg1 )
#define mm256_allbitsne( a )   _mm256_testnzc_si256( a, m256_neg1 )
#define mm256_anybits0         mm256_allbitsne
#define mm256_anybits1         mm256_allbitsne

#else  // AVX

// Bit-wise test of entire vector, useful to test results of cmp.
#define mm256_anybits0( a ) \
         ( (uint128_t)mm128_extr_hi128_256( a ) \
         | (uint128_t)mm128_extr_lo128_256( a ) )

#define mm256_anybits1( a ) \
         ( ( (uint128_t)mm128_extr_hi128_256( a ) + 1 ) \
         | ( (uint128_t)mm128_extr_lo128_256( a ) + 1 ) )

#define mm256_allbits0_256( a ) ( !mm256_anybits1(a) )
#define mm256_allbits1_256( a ) ( !mm256_anybits0(a) )

#endif   // AVX2 else AVX

// Parallel AES, for when x is expected to be in a 256 bit register.
// Use same 128 bit key.
#define mm256_aesenc_2x128( x, k ) \
   mm256_concat_128( _mm_aesenc_si128( mm128_extr_hi128_256( x ), k ), \
                     _mm_aesenc_si128( mm128_extr_lo128_256( x ), k ) )

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


// Gather scatter

#define mm256_gather_64( d, s0, s1, s2, s3 ) \
    ((uint64_t*)(d))[0] = (uint64_t)(s0); \
    ((uint64_t*)(d))[1] = (uint64_t)(s1); \
    ((uint64_t*)(d))[2] = (uint64_t)(s2); \
    ((uint64_t*)(d))[3] = (uint64_t)(s3);

#define mm256_gather_32( d, s0, s1, s2, s3, s4, s5, s6, s7 ) \
    ((uint32_t*)(d))[0] = (uint32_t)(s0); \
    ((uint32_t*)(d))[1] = (uint32_t)(s1); \
    ((uint32_t*)(d))[2] = (uint32_t)(s2); \
    ((uint32_t*)(d))[3] = (uint32_t)(s3); \
    ((uint32_t*)(d))[4] = (uint32_t)(s4); \
    ((uint32_t*)(d))[5] = (uint32_t)(s5); \
    ((uint32_t*)(d))[6] = (uint32_t)(s6); \
    ((uint32_t*)(d))[7] = (uint32_t)(s7);


// Scatter data from contiguous memory.
// All arguments are pointers
#define mm256_scatter_64( d0, d1, d2, d3, s ) \
   *((uint64_t*)(d0)) = ((uint64_t*)(s))[0]; \
   *((uint64_t*)(d1)) = ((uint64_t*)(s))[1]; \
   *((uint64_t*)(d2)) = ((uint64_t*)(s))[2]; \
   *((uint64_t*)(d3)) = ((uint64_t*)(s))[3];

#define mm256_scatter_32( d0, d1, d2, d3, d4, d5, d6, d7, s ) \
   *((uint32_t*)(d0)) = ((uint32_t*)(s))[0]; \
   *((uint32_t*)(d1)) = ((uint32_t*)(s))[1]; \
   *((uint32_t*)(d2)) = ((uint32_t*)(s))[2]; \
   *((uint32_t*)(d3)) = ((uint32_t*)(s))[3]; \
   *((uint32_t*)(d4)) = ((uint32_t*)(s))[4]; \
   *((uint32_t*)(d5)) = ((uint32_t*)(s))[5]; \
   *((uint32_t*)(d6)) = ((uint32_t*)(s))[6]; \
   *((uint32_t*)(d7)) = ((uint32_t*)(s))[7];


//
// Memory functions
// n = number of 256 bit (32 byte) vectors

static inline void memset_zero_256( __m256i *dst, int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = m256_zero; }

static inline void memset_256( __m256i *dst, const __m256i a,  int n )
{   for ( int i = 0; i < n; i++ ) dst[i] = a; }

static inline void memcpy_256( __m256i *dst, const __m256i *src, int n )
{   for ( int i = 0; i < n; i ++ ) dst[i] = src[i]; }

///////////////////////////////
//
//    AVX2 needed from now on.
//

#if defined(__AVX2__)

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
// but is of little value

//
// Rotate each element of v by c bits
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

//
// Rotate elements accross all lanes.
//
// AVX2 has no full vector permute for elements less than 32 bits.
// AVX512 has finer granularity full vector permutes.

// Swap 128 bit elements in 256 bit vector.
#define mm256_swap_128( v )     _mm256_permute4x64_epi64( v, 0x4e )

// Rotate 256 bit vector by one 64 bit element
#define mm256_ror_1x64( v )     _mm256_permute4x64_epi64( v, 0x39 )
#define mm256_rol_1x64( v )     _mm256_permute4x64_epi64( v, 0x93 )

// A little faster with avx512
// Rotate 256 bit vector by one 32 bit element. Use 64 bit set, it's faster.
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

// AVX512 can do 16 & 8 bit elements.
#if defined(__AVX512VL__)

// Rotate 256 bit vector by one 16 bit element.     
#define mm256_ror_1x16( v ) \
   _mm256_permutexvar_epi16( m256_const_64( \
                                 0x0000000f000e000d, 0x000c000b000a0009, \
                                 0x0008000700060005, 0x0004000300020001 ), v )

#define mm256_rol_1x16( v ) \
   _mm256_permutexvar_epi16( m256_const_64( \
                                 0x000e000d000c000b, 0x000a000900080007, \
                                 0x0006000500040003, 0x000200010000000f ), v )

// Rotate 256 bit vector by one byte.
#define mm256_ror_1x8( v ) m256_const_64( \
                                 0x001f1e1d1c1b1a19, 0x1817161514131211, \
                                 0x100f0e0d0c0b0a09, 0x0807060504030201 )

#define mm256_rol_1x8( v ) m256_const_64( \
                                 0x1e1d1c1b1a191817, 0x161514131211100f, \
                                 0x0e0d0c0b0a090807, 0x060504030201001f )

#endif  // AVX512

//
// Rotate elements within lanes of 256 bit vector.

// Swap 64 bit elements in each 128 bit lane.
#define mm256_swap64_128( v )   _mm256_shuffle_epi32( v, 0x4e )

// Rotate each 128 bit lane by one 32 bit element.
#define mm256_ror1x32_128( v )  _mm256_shuffle_epi32( v, 0x39 )
#define mm256_rol1x32_128( v )  _mm256_shuffle_epi32( v, 0x93 )

// Rotate each 128 bit lane by one 16 bit element.
#define mm256_rol1x16_128( v ) \
        _mm256_shuffle_epi8( v, _mm256_set_epi16( 6,5,4,3,2,1,0,7, \
                                                  6,5,4,3,2,1,0,7 ) )
#define mm256_ror1x16_128( v ) \
        _mm256_shuffle_epi8( v, _mm256_set_epi16( 0,7,6,5,4,3,2,1, \
                                                  0,7,6,5,4,3,2,1 ) )

// Rotate each 128 bit lane by one byte
#define mm256_rol1x8_128( v ) \
        _mm256_shuffle_epi8( v, _mm256_set_epi8(14,13,12,11,10, 9, 8, 7, \
                                                 6, 5, 4, 3, 2, 1, 0,15, \
                                                14,13,12,11,10, 9, 8, 7, \
                                                 6, 5, 4, 3, 2, 1, 0,15 ) )
#define mm256_ror1x8_128( v ) \
        _mm256_shuffle_epi8( v, _mm256_set_epi8( 0,15,14,13,12,11,10, 9, \
                                                 8, 7, 6, 5, 4, 3, 2, 1, \
                                                 0,15,14,13,12,11,10, 9, \
                                                 8, 7, 6, 5, 4, 3, 2, 1 ) )

// Rotate each 128 bit lane by c bytes.
#define mm256_bror_128( v, c ) \
  _mm256_or_si256( _mm256_bsrli_epi128( v, c ), \
                   _mm256_bslli_epi128( v, 16-(c) ) )
#define mm256_brol_128( v, c ) \
  _mm256_or_si256( _mm256_bslli_epi128( v, c ), \
                   _mm256_bsrli_epi128( v, 16-(c) ) )

// Swap 32 bit elements in each 64 bit lane
#define mm256_swap32_64( v )    _mm256_shuffle_epi32( v, 0xb1 )

#define mm256_ror16_64( v ) \
   _mm256_shuffle_epi8( v, _mm256_set_epi16( 4,7,6,5,0,3,2,1, \
                                             4,7,6,5,0,3,2,1 ) )
#define mm256_rol16_64( v ) \
   _mm256_shuffle_epi8( v, _mm256_set_epi16( 6,5,4,7,2,1,0,3, \
                                             6,5,4,7,2,1,0,3 ) )


// Swap 16 bit elements in each 32 bit lane
#define mm256_swap16_32( v ) \
   _mm256_shuffle_epi8( v, _mm256_set_epi16( 6,7,4,5,2,3,0,1, \
                                             6,7,4,5,2,3,0,1 ) )

//
// Swap bytes in vector elements, endian bswap.
#define mm256_bswap_64( v ) \
   _mm256_shuffle_epi8( v, m256_const_64( 0x08090a0b0c0d0e0f, \
                0x0001020304050607, 0x08090a0b0c0d0e0f, 0x0001020304050607 ) )

#define mm256_bswap_32( v ) \
   _mm256_shuffle_epi8( v, m256_const_64( 0x0c0d0e0f08090a0b, \
                0x0405060700010203, 0x0c0d0e0f08090a0b, 0x0405060700010203 ) )

#define mm256_bswap_16( v ) \
   _mm256_shuffle_epi8( v, _mm256_set_epi8(  14,15,  12,13,  10,11,   8, 9, \
                                              6, 7,   4, 5,   2, 3,   0, 1, \
                                             14,15,  12,13,  10,11,   8, 9, \
                                              6, 7,   4, 5,   2, 3,   0, 1 ) )

// 8 byte qword * 8 qwords * 4 lanes = 256 bytes
#define mm256_block_bswap_64( d, s ) do \
{ \
  __m256i ctl = m256_const_64( 0x08090a0b0c0d0e0f, 0x0001020304050607, \
                               0x08090a0b0c0d0e0f, 0x0001020304050607 ); \
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
  __m256i ctl = m256_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203, \
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

#define mm256_swap256_512 (v1, v2) \
   v1 = _mm256_xor_si256(v1, v2); \
   v2 = _mm256_xor_si256(v1, v2); \
   v1 = _mm256_xor_si256(v1, v2);

#define mm256_ror1x128_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 16 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 16 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x128_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 16 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 16 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x64_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 8 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 8 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x64_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 24 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 24 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x32_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 4 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 4 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x32_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 28 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 28 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x16_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 2 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x16_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 30 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 30 ); \
   v1 = t; \
} while(0)

#define mm256_ror1x8_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 1 ); \
   v1 = _mm256_alignr_epi8( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm256_rol1x8_512( v1, v2 ) \
do { \
   __m256i t = _mm256_alignr_epi8( v1, v2, 31 ); \
   v2 = _mm256_alignr_epi8( v2, v1, 31 ); \
   v1 = t; \
} while(0)

#endif // __AVX2__
#endif // __AVX__
#endif // SIMD_256_H__

