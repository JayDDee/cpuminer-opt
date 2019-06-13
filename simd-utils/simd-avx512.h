#if !defined(SIMD_AVX512_H__)
#define SIMD_AVX512_H__ 1

#if defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)


////////////////////////////////////////////////////////
//
// Some extentsions in AVX512 supporting operations on
// smaller elements in 256 bit vectors.

// Variable rotate, each element rotates by corresponding index.
#define mm256_rorv_16( v, c ) \
   _mm256_or_si256( \
         _mm256_srlv_epi16( v, _mm256_set1_epi16( c ) ), \
         _mm256_sllv_epi16( v, _mm256_set1_epi16( 16-(c) ) ) )

#define mm256_rolv_16( v, c ) \
   _mm256_or_si256( \
         _mm256_sllv_epi16( v, _mm256_set1_epi16( c ) ), \
         _mm256_srlv_epi16( v, _mm256_set1_epi16( 16-(c) ) ) )

// Invert vector: {7,6,5,4,3,2,1,0} -> {0,1,2,3,4,5,6,7}
#define mm256_invert_16 ( v ) \
     _mm256_permutex_epi16( v, _mm256_set_epi16( 0, 1, 2, 3, 4, 5, 6, 7, \
                                                 8, 9,10,11,12,13,14,15 ) )

#define mm256_invert_8( v ) \
     _mm256_permutex_epi8( v, _mm256_set_epi8( 0, 1, 2, 3, 4, 5, 6, 7, \
                                               8, 9,10,11,12,13,14,15, \
                                              16,17,18,19,20,21,22,23, \
                                              24,25,26,27,28,29,30,31 ) )

//////////////////////////////////////////////////////////////
//
//   AVX512 512 bit vectors
//
// Other AVX512 extensions that may be required for some functions.
// __AVX512VBMI__  __AVX512VAES__
//
// Experimental, not fully tested.


//
// Compile time vector constants and initializers.
//
// The following macro constants and functions should only be used
// for compile time initialization of constant and variable vector
// arrays. These constants use memory, use set instruction or pseudo
// constants at run time to avoid using memory.

// Constant initializers
#define mm512_const_64( x7, x6, x5, x4, x3, x2, x1, x0 ) \
                     {{ x7, x6, x5, x4, x3, x2, x1, x0 }}

#define mm512_const1_64( x ) {{ x,x,x,x,x,x,x }}

#define mm512_const_32( x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 ) \
                     {{ x15, x14, x13, x12, x11, x10, x09, x08, }} \
                        x07, x06, x05, x04, x03, x02, x01, x00 }}

#define mm512_const1_32( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

#define mm512_const_16( x31, x30, x29, x28, x27, x26, x25, x24, \
                        x23, x22, x21, x20, x19, x18, x17, x16, \
                        x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 ) \
                     {{ x31, x30, x29, x28, x27, x26, x25, x24, \
                        x23, x22, x21, x20, x19, x18, x17, x16, \
                        x15, x14, x13, x12, x11, x10, x09, x08, \
                        x07, x06, x05, x04, x03, x02, x01, x00 }}

#define mm512_const1_16( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                                x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

#define mm512_const_8( x63, x62, x61, x60, x59, x58, x57, x56, \
                       x55, x54, x53, x52, x51, x50, x49, x48, \
                       x47, x46, x45, x44, x43, x42, x41, x40, \
                       x39, x38, x37, x36, x35, x34, x33, x32, \
                       x31, x30, x29, x28, x27, x26, x25, x24, \
                       x23, x22, x21, x20, x19, x18, x17, x16, \
                       x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 ) \
                    {{ x63, x62, x61, x60, x59, x58, x57, x56, \
                       x55, x54, x53, x52, x51, x50, x49, x48, \
                       x47, x46, x45, x44, x43, x42, x41, x40, \
                       x39, x38, x37, x36, x35, x34, x33, x32, \
                       x31, x30, x29, x28, x27, x26, x25, x24, \
                       x23, x22, x21, x20, x19, x18, x17, x16, \
                       x15, x14, x13, x12, x11, x10, x09, x08, \
                       x07, x06, x05, x04, x03, x02, x01, x00 }}

#define mm512_const1_8( x ) {{ x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                               x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                               x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x, \
                               x,x,x,x, x,x,x,x, x,x,x,x, x,x,x,x }}

// Predefined compile time constant vectors.
#define c512_zero      mm512_const1_64(   0ULL )
#define c512_neg1      mm512_const1_64(   0xFFFFFFFFFFFFFFFFULL )
#define c512_one_512   mm512_const_epi64( 0ULL, 0ULL, 0ULL, 0ULL, \
                                          0ULL, 0ULL, 0ULL, 1ULL )
#define c512_one_256   mm512_const_64(    0ULL, 0ULL, 0ULL, 1ULL, \
                                          0ULL, 0ULL, 0ULL, 1ULL )
#define c512_one_128   mm512_const_64(    0ULL, 1ULL, 0ULL, 1ULL, \
                                          0ULL, 1ULL, 0ULL, 1ULL )
#define c512_one_64    mm512_const1_64(   1ULL )
#define c512_one_32    mm512_const1_32(   1UL )
#define c512_one_16    mm512_const1_16(   1U )
#define c512_one_8     mm512_const1_8(    1U )
#define c512_neg1_64   mm512_const1_64( 0xFFFFFFFFFFFFFFFFULL )
#define c512_neg1_32   mm512_const1_32( 0xFFFFFFFFUL )
#define c512_neg1_16   mm512_const1_32( 0xFFFFU )
#define c512_neg1_8    mm512_const1_32( 0xFFU )

//
// Pseudo constants.

// _mm512_setzero_si512 uses xor instruction. If needed frequently
// in a function is it better to define a register variable (const?)
// initialized to zero.
// It isn't clear to me yet how set or set1 actually work.

#define m512_zero       _mm512_setzero_si512()
#define m512_one_512    _mm512_set_epi64(  0ULL, 0ULL, 0ULL, 0ULL, \
                                           0ULL, 0ULL, 0ULL, 1ULL )
#define m512_one_256    _mm512_set4_epi64( 0ULL, 0ULL, 0ULL, 1ULL )
#define m512_one_128    _mm512_set4_epi64( 0ULL, 1ULL, 0ULL, 1ULL )
#define m512_one_64     _mm512_set1_epi64( 1ULL )
#define m512_one_32     _mm512_set1_epi32( 1UL )
#define m512_one_16     _mm512_set1_epi16( 1U )
#define m512_one_8      _mm512_set1_epi8(  1U )
#define m512_neg1       _mm512_set1_epi64( 0xFFFFFFFFFFFFFFFFULL )


//
// Basic operations without SIMD equivalent

#define mm512_not( x )       _mm512_xor_si512( x, m512_neg1 )
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

// Gather scatter

#define mm512_gather_64( d, s0, s1, s2, s3, s4, s5, s6, s7 ) \
    ((uint64_t*)(d))[0] = (uint64_t)(s0); \
    ((uint64_t*)(d))[1] = (uint64_t)(s1); \
    ((uint64_t*)(d))[2] = (uint64_t)(s2); \
    ((uint64_t*)(d))[3] = (uint64_t)(s3); \
    ((uint64_t*)(d))[4] = (uint64_t)(s4); \
    ((uint64_t*)(d))[5] = (uint64_t)(s5); \
    ((uint64_t*)(d))[6] = (uint64_t)(s6); \
    ((uint64_t*)(d))[7] = (uint64_t)(s7); 


#define mm512_gather_32( d, s00, s01, s02, s03, s04, s05, s06, s07, \
                   s08, s09, s10, s11, s12, s13, s14, s15 ) \
    ((uint32_t*)(d))[ 0] = (uint32_t)(s00); \
    ((uint32_t*)(d))[ 1] = (uint32_t)(s01); \
    ((uint32_t*)(d))[ 2] = (uint32_t)(s02); \
    ((uint32_t*)(d))[ 3] = (uint32_t)(s03); \
    ((uint32_t*)(d))[ 4] = (uint32_t)(s04); \
    ((uint32_t*)(d))[ 5] = (uint32_t)(s05); \
    ((uint32_t*)(d))[ 6] = (uint32_t)(s06); \
    ((uint32_t*)(d))[ 7] = (uint32_t)(s07); \
    ((uint32_t*)(d))[ 8] = (uint32_t)(s08); \
    ((uint32_t*)(d))[ 9] = (uint32_t)(s09); \
    ((uint32_t*)(d))[10] = (uint32_t)(s10); \
    ((uint32_t*)(d))[11] = (uint32_t)(s11); \
    ((uint32_t*)(d))[12] = (uint32_t)(s12); \
    ((uint32_t*)(d))[13] = (uint32_t)(s13); \
    ((uint32_t*)(d))[13] = (uint32_t)(s14); \
    ((uint32_t*)(d))[15] = (uint32_t)(s15);

// Scatter data from contiguous memory.
// All arguments are pointers
#define mm512_scatter_64( d0, d1, d2, d3, d4, d5, d6, d7, s ) \
   *((uint64_t*)(d0)) = ((uint64_t*)(s))[0]; \
   *((uint64_t*)(d1)) = ((uint64_t*)(s))[1]; \
   *((uint64_t*)(d2)) = ((uint64_t*)(s))[2]; \
   *((uint64_t*)(d3)) = ((uint64_t*)(s))[3]; \
   *((uint64_t*)(d4)) = ((uint64_t*)(s))[4]; \
   *((uint64_t*)(d5)) = ((uint64_t*)(s))[5]; \
   *((uint64_t*)(d6)) = ((uint64_t*)(s))[6]; \
   *((uint64_t*)(d7)) = ((uint64_t*)(s))[7];


#define mm512_scatter_32( d00, d01, d02, d03, d04, d05, d06, d07, \
                     d08, d09, d10, d11, d12, d13, d14, d15, s ) \
   *((uint32_t*)(d00)) = ((uint32_t*)(s))[ 0]; \
   *((uint32_t*)(d01)) = ((uint32_t*)(s))[ 1]; \
   *((uint32_t*)(d02)) = ((uint32_t*)(s))[ 2]; \
   *((uint32_t*)(d03)) = ((uint32_t*)(s))[ 3]; \
   *((uint32_t*)(d04)) = ((uint32_t*)(s))[ 4]; \
   *((uint32_t*)(d05)) = ((uint32_t*)(s))[ 5]; \
   *((uint32_t*)(d06)) = ((uint32_t*)(s))[ 6]; \
   *((uint32_t*)(d07)) = ((uint32_t*)(s))[ 7]; \
   *((uint32_t*)(d00)) = ((uint32_t*)(s))[ 8]; \
   *((uint32_t*)(d01)) = ((uint32_t*)(s))[ 9]; \
   *((uint32_t*)(d02)) = ((uint32_t*)(s))[10]; \
   *((uint32_t*)(d03)) = ((uint32_t*)(s))[11]; \
   *((uint32_t*)(d04)) = ((uint32_t*)(s))[12]; \
   *((uint32_t*)(d05)) = ((uint32_t*)(s))[13]; \
   *((uint32_t*)(d06)) = ((uint32_t*)(s))[14]; \
   *((uint32_t*)(d07)) = ((uint32_t*)(s))[15];


//
// Bit rotations.

// AVX512F has built-in bit fixed and variable rotation for 64 & 32 bit
// elements. There is no bit rotation or shift for larger elements.
//
// _mm512_rol_epi64,  _mm512_ror_epi64,  _mm512_rol_epi32,  _mm512_ror_epi32
// _mm512_rolv_epi64, _mm512_rorv_epi64, _mm512_rolv_epi32, _mm512_rorv_epi32
//
// Here is a bit rotate for 16 bit elements:
#define mm512_ror_16( v, c ) \
    _mm512_or_si512( _mm512_srli_epi16( v, c ), \
                     _mm512_slli_epi16( v, 16-(c) )
#define mm512_rol_16( v, c ) \
    _mm512_or_si512( _mm512_slli_epi16( v, c ), \
                     _mm512_srli_epi16( v, 16-(c) )

//
// Rotate elements in 512 bit vector.

#define mm512_swap_256( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 3,2,1,0,  7,6,5,4 ) )

#define mm512_ror_1x128( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 1,0,  7,6,  5,4,  3,2 ) )

#define mm512_rol_1x128( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 5,4,  3,2,  1,0,  7,6 ) )

#define mm512_ror_1x64( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 0,7,6,5,4,3,2,1 ) )

#define mm512_rol_1x64( v ) \
    _mm512_permutexvar_epi64( v, _mm512_set_epi64( 6,5,4,3,2,1,0,7 ) )

#define mm512_ror_1x32( v ) \
  _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                      0,15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1 ) )

#define mm512_rol_1x32( v ) \
  _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                     14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15 ) )

//  Although documented to exist in AVX512F the _mm512_set_epi8 &
//  _mm512_set_epi16 intrinsics fail to compile. Seems usefull to have
//  for endian byte swapping. Workaround by using _mm512_set_epi32.
//  Ugly but it works.

#define mm512_ror_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                       0x0000001F, 0x001E001D, 0x001C001B, 0x001A0019, \
                       0X00180017, 0X00160015, 0X00140013, 0X00120011, \
                       0X0010000F, 0X000E000D, 0X000C000B, 0X000A0009, \
                       0X00080007, 0X00060005, 0X00040003, 0X00020001 ) )

#define mm512_rol_1x16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi16( \
                       0x001E001D, 0x001C001B, 0x001A0019, 0x00180017, \
                       0X00160015, 0X00140013, 0X00120011, 0x0010000F, \
                       0X000E000D, 0X000C000B, 0X000A0009, 0X00080007, \
                       0X00060005, 0X00040003, 0X00020001, 0x0000001F ) )


#define mm512_ror_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
                       0x003F3E3D, 0x3C3B3A39, 0x38373635, 0x34333231, \
                       0x302F2E2D, 0x2C2B2A29, 0x28272625, 0x24232221, \
                       0x201F1E1D, 0x1C1B1A19. 0x18171615, 0x14131211, \
                       0x100F0E0D, 0x0C0B0A09, 0x08070605, 0x04030201 ) )

#define mm512_rol_1x8( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi8( \
                       0x3E3D3C3B, 0x3A393837, 0x36353433, 0x3231302F. \
                       0x2E2D2C2B, 0x2A292827, 0x26252423, 0x2221201F, \
                       0x1E1D1C1B, 0x1A191817, 0x16151413, 0x1211100F, \
                       0x0E0D0C0B, 0x0A090807, 0x06050403, 0x0201003F ) )

// Invert vector: {3,2,1,0} -> {0,1,2,3}
#define mm512_invert_128( v ) _mm512_permute4f128_epi32( a, 0x1b )

#define mm512_invert_64( v ) \
   _mm512_permutex_epi64( v, _mm512_set_epi64( 0,1,2,3,4,5,6,7 ) )

#define mm512_invert_32( v ) \
   _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                      0, 1, 2, 3, 4, 5, 6, 7,   8, 9,10,11,12,13,14,15 ) )


#define mm512_invert_16( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                       0x00000001, 0x00020003, 0x00040005, 0x00060007, \
                       0x00080009, 0x000A000B, 0x000C000D, 0x000E000F, \
                       0x00100011, 0x00120013, 0x00140015, 0x00160017, \
                       0x00180019, 0x001A001B, 0x001C001D, 0x001E001F ) )

#define mm512_invert_8(  v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, \
                       0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F, \
                       0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, \
                       0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F ) )

//
// Rotate elements within 256 bit lanes of 512 bit vector.

// Swap hi & lo 128 bits in each 256 bit lane
#define mm512_swap128_256( v )   _mm512_permutex_epi64( v, 0x4e )

// Rotate 256 bit lanes by one 64 bit element
#define mm512_ror1x64_256( v )   _mm512_permutex_epi64( v, 0x39 )
#define mm512_rol1x64_256( v )   _mm512_permutex_epi64( v, 0x93 )

// Rotate 256 bit lanes by one 32 bit element
#define mm512_ror1x32_256( v ) \
   _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                      8,15,14,13,12,11,10, 9,   0, 7, 6, 5, 4, 3, 2, 1 ) )
#define mm512_rol1x32_256( v ) \
   _mm512_permutexvar_epi32( v, _mm512_set_epi32( \
                     14,13,12,11,10, 9, 8,15,   6, 5, 4, 3, 2, 1, 0, 7 ) )
#define mm512_ror1x16_256( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                     0x0010001F, 0x001E001D, 0x001C001B, 0x001A0019, \
                     0x00180017, 0x00160015, 0x00140013, 0x00120011, \
                     0x0000000F, 0x000E000D, 0x000C000B, 0x000A0009, \
                     0x00080007, 0x00060005, 0x00040003, 0x00020001 ) )

#define mm512_rol1x16_256( v ) \
   _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                     0x001E001D, 0x001C001B, 0x001A0019, 0x00180017, \
                     0x00160015, 0x00140013, 0x00120011, 0x0000000F, \
                     0x000E000D, 0x000C000B, 0x000A0009, 0x00080007, \
                     0x00060005, 0x00040003, 0x00020001, 0x0000001F ) )

#define mm512_ror1x8_256( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                     0x203F3E3D, 0x3C3B3A39, 0x38373635, 0x34333231, \
                     0x302F2E2D, 0x2C2B2A29, 0x28272625, 0x24232221, \
                     0x001F1E1D, 0x1C1B1A19, 0x18171615, 0x14131211, \
                     0x100F0E0D, 0x0C0B0A09, 0x08070605, 0x04030201 ) )

#define mm512_rol1x8_256( v ) \
    _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                     0x3E3D3C3B, 0x3A393837, 0x36353433, 0x3231302F, \
                     0x2E2D2C2B, 0x2A292827, 0x26252423, 0x2221203F, \
                     0x1E1D1C1B, 0x1A191817, 0x16151413, 0x1211100F, \
                     0x0E0D0C0B, 0x0A090807, 0x06050403, 0x0201001F ) )

//
// Rotate elements within 128 bit lanes of 512 bit vector.

// Swap hi & lo 64 bits in each 128 bit lane
#define mm512_swap64_128( v )    _mm512_permutex_epi64( v, 0xb1 )

// Rotate 128 bit lanes by one 32 bit element
#define mm512_ror1x32_128( v )   _mm512_shuffle_epi32( v, 0x39 )
#define mm512_rol1x32_128( v )   _mm512_shuffle_epi32( v, 0x93 )

#define mm512_ror1x16_128( v ) \
    _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                     0x0018001F, 0x001E001D, 0x001C001B, 0x001A0019, \
                     0x00100017, 0x00160015, 0x00140013, 0x00120011, \
                     0x0008000F, 0x000E000D, 0x000C000B, 0x000A0009, \
                     0x00000007, 0x00060005, 0x00040003, 0x00020001 ) )

#define mm512_rol1x16_128( v ) \
    _mm512_permutexvar_epi16( v, _mm512_set_epi32( \
                     0x001E001D, 0x001C001B, 0x001A0019, 0x0018001F, \
                     0x00160015, 0x00140013, 0x00120011, 0x00100017, \
                     0x000E000D, 0x000C000B, 0x000A0009, 0x0008000F, \
                     0x00060005, 0x00040003, 0x00020001, 0x00000007 ) )

#define mm512_ror1x8_128( v ) \
    _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                     0x303F3E3D, 0x3C3B3A39, 0x38373635, 0x34333231, \
                     0x202F2E2D, 0x2C2B2A29, 0x28272625, 0x24232221, \
                     0x101F1E1D, 0x1C1B1A19, 0x18171615, 0x14131211, \
                     0x000F0E0D, 0x0C0B0A09, 0x08070605, 0x04030201 ) )

#define mm512_rol1x8_128( v ) \
    _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                     0x3E3D3C3B, 0x3A393837, 0x36353433. 0x3231303F, \
                     0x2E2D2C2B, 0x2A292827, 0x26252423, 0x2221202F, \
                     0x1E1D1C1B, 0x1A191817, 0x16151413, 0x1211101F, \
                     0x0E0D0C0B, 0x0A090807, 0x06050403, 0x0201000F ) )

// Rotate 128 bit lanes by c bytes.  
#define mm512_bror_128( v, c ) \
   _mm512_or_si512( _mm512_bsrli_epi128( v, c ), \
                    _mm512_bslli_epi128( v, 16-(c) ) )
#define mm512_brol_128( v, c ) \
   _mm512_or_si512( _mm512_bslli_epi128( v, c ), \
                    _mm512_bsrli_epi128( v, 16-(c) ) )


//
// Rotate elements within 64 bit lanes.

// Swap 32 bit elements in each 64 bit lane
#define mm512_swap32_64( v )      _mm512_shuffle_epi32( v, 0xb1 )

// _mm512_set_epi8 doesn't seem to work

// Rotate each 64 bit lane by one 16 bit element.
#define mm512_ror1x16_64( v ) \
    _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                      0x39383F3E, 0x3D3C3B3A,   0x31303736, 0x35343332, \
                      0x29282F2E, 0x2D2C2B2A,   0x21202726, 0x25242322, \
                      0x19181F1E, 0x1D1C1B1A,   0x11101716, 0x15141312, \
                      0x09080F0E, 0x0D0C0B0A,   0x01000706, 0x05040302 ) )

#define mm512_rol1x16_64( v ) \
    _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                      0x3D3C3B3A, 0x39383F3E,   0x35343332, 0x31303736 \
                      0x2D2C2B2A, 0x29282F2E,   0x25242322, 0x21202726 \
                      0x1D1C1B1A, 0x19181F1E,   0x15141312, 0x11101716 \
                      0x0D0C0B0A, 0x09080F0E,   0x05040302, 0x01000706 ) ) 

// Rotate each 64 bit lane by one byte.
#define mm512_ror1x8_64( v ) \
    _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                      0x383F3E3D, 0x3C3B3A39,   0x30373635, 0x34333231, \
                      0x282F2E2D, 0x2C2B2A29,   0x20272625, 0x24232221, \
                      0x181F1E1D, 0x1C1B1A19,   0x10171615, 0x14131211, \
                      0x080F0E0D, 0x0C0B0A09,   0x00070605, 0x0403020 )
#define mm512_rol1x8_64( v ) \
    _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x3E3D3C3B, 0x3A39383F,   0x36353433, 0x32313037, \
                       0x2E2D2C2B, 0x2A29282F,   0x26252423, 0x22212027, \
                       0x1E1D1C1B, 0x1A19181F,   0x16151413, 0x12111017, \
                       0x0E0D0C0B, 0x0A09080F,   0x06050403, 0x02010007 )

//
// Rotate elements within 32 bit lanes.

#define mm512_swap16_32( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x001D001C, 0x001F001E, 0x00190018, 0x001B001A, \
                       0x00150014, 0x00170016, 0x00110010, 0x00130012, \
                       0x000D000C, 0x000F000E, 0x00190008, 0x000B000A, \
                       0x00050004, 0x00070006, 0x00110000, 0x00030002 )

#define mm512_ror1x8_32( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x3C3F3E3D, 0x383B3A39, 0x34373635, 0x30333231, \
                       0x2C2F2E2D, 0x282B2A29, 0x24272625, 0x20232221, \
                       0x1C1F1E1D, 0x181B1A19, 0x14171615, 0x10131211, \
                       0x0C0F0E0D, 0x080B0A09, 0x04070605, 0x00030201 ) )

#define mm512_rol1x8_32( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x3E3D3C3F, 0x3A39383B, 0x36353437, 0x32313033, \
                       0x2E2D2C2F, 0x2A29282B, 0x26252427, 0x22212023, \
                       0x1E1D1C1F, 0x1A19181B, 0x16151417, 0x12111013, \
                       0x0E0D0C0F, 0x0A09080B, 0x06050407, 0x02010003 ) )

//
// Swap bytes in vector elements, vectorized bswap.

#define mm512_bswap_64( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x38393A3B, 0x3C3D3E3F,   0x20313233, 0x34353637, \
                       0x28292A2B, 0x2C2D2E2F,   0x20212223, 0x34353637, \
                       0x18191A1B, 0x1C1D1E1F,   0x10111213, 0x14151617, \
                       0x08090A0B, 0x0C0D0E0F,   0x00010203, 0x04050607 ) )

#define mm512_bswap_32( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi832( \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233, \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233, \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233, \
                       0x3C3D3E3F, 0x38393A3B, 0x34353637, 0x30313233 ) )

#define mm512_bswap_16( v ) \
   _mm512_permutexvar_epi8( v, _mm512_set_epi32( \
                       0x3E3F3C3D, 0x3A3B3839, 0x36373435, 0x32333031, \
                       0x2E2F2C2D, 0x2A2B2829, 0x26272425, 0x22232021, \
                       0x1E1F1C1D, 0x1A1B1819, 0x16171415, 0x12131011, \
                       0x0E0F0C0D, 0x0A0B0809, 0x06070405, 0x02030001 ) )

//
//  Rotate elements from 2 512 bit vectors in place, source arguments
//  are overwritten.
//  These can all be done with 2 permutex2var instructions but they are
//  slower than either xor or alignr.

#define mm512_swap512_1024(v1, v2) \
   v1 = _mm512_xor_si512(v1, v2); \
   v2 = _mm512_xor_si512(v1, v2); \
   v1 = _mm512_xor_si512(v1, v2);

#define mm512_ror1x256_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 4 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 4 ); \
   v2 = t; \
} while(0)

#define mm512_rol1x256_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 4 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 4 ); \
   v1 = t; \
} while(0)

#define mm512_ror1x128_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 2 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm512_rol1x128_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 6 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 6 ); \
   v1 = t; \
} while(0)

#define mm512_ror1x64_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi64( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1x64_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi64( v1, v2, 7 ); \
   v2 = _mm512_alignr_epi64( v2, v1, 7 ); \
   v1 = t; \
} while(0)

#define mm512_ror1x32_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi32( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi32( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1x32_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi32( v1, v2, 15 ); \
   v2 = _mm512_alignr_epi32( v2, v1, 15 ); \
   v1 = t; \
} while(0)

#define mm512_ror1x16_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 2 ); \
   v1 = _mm512_alignr_epi8( v2, v1, 2 ); \
   v2 = t; \
} while(0)

#define mm512_rol1x16_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 62 ); \
   v2 = _mm512_alignr_epi8( v2, v1, 62 ); \
   v1 = t; \
} while(0)

#define mm512_ror1x8_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 1 ); \
   v1 = _mm512_alignr_epi8( v2, v1, 1 ); \
   v2 = t; \
} while(0)

#define mm512_rol1x8_1024( v1, v2 ) \
do { \
   __m512i t = _mm512_alignr_epi8( v1, v2, 63 ); \
   v2 = _mm512_alignr_epi8( v2, v1, 63 ); \
   v1 = t; \
} while(0)

#endif // AVX512
#endif // SIMD_AVX512_H__
