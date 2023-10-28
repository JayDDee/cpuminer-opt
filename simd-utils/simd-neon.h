#if !defined(SIMD_NEON_H__)
#define SIMD_NEON_H__ 1

#if defined(__aarch64__) && defined(__ARM_NEON)

// Targeted functions supporting NEON SIMD 128 & 64 bit vectors.
// Size matters!
//
// Intel naming is generally used.
//
// documented instructions that aren't defined on RPi 4.
// They seem to be all 3 op instructionsi.
//
//  veor3q ie xor3
//  vxarq_u64( v1, v0, n )    ror( xor( v1, v0 ), n )
//  vraxlq_u64( v1, v0 )      xor( rol( v1, 1 ), rol( v0, 1 ) )
//  vbcaxq( v2, v1, v0 )      xor( v2, and( v1, not(v0) ) )
//
//  might not work, not tried yet:
//
//  vornq( v1, v0 )        or( v1, not( v0 ) )
//  vsraq_n( v1, v0, n )   add( v1, sr( v0, n ) )

#define v128_t                         uint32x4_t   // default, 
#define v128u64_t                      uint64x2_t
#define v128u32_t                      uint32x4_t
#define v128u16_t                      uint16x8_t
#define v128u8_t                       uint8x16_t

// load & store
#define v128_load( p )                 vld1q_u32( (uint32_t*)(p) )
#define v128_store( p, v )             vst1q_u32( (uint32_t*)(p), v )

// load & set1 combined
#define v128_load1_64(p)               vld1q_dup_u64( (uint64_t*)(p) )
#define v128_load1_32(p)               vld1q_dup_u32( (uint32_t*)(p) )
#define v128_load1_16(p)               vld1q_dup_u16( (uint16_t*)(p) )
#define v128_load1_8( p)               vld1q_dup_u8(  (uint8_t*) (p) )

// arithmetic
#define v128_add64                     vaddq_u64
#define v128_add32                     vaddq_u32
#define v128_add16                     vaddq_u16
#define v128_add8                      vaddq_u8

#define v128_add4_64( v3, v2, v1, v0 ) \
   vaddq_u64( vaddq_u64( v3, v2 ), vaddq_u64( v1, v0 ) )

#define v128_add4_32( v3, v2, v1, v0 ) \
   vaddq_u32( vaddq_u32( v3, v2 ), vaddq_u32( v1, v0 ) )

#define v128_sub64                     vsubq_u64
#define v128_sub32                     vsubq_u32
#define v128_sub16                     vsubq_u16
#define v128_sub8                      vsubq_u8

// returns low half, u64 undocumented, may not exist.
#define v128_mul64                     vmulq_u64
#define v128_mul32                     vmulq_u32
#define v128_mul16                     vmulq_u16

// slow, tested with argon2d
static inline uint64x2_t v128_mulw32( uint32x4_t v1, uint32x4_t v0 )
{
   return vmull_u32( vget_low_u32( vcopyq_laneq_u32( v1, 1, v1, 2 ) ),
                     vget_low_u32( vcopyq_laneq_u32( v0, 1, v0, 2 ) ) );
}

// compare
#define v128_cmpeq64                   vceqq_u64
#define v128_cmpeq32                   vceqq_u32
#define v128_cmpeq16                   vceqq_u16
#define v128_cmpeq8                    vceqq_u8

#define v128_cmpeq0                    vceqzq_u64

#define v128_cmpgt64                   vcgtq_u64
#define v128_cmpgt32                   vcgtq_u32
#define v128_cmpgt16                   vcgtq_u16
#define v128_cmpgt8                    vcgtq_u8

#define v128_cmplt64                   vcltq_u64
#define v128_cmplt32                   vcltq_u32
#define v128_cmplt16                   vcltq_u16
#define v128_cmplt8                    vcltq_u8

// bit shift
#define v128_sl64                      vshlq_n_u64
#define v128_sl32                      vshlq_n_u32
#define v128_sl16                      vshlq_n_u16
#define v128_sl8                       vshlq_n_u8

#define v128_sr64                      vshrq_n_u64
#define v128_sr32                      vshrq_n_u32
#define v128_sr16                      vshrq_n_u16
#define v128_sr8                       vshrq_n_u8

// Maybe signed shift will work.
#define v128_sra64                     vshrq_n_s64
#define v128_sra32                     vshrq_n_s32
#define v128_sra16                     vshrq_n_s16

// unary logic
#define v128_not                       vmvnq_u32

// binary
#define v128_or                        vorrq_u32
#define v128_and                       vandq_u32
#define v128_xor                       veorq_u32
#define v128_andnot                    vandq_u32
#define v128_xnor( v1, v0 )            v128_not( v128_xor( v1, v0 ) )
#define v128_ornot                     vornq_u32 

// ternary logic, veorq_u32 not defined
//#define v128_xor3                      veor3q_u32
#define v128_xor3( v2, v1, v0 )        veorq_u32( v2, veorq_u32( v1, v0 ) )
#define v128_nor                       vornq_u32
#define v128_xorandnot( v2, v1, v0 )   v128_xor( v2, v128_andnot( v1, v0 ) )
#define v128_and3( a, b, c )           v128_and( a, v128_and( b, c ) )
#define v128_or3( a, b, c )            v128_or( a, v128_or( b, c ) )
#define v128_xorand( a, b, c )         v128_xor( a, v128_and( b, c ) )
#define v128_andxor( a, b, c )         v128_and( a, v128_xor( b, c ) )
#define v128_xoror( a, b, c )          v128_xor( a, v128_or( b, c ) )
#define v128_orand( a, b, c )          v128_or( a, v128_and( b, c ) )

// shift 2 concatenated vectors right.
#define v128_alignr64( v1, v0, c )     vextq_u64( v0, v1, c )
#define v128_alignr32( v1, v0, c )     vextq_u32( v0, v1, c )
#define v128_alignr8(  v1, v0, c )     vextq_u8(  v0, v1, c ) 

// Intetleave high or low half of 2 vectors.
#define v128_unpacklo64( v1, v0 )      vzip1q_u64( v0, v1 )
#define v128_unpackhi64( v1, v0 )      vzip2q_u64( v0, v1 )
#define v128_unpacklo32( v1, v0 )      vzip1q_u32( v0, v1 )
#define v128_unpackhi32( v1, v0 )      vzip2q_u32( v0, v1 )
#define v128_unpacklo16( v1, v0 )      vzip1q_u16( v0, v1 )
#define v128_unpackhi16( v1, v0 )      vzip2q_u16( v0, v1 )
#define v128_unpacklo8(  v1, v0 )      vzip1q_u8(  v0, v1 )
#define v128_unpackhi8(  v1, v0 )      vzip2q_u8(  v0, v1 )

// Shorter achchitecture agnostic names for unpack using NEON-like mnemonics
#define v128_ziplo64                   vzip1q_u64
#define v128_ziphi64                   vzip2q_u64
#define v128_ziplo32                   vzip1q_u32
#define v128_ziphi32                   vzip2q_u32
#define v128_ziplo16                   vzip1q_u16
#define v128_ziphi16                   vzip2q_u16
#define v128_ziplo8                    vzip1q_u8
#define v128_ziphi8                    vzip2q_u8

// AES
// consistent with Intel AES, break up for optimizing
#define v128_aesenc( v, k )            vaesmcq_u8( vaeseq_u8( v, k ) )
#define v128_aesenclast( v, k )        vaeseq_u8( v, k )

#define v128_aesdec( v, k )            vaesimcq_u8( vaesdq_u8( v, k ) )
#define v128_aesdeclast( v, k )        vaesdq_u8( v, k )

typedef union
{
   uint32x4_t m128;
   uint32_t u32[4];
} __attribute__ ((aligned (16))) v128_ovly;

// pointer indexing
#define casti_v128( p, i )             (((uint32x4_t*)(p))[i])
#define cast_v128( p )                 (*((uint32x4_t*)(p)))
#define castp_v128( p )                ((uint32x4_t*)(p))

#define casti_v128u64( p, i )          (((uint64x2_t*)(p))[i])
#define cast_v128u64( p )              (*((uin64x24_t*)(p)))
#define castp_v128u64( p )             ((uint64x2_t*)(p))

#define casti_v128u32( p, i )          (((uint32x4_t*)(p))[i])
#define cast_v128u32( p )              (*((uint32x4_t*)(p)))
#define castp_v128u32( p )             ((uint32x4_t*)(p))

// use C cast, flexible source type
#define u32_to_u64                     vreinterpretq_u64_u32
#define u64_to_u32                     vreinterpretq_u32_u64

#define u64_to_u8                      vreinterpretq_u8_u64
#define u8_to_u64                      vreinterpretq_u64_u8

#define u32_to_u8                      vreinterpretq_u8_u32
#define u8_to_u32                      vreinterpretq_u32_u8

#define v128_zero                      v128_64( 0ull )

#define v128_cmpeq_zero                vceqzq_u64

#define v128_neg1                      v128_64( 0xffffffffffffffffull )

// set1
#define v128_64                        vmovq_n_u64
#define v128_32                        vmovq_n_u32
#define v128_16                        vmovq_n_u16
#define v128_8                         vmovq_n_u8

#define v64_set32( u32_1, u32_0 ) \
   vcreate_u32( ( (uint64_t)(u32_1) << 32 ) | (uint64_t)(u32_0) )

#define v64_set16( u16_3, u16_2, u16_1, u16_0 ) \
    vcreate_u16( ( (uint64_t)( ( (uint32_t)(u16_3) << 16 ) \
                               | (uint32_t)(u16_2)       ) << 32 ) \
               | ( (uint64_t)( ( (uint32_t)(u16_1) << 16 ) \
                               | (uint32_t)(u16_0)       )       ) )

#define v64_set8( u8_7, u8_6, u8_5, u8_4, u8_3, u8_2, u8_1, u8_0 ) \
    vcreate_u8( \
     ( (uint64_t)( ( (uint32_t)(((uint16_t)(u8_7) << 8 ) \
                               | (uint16_t)(u8_6)      ) << 16 ) \
                 | ( (uint32_t)(((uint16_t)(u8_5) << 8 ) \
                               | (uint16_t)(u8_4)      )       )) << 32 )  \
   | ( (uint64_t)( ( (uint32_t)(((uint16_t)(u8_3) << 8 ) \
                               | (uint16_t)(u8_2)      ) << 16 ) \
                 | ( (uint32_t)(((uint16_t)(u8_1) << 8 ) \
                               | (uint16_t)(u8_0)      )       ))       ))

#define v128_set64( u64_1, u64_0 ) \
   vcombine_u64( vcreate_u64( u64_0 ), vcreate_u64( u64_1 ) ) 

#define v128_set32( u32_3, u32_2, u32_1, u32_0 ) \
   vcombine_u32( v64_set32( u32_1, u32_0 ), v64_set32( u32_3, u32_2 ) )

#define v128_set16( u16_7, u16_6, u16_5, u16_4, u16_3, u16_2, u16_1, u16_0 ) \
  vcombine_u16( v64_set16( u16_3, u16_2, u16_1, u16_0 ), \
                v64_set16( u16_7, u16_6, u16_5, u16_4 ) )

#define v128_set8( u8_f, u8_e, u8_d, u8_c, u8_b, u8_a, u8_9, u8_8, \
                   u8_7, u8_6, u8_5, u8_4, u8_3, u8_2, u8_1, u8_0 ) \
  vcombine_u8( v64_set8( u8_7, u8_6, u8_5, u8_4, u8_3, u8_2, u8_1, u8_0 ), \
               v64_set8( u8_f, u8_e, u8_d, u8_c, u8_b, u8_a, u8_9, u8_8 ) )   


// move single element from source to dest,lanes must be immediate constant
// same as xim?
#define v128_movlane64( v1, l1, v0, l0 )     vcopyq_laneq_u64( v1, l1, v0, l0 )
#define v128_movlane32( v1, l1, v0, l0 )     vcopyq_laneq_u32( v1, l1, v0, l0 )
#define v128_movlane16( v1, l1, v0, l0 )     vcopyq_laneq_u16( v1, l1, v0, l0 )
#define v128_movlane8(  v1, l1, v0, l0 )     vcopyq_laneq_u8(  v1, l1, v0, l0 )

#define v128_get64( v, l )         vgetq_lane_u64( v, l )
#define v128_get32( v, l )         vgetq_lane_u32( v, l )
#define v128_get16( v, l )         vgetq_lane_u16( v, l )
#define v128_get8(  v, l )         vgetq_lane_u8(  v, l )

#define v128_put64( v, i64, l )    vsetq_lane_u64( i64, v, l )
#define v128_put32( v, i32, l )    vsetq_lane_u32( i32, v, l )
#define v128_put16( v, i16, l )    vsetq_lane_u16( i16, v, l )
#define v128_put8(  v, i8,  l )    vsetq_lane_u8(  i8,  v, l )

#define v128_negate64              vnegq_s64
#define v128_negate32              vnegq_s32
#define v128_negate16              vnegq_s16
#define v128_negate8               vnegq_s8

static inline void v128_memset_zero( void *dst, const int n )
{
   for( int i = 0; i < n; i++ )
      ((uint32x4_t*)dst)[n] = (uint32x4_t)(uint128_t)0;
}

static inline void v128_memset( void *dst, const void *src, const int n )
{
   for( int i = 0; i < n; i++ )
      ((uint32x4_t*)dst)[n] = ((const uint32x4_t*)src)[n];
}
   
static inline void v128_memcpy( void *dst, const void *src, const int n )
{
   for ( int i = 0; i < n; i ++ )
      ((uint32x4_t*)dst)[i] = ((const uint32x4_t*)src)[i];
}

// how to build a bitmask from vector elements?
#define v128_movmask32                 
#define v128_movmask64                

// Bit rotation
//TODO, maybe, Optimize 64 bit rotations
// Fall back for odd bit rotations
static inline uint64x2_t v128_ror64( uint64x2_t v, int c )
{
   return vsriq_n_u64( vshlq_n_u64( (uint64x2_t)v, 64-c ), (uint64x2_t)v, c );
}

static inline uint64x2_t v128_rol64( uint64x2_t v, int c )
{
   return vsliq_n_u64( vshrq_n_u64( (uint64x2_t)v, 64-c ), (uint64x2_t)v, c );
}

//static inline uint64x2_t v128_rol64( uint64x2_t v, int c )
//{  return vsriq_n_u64( vshlq_n_u64( v, c ), v, 64-c ); }

static inline uint32x4_t v128_ror32( uint32x4_t v, int c )
{  return vsriq_n_u32( vshlq_n_u32( v, 32-c ), v, c ); }

static inline uint32x4_t v128_rol32( uint32x4_t v, int c )
{  return vsliq_n_u32( vshrq_n_u32( v, 32-c ), v, c ); }

//static inline uint32x4_t v128_rol32( uint32x4_t v, int c )
//{  return vsriq_n_u32( vshlq_n_u32( v, c ), v, 32-c ); }

static inline uint16x8_t v128_ror16( uint16x8_t v, int c )
{  return vsriq_n_u16( vshlq_n_u16( v, 16-c ), v, c ); }

static inline uint16x8_t v128_rol16( uint16x8_t v, int c )
{  return vsliq_n_u16( vshrq_n_u16( v, 16-c ), v, c ); }

//static inline uint16x8_t v128_rol16( uint16x8_t v, int c )
//{  return vsriq_n_u16( vshlq_n_u16( v, c ), v, 16-c ); }

static inline uint8x16_t v128_ror8( uint8x16_t v, int c )
{  return vsriq_n_u8( vshlq_n_u8( v, 8-c ), v, c ); }

static inline uint8x16_t v128_rol8( uint8x16_t v, int c )
{  return vsliq_n_u8( vshrq_n_u8( v, 8-c ), v, c ); }

//static inline uint8x16_t v128_rol8( uint16x8_t v, int c )
//{  return vsriq_n_u8( vshlq_n_u8( v, c ), v, 8-c ); }

/*
// Optimzed for half element rotations (swap)
#define v128_ror64( v, c ) \
   ( (c) == 32 ) ? (uint64x2_t)vrev64q_u32( v ) : v128_ror64_neon( v, c )

#define v128_rol64( v, c ) \
   ( (c) == 32 ) ? (uint64x2_t)vrev64q_u32( v ) : v128_rol64_neon( v, c )
   
#define v128_ror32( v, c ) \
   ( (c) == 16 ) ? (uint32x4_t)vrev32q_u16( v ) : v128_ror32_neon( v, c )

#define v128_rol32( v, c ) \
   ( (c) == 16 ) ? (uint32x4_t)vrev32q_u16( v ) : v128_rol32_neon( v, c )
*/

#define v128_2ror64( v1, v0, c ) \
{ \
 uint64x2_t t0 = vshrq_n_u64( v0, c ); \
 uint64x2_t t1 = vshrq_n_u64( v1, c ); \
 v0 = vsliq_n_u64( v0, 64-(c) ); \
 v1 = vsliq_n_u64( v1, 64-(c) ); \
 v0 = vorrq_u64( v0, t0 ); \
 v1 = vorrq_u64( v1, t1 ); \
}

#define v128_2rol64_( v1, v0, c ) \
{ \
 uint64x2_t t0 = vshlq_n_u64( v0, c ); \
 uint64x2_t t1 = vshlq_n_u64( v1, c ); \
 v0 = vsriq_n_u64( v0, 64-(c) ); \
 v1 = vsriq_n_u64( v1, 64-(c) ); \
 v0 = vorrq_u64( v0, t0 ); \
 v1 = vorrq_u64( v1, t1 ); \
}

#define v128_2rorl32( v1, v0, c ) \
{ \
 uint32x4_t t0 = vshrq_n_u32( v0, c ); \
 uint32x4_t t1 = vshrq_n_u32( v1, c ); \
 v0 = vsliq_n_u32( v0, 32-(c) ); \
 v1 = vsliq_n_u32( v1, 32-(c) ); \
 v0 = vorrq_u32( v0, t0 ); \
 v1 = vorrq_u32( v1, t1 ); \
}

#define v128_2rorx32( v1, v0, c ) \
{ \
 uint32x4_t t0 = vshlq_n_u32( v0, c ); \
 uint32x4_t t1 = vshlq_n_u32( v1, c ); \
 v0 = vsriq_n_u32( v0, 32-(c) ); \
 v1 = vsriq_n_u32( v1, 32-(c) ); \
 v0 = vorrq_u32( v0, t0 ); \
 v1 = vorrq_u32( v1, t1 ); \
}

// vector rotation , size?
static inline uint64x2_t v128_swap64( uint64x2_t v )
{   return vextq_u64( v, v, 1 ); }

static inline uint32x4_t v128_shuflr32( uint32x4_t v )
{   return vextq_u32( v, v, 1 ); }

static inline uint32x4_t v128_shufll32( uint32x4_t v )
{   return vextq_u32( v, v, 3 ); }

// Cross lane shuffles, no programmable shuffle in NEON

// vector mask, use as last resort. prefer rev, alignr, etc
#define v128_shufflev32( v, vmask ) \
  v128_set32( ((uint32_t*)&v)[ ((uint32_t*)(&vmask))[3] ], \
              ((uint32_t*)&v)[ ((uint32_t*)(&vmask))[2] ], \
              ((uint32_t*)&v)[ ((uint32_t*)(&vmask))[1] ], \
              ((uint32_t*)&v)[ ((uint32_t*)(&vmask))[0] ] ) \

// compatible with x86_64, but very slow, avoid
#define v128_shuffle8( v, vmask ) \
   v128_set8( ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[15] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[14] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[13] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[12] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[11] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[10] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 9] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 8] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 7] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 6] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 5] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 4] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 3] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 2] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 1] ], \
              ((uint8_t*)&v)[ ((uint8_t*)(&vmask))[ 0] ] )

#define v128_swap64_32( v )             vrev64q_u32( v )
#define v128_v128_shuflr64_16( v )      v128_ror_64( v, 16 )
#define v128_v128_shufll64_16( v )      v128_rol_64( v, 16 )

// Don't use as an alias for byte sized bit rotation
#define v128_swap32_16( v )             vrev64q_u16( v )
#define v128_v128_shuflr32_8( v )       v128_ror_32( v, 8 )
#define v128_v128_shufll32_8( v )       v128_rol_32( v, 8 )

// reverse elements
#define v128_rev32( v )                vrev64q_u32( v )
#define v128_rev16( v )                vrev64q_u16( v )
#define v128_rev8( v )                 vrev64q_u8( v )

// reverse bits, nothing like it in x86_64
#define v128_bitrev8( v )              vrbitq_u8

// reverse byte order
#define v128_bswap16(v)                (uint16x8_t)vrev16q_u8( (uint8x16_t)(v) )
#define v128_bswap32(v)                (uint32x4_t)vrev32q_u8( (uint8x16_t)(v) )
#define v128_bswap64(v)                (uint64x2_t)vrev64q_u8( (uint8x16_t)(v) )
#define v128_bswap128(v)               (uint32x4_t)v128_swap64( v128_bswap64(v) )
#define v128_bswap256(p)               v128_bswap128( (p)[0], (p)[1] ) 

// Usefull for x86_64 but does nothing for ARM
#define v128_block_bswap32( dst, src ) \
{ \
   casti_v128u32( dst,0 ) = v128_bswap32( casti_v128u32( src,0 ) ); \
   casti_v128u32( dst,1 ) = v128_bswap32( casti_v128u32( src,1 ) ); \
   casti_v128u32( dst,2 ) = v128_bswap32( casti_v128u32( src,2 ) ); \
   casti_v128u32( dst,3 ) = v128_bswap32( casti_v128u32( src,3 ) ); \
   casti_v128u32( dst,4 ) = v128_bswap32( casti_v128u32( src,4 ) ); \
   casti_v128u32( dst,5 ) = v128_bswap32( casti_v128u32( src,5 ) ); \
   casti_v128u32( dst,6 ) = v128_bswap32( casti_v128u32( src,6 ) ); \
   casti_v128u32( dst,7 ) = v128_bswap32( casti_v128u32( src,7 ) ); \
}
#define v128_block_bswap32_256( dst, src ) \

#define v128_block_bswap32_512( dst, src ) \
{ \
   casti_v128u32( dst, 0 ) = v128_bswap32( casti_v128u32( src, 0 ) ); \
   casti_v128u32( dst, 1 ) = v128_bswap32( casti_v128u32( src, 1 ) ); \
   casti_v128u32( dst, 2 ) = v128_bswap32( casti_v128u32( src, 2 ) ); \
   casti_v128u32( dst, 3 ) = v128_bswap32( casti_v128u32( src, 3 ) ); \
   casti_v128u32( dst, 4 ) = v128_bswap32( casti_v128u32( src, 4 ) ); \
   casti_v128u32( dst, 5 ) = v128_bswap32( casti_v128u32( src, 5 ) ); \
   casti_v128u32( dst, 6 ) = v128_bswap32( casti_v128u32( src, 6 ) ); \
   casti_v128u32( dst, 7 ) = v128_bswap32( casti_v128u32( src, 7 ) ); \
   casti_v128u32( dst, 8 ) = v128_bswap32( casti_v128u32( src, 8 ) ); \
   casti_v128u32( dst, 9 ) = v128_bswap32( casti_v128u32( src, 9 ) ); \
   casti_v128u32( dst,10 ) = v128_bswap32( casti_v128u32( src,10 ) ); \
   casti_v128u32( dst,11 ) = v128_bswap32( casti_v128u32( src,11 ) ); \
   casti_v128u32( dst,12 ) = v128_bswap32( casti_v128u32( src,12 ) ); \
   casti_v128u32( dst,13 ) = v128_bswap32( casti_v128u32( src,13 ) ); \
   casti_v128u32( dst,14 ) = v128_bswap32( casti_v128u32( src,14 ) ); \
   casti_v128u32( dst,15 ) = v128_bswap32( casti_v128u32( src,15 ) ); \
}

#define v128_block_bswap64( dst, src ) \
{ \
   casti_v128u64( dst,0 ) = v128_bswap64( casti_v128u64( src,0 ) ); \
   casti_v128u64( dst,1 ) = v128_bswap64( casti_v128u64( src,1 ) ); \
   casti_v128u64( dst,2 ) = v128_bswap64( casti_v128u64( src,2 ) ); \
   casti_v128u64( dst,3 ) = v128_bswap64( casti_v128u64( src,3 ) ); \
   casti_v128u64( dst,4 ) = v128_bswap64( casti_v128u64( src,4 ) ); \
   casti_v128u64( dst,5 ) = v128_bswap64( casti_v128u64( src,5 ) ); \
   casti_v128u64( dst,6 ) = v128_bswap64( casti_v128u64( src,6 ) ); \
   casti_v128u64( dst,7 ) = v128_bswap64( casti_v128u64( src,7 ) ); \
}
#define v128_block_bswap64_512   v128_block_bswap64 \

#define v128_block_bswap64_1024( dst, src ) \
{ \
   casti_v128u64( dst, 0 ) = v128_bswap64( casti_v128u64( src, 0 ) ); \
   casti_v128u64( dst, 1 ) = v128_bswap64( casti_v128u64( src, 1 ) ); \
   casti_v128u64( dst, 2 ) = v128_bswap64( casti_v128u64( src, 2 ) ); \
   casti_v128u64( dst, 3 ) = v128_bswap64( casti_v128u64( src, 3 ) ); \
   casti_v128u64( dst, 4 ) = v128_bswap64( casti_v128u64( src, 4 ) ); \
   casti_v128u64( dst, 5 ) = v128_bswap64( casti_v128u64( src, 5 ) ); \
   casti_v128u64( dst, 6 ) = v128_bswap64( casti_v128u64( src, 6 ) ); \
   casti_v128u64( dst, 7 ) = v128_bswap64( casti_v128u64( src, 7 ) ); \
   casti_v128u64( dst, 8 ) = v128_bswap64( casti_v128u64( src, 8 ) ); \
   casti_v128u64( dst, 9 ) = v128_bswap64( casti_v128u64( src, 9 ) ); \
   casti_v128u64( dst,10 ) = v128_bswap64( casti_v128u64( src,10 ) ); \
   casti_v128u64( dst,11 ) = v128_bswap64( casti_v128u64( src,11 ) ); \
   casti_v128u64( dst,12 ) = v128_bswap64( casti_v128u64( src,12 ) ); \
   casti_v128u64( dst,13 ) = v128_bswap64( casti_v128u64( src,13 ) ); \
   casti_v128u64( dst,14 ) = v128_bswap64( casti_v128u64( src,14 ) ); \
   casti_v128u64( dst,15 ) = v128_bswap64( casti_v128u64( src,15 ) ); \
}

// Prograsmmable shuffles
// no compatible shuffles with x86_64, will require targeted user code.
              
#define v128_extractmask8( df, de, dd, dc, db, da, d9, d8, \
                           d7, d6, d5, d4, d3, d2, d1, d0, vmask )   \
  d0 = ((uint8_t*)(&vmask))[0];   d1 = ((uint8_t*)(&vmask))[1]; \
  d2 = ((uint8_t*)(&vmask))[2];   d3 = ((uint8_t*)(&vmask))[3]; \
  d4 = ((uint8_t*)(&vmask))[0];   d5 = ((uint8_t*)(&vmask))[1]; \
  d6 = ((uint8_t*)(&vmask))[2];   d7 = ((uint8_t*)(&vmask))[3]; \
  d8 = ((uint8_t*)(&vmask))[0];   d9 = ((uint8_t*)(&vmask))[1]; \
  da = ((uint8_t*)(&vmask))[2];   db = ((uint8_t*)(&vmask))[3]; \
  dc = ((uint8_t*)(&vmask))[0];   dd = ((uint8_t*)(&vmask))[1]; \
  de = ((uint8_t*)(&vmask))[2];   df = ((uint8_t*)(&vmask))[3]; 

// Blendv
#define v128_blendv( v1, v0, mask ) \
   v128_or( v128_andnot( mask, v1 ), v128_and( mask, v0 ) )

/*
// vbcaxq not defined
#define v128_blendv( v1, v0, mask ) \
   vbcaxq_u32( v128_and( mask, v1 ), v0, mask )
*/

#endif   // __ARM_NEON

#endif   // SIMD_NEON_H__
