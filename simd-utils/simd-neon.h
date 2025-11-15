#if !defined(SIMD_NEON_H__)
#define SIMD_NEON_H__ 1

#if defined(__aarch64__) && defined(__ARM_NEON)

// Targeted functions supporting NEON SIMD 128 & 64 bit vectors.
//
// Intel style naming is generally used, however, this not an attempt to emulate Intel
// intructions. It's focussed on the functions used in this program and the best way
// to implement them with NEON.
//
// Some advanced logical operations that require SHA3. Prior to GCC-13
// they also require armv8.2
//
//  veor3q( v2, v1, v0 )                xor3        v2 ^ v1 ^ v0   
//  vxarq_u64( v1, v0, n )              ror64xor    ( v1 ^ v0 ) >>> n )
//  vbcaxq_u{64,32,16,8}( v2, v1, v0 )  xorandnot   v2 ^ ( v1 & ~v0 )
//  vsraq_n_u{64,32,16,8}( v1, v0, n )  v1 + ( v0 >> n )
//
// not used anywhere yet
//  vrax1q_u64( v1, v0 )                v1 ^ ( v0 <<< 1 )

#define v128_t                        uint32x4_t   // default, 
#define v128u64_t                     uint64x2_t
#define v128u32_t                     uint32x4_t
#define v128u16_t                     uint16x8_t
#define v128u8_t                      uint8x16_t

// load & store
#define v128_load( p )                vld1q_u32( (uint32_t*)(p) )
#define v128_store( p, v )            vst1q_u32( (uint32_t*)(p), v )

#define v128u64_load( p )             vld1q_u64( (uint64_t*)(p) )
#define v128u64_store( p, v )         vst1q_u64( (uint64_t*)(p), v )
#define v128u32_load( p )             vld1q_u32( (uint32_t*)(p) )
#define v128u32_store( p, v )         vst1q_u32( (uint32_t*)(p), v )
#define v128u16_load( p )             vld1q_u16( (uint16_t*)(p) )
#define v128u16_store( p, v )         vst1q_u16( (uint16_t*)(p), v )
#define v128u8_load( p )              vld1q_u16( (uint8_t*)(p) )
#define v128u8_store( p, v )          vst1q_u16( (uint8_t*)(p), v )

// load & set1 combined. What if source is already loaded?
// Don't use, leave it up to the compiler to optimize.
// Same with vld1q_lane.
#define v128_load1_64(p)              vld1q_dup_u64( (uint64_t*)(p) )
#define v128_load1_32(p)              vld1q_dup_u32( (uint32_t*)(p) )
#define v128_load1_16(p)              vld1q_dup_u16( (uint16_t*)(p) )
#define v128_load1_8( p)              vld1q_dup_u8(  (uint8_t*) (p) )

// arithmetic
#define v128_add64                    vaddq_u64
#define v128_add32                    vaddq_u32
#define v128_add16                    vaddq_u16
#define v128_add8                     vaddq_u8

#define v128_add4_64( v3, v2, v1, v0 ) \
   vaddq_u64( vaddq_u64( v3, v2 ), vaddq_u64( v1, v0 ) )

#define v128_add4_32( v3, v2, v1, v0 ) \
   vaddq_u32( vaddq_u32( v3, v2 ), vaddq_u32( v1, v0 ) )

#define v128_sub64                    vsubq_u64
#define v128_sub32                    vsubq_u32
#define v128_sub16                    vsubq_u16
#define v128_sub8                     vsubq_u8

// returns low half
#define v128_mul32                    vmulq_u32
#define v128_mul16                    vmulq_u16

// Widening multiply, realign source elements from x86_64 to NEON.
#define v128_mulw32( v1, v0 ) \
   vmull_u32( vmovn_u64( v1 ), vmovn_u64( v0 ) )

// compare
#define v128_cmpeq64                  vceqq_u64
#define v128_cmpeq32                  vceqq_u32
#define v128_cmpeq16                  vceqq_u16
#define v128_cmpeq8                   vceqq_u8

// v128_cmp0, v128_cmpz, v128 testz
#define v128_iszero                   vceqzq_u64

// Not yet needed
//#define v128_cmpeq1
// Signed
#define v128_cmpgt64( v1, v0 )      vcgtq_s64( (int64x2_t)v1, (int64x2_t)(v0) )
#define v128_cmpgt32( v1, v0 )      vcgtq_s32( (int32x4_t)v1, (int32x4_t)(v0) )
#define v128_cmpgt16( v1, v0 )      vcgtq_s16( (int16x8_t)v1, (int16x8_t)(v0) )
#define v128_cmpgt8( v1, v0 )       vcgtq_s8( (int8x16_t)v1, (int8x16_t)(v0) )

#define v128_cmplt64( v1, v0 )      vcltq_s64( (int64x2_t)v1, (int64x2_t)(v0) )
#define v128_cmplt32( v1, v0 )      vcltq_s32( (int32x4_t)v1, (int32x4_t)(v0) )
#define v128_cmplt16( v1, v0 )      vcltq_s16( (int16x8_t)v1, (int16x8_t)(v0) )
#define v128_cmplt8( v1, v0 )       vcltq_s8( (int8x16_t)v1, (int8x16_t)(v0) )

#define v128_cmpeq_zero                vceqzq_u64

// Logical bit shift
#define v128_sl64                     vshlq_n_u64
#define v128_sl32                     vshlq_n_u32
#define v128_sl16                     vshlq_n_u16
#define v128_sl8                      vshlq_n_u8

#define v128_sr64                     vshrq_n_u64
#define v128_sr32                     vshrq_n_u32
#define v128_sr16                     vshrq_n_u16
#define v128_sr8                      vshrq_n_u8

// Arithmetic shift.
#define v128_sra64( v, c )            vshrq_n_s64( (int64x2_t)(v), c )
#define v128_sra32( v, c )            vshrq_n_s32( (int32x4_t)(v), c )
#define v128_sra16( v, c )            vshrq_n_s16( (int16x8_t)(v), c )

// unary logic

#define v128_not                      vmvnq_u32

// binary logic

#define v128_or                       vorrq_u32
#define v128_and                      vandq_u32
#define v128_xor                      veorq_u32

// ~v1 & v0
#define v128_andnot( v1, v0 )         vbicq_u32( v0, v1 )

// ~( v1 ^ v0 ), same as (~v1) ^ v0
#define v128_nxor( v1, v0 )           v128_not( v128_xor( v1, v0 ) )

// ~v1 | v0,  args reversed for consistency with x86_64
#define v128_ornot( v1, v0 )          vornq_u32( v0, v1 )

// ternary logic

// This will compile with GCC-11 on armv8.2 and above. At this time there is no
// known way to test arm minor version.
#if defined(__ARM_FEATURE_SHA3)
  #define v128_xor3                   veor3q_u32
  #define v128_xor4( v3, v2, v1, v0 ) veorq_u32( v3, veor3q_u32( v2, v1, v0 ) )
#else
  #define v128_xor3( v2, v1, v0 )     veorq_u32( veorq_u32( v2, v1 ), v0 )
  #define v128_xor4( v3, v2, v1, v0 ) veorq_u32 ( veorq_u32( v3, v2 ), \
                                                  veorq_u32( v1, v0 ) )
#endif

// v2 & v1 & v0
#define v128_and3( v2, v1, v0 )       v128_and( v128_and( v2, v1 ), v0 )

// v2 | v1 | v0
#define v128_or3( v2, v1, v0 )        v128_or( v128_or( v2, v1 ), v0 )

// v2 ^ ( ~v1 & v0 )
#if defined(__ARM_FEATURE_SHA3)
  #define v128_xorandnot( v2, v1, v0 )  vbcaxq_u32( v2, v0, v1 )
#else
  #define v128_xorandnot( v2, v1, v0 )  v128_xor( v2, v128_andnot( v1, v0 ) )
#endif

// v2 ^ ( v1 & v0 )
#define v128_xorand( v2, v1, v0 )     v128_xor( v2, v128_and( v1, v0 ) )

// v2 & ( v1 ^ v0 )
#define v128_andxor( v2, v1, v0 )     v128_and( v2, v128_xor( v1, v0 ) )

// v2 ^ ( v1 | v0 )
#define v128_xoror( v2, v1, v0 )      v128_xor( v2, v128_or( v1, v0 ) )

// v2 | ( v1 & v0 )
#define v128_orand( v2, v1, v0 )      v128_or( v2, v128_and( v1, v0 ) )

// shift 2 concatenated vectors right, args reversed for consistency with x86_64
#define v128_alignr64( v1, v0, c )    vextq_u64( v0, v1, c )
#define v128_alignr32( v1, v0, c )    vextq_u32( v0, v1, c )
#define v128_alignr8(  v1, v0, c )    vextq_u8(  v0, v1, c ) 

// Interleave high or low half of 2 vectors.
#define v128_unpacklo64( v1, v0 )     vzip1q_u64( v1, v0 )
#define v128_unpackhi64( v1, v0 )     vzip2q_u64( v1, v0 )
#define v128_unpacklo32( v1, v0 )     vzip1q_u32( v1, v0 )
#define v128_unpackhi32( v1, v0 )     vzip2q_u32( v1, v0 )
#define v128_unpacklo16( v1, v0 )     vzip1q_u16( v1, v0 )
#define v128_unpackhi16( v1, v0 )     vzip2q_u16( v1, v0 )
#define v128_unpacklo8(  v1, v0 )     vzip1q_u8(  v1, v0 )
#define v128_unpackhi8(  v1, v0 )     vzip2q_u8(  v1, v0 )

// vzipq_u32 can do hi & lo and return uint32x4x2, no 64 bit version.

// AES

// xor key with result after encryption, x86_64 format.
#define v128_aesencxor( v, k ) \
   v128_xor( vaesmcq_u8( vaeseq_u8( v, v128_zero ) ), k )
// default is x86_64 format.
#define v128_aesenc v128_aesencxor

// xor key with v before encryption, arm64 format.
#define v128_xoraesenc( v, k ) \
   vaesmcq_u8( vaeseq_u8( v, k ) )

// xor v with k_in before encryption then xor the result with k_out afterward.
// Uses the applicable optimization based on the target.
#define v128_xoraesencxor( v, k_in, k_out ) \
   v128_xor( v128_xoraesenc( v, k_in ), k_out )

#define v128_aesenc_nokey( v ) \
   vaesmcq_u8( vaeseq_u8( v, v128_zero ) )

#define v128_aesenclast( v, k ) \
   v128_xor( k, vaeseq_u8( v, v128_zero ) )

#define v128_aesenclast_nokey( v ) \
   vaeseq_u8( v, v128_zero )

#define v128_aesdec( v, k ) \
    v128_xor( k, vaesimcq_u8( vaesdq_u8( v, v128_zero ) ) )

#define v128_aesdec_nokey( v ) \
    vaesimcq_u8( vaesdq_u8( v, v128_zero ) )

#define v128_aesdeclast( v, k ) \
    v128_xor( k, vaesdq_u8( v, v128_zero ) )

#define v128_aesdeclast_nokey( v ) \
    vaesdq_u8( v, v128_zero )


typedef union
{
   uint32x4_t v128;
   uint32x4_t m128;
   uint32_t   u32[4];
} __attribute__ ((aligned (16))) v128_ovly;


// Broadcast lane 0 to all lanes, consistent with x86_64 broadcast
#define v128_bcast64(v)                vdupq_laneq_u64( v, 0 )
#define v128_bcast32(v)                vdupq_laneq_u32( v, 0 )
#define v128_bcast16(v)                vdupq_laneq_u16( v, 0 )

// Broadcast lane l to all lanes
#define v128_duplane64( v, l )         vdupq_laneq_u64( v, l )
#define v128_duplane32( v, l )         vdupq_laneq_u32( v, l )
#define v128_duplane16( v, l )         vdupq_laneq_u16( v, l )

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

// set1, integer argument
#define v128_64                        vmovq_n_u64
#define v128_32                        vmovq_n_u32
#define v128_16                        vmovq_n_u16
#define v128_8                         vmovq_n_u8

#define v128_zero                      v128_64( 0ull )
#define v128_neg1                      v128_64( 0xffffffffffffffffull )

#define v64_set32( u32_1, u32_0 ) \
  vcreate_u32( ( (uint64_t)(u32_1) << 32 ) | (uint64_t)(u32_0) )

#define v64_set16( u16_3, u16_2, u16_1, u16_0 ) \
  vcreate_u16( ( (uint64_t)( ( (uint32_t)(u16_3) << 16) \
                             | (uint32_t)(u16_2)       ) << 32 ) \
             | ( (uint64_t)( ( (uint32_t)(u16_1) << 16) \
                             | (uint32_t)(u16_0)       )       ) )

#define v64_set8( u8_7, u8_6, u8_5, u8_4, u8_3, u8_2, u8_1, u8_0 ) \
  vcreate_u8( \
     ( (uint64_t)( ( (uint32_t)( ((uint16_t)(u8_7) << 8) \
                                | (uint16_t)(u8_6)      ) << 16 ) \
                 | ( (uint32_t)( ((uint16_t)(u8_5) << 8) \
                                | (uint16_t)(u8_4)      )       ) ) << 32 )  \
   | ( (uint64_t)( ( (uint32_t)( ((uint16_t)(u8_3) << 8) \
                                | (uint16_t)(u8_2)      ) << 16 ) \
                 | ( (uint32_t)( ((uint16_t)(u8_1) << 8) \
                                | (uint16_t)(u8_0)      )       ) )       ) )

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

// Nothing else seems to work
static inline void v128_memset_zero( void *dst, const int n )
{
    memset( dst, 0, n*16 );
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

// how to build a bitmask from vector elements? Efficiently???
//#define v128_movmask32                 
//#define v128_movmask64                

#define v128_shuffle8( v, vmask ) \
     vqtbl1q_u8( (uint8x16_t)(v), (uint8x16_t)(vmask) )

// Bit rotation

#define v128_ror64( v, c ) \
  ( (c) == 32 ) ? (uint64x2_t)vrev64q_u32( ((uint32x4_t)(v)) ) \
                : vsriq_n_u64( vshlq_n_u64( ((uint64x2_t)(v)), 64-(c) ), \
                               ((uint64x2_t)(v)), c )

#define v128_rol64( v, c ) \
  ( (c) == 32 ) ? (uint64x2_t)vrev64q_u32( ((uint32x4_t)(v)) ) \
                : vsliq_n_u64( vshrq_n_u64( ((uint64x2_t)(v)), 64-(c) ), \
                               ((uint64x2_t)(v)), c )

#define v128_ror32( v, c ) \
  ( (c) == 16 ) ? (uint32x4_t)vrev32q_u16( ((uint16x8_t)(v)) ) \
                : vsriq_n_u32( vshlq_n_u32( ((uint32x4_t)(v)), 32-(c) ), \
                               ((uint32x4_t)(v)), c )

#define v128_rol32( v, c ) \
  ( (c) == 16 ) ? (uint32x4_t)vrev32q_u16( ((uint16x8_t)(v)) ) \
                : vsliq_n_u32( vshrq_n_u32( ((uint32x4_t)(v)), 32-(c) ), \
                               ((uint32x4_t)(v)), c )

/* not used
#define v128_ror16( v, c ) \
  ( (c) == 8 ) ? (uint16x8_t)vrev16q_u8( ((uint8x16_t)(v)) ) \
               : vsriq_n_u16( vshlq_n_u16( ((uint16x8_t)(v)), 16-(c) ), \
                             ((uint16x8_t)(v)), c )

#define v128_rol16( v, c ) \
  ( (c) == 8 ) ? (uint16x8_t)vrev16q_u8( ((uint8x16_t)(v)) ) \
               : vsliq_n_u16( vshrq_n_u16( ((uint16x8_t)(v)), 16-(c) ), \
                             ((uint16x8_t)(v)), c )

#define v128_ror8( v, c ) \
      vsriq_n_u8( vshlq_n_u8( ((uint8x16_t)(v)), 8-(c) ), \
                  ((uint8x16_t)(v)), c )

#define v128_rol8( v, c ) \
      vsliq_n_u8( vshrq_n_u8( ((uint8x16_t)(v)), 8-(c) ), \
                 ((uint8x16_t)(v)), c )
*/

// ( v1 ^ v0 ) >>> c 
#if defined(__ARM_FEATURE_SHA3)
  #define v128_ror64xor( v1, v0, c )  vxarq_u64( v1, v0, c ) 
#else
  #define v128_ror64xor( v1, v0, c )  v128_ror64( v128_xor( v1, v0 ), c ) 
#endif

/* not used
// v1 + ( v0 >> c )
#define v128_addsr64( v1, v0, c )     vsraq_n_u64( v1, v0, c )
#define v128_addsr32( v1, v0, c )     vsraq_n_u32( v1, v0, c )
*/

// Cross lane shuffle

// sub-vector shuffles sometimes mirror bit rotation. Shuffle is faster.
// Bit rotation already promotes faster widths. Usage is context sensitive.

// reverse elements in vector lanes
#define v128_qrev32            vrev64q_u32
#define v128_swap64_32         vrev64q_u32  // grandfathered

#define v128_qrev16            vrev64q_u16
#define v128_lrev16            vrev32q_u16

// full vector rotation

// reverse elements in vector
static inline uint64x2_t v128_rev64( uint64x2_t v )
{   return vextq_u64( v, v, 1 ); }
#define v128_swap64           v128_rev64   // grandfathered

#define v128_rev32(v)         v128_rev64( v128_qrev32( v ) )

// shuffle-rotate vector elements
static inline uint32x4_t v128_shuflr32( uint32x4_t v )
{   return vextq_u32( v, v, 1 ); }

static inline uint32x4_t v128_shufll32( uint32x4_t v )
{   return vextq_u32( v, v, 3 ); }

// reverse bits in bytes, nothing like it in x86_64
#define v128_bitrev8           vrbitq_u8

// reverse byte order
#define v128_bswap16(v)        (uint16x8_t)vrev16q_u8( (uint8x16_t)(v) )
#define v128_bswap32(v)        (uint32x4_t)vrev32q_u8( (uint8x16_t)(v) )
#define v128_bswap64(v)        (uint64x2_t)vrev64q_u8( (uint8x16_t)(v) )
#define v128_bswap128(v)       (uint32x4_t)v128_rev64( v128_bswap64(v) )

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
#define v128_block_bswap32_256    v128_block_bswap32

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

// Bitwise blend using vector mask, use only bytewise for compatibility
// with x86_64.
#define v128_blendv( v1, v0, mask )    vbslq_u32( mask, v0, v1 )

#endif   // __ARM_NEON
#endif   // SIMD_NEON_H__
