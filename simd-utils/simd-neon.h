#if defined(__aarch64__) && defined(__ARM_NEON)

// targeted functions using generic names makes portable obsolete

#define v128_t                         uint32x4_t

// load & store
#define v128_load( p )                 vld1q_u32( (uint32_t*)(p) )
#define v128_store( p, v )             vst1q_u32( (uint32_t*)(p), v )

// arithmetic
#define v128_add64                     vaddq_u64
#define v128_add32                     vaddq_u32
#define v128_add16                     vaddq_u16
#define v128_add8                      vaddq_u8

#define v128_sub64                     vsubq_u64
#define v128_sub32                     vsubq_u32
#define v128_sub16                     vsubq_u16
#define v128_sub8                      vsubq_u8

// return low half
#define v128_mullo64                   vmulq_u64
#define v128_mullo32                   vmulq_u32
#define v128_mullo16                   vmulq_u16

// widen not working, use placeholders
//#define v128_mul32                     vmull_u32  
//#define v128_mul16                     vmull_u16
#define v128_mul64                   vmulq_u64
#define v128_mul32                   vmulq_u32
#define v128_mul16                   vmulq_u16

// compare
#define v128_cmpeq64                   vceqq_u64
#define v128_cmpeq32                   vceqq_u32
#define v128_cmpeq16                   vceqq_u16

#define v128_cmpgt64                   vcgtq_u64
#define v128_cmpgt32                   vcgtq_u32
#define v128_cmpgt16                   vcgtq_u16

#define v128_cmplt64                   vcltq_u64
#define v128_cmplt32                   vcltq_u32
#define v128_cmplt16                   vcltq_u16

// bit shift & rotate
#define v128_sl64                      vshlq_n_u64
#define v128_sl32                      vshlq_n_u32
#define v128_sl16                      vshlq_n_u16

#define v128_sr64                      vshrq_n_u64
#define v128_sr32                      vshrq_n_u32
#define v128_sr16                      vshrq_n_u16

#define v128_sra64                     vshrq_n_s64
#define v128_sra32                     vshrq_n_s32
#define v128_sra16                     vshrq_n_s16

// logical ops
#define v128_or                        vorrq_u32
#define v128_and                       vandq_u32
#define v128_not                       vmvnq_u32
#define v128_xor                       veorq_u32

#define v128_xor3( v2, v1, v0 )        v128_xor( v2, v128_xor( v1, v0 ) )
//#define v128_xor3                      veor3q_u32
#define v128_nor                       vornq_u32
#define v128_andnot( v1, v0 )          vandq_u32( vmvnq_u32(v1), v0 )
#define v128_xorandnot( v2, v1, v0 )   v128_xor( v2, v128_andnot( v1, v0 ) )
#define v128_and3( a, b, c )           v128_and( a, v128_and( b, c ) )
#define v128_or3( a, b, c )            v128_or( a, v128_or( b, c ) )
#define v128_xorand( a, b, c )         v128_xor( a, v128_and( b, c ) )
#define v128_andxor( a, b, c )         v128_and( a, v128_xor( b, c ))
#define v128_xoror( a, b, c )          v128_xor( a, v128_or( b, c ) )
#define v128_orand( a, b, c )          v128_or( a, v128_and( b, c ) )
#define v128_xnor( a, b )              v128_not( v128_xor( a, b ) )

#define v128_alignr64                  vextq_u64
#define v128_alignr32                  vextq_u32
#define v128_alignr8                   vextq_u8 

#define v128_unpacklo64                vtrn1q_u64
#define v128_unpackhi64                vtrn2q_u64

#define v128_unpacklo32                vtrn1q_u32
#define v128_unpackhi32                vtrn2q_u32

#define v128_unpacklo16                vtrn1q_u16
#define v128_unpackhi16                vtrn2q_u16

#define v128_unpacklo8                 vtrn1q_u8
#define v128_unpackhi8                 vtrn2q_u8

// AES
// consistent with Intel AES, break up for optimizing
#define v128_aesenc( v, k )            vaesmcq_u8( vaeseq_u8( v, k ) )
#define v128_aesenclast( v, k )        vaeseq_u8( v, k )

#define v128_aesdec( v, k )            vaesimcq_u8( vaesdq_u8( v, k ) )
#define v128_aesdeclast( v, k )        vaesdq_u8( v, k )

// pointer indexing
#define casti_v128( p, i )             (((uint32x4_t*)(p))[i])

#define cast_v128( p )                 (*((uint32x4_t*)(p)))


// Many NEON instructions are sized when they don't need to be, for example
// zero, which may cause the compiler to complain when the sizes don't match.
// use "-flax_vector_conversions".

#define u32_to_u64                     vreinterpretq_u64_u32
#define u64_to_u32                     vreinterpretq_u32_u64

#define u64_to_u8                      vreinterpretq_u8_u64
#define u8_to_u64                      vreinterpretq_u64_u8

#define u32_to_u8                      vreinterpretq_u8_u32
#define u8_to_u32                      vreinterpretq_u32_u8

#define v128_zero                      v128_64( 0ull )
//#define v128_zero_fn()                 v128_64( 0ull )
//#define v128_zero                      v128_zero_fn 

// set1
#define v128_32                        vmovq_n_u32
#define v128_64                        vmovq_n_u64

#define v128_set64( u64_1, u64_0 ) \
   ( (uint64x2_t)( ( (uint128_t)(u64_1) << 64 ) | (uint128_t)(u64_0) ) )
#define v128_set_64                    v128_set64    // deprecated

#define v128_set32( u32_3, u32_2, u32_1, u32_0 ) \
    (uint32x4_t)( ( (uint128_t)(u32_3) << 96 ) | ( (uint128_t)(u32_2) << 64 ) \
    | ( (uint128_t)(u32_1) << 64 ) | ( (uint128_t)(u32_0) ) )
#define v128_set_32                    v128_set32  // deprecated


static inline void v128_memset_zero( uint32x4_t *dst, const int n )
{  for( int i = 0; i < n; i++ )     dst[n] = (uint32x4_t)(uint128_t)0; }

static inline void v128_memset( uint32x4_t *dst, const uint32x4_t *src,
                                 const int n )
{  for( int i = 0; i < n; i++ )     dst[n] = src[n]; }
   
static inline void v128_memcpy( uint32x4_t *dst, const uint32x4_t *src, const int n )
{  for ( int i = 0; i < n; i ++ )  dst[i] = src[i]; }

// select src & dst lanes
#define v128_mov32( dst, ld, src, ls )   vcopyq_laneq_u32( dst, ld, src, ls )

// move src u64 to lane 0, neon needs a source vector to write into
#define v128_mov64( u64 )              (uint64x2_t)(uint128_t)(u64)

static inline uint64x2_t v128_negate64( uint64x2_t v )
{   return v128_sub64( v128_xor( v, v ), v ); }

static inline uint32x4_t v128_negate32( uint32x4_t v )
{   return v128_sub32( v128_xor( v, v ), v ); }

static inline uint16x8_t v128_negate16( uint16x8_t v )
{   return v128_sub64( v128_xor( v, v ), v ); }

#define v128_add4_32( v3, v2, v1, v0 ) \
   vaddq_u32( vaddq_u32( v3, v2 ), vaddq_u32( v1, v0 ) )

// how to build a bitmask from vector elements?
#define v128_movmask32                 _Static_assert (0, "No ARM target: v128_movmask32")
#define v128_movmask64                 _Static_assert (0, "No ARM target: v128_movmask64")


static inline uint64x2_t v128_ror64( uint64x2_t v, const int c )
{   return vsriq_n_u64( vsliq_n_u64( v, v, 64-(c) ), v, c ); }

static inline uint64x2_t v128_rol64( uint64x2_t v, const int c )
{   return vsriq_n_u64( vsliq_n_u64( v, v, c ), v, 64-(c) ); } 

static inline uint32x4_t v128_ror32( uint32x4_t v, const int c )
{   return vsriq_n_u32( vsliq_n_u32( v, v, 32-(c) ), v, c ); }

static inline uint32x4_t v128_rol32( uint32x4_t v, const int c )
{   return vsriq_n_u32( vsliq_n_u32( v, v, c ), v, 32-(c) ); }

static inline uint16x8_t v128_ror16( uint16x8_t v, const int c )
{   return vsriq_n_u16( vsliq_n_u16( v, v, 16-(c) ), v, c ); }

static inline uint16x8_t v128_rol16( uint16x8_t v, const int c )
{   return vsriq_n_u16( vsliq_n_u16( v, v, c ), v, 16-(c) ); }

// reverse endian byte order
#define v128_bswap16(v)                u8_to_u16( vrev16q_u8( u16_to_u8(v) ))
#define v128_bswap32(v)                u8_to_u32( vrev32q_u8( u32_to_u8(v) ))
#define v128_bswap64(v)                u8_to_u64( vrev64q_u8( u64_to_u8(v) ))
#define v128_bswap128(v)               v128_swap64( v128_bswap64(v) )

#define v128_block_bswap32( dst, src ) \
   casti_v128( dst, 0 ) = v128_bswap32( casti_v128( src, 0 ) ); \
   casti_v128( dst, 1 ) = v128_bswap32( casti_v128( src, 1 ) ); \
   casti_v128( dst, 2 ) = v128_bswap32( casti_v128( src, 2 ) ); \
   casti_v128( dst, 3 ) = v128_bswap32( casti_v128( src, 3 ) ); \
   casti_v128( dst, 4 ) = v128_bswap32( casti_v128( src, 4 ) ); \
   casti_v128( dst, 5 ) = v128_bswap32( casti_v128( src, 5 ) ); \
   casti_v128( dst, 6 ) = v128_bswap32( casti_v128( src, 6 ) ); \
   casti_v128( dst, 7 ) = v128_bswap32( casti_v128( src, 7 ) );

#define v128_block_bswap64( dst, src ) \
   dst[0] = v128_bswap64( src[0] ); \
   dst[1] = v128_bswap64( src[1] ); \
   dst[2] = v128_bswap64( src[2] ); \
   dst[3] = v128_bswap64( src[3] ); \
   dst[4] = v128_bswap64( src[4] ); \
   dst[5] = v128_bswap64( src[5] ); \
   dst[6] = v128_bswap64( src[6] ); \
   dst[7] = v128_bswap64( src[7] );

#define v128_rev32( v )                vrev64q_u32( v )

static inline uint32x4_t v128_swap64( uint32x4_t v )
{   return vextq_u64( v, v, 1 ); }

static inline uint32x4_t v128_swap32( uint32x4_t v )
{   return vextq_u32( v, v, 2 ); }

static inline uint32x4_t v128_shuflr32( uint32x4_t v )
{   return vextq_u32( v, v, 1 ); }

static inline uint32x4_t v128_shufll32( uint32x4_t v )
{   return vextq_u32( v, v, 3 ); }

#define v128_swap64_32(v)              v128_ror64( v, 32 )
#define v128_shuflr64_24(v)            v128_ror64( v, 24 ) 
#define v128_shuflr64_16(v)            v128_ror64( v, 16 )

#define v128_swap32_16(v)              v128_ror32( v, 16 )
#define v128_shuflr32_8(v)             v128_ror32( v,  8 )

// Not the same as SSE2, this uses vector mask, SSE2 uses imm8 mask.
#define v128_blend16( v1, v0, mask ) \
   v128_or( v128_and( mask, v1 ), v128_andnot( mask, v0 ) )

#endif
