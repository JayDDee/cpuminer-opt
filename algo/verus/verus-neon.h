/* The 17 x86 intrinsics the vendored VerusHash sources use, mapped to NEON, so
 * those files stay byte-identical to upstream (which uses a full sse2neon shim).
 * _mm_aesenc_si128 and _mm_mulhrs_epi16 are not the obvious one-liner.
 *
 * AES and PMULL64 are selected independently below; a core without either
 * (Cortex-A53/A72: Pi 3, Pi 4, RK3328...) gets the bit-exact emulations from
 * simd-utils rather than having VerusHash compiled out. The rest is base ASIMD. */
#ifndef VERUS_NEON_H
#define VERUS_NEON_H

#include <arm_neon.h>
#include <stdint.h>
#include <string.h>

typedef uint8x16_t __m128i;

#define vrs_u64( v )   vreinterpretq_u64_u8( v )
#define vrs_u32( v )   vreinterpretq_u32_u8( v )
#define vrs_s16( v )   vreinterpretq_s16_u8( v )

/* FORCE_VERUS_AES_EMU / FORCE_VERUS_PMULL_EMU emulate on a core that has the
 * instruction, so the KAT covers the emulation without a Pi 3 on the desk. */
#if ( defined(__ARM_FEATURE_AES) || defined(__ARM_FEATURE_CRYPTO) ) \
      && !defined(FORCE_VERUS_AES_EMU)

/* x86 xors the round key after the round, arm64 aese before it: encrypt with a
 * zero key and xor after. Same form as v128_aesencxor in simd-utils. */
static inline __m128i _mm_aesenc_si128( __m128i v, __m128i k )
{ return veorq_u8( vaesmcq_u8( vaeseq_u8( v, vdupq_n_u8( 0 ) ) ), k ); }

#else

#define VERUS_AES_EMULATED 1
#include "simd-utils/simd-neon-aes.h"

/* the emulation is already x86 shaped */
static inline __m128i _mm_aesenc_si128( __m128i v, __m128i k )
{ return v128_aes_emu_enc( v, k ); }

#endif

static inline __m128i _mm_xor_si128( __m128i a, __m128i b )
{ return veorq_u8( a, b ); }

static inline __m128i _mm_load_si128( const __m128i *p )
{ return vld1q_u8( (const uint8_t*)p ); }
static inline void _mm_store_si128( __m128i *p, __m128i v )
{ vst1q_u8( (uint8_t*)p, v ); }
/* NEON loads/stores have no alignment requirement, so u and aligned are equal */
#define _mm_loadu_si128    _mm_load_si128
#define _mm_storeu_si128   _mm_store_si128

static inline __m128i _mm_loadl_epi64( const __m128i *p )
{
   uint64_t lo;
   memcpy( &lo, p, 8 );          /* callers pass a &uint64_t, not 16B-aligned */
   return vreinterpretq_u8_u64( vsetq_lane_u64( lo, vdupq_n_u64( 0 ), 0 ) );
}

static inline __m128i _mm_setr_epi8( char b0, char b1, char b2,  char b3,
                                     char b4, char b5, char b6,  char b7,
                                     char b8, char b9, char b10, char b11,
                                     char b12, char b13, char b14, char b15 )
{
   return (uint8x16_t){ (uint8_t)b0,  (uint8_t)b1,  (uint8_t)b2,  (uint8_t)b3,
                        (uint8_t)b4,  (uint8_t)b5,  (uint8_t)b6,  (uint8_t)b7,
                        (uint8_t)b8,  (uint8_t)b9,  (uint8_t)b10, (uint8_t)b11,
                        (uint8_t)b12, (uint8_t)b13, (uint8_t)b14, (uint8_t)b15 };
}

/* x86 set_* take the most significant element first */
static inline __m128i _mm_set_epi32( int e3, int e2, int e1, int e0 )
{
   return vreinterpretq_u8_u32( (uint32x4_t){ (uint32_t)e0, (uint32_t)e1,
                                              (uint32_t)e2, (uint32_t)e3 } );
}

static inline __m128i _mm_set_epi64x( int64_t hi, int64_t lo )
{ return vreinterpretq_u8_u64( (uint64x2_t){ (uint64_t)lo, (uint64_t)hi } ); }

static inline __m128i _mm_cvtsi64_si128( int64_t x )
{ return vreinterpretq_u8_u64( (uint64x2_t){ (uint64_t)x, 0 } ); }

static inline __m128i _mm_cvtsi32_si128( int x )
{ return vreinterpretq_u8_u32( (uint32x4_t){ (uint32_t)x, 0, 0, 0 } ); }

static inline int64_t _mm_cvtsi128_si64( __m128i v )
{ return (int64_t)vgetq_lane_u64( vrs_u64( v ), 0 ); }

static inline __m128i _mm_unpacklo_epi32( __m128i a, __m128i b )
{ return vreinterpretq_u8_u32( vzip1q_u32( vrs_u32( a ), vrs_u32( b ) ) ); }
static inline __m128i _mm_unpackhi_epi32( __m128i a, __m128i b )
{ return vreinterpretq_u8_u32( vzip2q_u32( vrs_u32( a ), vrs_u32( b ) ) ); }

/* pshufb zeroes on index bit 7, vqtbl1q on index >= 16, so they differ for
 * 16..127. Safe here: every mask is a literal 0..15 permutation or
 * precompReduction64's index, which is Q2 >> 64 and so always < 16. */
static inline __m128i _mm_shuffle_epi8( __m128i a, __m128i mask )
{ return vqtbl1q_u8( a, mask ); }

/* Do NOT use vqrdmulhq_s16: it saturates at 0x8000*0x8000 where x86 wraps, and
 * that case is frequent enough at mining rates to break digests. Widen-multiply
 * and rounding-narrow wraps like x86. */
static inline __m128i _mm_mulhrs_epi16( __m128i a, __m128i b )
{
   const int16x8_t va = vrs_s16( a ), vb = vrs_s16( b );
   const int32x4_t lo = vmull_s16( vget_low_s16( va ), vget_low_s16( vb ) );
   const int32x4_t hi = vmull_high_s16( va, vb );
   return vreinterpretq_u8_s16( vcombine_s16( vrshrn_n_s32( lo, 15 ),
                                              vrshrn_n_s32( hi, 15 ) ) );
}

/* byte shift right, zero filled */
#define _mm_srli_si128( v, n )  vextq_u8( v, vdupq_n_u8( 0 ), n )

#if ( defined(__ARM_FEATURE_PMULL) || defined(__ARM_FEATURE_CRYPTO) ) \
      && !defined(FORCE_VERUS_PMULL_EMU)

/* imm bit 0 picks a's 64-bit half, bit 4 picks b's. Operands hoisted to locals
 * so the branches (imm is always literal, so one survives) cannot
 * double-evaluate. */
#define VRS_CLMUL( a, b, la, lb ) \
   vreinterpretq_u8_p128( vmull_p64( (poly64_t)vgetq_lane_u64( a, la ), \
                                     (poly64_t)vgetq_lane_u64( b, lb ) ) )

#define _mm_clmulepi64_si128( va, vb, imm ) __extension__({ \
   const uint64x2_t _cla = vrs_u64( va ), _clb = vrs_u64( vb ); \
     (imm) == 0x00 ? VRS_CLMUL( _cla, _clb, 0, 0 ) \
   : (imm) == 0x01 ? VRS_CLMUL( _cla, _clb, 1, 0 ) \
   : (imm) == 0x10 ? VRS_CLMUL( _cla, _clb, 0, 1 ) \
   :                 VRS_CLMUL( _cla, _clb, 1, 1 ); })

#else

#define VERUS_PMULL_EMULATED 1
#include "simd-utils/simd-neon-clmul.h"

/* Same imm dispatch, but the emulation wants 8-byte halves, so pick the half up
 * front: vget_low/high are register subviews and cost nothing. */
#define VRS_CLMUL( a, b, la, lb ) \
   v128_pmull_emu( vreinterpret_p8_u8( vget_##la##_u8( a ) ), \
                   vreinterpret_p8_u8( vget_##lb##_u8( b ) ) )

#define _mm_clmulepi64_si128( va, vb, imm ) __extension__({ \
   const __m128i _cla = ( va ), _clb = ( vb ); \
     (imm) == 0x00 ? VRS_CLMUL( _cla, _clb, low,  low  ) \
   : (imm) == 0x01 ? VRS_CLMUL( _cla, _clb, high, low  ) \
   : (imm) == 0x10 ? VRS_CLMUL( _cla, _clb, low,  high ) \
   :                 VRS_CLMUL( _cla, _clb, high, high ); })

/* precompReduction64_si128() multiplies the high half by 0x1b, which in GF(2)[x]
 * is A ^ (A<<1) ^ (A<<3) ^ (A<<4) -- shifts, not the 8-column product. Once per
 * hash against ~80 clmuls, so worth ~1%; it lives here because a macro cannot
 * see the constant. */
#define VRS_CLMUL_X1B( va ) \
   v128_pmull_emu_small( vextq_u64( vrs_u64( va ), vdupq_n_u64( 0 ), 1 ), 0x1b )

#endif

#endif  /* VERUS_NEON_H */
