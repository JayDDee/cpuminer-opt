#if !defined(SIMD_NEON_CLMUL_H__)
#define SIMD_NEON_CLMUL_H__ 1

#if defined(__aarch64__) && defined(__ARM_NEON)

#include <arm_neon.h>

// 64 x 64 -> 128 carryless multiply for ARMv8 cores without the crypto
// extension, i.e. no PMULL64 (Cortex-A53/A72: Pi 3, Pi 4, RK3328, H5/H6).
//
// Only the 64 bit form of PMULL needs the extension; the 8 bit form
// (PMULL Vd.8H, Vn.8B, Vm.8B = vmull_p8) is base ASIMD, so the wide product is
// assembled from byte products:
//
//    a * b = sum over j of ( a * b_j ) << 8j         b_j = byte j of b
//
// vmull_p8 gives one whole column at a time, lane k = a_k * b_j at bit 8k.
// 8 PMULL + ~45 cheap ops, bit exact; 39.7 ns on an A55 against 5.0 hardware
// and 202 for a scalar bit loop. The op count, not the multiply count, is what
// to attack when tuning.

// One column: a * b_dup, every byte of b_dup the same byte of b. Returns the
// 72 bit product in bytes 0..8.
static inline uint8x16_t v128_pmull_emu_col( poly8x8_t a, poly8x8_t b_dup )
{
   const uint16x8_t p  = vreinterpretq_u16_p16( vmull_p8( a, b_dup ) );
   const uint8x16_t lo = vcombine_u8( vmovn_u16( p ), vdup_n_u8( 0 ) );
   const uint8x16_t hi = vcombine_u8( vshrn_n_u16( p, 8 ), vdup_n_u8( 0 ) );
   // hi holds the high byte of every 16 bit product, one byte further up
   return veorq_u8( lo, vextq_u8( vdupq_n_u8( 0 ), hi, 15 ) );
}

// vextq against zero is a byte shift left; the immediate must be a literal, so
// column 0 (no shift) cannot go through the same macro.
#define V128_PMULL_EMU_SHL( v, n ) \
   vextq_u8( vdupq_n_u8( 0 ), v, 16 - (n) )

#define V128_PMULL_EMU_COL( a, b, j ) \
   V128_PMULL_EMU_SHL( v128_pmull_emu_col( a, vdup_lane_p8( b, j ) ), j )

// Balanced xor tree, not a chain: the columns are independent and an in order
// core needs that exposed.
static inline uint8x16_t v128_pmull_emu( poly8x8_t a, poly8x8_t b )
{
   const uint8x16_t c0 = v128_pmull_emu_col( a, vdup_lane_p8( b, 0 ) );
   const uint8x16_t c1 = V128_PMULL_EMU_COL( a, b, 1 );
   const uint8x16_t c2 = V128_PMULL_EMU_COL( a, b, 2 );
   const uint8x16_t c3 = V128_PMULL_EMU_COL( a, b, 3 );
   const uint8x16_t c4 = V128_PMULL_EMU_COL( a, b, 4 );
   const uint8x16_t c5 = V128_PMULL_EMU_COL( a, b, 5 );
   const uint8x16_t c6 = V128_PMULL_EMU_COL( a, b, 6 );
   const uint8x16_t c7 = V128_PMULL_EMU_COL( a, b, 7 );

   return veorq_u8( veorq_u8( veorq_u8( c0, c1 ), veorq_u8( c2, c3 ) ),
                    veorq_u8( veorq_u8( c4, c5 ), veorq_u8( c6, c7 ) ) );
}

// Multiply the low 64 bits by a constant whose set bits all sit in the low 5:
// just sum of a << bit. For reduction modulo a sparse polynomial (0x1b for the
// (64,4,3,1,0) field), ~15 ops instead of ~55. c must be a literal.
//
// 128 bit left shift by n < 64; only the low half is populated, so nothing is
// lost off the top.
#define V128_PMULL_EMU_SHL_BITS( q, n ) \
   veorq_u8( vreinterpretq_u8_u64( vshlq_n_u64( q, n ) ), \
             vreinterpretq_u8_u64( vextq_u64( vdupq_n_u64( 0 ), \
                                   vshrq_n_u64( q, 64 - (n) ), 1 ) ) )

static inline uint8x16_t v128_pmull_emu_small( uint64x2_t alo, unsigned c )
{
   uint8x16_t r = ( c & 1 ) ? vreinterpretq_u8_u64( alo ) : vdupq_n_u8( 0 );
   if ( c & 2 )  r = veorq_u8( r, V128_PMULL_EMU_SHL_BITS( alo, 1 ) );
   if ( c & 4 )  r = veorq_u8( r, V128_PMULL_EMU_SHL_BITS( alo, 2 ) );
   if ( c & 8 )  r = veorq_u8( r, V128_PMULL_EMU_SHL_BITS( alo, 3 ) );
   if ( c & 16 ) r = veorq_u8( r, V128_PMULL_EMU_SHL_BITS( alo, 4 ) );
   return r;
}

#endif  // __aarch64__ && __ARM_NEON
#endif  // SIMD_NEON_CLMUL_H__
