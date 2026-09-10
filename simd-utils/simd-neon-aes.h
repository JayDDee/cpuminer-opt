#if !defined(SIMD_NEON_AES_H__)
#define SIMD_NEON_AES_H__ 1

#if defined(__aarch64__) && defined(__ARM_NEON)

#include <arm_neon.h>

// AES round for ARMv8 cores without the crypto extension (Cortex-A53/A72: Pi 3,
// Pi 4, RK3328, H5/H6). Base ASIMD only, bit exact with AESE+AESMC, in the x86
// shape the callers here are written against: 22.6 ns/round on an A55 against
// 4.4 hardware and 96.5 for the scalar software path.
//
// Table driven, so cache timing observable. Fine for PoW, where there is no
// secret; do not reuse for keyed crypto.

// Two S-boxes; the selector is below, and both are verified against the AES
// S-box for all 256 byte values at startup.

// (a) Direct 256-entry table. The S-box is not nibble separable, so all 256
// entries are needed. vqtbl4q_u8 covers 64 and returns 0 above that, so four of
// them tile it: subtract 64 between lookups and or the results. Indices that go
// negative wrap to >= 192 and stay out of range, which makes the select work.
// Pins 16 registers.
static inline uint8x16_t v128_aes_emu_sub_bytes_table( uint8x16_t x )
{
   static const uint8_t sbox[256] =
   { 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
     0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
     0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
     0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
     0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
     0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
     0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
     0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
     0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
     0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
     0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
     0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
     0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
     0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
     0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
     0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 };

   uint8x16x4_t t0, t1, t2, t3;
   t0.val[0] = vld1q_u8( sbox       ); t0.val[1] = vld1q_u8( sbox +  16 );
   t0.val[2] = vld1q_u8( sbox +  32 ); t0.val[3] = vld1q_u8( sbox +  48 );
   t1.val[0] = vld1q_u8( sbox +  64 ); t1.val[1] = vld1q_u8( sbox +  80 );
   t1.val[2] = vld1q_u8( sbox +  96 ); t1.val[3] = vld1q_u8( sbox + 112 );
   t2.val[0] = vld1q_u8( sbox + 128 ); t2.val[1] = vld1q_u8( sbox + 144 );
   t2.val[2] = vld1q_u8( sbox + 160 ); t2.val[3] = vld1q_u8( sbox + 176 );
   t3.val[0] = vld1q_u8( sbox + 192 ); t3.val[1] = vld1q_u8( sbox + 208 );
   t3.val[2] = vld1q_u8( sbox + 224 ); t3.val[3] = vld1q_u8( sbox + 240 );

   const uint8x16_t k64 = vdupq_n_u8( 64 );
   const uint8x16_t x1  = vsubq_u8( x,  k64 );
   const uint8x16_t x2  = vsubq_u8( x1, k64 );
   const uint8x16_t x3  = vsubq_u8( x2, k64 );

   return vorrq_u8( vorrq_u8( vqtbl4q_u8( t0, x  ), vqtbl4q_u8( t1, x1 ) ),
                    vorrq_u8( vqtbl4q_u8( t2, x2 ), vqtbl4q_u8( t3, x3 ) ) );
}

// (b) Tower field. S(x) = Affine(x^-1) + 0x63, and over
// GF(2^8) = GF(2^4)[Y]/(Y^2+Y+nu) with x = i*Y + k the inversion is
//
//    d = nu*i^2 + i*k + k^2        the norm, in GF(2^4)
//    x^-1 = (i/d)*Y + (i+k)/d
//
// so every step is a nibble lookup. The three GF(2^4) products go through
// log/antilog: an add and one 32-entry lookup each, with log(0) a 0x40 sentinel
// that lands out of TBL range and reads as 0, so x = 0 needs no branch.
//
// nu = 0xb, beta = 0x12 and all nine tables are derived rather than transcribed,
// and the composed sequence was verified against the real AES S-box over all 256
// inputs. 13 lookups against 4, but 10 constant registers against 16.
static inline uint8x16_t v128_aes_emu_sub_bytes_tower( uint8x16_t x )
{
   static const uint8_t ipt_lo[16] =
      { 0x00,0x01,0x2b,0x2a,0x43,0x42,0x68,0x69,0x49,0x48,0x62,0x63,0x0a,0x0b,0x21,0x20 };
   static const uint8_t ipt_hi[16] =
      { 0x00,0x3b,0xd6,0xed,0x33,0x08,0xe5,0xde,0xe1,0xda,0x37,0x0c,0xd2,0xe9,0x04,0x3f };
   static const uint8_t lg[16] =
      { 0x40,0x00,0x01,0x04,0x02,0x08,0x05,0x0a,0x03,0x0e,0x09,0x07,0x06,0x0d,0x0b,0x0c };
   static const uint8_t alg[32] =
      { 0x01,0x02,0x04,0x08,0x03,0x06,0x0c,0x0b,0x05,0x0a,0x07,0x0e,0x0f,0x0d,0x09,
        0x01,0x02,0x04,0x08,0x03,0x06,0x0c,0x0b,0x05,0x0a,0x07,0x0e,0x0f,0x0d,0x09,0x00,0x00 };
   static const uint8_t tnu2[16] =
      { 0x00,0x0b,0x0a,0x01,0x0e,0x05,0x04,0x0f,0x0d,0x06,0x07,0x0c,0x03,0x08,0x09,0x02 };
   static const uint8_t tsq[16] =
      { 0x00,0x01,0x04,0x05,0x03,0x02,0x07,0x06,0x0c,0x0d,0x08,0x09,0x0f,0x0e,0x0b,0x0a };
   static const uint8_t linv[16] =
      { 0x40,0x00,0x0e,0x0b,0x0d,0x07,0x0a,0x05,0x0c,0x01,0x06,0x08,0x09,0x02,0x04,0x03 };
   static const uint8_t sbo_h[16] =
      { 0x63,0xac,0xc6,0x09,0xb2,0x7d,0x17,0xd8,0x87,0x48,0x22,0xed,0x56,0x99,0xf3,0x3c };
   static const uint8_t sbo_l[16] =
      { 0x00,0x1f,0xb2,0xad,0xab,0xb4,0x19,0x06,0x36,0x29,0x84,0x9b,0x9d,0x82,0x2f,0x30 };

   uint8x16x2_t va;
   va.val[0] = vld1q_u8( alg );
   va.val[1] = vld1q_u8( alg + 16 );
   const uint8x16_t vlg = vld1q_u8( lg );
   const uint8x16_t m0f = vdupq_n_u8( 0x0f );

   // to the tower basis: i in the high nibble, k in the low nibble
   const uint8x16_t t =
      veorq_u8( vqtbl1q_u8( vld1q_u8( ipt_lo ), vandq_u8( x, m0f ) ),
                vqtbl1q_u8( vld1q_u8( ipt_hi ), vshrq_n_u8( x, 4 ) ) );
   const uint8x16_t k  = vandq_u8( t, m0f );
   const uint8x16_t i  = vshrq_n_u8( t, 4 );

   const uint8x16_t li = vqtbl1q_u8( vlg, i );
   const uint8x16_t lk = vqtbl1q_u8( vlg, k );

   // d = nu*i^2 + i*k + k^2
   const uint8x16_t d =
      veorq_u8( veorq_u8( vqtbl1q_u8( vld1q_u8( tnu2 ), i ),
                          vqtbl1q_u8( vld1q_u8( tsq  ), k ) ),
                vqtbl2q_u8( va, vaddq_u8( li, lk ) ) );

   const uint8x16_t le = vqtbl1q_u8( vld1q_u8( linv ), d );   // log( 1/d )
   const uint8x16_t ih = vqtbl2q_u8( va, vaddq_u8( li, le ) );
   const uint8x16_t il =
      vqtbl2q_u8( va, vaddq_u8( vqtbl1q_u8( vlg, veorq_u8( i, k ) ), le ) );

   // back to the AES basis, with the affine map and its 0x63 folded in
   return veorq_u8( vqtbl1q_u8( vld1q_u8( sbo_h ), ih ),
                    vqtbl1q_u8( vld1q_u8( sbo_l ), il ) );
}

// (b) wins the full hash on both cores measured while LOSING the isolated round
// -- RK3588S: A55 100.6 -> 130.4 kH/s (+30%) but 22.6 -> 27.5 ns/round, A76
// 312.6 -> 333.3. This emulation is register bound, so benchmark hashes, not
// rounds. V128_AES_EMU_TABLE reinstates (a) for an unmeasured core.
#if defined(V128_AES_EMU_TABLE)
  #define v128_aes_emu_sub_bytes  v128_aes_emu_sub_bytes_table
#else
  #define v128_aes_emu_sub_bytes  v128_aes_emu_sub_bytes_tower
#endif

// xtime: multiply each byte by x in GF(2^8), reducing by 0x11b.
static inline uint8x16_t v128_aes_emu_xtime( uint8x16_t x )
{
   // -1 where the high bit is set, 0 elsewhere
   const uint8x16_t m =
      vreinterpretq_u8_s8( vshrq_n_s8( vreinterpretq_s8_u8( x ), 7 ) );
   return veorq_u8( vshlq_n_u8( x, 1 ), vandq_u8( m, vdupq_n_u8( 0x1b ) ) );
}

// ShiftRows byte permutation of the AES state (column major, byte 4c+r is row
// r of column c): row r rotates left by r columns, so output 4c+r comes from
// input 4*((c+r)&3)+r.
#define V128_AES_EMU_SR   0, 5, 10, 15,  4, 9, 14,  3,  8, 13, 2,  7, 12, 1,  6, 11

// Rotate each 32 bit column right by one and by two bytes, without a constant
// register: SRI folds the or into the shift, REV32 is the 2-byte rotation
// outright. Registers are the scarce resource -- each one held across
// verusclhashv2_2 costs it ~2-3% on an A55.
#define V128_AES_EMU_ROR8( x ) \
   vreinterpretq_u8_u32( vsriq_n_u32( \
      vshlq_n_u32( vreinterpretq_u32_u8( x ), 24 ), \
      vreinterpretq_u32_u8( x ), 8 ) )

#define V128_AES_EMU_ROR16( x ) \
   vreinterpretq_u8_u16( vrev32q_u16( vreinterpretq_u16_u8( x ) ) )

// _mm_aesenc_si128. MixColumns per byte is
// out_r = 2*a_r ^ 3*a_{r+1} ^ a_{r+2} ^ a_{r+3} over the ShiftRows output a,
// which factors into one TBL1 and ~11 single cycle ops:
//
//    d = a ^ ror8(a)                    a_r ^ a_{r+1}
//    u = d ^ ror16(d)                   the column's xor, in every byte of it
//    out = xtime(d) ^ u ^ a ^ k         u ^ a_r = a_{r+1}^a_{r+2}^a_{r+3}
//
// Tabulating ror8 as a second permutation is within noise now that the tower
// S-box has freed the registers (A55 130.2 vs 130.4 kH/s, A76 338.2 vs 333.1);
// it cost 2.4% under the 16-register S-box. Kept derived, fewer registers.
static inline uint8x16_t v128_aes_emu_enc( uint8x16_t v, uint8x16_t k )
{
   static const uint8_t sr[16] = { V128_AES_EMU_SR };

   const uint8x16_t a = vqtbl1q_u8( v128_aes_emu_sub_bytes( v ),
                                    vld1q_u8( sr ) );
   const uint8x16_t d = veorq_u8( a, V128_AES_EMU_ROR8( a ) );
   const uint8x16_t u = veorq_u8( d, V128_AES_EMU_ROR16( d ) );

   return veorq_u8( veorq_u8( v128_aes_emu_xtime( d ), u ),
                    veorq_u8( a, k ) );
}

// _mm_aesenclast_si128: ShiftRows( SubBytes( v ) ) ^ k, no MixColumns.
static inline uint8x16_t v128_aes_emu_enclast( uint8x16_t v, uint8x16_t k )
{
   static const uint8_t idx[16] = { V128_AES_EMU_SR };
   return veorq_u8( vqtbl1q_u8( v128_aes_emu_sub_bytes( v ),
                               vld1q_u8( idx ) ), k );
}

// No decryption round: nothing here decrypts without the extension, and an
// untested InvMixColumns is worse than none. Add it when a consumer appears.

#endif  // __aarch64__ && __ARM_NEON
#endif  // SIMD_NEON_AES_H__
