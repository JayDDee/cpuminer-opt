/*
 * HeavyHash proof-of-work - Optical Bitcoin (OBTC), Ursula (URSA).
 *
 *   seed       = SHA3-256( header80[4..35] )   // prev block hash, job-constant
 *   mat[64][64]= xoshiro256++(seed) -> 4-bit values, retried until full rank
 *   first      = SHA3-256( header80 )
 *   product[i] = ( sum_j mat[i][j] * nibbles(first)[j] ) >> 10
 *   digest     = SHA3-256( first ^ pack_nibbles(product) )
 *
 * Consensus-critical. The nibble order, the >> 10 reduction, the little-endian
 * uint64 seed decode and the full-rank retry all follow obtc-core: src/hash.cpp,
 * src/primitives/block.cpp, src/crypto/{heavyhash.cpp,xoshiro256pp.h}. URSA uses
 * the same algorithm.
 *
 * Two conventions that are easy to get wrong:
 *   - SHA3-256 padding, not Keccak: register_heavyhash_algo sets
 *     hard_coded_eb = 6 before any hashing, self-test included.
 *   - The digest is consumed as little-endian uint32 words, so there is no byte
 *     reversal before valid_hash.
 */

#include "heavyhash-gate.h"
#include "heavyhash-kat.h"
#include "../keccak/keccak-gate.h"      // hard_coded_eb
#include "../keccak/sph_keccak.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#if defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>      // HWCAP_ASIMDDP
#endif

static inline uint64_t heavyhash_le64dec( const void *pp )
{
   const uint8_t *p = (const uint8_t*)pp;
   return  (uint64_t)p[0]        | ( (uint64_t)p[1] <<  8 )
        | ( (uint64_t)p[2] << 16 ) | ( (uint64_t)p[3] << 24 )
        | ( (uint64_t)p[4] << 32 ) | ( (uint64_t)p[5] << 40 )
        | ( (uint64_t)p[6] << 48 ) | ( (uint64_t)p[7] << 56 );
}

static inline uint64_t heavyhash_rotl64( const uint64_t x, int k )
{
   return ( x << k ) | ( x >> ( 64 - k ) );
}

// xoshiro256++ -- the "++" scrambler, rotl(s0+s3,23)+s0. Not xoshiro256**,
// which some sources name it; the wrong scrambler changes every matrix element.
static inline uint64_t heavyhash_xoshiro_gen( struct heavyhash_xoshiro_state *st )
{
   const uint64_t result = heavyhash_rotl64( st->s[0] + st->s[3], 23 ) + st->s[0];
   const uint64_t t = st->s[1] << 17;

   st->s[2] ^= st->s[0];
   st->s[3] ^= st->s[1];
   st->s[1] ^= st->s[2];
   st->s[0] ^= st->s[3];
   st->s[2] ^= t;
   st->s[3] = heavyhash_rotl64( st->s[3], 45 );

   return result;
}

// Full-rank gate, computed exactly over a prime field. obtc-core uses a 64x64
// SVD (reject if the smallest singular value is < 1.000009e-12); full rank mod p
// implies nonsingular over the rationals, which implies that test passes. Two
// primes, because a nonsingular matrix can lose rank modulo one of them
// (chance ~1/p). Exact arithmetic keeps this file free of floating point.
//
// Entries are 4-bit, so a singular matrix is vanishingly unlikely and the retry
// loop runs once in practice. obtc-core's other gate, Is4BitPrecision, is
// omitted: `>> (4*shift) & 0xF` makes it true by construction.

#define HH_RANK_P1  2147483647u    /* 2^31-1, Mersenne prime */
#define HH_RANK_P2  2147483629u    /* prime */

static uint32_t hh_pow_mod( uint32_t base, uint32_t exp, uint32_t p )
{
   uint64_t result = 1, b = base;
   while ( exp )
   {
      if ( exp & 1 ) result = ( result * b ) % p;
      b = ( b * b ) % p;
      exp >>= 1;
   }
   return (uint32_t)result;
}

// Row-echelon reduction over GF(p); returns the number of pivots.
static int hh_rank_mod_p( const uint32_t A[64][64], uint32_t p )
{
   uint32_t a[64][64];
   memcpy( a, A, sizeof a );      // entries are 0..15, already reduced mod p

   int row = 0;
   for ( int col = 0; col < 64; ++col )
   {
      int piv = -1;
      for ( int r = row; r < 64; ++r )
         if ( a[r][col] ) { piv = r; break; }
      if ( piv < 0 ) continue;

      if ( piv != row )
         for ( int c = col; c < 64; ++c )
         {
            uint32_t t = a[row][c]; a[row][c] = a[piv][c]; a[piv][c] = t;
         }

      const uint32_t inv = hh_pow_mod( a[row][col], p - 2, p );
      for ( int c = col; c < 64; ++c )
         a[row][c] = (uint32_t)( ( (uint64_t)a[row][c] * inv ) % p );

      for ( int r = row + 1; r < 64; ++r )
         if ( a[r][col] )
         {
            const uint64_t f = a[r][col];
            for ( int c = col; c < 64; ++c )
               a[r][c] = (uint32_t)( ( a[r][c] + p
                                     - ( f * a[row][c] ) % p ) % p );
         }
      ++row;
   }
   return row;
}

static bool heavyhash_is_full_rank( const uint32_t matrix[64][64] )
{
   return hh_rank_mod_p( matrix, HH_RANK_P1 ) == 64
       || hh_rank_mod_p( matrix, HH_RANK_P2 ) == 64;
}

// Job-constant: reads header bytes 4..35 (the prev block hash) only, never
// nNonce at 76..79. The PRNG state is not reset between retries, so a rejected
// matrix advances the stream; that is consensus too.
void heavyhash_matrix_gen( const void *header80, uint32_t matrix[64][64] )
{
   struct heavyhash_xoshiro_state state;
   uint8_t seed[32];

   sph_keccak256_context ctx;
   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, (const uint8_t*)header80 + 4, 32 );
   sph_keccak256_close( &ctx, seed );

   for ( int i = 0; i < 4; ++i )
      state.s[i] = heavyhash_le64dec( seed + 8 * i );

   do {
      for ( int i = 0; i < 64; ++i )
         for ( int j = 0; j < 64; j += 16 )
         {
            uint64_t value = heavyhash_xoshiro_gen( &state );
            for ( int shift = 0; shift < 16; ++shift )
               matrix[i][j + shift] = ( value >> ( 4 * shift ) ) & 0xF;
         }
   } while ( !heavyhash_is_full_rank( matrix ) );
}

/* The 64x64 matrix product auto-vectorizes at -O3 but not -O2, on both x86 and
 * aarch64. x86 ships -O3; build-armv8.sh ships -O2, where the algorithm runs
 * ~2.6x slower. Requested per-function rather than raising -O for the tree,
 * because that -O2 was chosen for other algorithms. No-op on an -O3 build.
 * Bit-exact, not a fast-math trade: there is no floating point here.
 * clang does not honour optimize(); it warns and ignores, so guard it. */
#if defined(__GNUC__) && !defined(__clang__)
#define HEAVYHASH_VECTORIZE __attribute__((optimize("O3")))
#else
#define HEAVYHASH_VECTORIZE
#endif

// Mining always passes len == 80; the length exists so obtc-core's own vectors
// (test/functional/heavy_hash.py, 1- and 4-byte inputs) can run verbatim.
HEAVYHASH_VECTORIZE
void heavyhash_core_len( const uint32_t matrix[64][64], const void *data,
                         size_t len, void *output )
{
   uint8_t _ALIGN(64) hash_first[32];
   uint8_t _ALIGN(64) hash_xored[32];
   uint32_t vector[64];
   uint32_t product[64];
   sph_keccak256_context ctx;

   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, data, len );
   sph_keccak256_close( &ctx, hash_first );

   for ( int i = 0; i < 32; ++i )
   {
      vector[2*i    ] = hash_first[i] >> 4;
      vector[2*i + 1] = hash_first[i] & 0xF;
   }

   for ( int i = 0; i < 64; ++i )
   {
      uint32_t sum = 0;
      for ( int j = 0; j < 64; ++j )
         sum += matrix[i][j] * vector[j];
      product[i] = sum >> 10;
   }

   // Each product fits a nibble: max sum is 64*15*15 = 14400, >> 10 = 14.
   for ( int i = 0; i < 32; ++i )
      hash_xored[i] = hash_first[i]
                    ^ (uint8_t)( ( product[2*i] << 4 ) | product[2*i + 1] );

   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, hash_xored, 32 );
   sph_keccak256_close( &ctx, output );
}

void heavyhash_core( const uint32_t matrix[64][64], const void *header80,
                     void *output )
{
   heavyhash_core_len( matrix, header80, 80, output );
}

void heavyhash_hash( void *output, const void *input )
{
   uint32_t matrix[64][64];      // 16 KB
   heavyhash_matrix_gen( input, matrix );
   heavyhash_core( (const uint32_t (*)[64])matrix, input, output );
}

/* ===================== byte-packed matrix path ===========================
 * Every matrix entry is 0..15, so uint8 storage is both 4 KB instead of 16 KB
 * and the operand form the byte-multiply instructions want. Two measured
 * results decided the shape of the code below:
 *
 *   - On x86 the byte matrix on its own is *slower* than uint32: gcc unpacks
 *     each byte back to 32 bits and that costs more than the narrower loads
 *     save. It only pays together with a pairwise multiply, so x86 takes the
 *     intrinsics and an SSE2-only build keeps the uint32 nest.
 *   - On aarch64 the reverse: plain C over the byte matrix beat every NEON
 *     kernel hand-written for it, because gcc's reduction vectorizer schedules
 *     UDOT/UMLAL better than hand-rolled accumulator blocking. So ARM gets no
 *     intrinsics at all -- see the note on v128_maddw8 in simd-neon.h.
 *
 * The packing is per job, not per nonce, so its cost is not in the loop.
 * Bit-exactness is not a judgement call here: the operands are integers and
 * every form computes the same sum, which register_heavyhash_algo checks
 * against the consensus KATs through this path on every start.
 */

/* -DHH_NO_BYTE_MATVEC leaves the uint32 scalar nest, so this path can be
 * measured as a paired A/B from a single source. */
#if !defined(HH_NO_BYTE_MATVEC)

#if defined(__aarch64__) && defined(__ARM_NEON)
#define HH_BYTE_MATVEC     1
#define HH_MATVEC_ROWMAJOR 1
   // The shipping ARM recipe (build-armv8.sh) is -march=armv8-a+crypto+sha2+aes,
   // which cannot reach UDOT, and raising it would drop every pre-8.2 board.
   // Instead compile a second copy of the same C under a higher target and pick
   // it at runtime by HWCAP. gcc only: clang does not honour optimize() and
   // spells the target differently, so under clang the base kernel is used
   // unless the march already enables dotprod, in which case it is emitted
   // anyway and no dispatch is needed.
#  if !defined(__ARM_FEATURE_DOTPROD) && defined(__GNUC__) && !defined(__clang__)
#     define HH_DOTPROD_DISPATCH 1
#  endif
   // -DHH_NO_DP4 forces the pairwise kernel on a VNNI host, so the VNNI matvec
   // can be A/B'd at one -march with nothing else changing.
#elif defined(__AVX512VNNI__) && defined(SIMD512) && !defined(HH_NO_DP4)
   // VPDPBUSD roughly halves the matrix stage against the AVX2 pairwise
   // kernel. Different operand layout, so it is a separate branch rather than
   // a widening of the column-pair one.
#define HH_BYTE_MATVEC     1
#define HH_MATVEC_DP4      1
#elif defined(__SSSE3__)
#define HH_BYTE_MATVEC     1
#define HH_MATVEC_COLPAIR  1
#endif

#endif  /* !HH_NO_BYTE_MATVEC */

#if defined(HH_BYTE_MATVEC)

/* Every call site passes distinct objects: the matrix is thread-local,
 * the nibble/product/digest buffers are locals, and `output` is always a
 * caller buffer that is never one of them -- so the aliasing the compiler must
 * otherwise assume (a store to `xored` invalidating `first` or `product`)
 * cannot happen. -DHH_NO_RESTRICT drops it so the effect can be A/B'd. */
#if defined(HH_NO_RESTRICT)
#define HH_RST
#else
#define HH_RST restrict
#endif

// sha3_256_prepad80/32. Included here rather than at the top of the file
// because this header needs v128_t: every target with a byte path has it, but
// heavyhash.c is also expected to compile under -mno-sse2, where it does
// not exist and where none of this code is built anyway.
#include "../keccak/keccak-hash-4way.h"

#define HH_PACKED_BYTES 4096

#if defined(HH_MATVEC_COLPAIR)
/* Column-pair interleave, because PMADDUBSW sums *adjacent byte pairs*:
 *   p[cp*128 + row*2 + {0,1}] = m[row][2cp], m[row][2cp+1]
 * A 16-byte load then covers 8 rows and a 32-byte load 16, so one memory image
 * serves SSSE3 and AVX2 -- result lane k is byte pair k at either width. The
 * payoff is that each accumulator lane is one matrix row, which removes the
 * horizontal reduction a row-major dot product would need per row. */
static void heavyhash_matrix_pack( const uint32_t m[64][64], uint8_t *p )
{
   for ( int cp = 0; cp < 32; ++cp )
      for ( int row = 0; row < 64; ++row )
      {
         p[cp*128 + row*2    ] = (uint8_t)m[row][2*cp    ];
         p[cp*128 + row*2 + 1] = (uint8_t)m[row][2*cp + 1];
      }
}

// Nothing saturates or wraps: a pair product is <= 2*15*15 = 450, well inside
// PMADDUBSW's signed 16-bit result, and the accumulator tops out at the same
// 64*15*15 = 14400 the scalar nest reaches.
static void hh_matvec( const uint8_t *HH_RST p, const uint8_t *HH_RST nib,
                       uint16_t *HH_RST product )
{
#if defined(__AVX2__)
   __m256i a0 = _mm256_setzero_si256(), a1 = _mm256_setzero_si256();
   __m256i a2 = _mm256_setzero_si256(), a3 = _mm256_setzero_si256();

   for ( int cp = 0; cp < 32; ++cp )
   {
      uint16_t vp;
      memcpy( &vp, nib + 2*cp, 2 );
      const __m256i b = _mm256_set1_epi16( (short)vp );
      const __m256i *a = (const __m256i*)( p + cp*128 );
      a0 = _mm256_add_epi16( a0, v256_maddw8( _mm256_loadu_si256( a+0 ), b ) );
      a1 = _mm256_add_epi16( a1, v256_maddw8( _mm256_loadu_si256( a+1 ), b ) );
      a2 = _mm256_add_epi16( a2, v256_maddw8( _mm256_loadu_si256( a+2 ), b ) );
      a3 = _mm256_add_epi16( a3, v256_maddw8( _mm256_loadu_si256( a+3 ), b ) );
   }
   _mm256_storeu_si256( (__m256i*)( product +  0 ), a0 );
   _mm256_storeu_si256( (__m256i*)( product + 16 ), a1 );
   _mm256_storeu_si256( (__m256i*)( product + 32 ), a2 );
   _mm256_storeu_si256( (__m256i*)( product + 48 ), a3 );
#else
   __m128i acc[8];
   for ( int g = 0; g < 8; ++g ) acc[g] = _mm_setzero_si128();

   for ( int cp = 0; cp < 32; ++cp )
   {
      uint16_t vp;
      memcpy( &vp, nib + 2*cp, 2 );
      const __m128i b = _mm_set1_epi16( (short)vp );
      const __m128i *a = (const __m128i*)( p + cp*128 );
      for ( int g = 0; g < 8; ++g )
         acc[g] = _mm_add_epi16( acc[g],
                     v128_maddw8( _mm_loadu_si128( a + g ), b ) );
   }
   for ( int g = 0; g < 8; ++g )
      _mm_storeu_si128( (__m128i*)( product + 8*g ), acc[g] );
#endif
}

#elif defined(HH_MATVEC_DP4)
/* 4-column blocks, because VPDPBUSD sums *4-byte groups* into one 32-bit lane:
 *   p[cb*256 + row*4 + c] = m[row][4cb + c]
 * One zmm load covers 16 rows, so 64 rows need 4 accumulators and again there
 * is no horizontal reduction -- lane k of accumulator g is row 16g + k.
 * VPDPBUSD has no indexed form, but a fixed column block means every lane wants
 * the same four vector bytes, so a 32-bit broadcast supplies b. */
static void heavyhash_matrix_pack( const uint32_t m[64][64], uint8_t *p )
{
   for ( int cb = 0; cb < 16; ++cb )
      for ( int row = 0; row < 64; ++row )
         for ( int c = 0; c < 4; ++c )
            p[cb*256 + row*4 + c] = (uint8_t)m[row][4*cb + c];
}

/* No standalone hh_matvec for this layout: measurement showed that narrowing the
 * 32-bit products to 16 and storing them, only for the pack loop to read them
 * straight back two bytes at a time, is a store-forwarding stall costing more
 * than the pack itself. The DP4 kernel is therefore fused into hh_middle below
 * and keeps its accumulators in registers -- 1.522x on that stage. Keeping a
 * separate hh_matvec here would mean two copies of the same dpbusd loop, one of
 * them dead. */

#else   /* HH_MATVEC_ROWMAJOR */

static void heavyhash_matrix_pack( const uint32_t m[64][64], uint8_t *p )
{
   for ( int i = 0; i < 64; ++i )
      for ( int j = 0; j < 64; ++j ) p[i*64 + j] = (uint8_t)m[i][j];
}

/* A macro, not a shared inline helper, because the two copies differ only in
 * their function attributes and gcc will not inline across a target mismatch
 * -- writing it once as a macro is the only way to guarantee the dotprod copy
 * and the base copy stay the same arithmetic. */
#define HH_MATVEC_BODY( M, NIB, PROD )                                        \
   for ( int i = 0; i < 64; ++i )                                             \
   {                                                                          \
      uint32_t sum = 0;                                                       \
      for ( int j = 0; j < 64; ++j )                                          \
         sum += (uint32_t)(M)[i*64 + j] * (uint32_t)(NIB)[j];                 \
      (PROD)[i] = (uint16_t)sum;                                              \
   }

HEAVYHASH_VECTORIZE
static void hh_matvec_base( const uint8_t *HH_RST p, const uint8_t *HH_RST nib,
                            uint16_t *HH_RST product )
{
   HH_MATVEC_BODY( p, nib, product )
}

#if defined(HH_DOTPROD_DISPATCH)
static bool hh_use_dotprod = false;

__attribute__((optimize("O3"),target("arch=armv8.2-a+dotprod")))
static void hh_matvec_dp( const uint8_t *HH_RST p, const uint8_t *HH_RST nib,
                          uint16_t *HH_RST product )
{
   HH_MATVEC_BODY( p, nib, product )
}
#endif

static inline void hh_matvec( const uint8_t *HH_RST p, const uint8_t *HH_RST nib,
                              uint16_t *HH_RST product )
{
#if defined(HH_DOTPROD_DISPATCH)
   // Perfectly predicted, and it costs far less than the 2.7x the dotprod
   // kernel wins where the hardware has it.
   if ( hh_use_dotprod ) { hh_matvec_dp( p, nib, product ); return; }
#endif
   hh_matvec_base( p, nib, product );
}

#endif  /* layout */

/* The whole between-the-keccaks step for one lane: nibble split, matrix
 * product, >> 10 reduction, XOR pack. Factored out so the 1-way and n-way
 * drivers cannot drift apart -- this is the only copy of that arithmetic.
 *
 * Two reworkings of this were measured and only one kept:
 *
 *   - Deriving the matvec's broadcast operand from `first` so the 64-byte
 *     nib[] never exists is a LOSS on every x86 layout. Materialising nib[]
 *     lets each iteration use one fused load-broadcast; computing the operand
 *     in GPRs puts scalar work and a GPR->vector move on the critical path.
 *   - The DP4 pack was far more expensive than the AVX2 one for identical
 *     source, because that kernel narrows the products, stores them, and the
 *     pack reads them straight back two bytes at a time -- a store-forwarding
 *     stall. Doing the pack in-register fixes it, so DP4 has its own version.
 */
#if defined(HH_MATVEC_DP4)
HEAVYHASH_VECTORIZE
static void hh_middle( const uint8_t *HH_RST packed, const uint8_t *HH_RST first,
                       uint8_t *HH_RST xored )
{
   uint8_t _ALIGN(64) nib[64];

   for ( int i = 0; i < 32; ++i )
   {
      nib[2*i    ] = first[i] >> 4;
      nib[2*i + 1] = first[i] & 0xF;
   }

   __m512i a0 = _mm512_setzero_si512(), a1 = _mm512_setzero_si512();
   __m512i a2 = _mm512_setzero_si512(), a3 = _mm512_setzero_si512();
   for ( int cb = 0; cb < 16; ++cb )
   {
      uint32_t vg;
      memcpy( &vg, nib + 4*cb, 4 );
      const __m512i b = _mm512_set1_epi32( (int)vg );
      const __m512i *a = (const __m512i*)( packed + cb*256 );
      a0 = v512_dpbusd32( a0, _mm512_loadu_si512( a + 0 ), b );
      a1 = v512_dpbusd32( a1, _mm512_loadu_si512( a + 1 ), b );
      a2 = v512_dpbusd32( a2, _mm512_loadu_si512( a + 2 ), b );
      a3 = v512_dpbusd32( a3, _mm512_loadu_si512( a + 3 ), b );
   }

   /* >> 10 leaves a nibble; madd against {16,1} pairs adjacent rows into one
    * byte (max 14*16+14 = 238, so narrowing to u8 cannot overflow); the four
    * 8-byte groups are rows 0..15, 16..31, 32..47, 48..63 = bytes 0..31. */
   const __m256i mul = _mm256_set1_epi32( 0x00010010 );
   const __m128i b0 = _mm256_cvtepi32_epi8( _mm256_madd_epi16(
            _mm512_cvtepi32_epi16( _mm512_srli_epi32( a0, 10 ) ), mul ) );
   const __m128i b1 = _mm256_cvtepi32_epi8( _mm256_madd_epi16(
            _mm512_cvtepi32_epi16( _mm512_srli_epi32( a1, 10 ) ), mul ) );
   const __m128i b2 = _mm256_cvtepi32_epi8( _mm256_madd_epi16(
            _mm512_cvtepi32_epi16( _mm512_srli_epi32( a2, 10 ) ), mul ) );
   const __m128i b3 = _mm256_cvtepi32_epi8( _mm256_madd_epi16(
            _mm512_cvtepi32_epi16( _mm512_srli_epi32( a3, 10 ) ), mul ) );

   _mm256_storeu_si256( (__m256i*)xored,
      _mm256_xor_si256( _mm256_set_m128i( _mm_unpacklo_epi64( b2, b3 ),
                                          _mm_unpacklo_epi64( b0, b1 ) ),
                        _mm256_loadu_si256( (const __m256i*)first ) ) );
}
#else
HEAVYHASH_VECTORIZE
static void hh_middle( const uint8_t *HH_RST packed, const uint8_t *HH_RST first,
                       uint8_t *HH_RST xored )
{
   uint8_t  _ALIGN(64) nib[64];
   uint16_t _ALIGN(64) product[64];

   for ( int i = 0; i < 32; ++i )
   {
      nib[2*i    ] = first[i] >> 4;
      nib[2*i + 1] = first[i] & 0xF;
   }

   hh_matvec( packed, nib, product );

   // product[] still holds the raw sums; >> 10 leaves a nibble, as above.
   for ( int i = 0; i < 32; ++i )
      xored[i] = first[i] ^ (uint8_t)( ( ( product[2*i] >> 10 ) << 4 )
                                     |   ( product[2*i + 1] >> 10 ) );
}
#endif  /* HH_MATVEC_DP4 */

/* Same digest as heavyhash_core_len, from the packed matrix.
 *
 * The 80-byte mining case uses the pre-padded driver instead of
 * init/update/close, dropping a state memset, a message memcpy, a padding VLA
 * and 4 of the 6 closing NOT64s -- per pass, twice per nonce. This is the only
 * keccak lever aarch64 has: n-way across nonces is a measured loss there.
 *
 * The `len != 80` path keeps sph_keccak: it exists only for obtc-core's own
 * 1- and 4-byte core vectors, which are not single-block-with-this-padding and
 * are not on any hot path. */
static void heavyhash_core_packed( const uint8_t *HH_RST packed,
                                   const void *HH_RST data,
                                   size_t len, void *HH_RST output )
{
   uint8_t _ALIGN(64) hash_first[32];
   uint8_t _ALIGN(64) hash_xored[32];

   // -DHH_NO_PREPAD restores the sph path, so the prepad can be compared from
   // one source -- same ablation pattern as HH_NO_BYTE_MATVEC and HH_NO_NWAY.
#if defined(HH_NO_PREPAD)
   sph_keccak256_context ctx;
   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, data, len );
   sph_keccak256_close( &ctx, hash_first );

   hh_middle( packed, hash_first, hash_xored );

   sph_keccak256_init( &ctx );
   sph_keccak256( &ctx, hash_xored, 32 );
   sph_keccak256_close( &ctx, output );
#else
   if ( likely( len == 80 ) )
      sha3_256_prepad80( hash_first, data );
   else
   {
      sph_keccak256_context ctx;
      sph_keccak256_init( &ctx );
      sph_keccak256( &ctx, data, len );
      sph_keccak256_close( &ctx, hash_first );
   }

   hh_middle( packed, hash_first, hash_xored );

   sha3_256_prepad32( output, hash_xored );
#endif
}

/* ============== n-way keccak across nonces =================================
 * After the byte-matrix work the two keccak permutations dominate a nonce on
 * x86, so they are batched across nonces using the existing keccak256_Nx64
 * cores. Widest available wins on x86 (8-way > 4-way > 2-way); 512-bit
 * frequency licensing erodes the 8-way margin under load but does not reverse
 * it. AVX512VL also speeds up the narrower cores, because it gives them native
 * 64-bit rotates and keccak is rotation-dominated.
 *
 * x86 only: on aarch64 a 128-bit vector holds just two 64-bit lanes and the
 * cores there have more scalar integer ports than NEON pipes, so vectorising
 * keccak measured SLOWER than 1-way even before the interleave traffic. ARM's
 * keccak lever is the pre-padded driver instead.
 *
 * Interleave/de-interleave is real per-group work and is counted as such.
 *
 * Requires the column-pair or DP4 byte path, i.e. SSSE3+. An SSE2-only x86
 * build keeps the 1-way uint32 nest: it would gain here, but it has no
 * hh_matvec to call and such CPUs predate 2006.
 */
/* -DHH_NO_NWAY leaves the 1-way driver, for a paired A/B from one source.
 * -DHH_FORCE_NWAY=N pins the width; otherwise the widest available is used. */
/* Gated on "x86 has a byte path", not on one particular layout: the DP4 layout
 * arrived later and gating on COLPAIR would have silently disabled n-way on
 * exactly the CPUs that benefit from it most. */
#if defined(HH_BYTE_MATVEC) && !defined(HH_MATVEC_ROWMAJOR) && !defined(HH_NO_NWAY)
#  if defined(HH_FORCE_NWAY)
#    define HH_NWAY HH_FORCE_NWAY
#  elif defined(SIMD512)
#    define HH_NWAY 8
#  elif defined(__AVX2__)
#    define HH_NWAY 4
#  else
#    define HH_NWAY 2
#  endif
#endif

#if defined(HH_NWAY)

// keccak-hash-4way.h is already included above: HH_NWAY implies HH_BYTE_MATVEC.

#if HH_NWAY == 8
#define HH_KCTX      keccak256_8x64_context
#define HH_KINIT     keccak256_8x64_init
#define HH_KUPDATE   keccak256_8x64_update
#define HH_KCLOSE    keccak256_8x64_close
#define HH_EXTR      extr_lane_8x64
#define HH_INTRLV( d, s, bits )                                               \
           intrlv_8x64( d, (s)[0], (s)[1], (s)[2], (s)[3],                    \
                           (s)[4], (s)[5], (s)[6], (s)[7], bits )
#elif HH_NWAY == 4
#define HH_KCTX      keccak256_4x64_context
#define HH_KINIT     keccak256_4x64_init
#define HH_KUPDATE   keccak256_4x64_update
#define HH_KCLOSE    keccak256_4x64_close
#define HH_EXTR      extr_lane_4x64
#define HH_INTRLV( d, s, bits ) \
           intrlv_4x64( d, (s)[0], (s)[1], (s)[2], (s)[3], bits )
#else
#define HH_KCTX      keccak256_2x64_context
#define HH_KINIT     keccak256_2x64_init
#define HH_KUPDATE   keccak256_2x64_update
#define HH_KCLOSE    keccak256_2x64_close
#define HH_EXTR      extr_lane_2x64
#define HH_INTRLV( d, s, bits ) intrlv_2x64( d, (s)[0], (s)[1], bits )
#endif

// HH_NWAY nonces at once. `elanes` holds HH_NWAY copies of the 80-byte header
// differing only at the nonce; `out` receives one 32-byte digest per lane, in
// the little-endian uint32 word order valid_hash expects.
static void heavyhash_core_nway( const uint8_t *packed,
                                 const uint32_t elanes[HH_NWAY][20],
                                 uint32_t out[HH_NWAY][8] )
{
   uint32_t _ALIGN(64) vdata[20 * HH_NWAY];      // 80 B per lane, 64-bit intrlv
   uint32_t _ALIGN(64) vmid[8 * HH_NWAY];        // 32 B per lane
   uint32_t _ALIGN(64) h1[8 * HH_NWAY];
   uint8_t  _ALIGN(64) first[HH_NWAY][32];
   uint8_t  _ALIGN(64) xored[HH_NWAY][32];
   HH_KCTX ctx;

   HH_INTRLV( vdata, elanes, 640 );

   HH_KINIT( &ctx );
   HH_KUPDATE( &ctx, vdata, 80 );
   HH_KCLOSE( &ctx, h1 );

   for ( int l = 0; l < HH_NWAY; ++l )
   {
      HH_EXTR( first[l], h1, l, 256 );
      hh_middle( packed, first[l], xored[l] );
   }

   HH_INTRLV( vmid, xored, 256 );

   HH_KINIT( &ctx );
   HH_KUPDATE( &ctx, vmid, 32 );
   HH_KCLOSE( &ctx, h1 );

   for ( int l = 0; l < HH_NWAY; ++l ) HH_EXTR( out[l], h1, l, 256 );
}

#endif  /* HH_NWAY */

#endif  /* HH_BYTE_MATVEC */

static void heavyhash_log_mismatch( const char *what, const uint8_t *got,
                                    const uint8_t *expected )
{
   char g[65], e[65];
   for ( int i = 0; i < 32; i++ )
   {
      sprintf( g + i*2, "%02x", got[i] );
      sprintf( e + i*2, "%02x", expected[i] );
   }
   applog( LOG_ERR, "heavyhash %s FAILED (consensus KAT mismatch)", what );
   applog( LOG_ERR, "  got:      %s", g );
   applog( LOG_ERR, "  expected: %s", e );
}

// Hard fail: a wrong digest means every share is rejected, so refusing to start
// is the cheap outcome. See heavyhash-kat.h for what the two groups cover.
bool heavyhash_self_test( void )
{
   uint8_t hash[32];

   for ( int v = 0; v < HEAVYHASH_KAT_HEADER_COUNT; v++ )
   {
      heavyhash_hash( hash, heavyhash_kat_header_input[v] );
      if ( memcmp( hash, heavyhash_kat_header_expected[v], 32 ) != 0 )
      {
         heavyhash_log_mismatch( heavyhash_kat_header_name[v], hash,
                                 heavyhash_kat_header_expected[v] );
         return false;
      }
   }

   for ( int v = 0; v < HEAVYHASH_KAT_CORE_COUNT; v++ )
   {
      heavyhash_core_len( heavyhash_kat_core_matrix,
                          heavyhash_kat_core_input[v],
                          heavyhash_kat_core_inlen[v], hash );
      if ( memcmp( hash, heavyhash_kat_core_expected[v], 32 ) != 0 )
      {
         heavyhash_log_mismatch( "obtc-core core vector", hash,
                                 heavyhash_kat_core_expected[v] );
         return false;
      }
   }

#if defined(HH_BYTE_MATVEC)
   // A start-up gate, not just a bench-time claim: the byte path is
   // checked against the same consensus constants, on whatever build and
   // whatever CPU the miner actually came up on. That also covers the runtime
   // dotprod choice, which no compile-time test can reach.
   {
      uint8_t _ALIGN(64) packed[HH_PACKED_BYTES];
      uint32_t matrix[64][64];

      for ( int v = 0; v < HEAVYHASH_KAT_HEADER_COUNT; v++ )
      {
         heavyhash_matrix_gen( heavyhash_kat_header_input[v], matrix );
         heavyhash_matrix_pack( (const uint32_t (*)[64])matrix, packed );
         heavyhash_core_packed( packed, heavyhash_kat_header_input[v], 80, hash );
         if ( memcmp( hash, heavyhash_kat_header_expected[v], 32 ) != 0 )
         {
            heavyhash_log_mismatch( "byte-matrix path, header vector", hash,
                                    heavyhash_kat_header_expected[v] );
            return false;
         }
      }

      heavyhash_matrix_pack( heavyhash_kat_core_matrix, packed );
      for ( int v = 0; v < HEAVYHASH_KAT_CORE_COUNT; v++ )
      {
         heavyhash_core_packed( packed, heavyhash_kat_core_input[v],
                                heavyhash_kat_core_inlen[v], hash );
         if ( memcmp( hash, heavyhash_kat_core_expected[v], 32 ) != 0 )
         {
            heavyhash_log_mismatch( "byte-matrix path, core vector", hash,
                                    heavyhash_kat_core_expected[v] );
            return false;
         }
      }

#if defined(HH_NWAY)
      // Every lane of the n-way driver against the same consensus constants.
      // The header KATs are 80-byte headers, which is what the n-way path
      // takes, and running the vector through all HH_NWAY lanes catches a
      // lane-indexing or interleave error rather than trusting the layout.
      for ( int v = 0; v < HEAVYHASH_KAT_HEADER_COUNT; v++ )
      {
         uint32_t _ALIGN(64) elanes[HH_NWAY][20];
         uint32_t _ALIGN(64) douts[HH_NWAY][8];

         heavyhash_matrix_gen( heavyhash_kat_header_input[v], matrix );
         heavyhash_matrix_pack( (const uint32_t (*)[64])matrix, packed );
         for ( int l = 0; l < HH_NWAY; ++l )
            memcpy( elanes[l], heavyhash_kat_header_input[v], 80 );

         heavyhash_core_nway( packed, (const uint32_t (*)[20])elanes, douts );

         for ( int l = 0; l < HH_NWAY; ++l )
            if ( memcmp( douts[l], heavyhash_kat_header_expected[v], 32 ) != 0 )
            {
               heavyhash_log_mismatch( "n-way path, header vector",
                                       (const uint8_t*)douts[l],
                                       heavyhash_kat_header_expected[v] );
               return false;
            }
      }
#endif
   }
#endif

   // Print the lane count as a number, not a hand-written string per width:
   // an #else that assumed 2 mislabelled an 8-way build as "2-way", and a
   // status line that lies about which kernel is live misdirects every later
   // investigation.
#if defined(HH_NWAY)
   applog( LOG_NOTICE, "heavyhash self-test PASSED (%d header + %d core "
           "consensus vectors, OBTC genesis anchored, scalar + byte-matrix + "
           "%d-way paths)", HEAVYHASH_KAT_HEADER_COUNT,
           HEAVYHASH_KAT_CORE_COUNT, HH_NWAY );
#else
   applog( LOG_NOTICE, "heavyhash self-test PASSED (%d header + %d core "
           "consensus vectors, OBTC genesis anchored%s)",
           HEAVYHASH_KAT_HEADER_COUNT, HEAVYHASH_KAT_CORE_COUNT,
#  if defined(HH_BYTE_MATVEC)
           ", scalar and byte-matrix paths"
#  else
           ""
#  endif
         );
#endif
   return true;
}

// Per-thread matrix cache. The matrix is a pure function of the 32 seed bytes,
// so keying on those is exact: a hit cannot return a stale matrix. Generation
// costs orders of magnitude more than a nonce, and scanhash is called many
// times per job, so it must not be paid per call.
//
// Where a byte path exists the cache holds the 4 KB packed form and the uint32
// matrix is only scratch for generation and the rank check. It stays in TLS
// rather than on the stack, where the per-job packing already puts it; the extra
// 16 KB per thread is touched once per job, not per nonce.
#if defined(HH_BYTE_MATVEC)
static __thread uint8_t  _ALIGN(64) hh_cached_packed[HH_PACKED_BYTES];
static __thread uint32_t _ALIGN(64) hh_gen_scratch[64][64];
#else
static __thread uint32_t _ALIGN(64) hh_cached_matrix[64][64];
#endif
static __thread uint8_t  hh_cached_seed[32];
static __thread bool     hh_cache_valid = false;

int scanhash_heavyhash( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
#if !defined(HH_NWAY)
   uint32_t _ALIGN(64) hash32[8];      // n-way keeps its digests per lane
#endif
   uint32_t _ALIGN(64) edata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   uint32_t n = first_nonce;

   for ( int i = 0; i < 19; i++ )
      be32enc( &edata[i], pdata[i] );

   if ( !hh_cache_valid
        || memcmp( hh_cached_seed, (const uint8_t*)edata + 4, 32 ) != 0 )
   {
#if defined(HH_BYTE_MATVEC)
      heavyhash_matrix_gen( edata, hh_gen_scratch );
      heavyhash_matrix_pack( (const uint32_t (*)[64])hh_gen_scratch,
                             hh_cached_packed );
#else
      heavyhash_matrix_gen( edata, hh_cached_matrix );
#endif
      memcpy( hh_cached_seed, (const uint8_t*)edata + 4, 32 );
      hh_cache_valid = true;
   }

#if defined(HH_NWAY)
   uint32_t _ALIGN(64) elanes[HH_NWAY][20];
   uint32_t _ALIGN(64) douts[HH_NWAY][8];

   for ( int l = 0; l < HH_NWAY; ++l ) memcpy( elanes[l], edata, 80 );

   // Same shape as the tree's other n-way scanhashes (see keccak-4way.c): stop
   // HH_NWAY short so a group never runs past max_nonce.
   const uint32_t group_last = last_nonce > HH_NWAY ? last_nonce - HH_NWAY : 0;

   do {
      for ( int l = 0; l < HH_NWAY; ++l ) be32enc( &elanes[l][19], n + l );

      heavyhash_core_nway( hh_cached_packed,
                           (const uint32_t (*)[20])elanes, douts );

      for ( int l = 0; l < HH_NWAY; ++l )
         if ( unlikely( valid_hash( douts[l], ptarget ) && !bench ) )
         {
            pdata[19] = n + l;
            submit_solution( work, douts[l], mythr );
         }
      n += HH_NWAY;
   } while ( likely( n < group_last && !work_restart[thr_id].restart ) );
#else
   do {
      be32enc( &edata[19], n );
#if defined(HH_BYTE_MATVEC)
      heavyhash_core_packed( hh_cached_packed, edata, 80, hash32 );
#else
      heavyhash_core( (const uint32_t (*)[64])hh_cached_matrix, edata, hash32 );
#endif

      if ( unlikely( valid_hash( hash32, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash32, mythr );
      }
      n++;
   } while ( likely( n < last_nonce && !work_restart[thr_id].restart ) );
#endif

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

bool register_heavyhash_algo( algo_gate_t *gate )
{
   // SHA3 padding, not Keccak. Must precede the self-test.
   hard_coded_eb = 6;

#if defined(HH_DOTPROD_DISPATCH)
   // Must also precede the self-test, so the KATs exercise the kernel this CPU
   // will really run. Test the macro before using it (the kernel headers may
   // predate FEAT_DotProd); without it the base kernel is simply kept.
#  if defined(AT_HWCAP) && defined(HWCAP_ASIMDDP)
   hh_use_dotprod = ( getauxval( AT_HWCAP ) & HWCAP_ASIMDDP ) != 0;
   applog( LOG_INFO, "heavyhash: matrix product using %s",
           hh_use_dotprod ? "UDOT (FEAT_DotProd detected)"
                          : "UMULL/UMLAL (no FEAT_DotProd)" );
#  endif
#endif

   if ( !heavyhash_self_test() )
   {
      applog( LOG_ERR, "heavyhash self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_heavyhash;
   gate->hash          = (void*)&heavyhash_hash;
   gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
   // Plain 256-bit digest on a Bitcoin-style header: standard 0xffff difficulty
   // base. Confirmed against observed share difficulties.
   opt_target_factor   = 1.0;
   return true;
}
