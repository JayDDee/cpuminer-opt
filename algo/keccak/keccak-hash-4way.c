#include <stddef.h>
#include <stdint.h>
#include "keccak-hash-4way.h"
#include "keccak-gate.h"

//#if defined(__AVX2__)

static const uint64_t RC[] = {
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008
};

// generic macros

#define a00   (kc->w[ 0])
#define a10   (kc->w[ 1])
#define a20   (kc->w[ 2])
#define a30   (kc->w[ 3])
#define a40   (kc->w[ 4])
#define a01   (kc->w[ 5])
#define a11   (kc->w[ 6])
#define a21   (kc->w[ 7])
#define a31   (kc->w[ 8])
#define a41   (kc->w[ 9])
#define a02   (kc->w[10])
#define a12   (kc->w[11])
#define a22   (kc->w[12])
#define a32   (kc->w[13])
#define a42   (kc->w[14])
#define a03   (kc->w[15])
#define a13   (kc->w[16])
#define a23   (kc->w[17])
#define a33   (kc->w[18])
#define a43   (kc->w[19])
#define a04   (kc->w[20])
#define a14   (kc->w[21])
#define a24   (kc->w[22])
#define a34   (kc->w[23])
#define a44   (kc->w[24])

#define MOV64(d, s)      (d = s)
#define XOR64_IOTA       XOR


#define LPAR   (
#define RPAR   )

#define DO(x)   x

/*
 * sha3t = SHA3-256^3( 80-byte header ), driven from pre-padded state.  Emitted
 * once per ISA section below, where VEC/KCTX/SPLAT/XORV and KECCAK_F_1600 are
 * already defined for that target.  Additive: keccak256_*_ctx is untouched.
 *
 * All three messages are one SHA3-256 rate block (136 B) with padding known at
 * compile time, so no buf, message memcpy, padding VLA or INPUT_BUF is needed.
 *
 * NOTE: SHA3 padding (0x06) is baked in and hard_coded_eb is ignored -- not
 * usable for keccak/sha3d, which need 0x01.
 *
 * Lanes 0..3 carry between passes unchanged: pass 1 leaves ( w0, ~w1, ~w2, w3 )
 * and pass 2 wants complement-init XOR digest, where neg1 ^ ~x == x.  Only the
 * final digest needs uncomplementing, so 2 NOT64s instead of 18.
 */
#define SHA3T_PREPAD_FN( NAME, VEC, KCTX, VZERO, VNEG1, SPLAT, XORV )         \
void NAME( void *dst, const void *vdata )                                     \
{                                                                             \
   KCTX ctx;                                                                  \
   KCTX *kc = &ctx;              /* the a00..a44 macros dereference kc */     \
   const VEC *h = (const VEC*)vdata;                                          \
   const VEC zero  = VZERO;                                                   \
   const VEC neg1  = VNEG1;                                                   \
   const VEC pad06 = SPLAT( 0x06 );                                           \
   const VEC pad80 = SPLAT( 0x8000000000000000ull );                          \
                                                                              \
   /* pass 1: complement-init XOR ( header | 0x06 | 0.. | 0x80 ) */           \
   kc->w[ 0] = h[0];               kc->w[ 1] = XORV( neg1, h[1] );            \
   kc->w[ 2] = XORV( neg1, h[2] );                                            \
   kc->w[ 3] = h[3];               kc->w[ 4] = h[4];                          \
   kc->w[ 5] = h[5];               kc->w[ 6] = h[6];                          \
   kc->w[ 7] = h[7];                                                          \
   kc->w[ 8] = XORV( neg1, h[8] );                                            \
   kc->w[ 9] = h[9];                                                          \
   kc->w[10] = pad06;              kc->w[11] = zero;                          \
   kc->w[12] = neg1;               kc->w[13] = zero;                          \
   kc->w[14] = zero;               kc->w[15] = zero;                          \
   kc->w[16] = pad80;              kc->w[17] = neg1;                          \
   kc->w[18] = zero;               kc->w[19] = zero;                          \
   kc->w[20] = neg1;               kc->w[21] = zero;                          \
   kc->w[22] = zero;               kc->w[23] = zero;                          \
   kc->w[24] = zero;                                                          \
   KECCAK_F_1600;                                                             \
                                                                              \
   /* passes 2 and 3: lanes 0..3 carry over, the other 21 are constants */    \
   for ( int pass = 0; pass < 2; pass++ )                                     \
   {                                                                          \
      kc->w[ 4] = pad06;           kc->w[ 5] = zero;                          \
      kc->w[ 6] = zero;            kc->w[ 7] = zero;                          \
      kc->w[ 8] = neg1;            kc->w[ 9] = zero;                          \
      kc->w[10] = zero;            kc->w[11] = zero;                          \
      kc->w[12] = neg1;            kc->w[13] = zero;                          \
      kc->w[14] = zero;            kc->w[15] = zero;                          \
      kc->w[16] = pad80;           kc->w[17] = neg1;                          \
      kc->w[18] = zero;            kc->w[19] = zero;                          \
      kc->w[20] = neg1;            kc->w[21] = zero;                          \
      kc->w[22] = zero;            kc->w[23] = zero;                          \
      kc->w[24] = zero;                                                       \
      KECCAK_F_1600;                                                          \
   }                                                                          \
                                                                              \
   VEC *out = (VEC*)dst;                                                      \
   out[0] = kc->w[0];                                                         \
   out[1] = XORV( neg1, kc->w[1] );   /* undo the lane complement */          \
   out[2] = XORV( neg1, kc->w[2] );                                           \
   out[3] = kc->w[3];                                                         \
}

#if defined(SIMD512)

#define INPUT_BUF(size)   do { \
    size_t j; \
    for (j = 0; j < (size>>3); j++ ) \
        kc->w[j ] = _mm512_xor_si512( kc->w[j], buf[j] ); \
} while (0)

// Targetted macros, keccak-macros.h is included for each target.

#define DECL64(x)          __m512i x
#define XOR(d, a, b)       (d = _mm512_xor_si512(a,b))
#define XOR64              XOR
#define AND64(d, a, b)     (d = _mm512_and_si512(a,b))
#define OR64(d, a, b)      (d = _mm512_or_si512(a,b))
#define NOT64(d, s)        (d = mm512_not( s ) )
#define ROL64(d, v, n)     (d = mm512_rol_64(v, n))
#define XOROR(d, a, b, c)  (d = mm512_xoror(a, b, c))
#define XORAND(d, a, b, c) (d = mm512_xorand(a, b, c))
#define XOR3( d, a, b, c ) (d = mm512_xor3( a, b, c ))

#include "keccak-macros.c"

#define KECCAK_F_1600   DO(KECCAK_F_1600_512)

// One group of 8 rounds; P8_TO_P0 restores the variable naming, so a
// permutation is three of these. `j` must be a literal, so the RC[] indices
// stay compile-time constants.
#define KECCAK_8ROUNDS_512( j )   do { \
       KF_ELT( 0,  1, _mm512_set1_epi64( RC[(j) + 0] ) ); \
       KF_ELT( 1,  2, _mm512_set1_epi64( RC[(j) + 1] ) ); \
       KF_ELT( 2,  3, _mm512_set1_epi64( RC[(j) + 2] ) ); \
       KF_ELT( 3,  4, _mm512_set1_epi64( RC[(j) + 3] ) ); \
       KF_ELT( 4,  5, _mm512_set1_epi64( RC[(j) + 4] ) ); \
       KF_ELT( 5,  6, _mm512_set1_epi64( RC[(j) + 5] ) ); \
       KF_ELT( 6,  7, _mm512_set1_epi64( RC[(j) + 6] ) ); \
       KF_ELT( 7,  8, _mm512_set1_epi64( RC[(j) + 7] ) ); \
       P8_TO_P0; \
} while (0)

// Fully unrolled: the 3-iteration loop this replaced was not being unrolled by
// GCC, so each group ended at a scheduling barrier and RC[] stayed indexed.
// NOTE: 8-way only -- a loss on the narrower widths, see KECCAK_F_1600_256.
#define KECCAK_F_1600_512   do { \
    KECCAK_8ROUNDS_512(  0 ); \
    KECCAK_8ROUNDS_512(  8 ); \
    KECCAK_8ROUNDS_512( 16 ); \
} while (0)

static void keccak64_8way_init( keccak64_ctx_m512i *kc, unsigned out_size )
{
   __m512i zero = m512_zero;
   __m512i neg1 = m512_neg1;

   // Initialization for the "lane complement".
   kc->w[ 0] = zero;   kc->w[ 1] = neg1;
   kc->w[ 2] = neg1;   kc->w[ 3] = zero;
   kc->w[ 4] = zero;   kc->w[ 5] = zero;
   kc->w[ 6] = zero;   kc->w[ 7] = zero;
   kc->w[ 8] = neg1;   kc->w[ 9] = zero;
   kc->w[10] = zero;   kc->w[11] = zero;
   kc->w[12] = neg1;   kc->w[13] = zero;
   kc->w[14] = zero;   kc->w[15] = zero;
   kc->w[16] = zero;   kc->w[17] = neg1;
   kc->w[18] = zero;   kc->w[19] = zero;
   kc->w[20] = neg1;   kc->w[21] = zero;
   kc->w[22] = zero;   kc->w[23] = zero;
   kc->w[24] = zero;   kc->ptr = 0;
   kc->lim = 200 - (out_size >> 2);
}

static void
keccak64_8way_core( keccak64_ctx_m512i *kc, const void *data, size_t len,
               size_t lim )
{
    __m512i *buf;
    __m512i *vdata = (__m512i*)data;
    size_t ptr;

    buf = kc->buf;
    ptr = kc->ptr;

    if ( len < (lim - ptr) )
    {
        memcpy_512( buf + (ptr>>3), vdata, len>>3 );
        kc->ptr = ptr + len;
        return;
    }
    while ( len > 0 )
    {
        size_t clen;

        clen = (lim - ptr);
        if ( clen > len )
             clen = len;
        memcpy_512( buf + (ptr>>3), vdata, clen>>3 );
        ptr += clen;
        vdata = vdata + (clen>>3);
        len -= clen;
        if ( ptr == lim )
        {
            INPUT_BUF( lim );
            KECCAK_F_1600;
            ptr = 0;
        }
    }
    kc->ptr = ptr;
}

static void keccak64_8way_close( keccak64_ctx_m512i *kc, void *dst,
                                 size_t byte_len, size_t lim )
{
    __m512i tmp[lim + 1] __attribute__ ((aligned (64)));
    size_t j;
    size_t m512_len = byte_len >> 3;
    const unsigned eb = hard_coded_eb;

    if ( kc->ptr == (lim - 8) )
    {
        const uint64_t t = eb | 0x8000000000000000;
        tmp[0] = _mm512_set1_epi64( t );
        j = 8;
    }
    else
    {
        j = lim - kc->ptr;
        tmp[0] = _mm512_set1_epi64( eb );
        memset_zero_512( tmp + 1, (j>>3) - 2 );
        tmp[ (j>>3) - 1] = _mm512_set1_epi64( 0x8000000000000000 );
    }
    keccak64_8way_core( kc, tmp, j, lim );
    /* Finalize the "lane complement" */
    NOT64( kc->w[ 1], kc->w[ 1] );
    NOT64( kc->w[ 2], kc->w[ 2] );
    NOT64( kc->w[ 8], kc->w[ 8] );
    NOT64( kc->w[12], kc->w[12] );
    NOT64( kc->w[17], kc->w[17] );
    NOT64( kc->w[20], kc->w[20] );
    memcpy_512( dst, kc->w, m512_len );
}

void keccak256_8x64_init( void *kc )
{
   keccak64_8way_init( kc, 256 );
}

void
keccak256_8x64_update(void *cc, const void *data, size_t len)
{
    keccak64_8way_core(cc, data, len, 136);
}

void
keccak256_8x64_close(void *cc, void *dst)
{
    keccak64_8way_close(cc, dst, 32, 136);
}

void keccak256_8x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak256_8x64_init( cc );
   keccak256_8x64_update( cc, data, len );
   keccak256_8x64_close( cc, dst );
}

void keccak512_8x64_init( void *kc )
{
   keccak64_8way_init( kc, 512 );
}

void
keccak512_8x64_update(void *cc, const void *data, size_t len)
{
        keccak64_8way_core(cc, data, len, 72);
}

void
keccak512_8x64_close(void *cc, void *dst)
{
        keccak64_8way_close(cc, dst, 64, 72);
}

void keccak512_8x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak512_8x64_init( cc );
   keccak512_8x64_update( cc, data, len );
   keccak512_8x64_close( cc, dst );
}

// 8-lane sha3t; see SHA3T_PREPAD_FN above.
SHA3T_PREPAD_FN( sha3t_8x64_prepad, __m512i, keccak64_ctx_m512i,
                 m512_zero, m512_neg1, _mm512_set1_epi64, _mm512_xor_si512 )

#undef INPUT_BUF
#undef DECL64
#undef XOR64
#undef XOR
#undef AND64
#undef OR64
#undef NOT64
#undef ROL64
#undef KECCAK_F_1600
#undef XOROR
#undef XORAND
#undef XOR3

#endif  // AVX512

#if defined(__AVX2__)

#define INPUT_BUF(size)   do { \
    size_t j; \
    for (j = 0; j < (size>>3); j++ ) \
        kc->w[j ] = _mm256_xor_si256( kc->w[j], buf[j] ); \
} while (0)

#define DECL64(x)          __m256i x
#define XOR(d, a, b)       (d = _mm256_xor_si256(a,b))
#define XOR64              XOR
#define AND64(d, a, b)     (d = _mm256_and_si256(a,b))
#define OR64(d, a, b)      (d = _mm256_or_si256(a,b))
#define NOT64(d, s)        (d = mm256_not( s ) )
#define ROL64(d, v, n)     (d = mm256_rol_64(v, n))
#define XOROR(d, a, b, c)  (d = mm256_xoror( a, b, c ) )
#define XORAND(d, a, b, c) (d = mm256_xorand( a, b, c ) )
#define XOR3( d, a, b, c ) (d = mm256_xor3( a, b, c ))

#include "keccak-macros.c"

#define KECCAK_F_1600   DO(KECCAK_F_1600_256)

// NOTE: Deliberately still a loop, unlike the 8-way above. Unrolling measured a
// LOSS here: -6.2% AVX2, -5.1% SSE2, against +3.4% AVX-512. These have 16
// vector registers to the 8-way's 32 and already spill a 25-lane state, so the
// bigger scheduling region costs more than the loop overhead. Don't "fix" it.
#define KECCAK_F_1600_256   do { \
    int j; \
    for (j = 0; j < 24; j += 8) \
    { \
       KF_ELT( 0,  1, _mm256_set1_epi64x( RC[j + 0] ) ); \
       KF_ELT( 1,  2, _mm256_set1_epi64x( RC[j + 1] ) ); \
       KF_ELT( 2,  3, _mm256_set1_epi64x( RC[j + 2] ) ); \
       KF_ELT( 3,  4, _mm256_set1_epi64x( RC[j + 3] ) ); \
       KF_ELT( 4,  5, _mm256_set1_epi64x( RC[j + 4] ) ); \
       KF_ELT( 5,  6, _mm256_set1_epi64x( RC[j + 5] ) ); \
       KF_ELT( 6,  7, _mm256_set1_epi64x( RC[j + 6] ) ); \
       KF_ELT( 7,  8, _mm256_set1_epi64x( RC[j + 7] ) ); \
       P8_TO_P0; \
    } \
} while (0)


static void keccak64_init( keccak64_ctx_m256i *kc, unsigned out_size )
{
   __m256i zero = m256_zero;
   __m256i neg1 = m256_neg1;

   // Initialization for the "lane complement".
   kc->w[ 0] = zero;   kc->w[ 1] = neg1;
   kc->w[ 2] = neg1;   kc->w[ 3] = zero;
   kc->w[ 4] = zero;   kc->w[ 5] = zero;
   kc->w[ 6] = zero;   kc->w[ 7] = zero;
   kc->w[ 8] = neg1;   kc->w[ 9] = zero;
   kc->w[10] = zero;   kc->w[11] = zero;
   kc->w[12] = neg1;   kc->w[13] = zero;
   kc->w[14] = zero;   kc->w[15] = zero;
   kc->w[16] = zero;   kc->w[17] = neg1;
   kc->w[18] = zero;   kc->w[19] = zero;
   kc->w[20] = neg1;   kc->w[21] = zero;
   kc->w[22] = zero;   kc->w[23] = zero;
   kc->w[24] = zero;   kc->ptr = 0;
   kc->lim = 200 - (out_size >> 2);
}

static void
keccak64_core( keccak64_ctx_m256i *kc, const void *data, size_t len,
               size_t lim )
{
    __m256i *buf;
    __m256i *vdata = (__m256i*)data;
    size_t ptr;

    buf = kc->buf;
    ptr = kc->ptr;

    if ( len < (lim - ptr) )
    {
        memcpy_256( buf + (ptr>>3), vdata, len>>3 );
        kc->ptr = ptr + len;
        return;
    }

    while ( len > 0 )
    {
        size_t clen;

        clen = (lim - ptr);
        if ( clen > len )
             clen = len;
        memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
        ptr += clen;
        vdata = vdata + (clen>>3);
        len -= clen;
        if ( ptr == lim )
        {
            INPUT_BUF( lim );
            KECCAK_F_1600;
            ptr = 0;
        }
    }
    kc->ptr = ptr;
}

static void keccak64_close( keccak64_ctx_m256i *kc, void *dst, size_t byte_len,
            size_t lim )
{
    __m256i tmp[lim + 1] __attribute__ ((aligned (32)));
    size_t j;
    size_t m256_len = byte_len >> 3;
    const unsigned eb = hard_coded_eb;

    if ( kc->ptr == (lim - 8) )
    {
        const uint64_t t = eb | 0x8000000000000000;
        tmp[0] = _mm256_set1_epi64x( t );
        j = 8;
    }
    else
    {
        j = lim - kc->ptr;
        tmp[0] = _mm256_set1_epi64x( eb );
        memset_zero_256( tmp + 1, (j>>3) - 2 );
        tmp[ (j>>3) - 1] = _mm256_set1_epi64x( 0x8000000000000000 );
    }
    keccak64_core( kc, tmp, j, lim );
    /* Finalize the "lane complement" */
    NOT64( kc->w[ 1], kc->w[ 1] );
    NOT64( kc->w[ 2], kc->w[ 2] );
    NOT64( kc->w[ 8], kc->w[ 8] );
    NOT64( kc->w[12], kc->w[12] );
    NOT64( kc->w[17], kc->w[17] );
    NOT64( kc->w[20], kc->w[20] );
    memcpy_256( dst, kc->w, m256_len );
}

void keccak256_4x64_init( void *kc )
{
   keccak64_init( kc, 256 );
}

void
keccak256_4x64_update(void *cc, const void *data, size_t len)
{
    keccak64_core(cc, data, len, 136);
}

void
keccak256_4x64_close(void *cc, void *dst)
{
    keccak64_close(cc, dst, 32, 136);
}

void keccak256_4x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak256_4x64_init( cc );
   keccak256_4x64_update( cc, data, len );
   keccak256_4x64_close( cc, dst );
}

void keccak512_4x64_init( void *kc )
{
   keccak64_init( kc, 512 );
}

void
keccak512_4x64_update(void *cc, const void *data, size_t len)
{
   keccak64_core(cc, data, len, 72);
}

void
keccak512_4x64_close(void *cc, void *dst)
{
   keccak64_close(cc, dst, 64, 72);
}

void keccak512_4x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak512_4x64_init( cc );
   keccak512_4x64_update( cc, data, len );
   keccak512_4x64_close( cc, dst );
}

// 4-lane sha3t; see SHA3T_PREPAD_FN above.
SHA3T_PREPAD_FN( sha3t_4x64_prepad, __m256i, keccak64_ctx_m256i,
                 m256_zero, m256_neg1, _mm256_set1_epi64x, _mm256_xor_si256 )

#undef INPUT_BUF
#undef DECL64
#undef XOR64
#undef XOR
#undef AND64
#undef OR64
#undef NOT64
#undef ROL64
#undef KECCAK_F_1600
#undef KECCAK_F_1600_256
#undef XOROR
#undef XORAND
#undef XOR3

#endif  // AVX2

// SSE2 & NEON

#define INPUT_BUF(size)   do { \
    size_t j; \
    for (j = 0; j < (size>>3); j++ ) \
        kc->w[j ] = v128_xor( kc->w[j], buf[j] ); \
} while (0)

#define DECL64(x)          v128_t x
#define XOR(d, a, b)       (d = v128_xor(a,b))
#define XOR64              XOR
#define AND64(d, a, b)     (d = v128_and(a,b))
#define OR64(d, a, b)      (d = v128_or(a,b))
#define NOT64(d, s)        (d = v128_not( s ) )
#define ROL64(d, v, n)     (d = v128_rol64(v, n))
#define XOROR(d, a, b, c)  (d = v128_xoror( a, b, c ) )
#define XORAND(d, a, b, c) (d = v128_xorand( a, b, c ) )
#define XOR3( d, a, b, c ) (d = v128_xor3( a, b, c ))

#include "keccak-macros.c"

#define KECCAK_F_1600   DO(KECCAK_F_1600_256)

// NOTE: Still a loop, same measured reason as the 4-way above (-5.1% unrolled).
// Also the aarch64/NEON path, which has 32 registers and might behave like the
// 8-way -- but that has never been measured on ARM, so it stays.
#define KECCAK_F_1600_256   do { \
    int j; \
    for (j = 0; j < 24; j += 8) \
    { \
       KF_ELT( 0,  1, v128_64( RC[j + 0] ) ); \
       KF_ELT( 1,  2, v128_64( RC[j + 1] ) ); \
       KF_ELT( 2,  3, v128_64( RC[j + 2] ) ); \
       KF_ELT( 3,  4, v128_64( RC[j + 3] ) ); \
       KF_ELT( 4,  5, v128_64( RC[j + 4] ) ); \
       KF_ELT( 5,  6, v128_64( RC[j + 5] ) ); \
       KF_ELT( 6,  7, v128_64( RC[j + 6] ) ); \
       KF_ELT( 7,  8, v128_64( RC[j + 7] ) ); \
       P8_TO_P0; \
    } \
} while (0)

static void keccak64x2_init( keccak64_ctx_v128 *kc, unsigned out_size )
{
   v128_t zero = v128_zero;
   v128_t neg1 = v128_neg1;

   // Initialization for the "lane complement".
   kc->w[ 0] = zero;   kc->w[ 1] = neg1;
   kc->w[ 2] = neg1;   kc->w[ 3] = zero;
   kc->w[ 4] = zero;   kc->w[ 5] = zero;
   kc->w[ 6] = zero;   kc->w[ 7] = zero;
   kc->w[ 8] = neg1;   kc->w[ 9] = zero;
   kc->w[10] = zero;   kc->w[11] = zero;
   kc->w[12] = neg1;   kc->w[13] = zero;
   kc->w[14] = zero;   kc->w[15] = zero;
   kc->w[16] = zero;   kc->w[17] = neg1;
   kc->w[18] = zero;   kc->w[19] = zero;
   kc->w[20] = neg1;   kc->w[21] = zero;
   kc->w[22] = zero;   kc->w[23] = zero;
   kc->w[24] = zero;   kc->ptr = 0;
   kc->lim = 200 - (out_size >> 2);
}

static void
keccak64x2_core( keccak64_ctx_v128 *kc, const void *data, size_t len,
               size_t lim )
{
    v128_t *buf;
    v128_t *vdata = (v128_t*)data;
    size_t ptr;

    buf = kc->buf;
    ptr = kc->ptr;

    if ( len < (lim - ptr) )
    {
        v128_memcpy( buf + (ptr>>3), vdata, len>>3 );
        kc->ptr = ptr + len;
        return;
    }

    while ( len > 0 )
    {
        size_t clen;

        clen = (lim - ptr);
        if ( clen > len )
             clen = len;
        v128_memcpy( buf + (ptr>>3), vdata, clen>>3 );
        ptr += clen;
        vdata = vdata + (clen>>3);
        len -= clen;
        if ( ptr == lim )
        {
            INPUT_BUF( lim );
            KECCAK_F_1600;
            ptr = 0;
        }
    }
    kc->ptr = ptr;
}

static void keccak64x2_close( keccak64_ctx_v128 *kc, void *dst,
                              size_t byte_len, size_t lim )
{
    unsigned eb;
    union {
       v128_t tmp[140];
       uint64_t dummy;   /* for alignment */
    } u;
    size_t j;
    size_t v128_len = byte_len >> 3;

    eb = hard_coded_eb;
    if ( kc->ptr == (lim - 8) )
    {
        const uint64_t t = eb | 0x8000000000000000;
        u.tmp[0] = v128_64( t );
        j = 8;
    }
    else
    {
        j = lim - kc->ptr;
        u.tmp[0] = v128_64( eb );
        v128_memset_zero( u.tmp + 1, (j>>3) - 2 );
        u.tmp[ (j>>3) - 1] = v128_64( 0x8000000000000000 );
    }
    keccak64x2_core( kc, u.tmp, j, lim );
    /* Finalize the "lane complement" */
    NOT64( kc->w[ 1], kc->w[ 1] );
    NOT64( kc->w[ 2], kc->w[ 2] );
    NOT64( kc->w[ 8], kc->w[ 8] );
    NOT64( kc->w[12], kc->w[12] );
    NOT64( kc->w[17], kc->w[17] );
    NOT64( kc->w[20], kc->w[20] );
    v128_memcpy( dst, kc->w, v128_len );
}

void keccak256_2x64_init( void *kc )
{
   keccak64x2_init( kc, 256 );
}

void
keccak256_2x64_update(void *cc, const void *data, size_t len)
{
    keccak64x2_core(cc, data, len, 136);
}

void
keccak256_2x64_close(void *cc, void *dst)
{
    keccak64x2_close(cc, dst, 32, 136);
}

void keccak256_2x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak256_2x64_init( cc );
   keccak256_2x64_update( cc, data, len );
   keccak256_2x64_close( cc, dst );
}

void keccak512_2x64_init( void *kc )
{
   keccak64x2_init( kc, 512 );
}

void
keccak512_2x64_update(void *cc, const void *data, size_t len)
{
   keccak64x2_core(cc, data, len, 72);
}

void
keccak512_2x64_close(void *cc, void *dst)
{
   keccak64x2_close(cc, dst, 64, 72);
}

void keccak512_2x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak512_2x64_init( cc );
   keccak512_2x64_update( cc, data, len );
   keccak512_2x64_close( cc, dst );
}

// 2-lane sha3t; see SHA3T_PREPAD_FN above. Also the aarch64/NEON path, but
// sha3t only selects 2x64 on ARM under FEAT_SHA3 (keccak-gate.h).
SHA3T_PREPAD_FN( sha3t_2x64_prepad, v128_t, keccak64_ctx_v128,
                 v128_zero, v128_neg1, v128_64, v128_xor )

#undef INPUT_BUF
#undef DECL64
#undef XOR64
#undef XOR
#undef AND64
#undef OR64
#undef NOT64
#undef ROL64
#undef KECCAK_F_1600
#undef XOROR
#undef XORAND
#undef XOR3
        

/* ===================== scalar (1-way) pre-padded SHA3-256 =================
 * Single-block SHA3-256 driven from a directly built state -- the 1-way
 * analogue of sha3t_*_prepad above. Additive: nothing else in this file
 * changes, and the macros below are instantiated for uint64_t exactly as the
 * three vector sections instantiate them for their own types, so the round
 * function and round constants are shared. There is no second copy of keccak.
 *
 * Why: the generic init/update/close path memsets a 200-byte state, memcpys the
 * message into a buffer, builds a padding VLA and finishes with 6 NOT64s, all
 * around a single permutation. A caller hashing one block per pass pays that
 * every time; heavyhash pays it twice per nonce.
 *
 * NOTE: SHA3 padding (0x06) is baked in and hard_coded_eb is IGNORED, exactly
 * as for sha3t_*_prepad -- NOT usable for keccak/sha3d, which need 0x01.
 * Little-endian hosts only, like the rest of this file. */

typedef struct { uint64_t w[25]; } keccak64_ctx_1way;

#define DECL64(x)          uint64_t x
#define XOR(d, a, b)       (d = (a) ^ (b))
#define XOR64              XOR
#define AND64(d, a, b)     (d = (a) & (b))
#define OR64(d, a, b)      (d = (a) | (b))
#define NOT64(d, s)        (d = ~(s))
// The ternary folds away -- every call site passes a literal rho offset. It is
// there because an offset of 0 would make `v >> 64` undefined behaviour.
#define ROL64(d, v, n)     (d = (n) ? ( ((v) << (n)) | ((v) >> ( 64 - (n) )) ) \
                                    : (v))
#define XOROR(d, a, b, c)  (d = (a) ^ ( (b) | (c) ))
#define XORAND(d, a, b, c) (d = (a) ^ ( (b) & (c) ))
#define XOR3(d, a, b, c)   (d = (a) ^ (b) ^ (c))

#include "keccak-macros.c"

#define KECCAK_F_1600_1W_BODY   do { \
    int j; \
    for ( j = 0; j < 24; j += 8 ) \
    { \
       KF_ELT( 0,  1, RC[j + 0] ); \
       KF_ELT( 1,  2, RC[j + 1] ); \
       KF_ELT( 2,  3, RC[j + 2] ); \
       KF_ELT( 3,  4, RC[j + 3] ); \
       KF_ELT( 4,  5, RC[j + 4] ); \
       KF_ELT( 5,  6, RC[j + 5] ); \
       KF_ELT( 6,  7, RC[j + 6] ); \
       KF_ELT( 7,  8, RC[j + 7] ); \
       P8_TO_P0; \
    } \
} while (0)

// KF_ELT defers THETA/RHO/KHI through LPAR/RPAR, which needs one further
// expansion pass; DO() supplies it, the same way KECCAK_F_1600 does above.
// Without it the compiler reports THETA as an implicit function declaration.
#define KECCAK_F_1600_1W   DO(KECCAK_F_1600_1W_BODY)

#define KEC1W_PAD06   0x0000000000000006ull
#define KEC1W_PAD80   0x8000000000000000ull

/* Lanes 1,2,8,12,17,20 are held complemented and the round function accounts
 * for it, so a pre-padded state is those constants XORed with the message.
 * Only lanes 0..3 are read back and only 1 and 2 of those are complemented, so
 * 2 NOT64s replace the close path's 6. `first_free` is the lane holding the
 * 0x06 pad byte, i.e. message length in lanes. */
static inline void kec1w_tail( keccak64_ctx_1way *kc, int first_free )
{
   const uint64_t neg1 = ~(uint64_t)0;
   for ( int i = first_free; i < 25; ++i ) kc->w[i] = 0;
   kc->w[first_free] = KEC1W_PAD06;
   // Lane 8 is inside an 80-byte message (the caller XORs it) but past a
   // 32-byte one, where it is just the complement constant.
   if ( first_free <= 8 ) kc->w[8] = neg1;
   kc->w[12] = neg1;
   kc->w[16] = KEC1W_PAD80;
   kc->w[17] = neg1;
   kc->w[20] = neg1;
}

static inline uint64_t kec1w_le64dec( const uint8_t *p )
{
   uint64_t v;
   memcpy( &v, p, 8 );
   return v;
}

void sha3_256_prepad80( void *dst, const void *src )
{
   keccak64_ctx_1way ctx;
   keccak64_ctx_1way *kc = &ctx;       // the a00.. macros dereference `kc`
   const uint64_t neg1 = ~(uint64_t)0;
   const uint8_t *p = (const uint8_t*)src;

   for ( int i = 0; i < 10; ++i ) kc->w[i] = kec1w_le64dec( p + 8*i );
   kc->w[1] ^= neg1;  kc->w[2] ^= neg1;  kc->w[8] ^= neg1;
   kec1w_tail( kc, 10 );

   KECCAK_F_1600_1W;

   const uint64_t d[4] = { kc->w[0], ~kc->w[1], ~kc->w[2], kc->w[3] };
   memcpy( dst, d, 32 );
}

void sha3_256_prepad32( void *dst, const void *src )
{
   keccak64_ctx_1way ctx;
   keccak64_ctx_1way *kc = &ctx;
   const uint64_t neg1 = ~(uint64_t)0;
   const uint8_t *p = (const uint8_t*)src;

   for ( int i = 0; i < 4; ++i ) kc->w[i] = kec1w_le64dec( p + 8*i );
   kc->w[1] ^= neg1;  kc->w[2] ^= neg1;
   kec1w_tail( kc, 4 );

   KECCAK_F_1600_1W;

   const uint64_t d[4] = { kc->w[0], ~kc->w[1], ~kc->w[2], kc->w[3] };
   memcpy( dst, d, 32 );
}

#undef KECCAK_F_1600_1W
#undef KECCAK_F_1600_1W_BODY
