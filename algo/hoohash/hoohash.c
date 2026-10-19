// HoohashV110 (PePePoW) proof-of-work, ported into cpuminer-opt.
//
// Algorithm + the FP math below are adapted verbatim (consensus-critical, must
// stay bit-identical) from the MIT-licensed reference:
//   github.com/MattF42/PePePow_multi-hashing  crypto/hoohash/hoohash.c
//   Copyright (c) 2024 Hoosat Oy
//   Copyright (c) 2024 PePe-core developers
//   Adapted from github.com/HoosatNetwork/hoohash commit 9634f114.
//
// FP DETERMINISM: the matrix multiply uses double-precision sin/cos/exp/sqrt
// with a NaN/Inf rejection loop. -ffast-math / -Ofast imply -ffinite-math-only,
// which folds isnan/isinf to false and breaks that loop -> a different (wrong)
// digest. cpuminer-opt uses one global CFLAGS (and -Ofast on ARM), so we pin
// strict FP for THIS translation unit only.
//
// FMA CONTRACTION MUST STAY ON. Consensus matches the contracted arithmetic
// (PePe-core is built with GCC's default -ffp-contract=fast): this file emits 3
// vfmadd*sd, and removing them changes 72% of digests. Never add
// -ffp-contract=off, never build for a non-FMA target. GCC < 14 ignores the
// FP_CONTRACT pragma below, which is why contraction has always been on; GCC >= 14
// honours it and would flip the digest. KAT vector 1 is the sentinel.

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC optimize ("no-fast-math")
#endif
#if defined(__clang__)
#pragma clang fp contract(off)
#endif
#pragma STDC FP_CONTRACT OFF   /* inert on GCC < 14 -- see the note above */

#include "hoohash-gate.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include "algo/blake3/blake3.h"

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define PI 3.14159265358979323846
#define EPS 1e-9
#define COMPLEX_TRANSFORM_MULTIPLIER 0.000001

// xoshiro256** PRNG state
typedef struct {
    uint64_t s0;
    uint64_t s1;
    uint64_t s2;
    uint64_t s3;
} xoshiro_state;

// Safe memory read functions to avoid UB from unaligned access
static inline uint64_t read_uint64_le(const uint8_t *data) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result |= ((uint64_t)data[i]) << (i * 8);
    }
    return result;
}

static inline uint32_t read_uint32_le(const uint8_t *data) {
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static inline uint32_t read_uint32_be(const uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

// xoshiro256** functions
static inline uint64_t rotl64(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static void xoshiro_init(xoshiro_state *state, const uint8_t *bytes) {
    state->s0 = read_uint64_le(&bytes[0]);
    state->s1 = read_uint64_le(&bytes[8]);
    state->s2 = read_uint64_le(&bytes[16]);
    state->s3 = read_uint64_le(&bytes[24]);
}

static uint64_t xoshiro_gen(xoshiro_state *x) {
    uint64_t res = rotl64(x->s0 + x->s3, 23) + x->s0;
    uint64_t t = x->s1 << 17;

    x->s2 ^= x->s0;
    x->s3 ^= x->s1;
    x->s1 ^= x->s2;
    x->s0 ^= x->s3;

    x->s2 ^= t;
    x->s3 = rotl64(x->s3, 45);

    return res;
}

// Complex nonlinear transformations
static double MediumComplexNonLinear(double x) {
    return exp(sin(x) + cos(x));
}

static double IntermediateComplexNonLinear(double x) {
    if (fabs(x - PI / 2) < EPS || fabs(x - 3 * PI / 2) < EPS) {
        return 0; // Avoid singularity
    }
    return sin(x) * sin(x);
}

static double HighComplexNonLinear(double x) {
    return 1.0 / sqrt(fabs(x) + 1);
}

static double ComplexNonLinear(double x) {
    double transformFactorOne = (x * COMPLEX_TRANSFORM_MULTIPLIER) / 8.0 - floor((x * COMPLEX_TRANSFORM_MULTIPLIER) / 8.0);
    double transformFactorTwo = (x * COMPLEX_TRANSFORM_MULTIPLIER) / 4.0 - floor((x * COMPLEX_TRANSFORM_MULTIPLIER) / 4.0);

    if (transformFactorOne < 0.33) {
        if (transformFactorTwo < 0.25) {
            return MediumComplexNonLinear(x + (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.5) {
            return MediumComplexNonLinear(x - (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.75) {
            return MediumComplexNonLinear(x * (1 + transformFactorTwo));
        } else {
            return MediumComplexNonLinear(x / (1 + transformFactorTwo));
        }
    } else if (transformFactorOne < 0.66) {
        if (transformFactorTwo < 0.25) {
            return IntermediateComplexNonLinear(x + (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.5) {
            return IntermediateComplexNonLinear(x - (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.75) {
            return IntermediateComplexNonLinear(x * (1 + transformFactorTwo));
        } else {
            return IntermediateComplexNonLinear(x / (1 + transformFactorTwo));
        }
    } else {
        if (transformFactorTwo < 0.25) {
            return HighComplexNonLinear(x + (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.5) {
            return HighComplexNonLinear(x - (1 + transformFactorTwo));
        } else if (transformFactorTwo < 0.75) {
            return HighComplexNonLinear(x * (1 + transformFactorTwo));
        } else {
            return HighComplexNonLinear(x / (1 + transformFactorTwo));
        }
    }
}

// NOTE (consensus quirk, preserve verbatim): the rejection loop never recomputes
// `transformedValue`, so the finite path always returns value*1 and the NaN/Inf
// path always returns 0. Do not "fix" this.
static double SafeComplexTransform(double input) {
    double transformedValue;
    double rounds = 1;
    transformedValue = ComplexNonLinear(input);
    while (isnan(transformedValue) || isinf(transformedValue)) {
        input = input * 0.1;
        if (input <= 0.0000000000001) {
            return 0;
        }
        rounds++;
    }
    return transformedValue * rounds;
}

static void generateHoohashMatrix(const uint8_t *hash, double mat[64][64]) {
    xoshiro_state state;
    xoshiro_init(&state, hash);
    double normalize = 1000000.0;
    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            uint64_t val = xoshiro_gen(&state);
            uint32_t lower_4_bytes = val & 0xFFFFFFFF;
            mat[i][j] = (double)lower_4_bytes / (double)UINT32_MAX * normalize;
        }
    }
}

static double TransformFactor(double x) {
    const double granularity = 1024.0;
    return x / granularity - floor(x / granularity);
}

static void ConvertBytesToUint32Array(uint32_t *H, const uint8_t *bytes) {
    for (int i = 0; i < 8; i++) {
        H[i] = read_uint32_be(&bytes[i * 4]);
    }
}

static void HoohashMatrixMultiplication(double mat[64][64], const uint8_t *hashBytes, uint8_t *output, uint64_t nonce) {
    uint8_t scaledValues[32] = {0};
    uint8_t vector[64] = {0};
    double product[64] = {0};
    uint8_t result[32] = {0};
    uint32_t H[8] = {0};

    ConvertBytesToUint32Array(H, hashBytes);
    double hashXor = (double)(H[0] ^ H[1] ^ H[2] ^ H[3] ^ H[4] ^ H[5] ^ H[6] ^ H[7]);
    double nonceMod = (double)(nonce & 0xFF);
    double divider = 0.0001;
    double multiplier = 1234;
    double sw = 0.0;

    for (int i = 0; i < 32; i++) {
        vector[2 * i] = hashBytes[i] >> 4;
        vector[2 * i + 1] = hashBytes[i] & 0x0F;
    }

    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            if (sw <= 0.02) {
                double input = (mat[i][j] * hashXor * (double)vector[j] + nonceMod);
                double output_val = SafeComplexTransform(input) * (double)vector[j] * multiplier;
                product[i] += output_val;
            } else {
                double output_val = mat[i][j] * divider * (double)vector[j];
                product[i] += output_val;
            }
            sw = TransformFactor(product[i]);
        }
    }

    for (int i = 0; i < 64; i += 2) {
        uint64_t pval = (uint64_t)product[i] + (uint64_t)product[i + 1];
        scaledValues[i / 2] = (uint8_t)(pval & 0xFF);
    }

    for (int i = 0; i < 32; i++) {
        result[i] = hashBytes[i] ^ scaledValues[i];
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, result, HOOHASH_HASH_SIZE);
    blake3_hasher_finalize(&hasher, output, HOOHASH_HASH_SIZE);
}

// Nonce batching: HOO_LANES nonces per call, run either as SIMD (HOO_SIMD, all
// lanes per instruction) or as a scalar interleave (independent chains filling
// the ~17-cycle product[i] -> sw -> branch dependency chain above). SIMD wins on
// both targets; the interleave is only for ARMv7, which has no FP64 in NEON.
//
// Either batched path adds a scalar-vs-N-way differential at registration, so a
// codegen divergence fails closed before a share is submitted. Defaults below,
// override with -DHOO_LANES=N / -DHOO_SIMD.
#ifndef HOO_LANES
#if defined(__AVX__)
#define HOO_LANES 4
#define HOO_SIMD  1
#elif defined(__aarch64__)
#define HOO_LANES 2
#define HOO_SIMD  1
#elif defined(__arm__)          /* ARMv7 NEON has no FP64: interleave only */
#define HOO_LANES 4
#else
#define HOO_LANES 1
#endif
#endif

// SIMD across nonces. GCC vector extensions rather than intrinsics on purpose:
// identical expression shapes make the compiler reproduce the scalar path's FP
// contraction, which consensus depends on (fusions seen in the scalar asm):
//     product[i] += mat*divider*vector[j]       -> fma(mat*divider, vector, product)
//     input = mat*hashXor*vector[j] + nonceMod  -> fma(mat*hashXor, vector, nonceMod)
//     product[i] += SCT(input)*vector[j]*mult   -> fma(t, 1234.0, product)
// TransformFactor does NOT fuse. Intrinsics would have to reproduce all of that
// by hand; the registration differential proves it held.
#if defined(HOO_SIMD) && HOO_LANES > 1

typedef double  hoo_vdf __attribute__((vector_size(HOO_LANES * 8)));
typedef int64_t hoo_vdi __attribute__((vector_size(HOO_LANES * 8)));

// floor() and "any lane set" must stay in vector registers: as element-wise loops
// over x[k] they look portable, but GCC spills the vector and scalarises the whole
// loop body (zero packed ops, scalar speed).
#if defined(__AVX512F__) && defined(__AVX512DQ__) && HOO_LANES == 8
#include <immintrin.h>
static inline hoo_vdf hoo_vfloor(hoo_vdf x)
{ return (hoo_vdf)_mm512_roundscale_pd((__m512d)x, 1); }   /* 1 = round down */
static inline int hoo_vany(hoo_vdi m)
{ return _mm512_movepi64_mask((__m512i)m) != 0; }

#elif defined(__AVX__) && HOO_LANES == 4
#include <immintrin.h>
static inline hoo_vdf hoo_vfloor(hoo_vdf x)
{ return (hoo_vdf)_mm256_floor_pd((__m256d)x); }
static inline int hoo_vany(hoo_vdi m)
{ return _mm256_movemask_pd((__m256d)m) != 0; }

#elif defined(__SSE4_1__) && HOO_LANES == 2
#include <smmintrin.h>
static inline hoo_vdf hoo_vfloor(hoo_vdf x)
{ return (hoo_vdf)_mm_floor_pd((__m128d)x); }
static inline int hoo_vany(hoo_vdi m)
{ return _mm_movemask_pd((__m128d)m) != 0; }

#elif defined(__aarch64__) && HOO_LANES == 2
#include <arm_neon.h>
static inline hoo_vdf hoo_vfloor(hoo_vdf x)
{ return (hoo_vdf)vrndmq_f64((float64x2_t)x); }
static inline int hoo_vany(hoo_vdi m)
{ return vmaxvq_u32(vreinterpretq_u32_s64((int64x2_t)m)) != 0; }

#else
#error "HOO_SIMD: no vector floor/any for this target+width; use the scalar path"
#endif

static inline hoo_vdf hoo_vbcast(double x)
{
    hoo_vdf r;
    for (int k = 0; k < HOO_LANES; k++)
        r[k] = x;
    return r;                        /* loop-invariant, hoisted out of the loop */
}

static void HoohashMatrixMultiplicationV(double mat[64][64],
        const uint8_t hashBytes[HOO_LANES][HOOHASH_HASH_SIZE],
        uint8_t output[HOO_LANES][HOOHASH_HASH_SIZE], const uint64_t *nonce)
{
    double _ALIGN(64) vecT[64][HOO_LANES];    /* transposed: lanes contiguous per j */
    uint8_t vector[HOO_LANES][64];
    double product[HOO_LANES][64];
    hoo_vdf hashXor, nonceMod, sw;
    const double divider = 0.0001;
    const double multiplier = 1234;
    const hoo_vdf granularity = hoo_vbcast(1024.0);
    const hoo_vdf thresh      = hoo_vbcast(0.02);

    for (int l = 0; l < HOO_LANES; l++) {
        uint32_t H[8] = {0};
        ConvertBytesToUint32Array(H, hashBytes[l]);
        hashXor[l] = (double)(H[0] ^ H[1] ^ H[2] ^ H[3] ^ H[4] ^ H[5] ^ H[6] ^ H[7]);
        nonceMod[l] = (double)(nonce[l] & 0xFF);
        sw[l] = 0.0;
        for (int i = 0; i < 32; i++) {
            vector[l][2 * i] = hashBytes[l][i] >> 4;
            vector[l][2 * i + 1] = hashBytes[l][i] & 0x0F;
        }
        for (int j = 0; j < 64; j++)
            vecT[j][l] = (double)vector[l][j];
    }

    for (int i = 0; i < 64; i++) {
        hoo_vdf prod = hoo_vbcast(0.0);
        for (int j = 0; j < 64; j++) {
            const double mv = mat[i][j];
            const hoo_vdf m = hoo_vbcast(mv);
            const hoo_vdf vec = *(const hoo_vdf *)vecT[j];
            const hoo_vdi mask = (sw <= thresh);

            /* cheap path, all lanes: same expression -> same fusion as scalar */
            hoo_vdf next = prod + m * divider * vec;

            if (__builtin_expect(hoo_vany(mask), 0)) {
                /* expensive lanes: scalar libm, expression for expression as the
                   reference. Blend finished products, never intermediates. */
                hoo_vdf slow = next;
                for (int l = 0; l < HOO_LANES; l++) {
                    if (!mask[l]) continue;
                    double p = prod[l];
                    double input = (mv * hashXor[l] * vecT[j][l] + nonceMod[l]);
                    p += SafeComplexTransform(input) * vecT[j][l] * multiplier;
                    slow[l] = p;
                }
                next = (hoo_vdf)(((hoo_vdi)slow & mask) | ((hoo_vdi)next & ~mask));
            }

            prod = next;
            sw = prod / granularity - hoo_vfloor(prod / granularity);
        }
        for (int l = 0; l < HOO_LANES; l++)
            product[l][i] = prod[l];
    }

    for (int l = 0; l < HOO_LANES; l++) {
        uint8_t scaledValues[32] = {0};
        uint8_t result[32] = {0};

        for (int i = 0; i < 64; i += 2) {
            uint64_t pval = (uint64_t)product[l][i] + (uint64_t)product[l][i + 1];
            scaledValues[i / 2] = (uint8_t)(pval & 0xFF);
        }
        for (int i = 0; i < 32; i++)
            result[i] = hashBytes[l][i] ^ scaledValues[i];

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, result, HOOHASH_HASH_SIZE);
        blake3_hasher_finalize(&hasher, output[l], HOOHASH_HASH_SIZE);
    }
}
#endif   /* HOO_SIMD */

#if HOO_LANES > 1

static void HoohashMatrixMultiplicationN(double mat[64][64],
        const uint8_t hashBytes[HOO_LANES][HOOHASH_HASH_SIZE],
        uint8_t output[HOO_LANES][HOOHASH_HASH_SIZE], const uint64_t *nonce)
{
    uint8_t vector[HOO_LANES][64];
    double product[HOO_LANES][64];
    double hashXor[HOO_LANES], nonceMod[HOO_LANES], sw[HOO_LANES];
    const double divider = 0.0001;
    const double multiplier = 1234;

    for (int l = 0; l < HOO_LANES; l++) {
        uint32_t H[8] = {0};
        ConvertBytesToUint32Array(H, hashBytes[l]);
        hashXor[l] = (double)(H[0] ^ H[1] ^ H[2] ^ H[3] ^ H[4] ^ H[5] ^ H[6] ^ H[7]);
        nonceMod[l] = (double)(nonce[l] & 0xFF);
        sw[l] = 0.0;
        for (int i = 0; i < 64; i++)
            product[l][i] = 0.0;
        for (int i = 0; i < 32; i++) {
            vector[l][2 * i] = hashBytes[l][i] >> 4;
            vector[l][2 * i + 1] = hashBytes[l][i] & 0x0F;
        }
    }

    for (int i = 0; i < 64; i++) {
        for (int j = 0; j < 64; j++) {
            const double m = mat[i][j];   /* shared by all lanes */
            for (int l = 0; l < HOO_LANES; l++) {
                if (sw[l] <= 0.02) {
                    double input = (m * hashXor[l] * (double)vector[l][j] + nonceMod[l]);
                    double output_val = SafeComplexTransform(input) * (double)vector[l][j] * multiplier;
                    product[l][i] += output_val;
                } else {
                    double output_val = m * divider * (double)vector[l][j];
                    product[l][i] += output_val;
                }
                sw[l] = TransformFactor(product[l][i]);
            }
        }
    }

    for (int l = 0; l < HOO_LANES; l++) {
        uint8_t scaledValues[32] = {0};
        uint8_t result[32] = {0};

        for (int i = 0; i < 64; i += 2) {
            uint64_t pval = (uint64_t)product[l][i] + (uint64_t)product[l][i + 1];
            scaledValues[i / 2] = (uint8_t)(pval & 0xFF);
        }
        for (int i = 0; i < 32; i++)
            result[i] = hashBytes[l][i] ^ scaledValues[i];

        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, result, HOOHASH_HASH_SIZE);
        blake3_hasher_finalize(&hasher, output[l], HOOHASH_HASH_SIZE);
    }
}
#endif   /* HOO_LANES > 1 */

// The two halves of the hash over an 80-byte header:
//   hoohash_matrix_gen()  JOB-CONSTANT -- matrixSeed = BLAKE3(header80 with nNonce
//     zeroed) -> 64x64 double matrix. Depends only on bytes 0..75 (the PePePoW
//     consensus change made the matrix nonce-independent), so scanhash builds it
//     once per call rather than once per nonce: ~22% of the per-nonce cost, and
//     bit-exact since it is the same values computed once instead of N times.
//   hoohashv110_core()    NONCE-DEPENDENT -- firstPass = BLAKE3(full header), then
//     the matrix multiply.
static void hoohash_matrix_gen(const uint8_t *data, double mat[64][64])
{
    blake3_hasher hasher;
    uint8_t matrixSeed[HOOHASH_HASH_SIZE];
    uint8_t masked_header[80] = {0};   /* nNonce (4B @ offset 76) stays zero */

    memcpy(masked_header, data, 76);

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, masked_header, 80);
    blake3_hasher_finalize(&hasher, matrixSeed, HOOHASH_HASH_SIZE);

    generateHoohashMatrix(matrixSeed, mat);
}

static void hoohashv110_core(const uint8_t *data, double mat[64][64],
                             uint8_t output[HOOHASH_HASH_SIZE])
{
    blake3_hasher hasher;
    uint8_t firstPass[HOOHASH_HASH_SIZE];

    // First BLAKE3 pass on the full 80-byte header (nonce included).
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, 80);
    blake3_hasher_finalize(&hasher, firstPass, HOOHASH_HASH_SIZE);

    // Bitcoin/Dash-style header: nonce is 4 bytes at offset 76, little-endian.
    const uint64_t nonce = (uint64_t)read_uint32_le(data + 76);

    HoohashMatrixMultiplication(mat, firstPass, output, nonce);
}

#if HOO_LANES > 1
// HOO_LANES headers sharing one matrix (they differ only in nNonce, which the
// matrix seed masks away). Mirrors hoohashv110_core() per lane.
static void hoohashv110_core_lanes(const uint8_t data[HOO_LANES][80], double mat[64][64],
                                   uint8_t output[HOO_LANES][HOOHASH_HASH_SIZE])
{
    uint8_t firstPass[HOO_LANES][HOOHASH_HASH_SIZE];
    uint64_t nonce[HOO_LANES];

    for (int l = 0; l < HOO_LANES; l++) {
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, data[l], 80);
        blake3_hasher_finalize(&hasher, firstPass[l], HOOHASH_HASH_SIZE);
        nonce[l] = (uint64_t)read_uint32_le(data[l] + 76);
    }

#ifdef HOO_SIMD
    HoohashMatrixMultiplicationV(mat, firstPass, output, nonce);
#else
    HoohashMatrixMultiplicationN(mat, firstPass, output, nonce);
#endif
}
#endif   /* HOO_LANES > 1 */

// cpuminer entry point: `input` is the 80-byte serialized header. Standalone
// (self-test / gate->hash) path, so it pays for its own matrix.
int hoohashv110_hash( void *output, const void *input, int thr_id )
{
    double mat[64][64];

    (void)thr_id;
    hoohash_matrix_gen( (const uint8_t*)input, mat );
    hoohashv110_core( (const uint8_t*)input, mat, (uint8_t*)output );
    return 1;
}

// ---------------------------------------------------------------------------
// Known-answer self-test + a CRITICAL caveat on this algorithm's determinism.
//
// The matrix multiply feeds sin/cos/exp arguments that routinely reach ~1e16
// (|arg| up to ~3e16 measured). libm argument-reduction at that magnitude is
// NOT portable: different glibc *versions* return different last-ULP results,
// and one divergent transcendental flips the whole digest. So this PoW is
// inherently libm-version-sensitive — "bit-identical across platforms" only
// holds when both sides link compatible libm. Consensus == whatever libm
// PePe-core (the validating daemon) links; matching it is the real requirement,
// and only LIVE POOL shares prove it.
//
// EMPIRICAL FINDINGS:
//  - The anchor header below hashes to a64993e8... bit-identically on x86-64
//    glibc 2.35 AND aarch64 glibc (NanoPi R6S). Stable -> used as the KAT.
//  - Synthetic uniform-random headers (splitmix64) DIVERGED between glibc 2.35
//    and newer glibc (they hit the ~1e16 sin regime), so they are NOT shipped
//    as a hard gate — they live in scratchpad/gen_vectors.c (set NSPLIT>0) for
//    DIAGNOSTIC cross-platform divergence testing only.
//  - A KAT generated with MinGW's libm was simply wrong; never use non-glibc.
//
// The shipped KAT is therefore a regression guard (the miner refuses to start on
// mismatch), NOT a proof of consensus. Two vectors, with distinct jobs:
//   [0] anchor       - the original stable BTC-style header.
//   [1] FMA sentinel - fails closed if the compiler stops contracting to FMA,
//                      which [0] cannot detect. See hoohash-kat.h.
// TODO: augment with a REAL PePePoW block's (header -> known hash) once available.
// If the pool rejects a *fraction* of shares (not all -> that'd be byte order),
// suspect FMA-contraction mismatch (check vector [1]) or this libm divergence;
// the fix for the latter is bundling a fixed transcendental impl matching PePe-core.
// ---------------------------------------------------------------------------
// KAT machine-generated on x86-64 glibc by scratchpad/gen_vectors.c (which links
// this same hoohashv110_hash). Regenerate with that tool; never hand-edit.
// Defines HOOHASH_KAT_COUNT, hoohashv110_kat_input[][80], _kat_expected[][32].
#include "hoohash-kat.h"

bool hoohashv110_self_test( void )
{
   for ( int v = 0; v < HOOHASH_KAT_COUNT; v++ )
   {
      uint8_t hash[32];
      hoohashv110_hash( hash, hoohashv110_kat_input[v], 0 );

      if ( memcmp( hash, hoohashv110_kat_expected[v], 32 ) != 0 )
      {
         char got[65], exp[65];
         for ( int i = 0; i < 32; i++ )
         {
            sprintf( got + i * 2, "%02x", hash[i] );
            sprintf( exp + i * 2, "%02x", hoohashv110_kat_expected[v][i] );
         }
         applog( LOG_ERR, "HoohashV110 self-test FAILED at vector %d "
                          "(FP/consensus mismatch)", v );
         applog( LOG_ERR, "  got:      %s", got );
         applog( LOG_ERR, "  expected: %s", exp );
         return false;
      }
   }

#if HOO_LANES > 1
   // The batched path scanhash uses must reproduce the scalar path byte for byte.
   // A few dozen hashes, and it catches a codegen divergence (e.g. different FMA
   // contraction in the wider loop) before a share is submitted.
   uint8_t hdr[HOO_LANES][80], want[HOO_LANES][32], got[HOO_LANES][32];
   double mat[64][64];

   for ( int g = 0; g < 4; g++ )
   {
      for ( int l = 0; l < HOO_LANES; l++ )
      {
         uint32_t n = 1 + g * HOO_LANES + l;
         memcpy( hdr[l], hoohashv110_kat_input[0], 80 );
         hdr[l][76] =   n         & 0xff;
         hdr[l][77] = ( n >>  8 ) & 0xff;
         hdr[l][78] = ( n >> 16 ) & 0xff;
         hdr[l][79] = ( n >> 24 ) & 0xff;
         hoohashv110_hash( want[l], hdr[l], 0 );
      }

      hoohash_matrix_gen( hdr[0], mat );          // lanes share bytes 0..75
      hoohashv110_core_lanes( (const uint8_t (*)[80])hdr, mat, got );

      for ( int l = 0; l < HOO_LANES; l++ )
         if ( memcmp( want[l], got[l], 32 ) != 0 )
         {
            applog( LOG_ERR, "HoohashV110 %d-way differential FAILED: group %d lane %d",
                    HOO_LANES, g, l );
            return false;
         }
   }

   applog( LOG_NOTICE,
           "HoohashV110 self-test PASSED (%d/%d glibc KAT vectors + %d-way differential)",
           HOOHASH_KAT_COUNT, HOOHASH_KAT_COUNT, HOO_LANES );
#else
   applog( LOG_NOTICE, "HoohashV110 self-test PASSED (%d/%d glibc KAT vectors)",
           HOOHASH_KAT_COUNT, HOOHASH_KAT_COUNT );
#endif
   return true;
}

// ---------------------------------------------------------------------------
// scanhash
//
// CONSENSUS byte order — VERIFIED against a real PePePoW block (height ~0x4734dd,
// 2026-06-28; see scratchpad/verify_block.c + fulltest_harness.c):
//   * Input:  be32enc the 19 header words + nonce. Combined with the standard
//     stratum work-builder (std_build_block_header), this reconstructs the
//     daemon's raw 80-byte serialization byte-for-byte (e.g. version word
//     0x00400020 -> bytes 00 40 00 20). The winning nonce only validates with
//     this exact input.
//   * Output: HoohashV110 (Hoosat/Kaspa-family) compares the digest as a
//     BIG-ENDIAN 256-bit number (byte 0 = MSB) — the OPPOSITE of Bitcoin's
//     reversed convention. cpuminer's valid_hash treats the digest as
//     little-endian uint32 words (word 7 = MSB), so we byte-REVERSE the digest
//     before valid_hash / submit. (Proven: the real block's winning nonce lands
//     under target only after this reversal; a tampered nonce fails.)
// ---------------------------------------------------------------------------
int scanhash_hoohashv110( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hashbe[8];
   uint32_t _ALIGN(64) edata[HOO_LANES][20];
   uint8_t  _ALIGN(64) digest[HOO_LANES][HOOHASH_HASH_SIZE];
   double   _ALIGN(64) mat[64][64];   // 32 KB, job-constant (see hoohash_matrix_gen)
   /* HOO_LANES == 1 keeps the plain scalar loop -- see the note above it. */
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - HOO_LANES;
   const uint32_t targ32 = ptarget[7];
   const int thr_id = mythr->id;
   uint32_t n = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   for ( int i = 0; i < 19; i++ )
      be32enc( &edata[0][i], pdata[i] );
   for ( int l = 1; l < HOO_LANES; l++ )
      memcpy( edata[l], edata[0], 76 );

   // The matrix seed masks the nonce away, so the matrix is constant for this
   // entire nonce range -- build it once here, not once per nonce.
   hoohash_matrix_gen( (const uint8_t*)edata[0], mat );

   do
   {
      for ( int l = 0; l < HOO_LANES; l++ )
         be32enc( &edata[l][19], n + l );

#if HOO_LANES > 1
      hoohashv110_core_lanes( (const uint8_t (*)[80])edata, mat, digest );
#else
      hoohashv110_core( (const uint8_t*)edata[0], mat, digest[0] );
#endif

      for ( int l = 0; l < HOO_LANES; l++ )
      {
         // The digest is big-endian, so its most significant word is bytes 0..3.
         // valid_hash can only pass if that word is under target, so test it
         // before paying for the full byte reversal.
         if ( unlikely( be32dec( digest[l] ) <= targ32 ) )
         {
            // Big-endian digest -> little-endian words for cpuminer's comparator.
            for ( int i = 0; i < 32; i++ )
               ( (uint8_t*)hashbe )[i] = digest[l][31 - i];

            if ( valid_hash( hashbe, ptarget ) && !bench )
            {
               pdata[19] = n + l;
               submit_solution( work, hashbe, mythr );
            }
         }
      }
      n += HOO_LANES;
   } while ( n < last_nonce && !(*restart) );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

bool register_hoohashv110_algo( algo_gate_t *gate )
{
   if ( !hoohashv110_self_test() )
   {
      applog( LOG_ERR, "HoohashV110 self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_hoohashv110;
   gate->hash          = (void*)&hoohashv110_hash;
   gate->optimizations = SSE2_OPT | AVX2_OPT | NEON_OPT;
   // Plain 256-bit-output hash: standard Bitcoin difficulty scale (0xffff base).
   // (A 256.0 factor would make targetdiff 256x too easy -> pool rejects shares
   // as "low difficulty"; see the skydoge port notes.)
   opt_target_factor   = 1.0;
   return true;
}
