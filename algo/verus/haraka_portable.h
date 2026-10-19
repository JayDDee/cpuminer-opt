/* Haraka software-AES reference implementation. MIT, (c) 2016 kste. */
#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

#include "verus-simd.h"   /* immintrin.h on x86, verus-neon.h on aarch64 */

#define NUMROUNDS 5

#ifdef _WIN32
typedef unsigned long long u64;
#else
typedef unsigned long u64;
#endif
typedef __m128i u128;

/* EDIT (vendoring): upstream has no extern "C" guards, so including this from
 * C++ mangles every declaration, and the portable path then cannot link against
 * a C-compiled haraka_portable.c. */
#ifdef __cplusplus
extern "C" {
#endif

extern void aesenc(unsigned char *s, const unsigned char *rk);

#define AES2_EMU(s0, s1, rci) \
  aesenc((unsigned char *)&s0, (unsigned char *)&(rc[rci])); \
  aesenc((unsigned char *)&s1, (unsigned char *)&(rc[rci + 1])); \
  aesenc((unsigned char *)&s0, (unsigned char *)&(rc[rci + 2])); \
  aesenc((unsigned char *)&s1, (unsigned char *)&(rc[rci + 3]));

typedef unsigned int uint32_t;

static inline __m128i _mm_unpacklo_epi32_emu(__m128i a, __m128i b)
{
    uint32_t result[4];
    uint32_t *tmp1 = (uint32_t *)&a, *tmp2 = (uint32_t *)&b;
    result[0] = tmp1[0];
    result[1] = tmp2[0];
    result[2] = tmp1[1];
    result[3] = tmp2[1];
    return *(__m128i *)result;
}

static inline __m128i _mm_unpackhi_epi32_emu(__m128i a, __m128i b)
{
    uint32_t result[4];
    uint32_t *tmp1 = (uint32_t *)&a, *tmp2 = (uint32_t *)&b;
    result[0] = tmp1[2];
    result[1] = tmp2[2];
    result[2] = tmp1[3];
    result[3] = tmp2[3];
    return *(__m128i *)result;
}

#define MIX2_EMU(s0, s1) \
  tmp = _mm_unpacklo_epi32_emu(s0, s1); \
  s1 = _mm_unpackhi_epi32_emu(s0, s1); \
  s0 = tmp;

/* load constants */
void load_constants_port();

/* Haraka-512 with caller-supplied round constants, full 32-byte output. The
 * AES-NI haraka512_keyed is truncated to out[28..31], so candidates are
 * re-hashed here to get the whole digest. */
void haraka512_port_keyed(unsigned char *out, const unsigned char *in, const u128 *rc);

#ifdef __cplusplus
}
#endif

#endif
