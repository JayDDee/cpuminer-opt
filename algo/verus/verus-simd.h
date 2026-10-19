/* Decides whether VerusHash can be built for this target and which intrinsic
 * header the vendored sources get. x86 needs hardware AES + carryless multiply;
 * aarch64 does not, since verus-neon.h can emulate both. Otherwise the whole
 * implementation compiles out and register_verus_algo() says why. */
#ifndef VERUS_SIMD_H
#define VERUS_SIMD_H

#if defined(__AES__) && defined(__PCLMUL__)

#define VERUS_HAVE_SIMD 1
#include <immintrin.h>

#elif defined(__aarch64__) && defined(__ARM_NEON)

#define VERUS_HAVE_SIMD 1
/* upstream's own "not x86" macro; it already guards the cpuid helper in
 * verus_clhash.h, which is x86-only and unused here. */
#define ARM 1
/* sets VERUS_AES_EMULATED / VERUS_PMULL_EMULATED, which the gate reports */
#include "verus-neon.h"

#endif

#endif  /* VERUS_SIMD_H */
