/* Reports which compile-time paths the vendored RandomX core was actually built
 * with. This file MUST be compiled into librandomx.a, with the library's own
 * flags -- asking these macros from any other translation unit gives that TU's
 * answer, which is a different question and has silently lied before.
 *
 * randomx_get_flags() cannot substitute: it ANDs the compile-time answer with
 * runtime CPUID, so a zero there is ambiguous between "not compiled in" and
 * "this CPU lacks it".
 */

#include "randomx-buildinfo.h"

#include "randomx/intrin_portable.h"   /* defines HAVE_AES (0 or 1) */
#include "randomx/common.hpp"          /* defines RANDOMX_HAVE_COMPILER */
#include "randomx/argon2.h"            /* randomx_argon2_impl_{ssse3,avx2}() */

extern "C" {

int randomx_build_have_aes(void)      { return HAVE_AES ? 1 : 0; }
int randomx_build_have_compiler(void) { return RANDOMX_HAVE_COMPILER ? 1 : 0; }

int randomx_build_have_argon2_ssse3(void)
{
	return randomx_argon2_impl_ssse3() != NULL ? 1 : 0;
}

int randomx_build_have_argon2_avx2(void)
{
	return randomx_argon2_impl_avx2() != NULL ? 1 : 0;
}

const char *randomx_build_jit_arch(void)
{
#if defined(_M_X64) || defined(__x86_64__)
	return "x86-64";
#elif defined(__aarch64__)
	return "aarch64";
#else
	return "none (interpreter only)";
#endif
}

const char *randomx_build_simd(void)
{
#if defined(__AVX2__)
	return "avx2";
#elif defined(__SSSE3__)
	return "ssse3";
#elif defined(__SSE2__)
	return "sse2";
#elif defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES)
	return "neon+crypto";
#elif defined(__ARM_NEON)
	return "neon";
#else
	return "portable";
#endif
}

/* This TU is compiled once per variant core, so these report the constants
 * THIS core was built with -- which is the whole point: a caller reading
 * configuration.h directly always gets rx/0's values. */
unsigned long randomx_build_scratchpad_size(void)
{
	return (unsigned long)RANDOMX_SCRATCHPAD_L3;
}

unsigned long randomx_build_program_count(void)
{
	return (unsigned long)RANDOMX_PROGRAM_COUNT;
}

unsigned long randomx_build_program_iterations(void)
{
	return (unsigned long)RANDOMX_PROGRAM_ITERATIONS;
}

/* Defined in this core's dataset.cpp; each core has its own copy, so this
 * reports the salt in force for THIS core rather than the stock one. */
extern const unsigned char *randomx_argon_salt;
extern unsigned int         randomx_argon_salt_len;

unsigned long randomx_build_argon_salt_len(void)
{
	(void)randomx_argon_salt;
	return (unsigned long)randomx_argon_salt_len;
}

unsigned long randomx_build_argon_memory(void)
{
	return (unsigned long)RANDOMX_ARGON_MEMORY;
}

unsigned long randomx_build_program_size(void)
{
	return (unsigned long)RANDOMX_PROGRAM_SIZE_V1;
}

unsigned long randomx_build_argon_iterations(void)
{
	return (unsigned long)RANDOMX_ARGON_ITERATIONS;
}

unsigned long randomx_build_superscalar_latency(void)
{
	return (unsigned long)RANDOMX_SUPERSCALAR_LATENCY;
}

} /* extern "C" */
