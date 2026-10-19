#ifndef RANDOMX_BUILDINFO_H
#define RANDOMX_BUILDINFO_H

/* Compile-time build selections of librandomx.a, reported from inside the
 * library. See randomx-buildinfo.cpp for why this cannot be asked elsewhere.
 */

#ifdef __cplusplus
extern "C" {
#endif

int randomx_build_have_aes(void);
int randomx_build_have_compiler(void);
int randomx_build_have_argon2_ssse3(void);
int randomx_build_have_argon2_avx2(void);
const char *randomx_build_jit_arch(void);
const char *randomx_build_simd(void);

/* Configuration values that differ between variant cores. Asked of the
 * library rather than read from configuration.h by the caller: the caller is
 * compiled once against the STOCK configuration, so its macros describe rx/0
 * no matter which core is selected. Getting this wrong understates a variant's
 * huge-page requirement instead of failing. */
unsigned long randomx_build_scratchpad_size(void);
unsigned long randomx_build_program_count(void);
unsigned long randomx_build_program_iterations(void);
/* The salt length THIS core will actually use: its compile-time default,
 * or a runtime override if one was applied to this core. */
unsigned long randomx_build_argon_salt_len(void);
/* Cache size in KiB. Not every variant uses 256 MiB, and the huge-page
 * advice sums it per thread. */
unsigned long randomx_build_argon_memory(void);
/* Program size in instructions; the v1 value, as v2 is not mined here. */
unsigned long randomx_build_program_size(void);
/* A variant's startup banner must differ from rx/0's in at least one field or
 * a misbuilt core cannot be spotted by eye, and some variants change only
 * these two, so both are reported for every core. */
unsigned long randomx_build_argon_iterations(void);
unsigned long randomx_build_superscalar_latency(void);

#ifdef __cplusplus
}
#endif

#endif /* RANDOMX_BUILDINFO_H */
