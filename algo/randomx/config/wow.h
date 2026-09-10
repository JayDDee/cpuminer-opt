/* RandomWOW (Wownero) -- pool algo "rx/wow".
 *
 * Tier 2: moves scratchpad sizes, program iterations/count and eight
 * instruction frequencies. Those are constexpr in the core's common.hpp and
 * the L3 size is an immediate in jit_compiler_x86_static.S, so this variant
 * gets its own compiled core and this header is injected into it. Injecting
 * it into the shared core would corrupt rx/0.
 *
 * Constants from the consensus source:
 *   wownero/wownero .gitmodules -> external/randomwow
 *       -> codeberg.org/wownero/RandomWOW   (Codeberg, not GitHub)
 *   pinned commit 27b099b6dd6fef6e17f58c6dfe00009e9c5df587,
 *   src/configuration.h and src/aes_hash.cpp
 * Everything not listed below matches rx/0.
 *
 * Mined with RANDOMX_FLAG_V2 clear, as rx/0 is. RandomWOW forked an older
 * RandomX with a single RANDOMX_PROGRAM_SIZE of 256, which is our _V1
 * default and so is not overridden.
 */

#ifndef CPUMINER_RANDOMX_CONFIG_WOW_H
#define CPUMINER_RANDOMX_CONFIG_WOW_H

#define RANDOMX_ARGON_SALT         "RandomWOW\x01"

#define RANDOMX_PROGRAM_ITERATIONS 1024
#define RANDOMX_PROGRAM_COUNT      16

#define RANDOMX_SCRATCHPAD_L3      1048576
#define RANDOMX_SCRATCHPAD_L2      131072
/* L1 is 16384 in both and is deliberately not overridden. */

/* Eight of the thirty frequencies differ; the rest match rx/0. */
#define RANDOMX_FREQ_IADD_RS       25
#define RANDOMX_FREQ_IROR_R        10
#define RANDOMX_FREQ_IROL_R         0
#define RANDOMX_FREQ_FSWAP_R        8
#define RANDOMX_FREQ_FADD_R        20
#define RANDOMX_FREQ_FSUB_R        20
#define RANDOMX_FREQ_FMUL_R        20
#define RANDOMX_FREQ_CBRANCH       16

/* AesGenerator4R round keys 0-3 differ; 4-7 match rx/0 and are not
 * overridden. These live in aes_hash.cpp, NOT configuration.h, which is why
 * that file's constants are #ifndef-wrapped too: a variant wired from
 * configuration.h alone would hash wrongly with no other symptom. */
#define AES_GEN_4R_KEY0 0xcf359e95, 0x141f82b7, 0x7ffbe4a6, 0xf890465d
#define AES_GEN_4R_KEY1 0x6741ffdc, 0xbd5c5ac3, 0xfee8278a, 0x6a55c450
#define AES_GEN_4R_KEY2 0x3d324aac, 0xa7279ad2, 0xd524fde4, 0x114c47a4
#define AES_GEN_4R_KEY3 0x76f6db08, 0x42d3dbd9, 0x99a9aeff, 0x810c3a2a

#endif
